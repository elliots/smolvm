//! A machine's RAM base: the RAM image of its last pause, kept in the
//! machine's data directory while it runs again, so that its next pause
//! writes only the 4 KiB pages that changed.
//!
//! `ram-base/memory.bin` is the image in the format the VMM writes and a
//! resume reads, sparse, service-owned and read-only. A local checkpoint's
//! `checkpoint/memory.bin` is a hard link to it. `ram-base/index.bin` holds,
//! per page, whether it reads as zeros, and otherwise a seeded XXH3-128 that
//! tells whether the page changed; and per 2 MiB block the SHA-256 of what is
//! on disk.
//!
//! A delta pause marks the index `applying`, sends the VMM the page table
//! (`FINISH_SAVE_DELTA`), and, for each block the VMM streams back, writes
//! its changed pages at their offsets in the base, punching holes for zeros.
//! It then hashes each changed block again from the base. The VMM never gets
//! a descriptor of the base. Each entry of the index is computed from the
//! bytes written, so the index stays true for every page written so far,
//! however the stream ends. An index left `applying` (the process died while
//! writing) drops the base, and the next pause writes the image in full.
//!
//! The index format, little-endian: a 4 KiB header of `SMOLRBX1`, version
//! u32, state u32 (0 clean, 1 applying), block size u64, page size u64, image
//! length u64, seed u64, generation u64, SHA-256 of the image's region layout
//! (32 bytes), block count u64 and page count u64, zero-padded; then per
//! block a state byte (0 unknown, 1 hole, 2 data) and the SHA-256 (32 bytes);
//! then per page a state byte and the XXH3-128 (16 bytes). A delta rewrites
//! the index in place, the header last.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::{Error, Result};

use super::RAM_BASE_DIR;
/// The block size of the index's digests and of a delta's frames.
pub(crate) const BLOCK: u64 = 2 << 20;
/// The page size of change detection.
pub(crate) const PAGE: u64 = 4096;
const BLOCK_PAGES: usize = (BLOCK / PAGE) as usize;
const BITMAP: usize = BLOCK_PAGES / 8;
const MEMORY: &str = "memory.bin";
const INDEX: &str = "index.bin";
const INDEX_MAGIC: &[u8; 8] = b"SMOLRBX1";
const INDEX_VERSION: u32 = 2;
const INDEX_HEADER: usize = PAGE as usize;
const INDEX_FIELDS: usize = 104;
const BLOCK_ENTRY: usize = 33;
const PAGE_ENTRY: usize = 17;
/// The VMM's page table and stream (libkrun `vmm::snapshot::delta`).
const TABLE_MAGIC: &[u8; 8] = b"SMOLDTB2";
const TABLE_HEADER: usize = 48;
pub(crate) const STREAM_MAGIC: &[u8; 8] = b"SMOLDLT2";
const FRAME_ABORT: u8 = 0;
const FRAME_PAGES: u8 = 1;
const FRAME_END: u8 = 3;
const THREADS: usize = 4;

/// What a page of the base holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PageState {
    /// Not known, for example because a write of it failed: the next delta
    /// writes it again.
    Unknown,
    /// Reads as zeros.
    Hole,
    /// Data, with the hash in its entry.
    Data,
}

/// One page's entry in the index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PageEntry {
    pub state: PageState,
    pub xxh3: u128,
}

impl PageEntry {
    pub const UNKNOWN: Self = Self {
        state: PageState::Unknown,
        xxh3: 0,
    };
    pub const HOLE: Self = Self {
        state: PageState::Hole,
        xxh3: 0,
    };

    /// The entry of a page holding `bytes`.
    pub fn of(bytes: &[u8], seed: u64) -> Self {
        if is_zero(bytes) {
            return Self::HOLE;
        }
        Self {
            state: PageState::Data,
            xxh3: xxhash_rust::xxh3::xxh3_128_with_seed(bytes, seed),
        }
    }
}

/// The SHA-256 of a block of the base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockDigest {
    /// Not known: the block was written and not hashed again yet.
    Unknown,
    /// Reads as zeros.
    Hole,
    Data([u8; 32]),
}

impl BlockDigest {
    /// The digest of a block holding `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        if is_zero(bytes) {
            return Self::Hole;
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
        Self::Data(digest.as_ref().try_into().expect("SHA-256 is 32 bytes"))
    }

    /// The lowercase hex SHA-256 of a data block, or an empty string for a hole.
    pub fn sha256_hex(&self) -> String {
        match self {
            Self::Data(sha256) => hex::encode(sha256),
            _ => String::new(),
        }
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    // SAFETY: any bit pattern is a valid u128.
    let (head, body, tail) = unsafe { bytes.align_to::<u128>() };
    head.iter().all(|&b| b == 0) && body.iter().all(|&w| w == 0) && tail.iter().all(|&b| b == 0)
}

/// The block digests and page entries of an image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ImageHashes {
    pub blocks: Vec<BlockDigest>,
    pub pages: Vec<PageEntry>,
}

/// Whether the index describes the base, or the base is being written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IndexState {
    Clean,
    Applying,
}

/// The index of a RAM base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RamIndex {
    pub state: IndexState,
    pub image_len: u64,
    pub seed: u64,
    /// Incremented by each write of the index.
    pub generation: u64,
    /// SHA-256 of the `manifest.bin` that described the image's regions.
    pub layout_sha256: [u8; 32],
    pub blocks: Vec<BlockDigest>,
    pub pages: Vec<PageEntry>,
}

fn invalid(reason: impl Into<String>) -> Error {
    Error::agent("read RAM base", reason.into())
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

impl RamIndex {
    pub fn new(image_len: u64, seed: u64, layout_sha256: [u8; 32], hashes: ImageHashes) -> Self {
        Self {
            state: IndexState::Clean,
            image_len,
            seed,
            generation: 0,
            layout_sha256,
            blocks: hashes.blocks,
            pages: hashes.pages,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            INDEX_HEADER + self.blocks.len() * BLOCK_ENTRY + self.pages.len() * PAGE_ENTRY,
        );
        bytes.extend_from_slice(INDEX_MAGIC);
        bytes.extend_from_slice(&INDEX_VERSION.to_le_bytes());
        let state: u32 = match self.state {
            IndexState::Clean => 0,
            IndexState::Applying => 1,
        };
        bytes.extend_from_slice(&state.to_le_bytes());
        for value in [BLOCK, PAGE, self.image_len, self.seed, self.generation] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&self.layout_sha256);
        for value in [self.blocks.len() as u64, self.pages.len() as u64] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        debug_assert_eq!(bytes.len(), INDEX_FIELDS);
        bytes.resize(INDEX_HEADER, 0);
        for block in &self.blocks {
            let (state, sha256) = match block {
                BlockDigest::Unknown => (0, [0; 32]),
                BlockDigest::Hole => (1, [0; 32]),
                BlockDigest::Data(sha256) => (2, *sha256),
            };
            bytes.push(state);
            bytes.extend_from_slice(&sha256);
        }
        for page in &self.pages {
            bytes.push(match page.state {
                PageState::Unknown => 0,
                PageState::Hole => 1,
                PageState::Data => 2,
            });
            bytes.extend_from_slice(&page.xxh3.to_le_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 || &bytes[..8] != INDEX_MAGIC {
            return Err(invalid("not a RAM base index"));
        }
        if le_u32(bytes, 8) != INDEX_VERSION {
            return Err(invalid("unknown RAM base index version"));
        }
        if bytes.len() < INDEX_HEADER {
            return Err(invalid("RAM base index is truncated"));
        }
        let state = match le_u32(bytes, 12) {
            0 => IndexState::Clean,
            1 => IndexState::Applying,
            _ => return Err(invalid("unknown RAM base index state")),
        };
        if le_u64(bytes, 16) != BLOCK || le_u64(bytes, 24) != PAGE {
            return Err(invalid("unsupported RAM base block or page size"));
        }
        let image_len = le_u64(bytes, 32);
        let block_count = le_u64(bytes, 88);
        let page_count = le_u64(bytes, 96);
        let expected = INDEX_HEADER as u128
            + block_count as u128 * BLOCK_ENTRY as u128
            + page_count as u128 * PAGE_ENTRY as u128;
        if block_count != image_len.div_ceil(BLOCK)
            || page_count != image_len.div_ceil(PAGE)
            || bytes.len() as u128 != expected
        {
            return Err(invalid("RAM base index does not match its image length"));
        }
        let pages_at = INDEX_HEADER + block_count as usize * BLOCK_ENTRY;
        let blocks = bytes[INDEX_HEADER..pages_at]
            .as_chunks::<BLOCK_ENTRY>()
            .0
            .iter()
            .map(|entry| match entry[0] {
                0 => Ok(BlockDigest::Unknown),
                1 => Ok(BlockDigest::Hole),
                2 => Ok(BlockDigest::Data(entry[1..].try_into().unwrap())),
                _ => Err(invalid("unknown RAM base block state")),
            })
            .collect::<Result<_>>()?;
        let pages = bytes[pages_at..]
            .as_chunks::<PAGE_ENTRY>()
            .0
            .iter()
            .map(|entry| {
                let state = match entry[0] {
                    0 => PageState::Unknown,
                    1 => PageState::Hole,
                    2 => PageState::Data,
                    _ => return Err(invalid("unknown RAM base page state")),
                };
                Ok(PageEntry {
                    state,
                    xxh3: u128::from_le_bytes(entry[1..].try_into().unwrap()),
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            state,
            image_len,
            seed: le_u64(bytes, 40),
            generation: le_u64(bytes, 48),
            layout_sha256: bytes[56..88].try_into().unwrap(),
            blocks,
            pages,
        })
    }

    /// The page table a VMM's `FINISH_SAVE_DELTA` reads.
    pub fn table(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TABLE_HEADER + self.pages.len() * PAGE_ENTRY);
        bytes.extend_from_slice(TABLE_MAGIC);
        for value in [
            BLOCK,
            PAGE,
            self.image_len,
            self.seed,
            self.pages.len() as u64,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for page in &self.pages {
            let (state, hash) = match page.state {
                PageState::Unknown => (0_u8, 0),
                PageState::Hole => (1, 0),
                PageState::Data => (2, page.xxh3),
            };
            bytes.push(state);
            bytes.extend_from_slice(&hash.to_le_bytes());
        }
        bytes
    }
}

/// A random XXH3 seed for a base written in full.
pub(crate) fn new_seed() -> u64 {
    let mut seed = [0_u8; 8];
    if let Err(error) = getrandom::fill(&mut seed) {
        tracing::warn!(%error, "no random seed for the RAM base; using the clock");
        return std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64);
    }
    u64::from_le_bytes(seed)
}

/// The SHA-256 of a file's bytes, such as the image's `manifest.bin`.
pub(crate) fn file_sha256(path: &Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path)?;
    Ok(ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes"))
}

/// The first offset at or after `offset` in `file` that holds data, or `None`.
fn next_data(file: &File, offset: u64) -> Result<Option<u64>> {
    let data = unsafe { libc::lseek(file.as_raw_fd(), offset as libc::off_t, libc::SEEK_DATA) };
    if data >= 0 {
        return Ok(Some(data as u64));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENXIO) {
        return Ok(None);
    }
    Err(error.into())
}

/// Read each of `blocks` of the image in `file` on four threads and map it
/// with `map`, in order. A block with no data extent is mapped from `None`
/// without being read.
fn map_blocks<T: Send>(
    file: &File,
    blocks: &[u64],
    map: impl Fn(Option<&[u8]>) -> T + Sync,
) -> Result<Vec<T>> {
    let len = file.metadata()?.len();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let work = || -> Result<Vec<(usize, T)>> {
        let mut done = Vec::new();
        let mut buffer = vec![0_u8; BLOCK as usize];
        loop {
            let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let Some(&block) = blocks.get(at) else {
                return Ok(done);
            };
            let start = block * BLOCK;
            let end = (start + BLOCK).min(len);
            if start >= end {
                return Err(invalid("a RAM base block lies past the image"));
            }
            let mapped = match next_data(file, start)? {
                Some(data) if data < end => {
                    let bytes = &mut buffer[..(end - start) as usize];
                    file.read_exact_at(bytes, start)?;
                    map(Some(bytes))
                }
                _ => map(None),
            };
            done.push((at, mapped));
        }
    };
    let mut mapped: Vec<Option<T>> = std::iter::repeat_with(|| None).take(blocks.len()).collect();
    std::thread::scope(|scope| -> Result<()> {
        let workers: Vec<_> = (0..THREADS).map(|_| scope.spawn(work)).collect();
        for worker in workers {
            let done = worker
                .join()
                .map_err(|_| Error::agent("hash RAM image", "hash thread panicked"))??;
            for (at, value) in done {
                mapped[at] = Some(value);
            }
        }
        Ok(())
    })?;
    Ok(mapped
        .into_iter()
        .map(|value| value.expect("every block is mapped"))
        .collect())
}

/// Hash every block and page of the image in `file` on four threads. Blocks
/// with no data extent are holes without being read.
pub(crate) fn hash_image(file: &File, seed: u64) -> Result<ImageHashes> {
    let len = file.metadata()?.len();
    let all: Vec<u64> = (0..len.div_ceil(BLOCK)).collect();
    let hashed = map_blocks(file, &all, |bytes| match bytes {
        Some(bytes) => (
            BlockDigest::of(bytes),
            bytes
                .chunks(PAGE as usize)
                .map(|page| PageEntry::of(page, seed))
                .collect(),
        ),
        None => (BlockDigest::Hole, Vec::new()),
    })?;
    let mut hashes = ImageHashes {
        blocks: Vec::with_capacity(hashed.len()),
        pages: Vec::with_capacity(len.div_ceil(PAGE) as usize),
    };
    for (block, (digest, pages)) in hashed.into_iter().enumerate() {
        hashes.blocks.push(digest);
        if pages.is_empty() {
            let start = block as u64 * BLOCK;
            let count = ((len - start).min(BLOCK)).div_ceil(PAGE) as usize;
            hashes
                .pages
                .extend(std::iter::repeat_n(PageEntry::HOLE, count));
        } else {
            hashes.pages.extend(pages);
        }
    }
    Ok(hashes)
}

/// The SHA-256 of every block of the image in `file`, hashed on four threads.
pub(crate) fn block_digests(file: &File) -> Result<Vec<BlockDigest>> {
    let all: Vec<u64> = (0..file.metadata()?.len().div_ceil(BLOCK)).collect();
    map_blocks(file, &all, |bytes| {
        bytes.map_or(BlockDigest::Hole, BlockDigest::of)
    })
}

/// Hash again, from the base, every block whose digest is unknown, such as
/// the blocks a delta wrote. The base's pages are in the page cache. Returns
/// the blocks hashed.
pub(crate) fn refresh_digests(memory: &File, index: &mut RamIndex) -> Result<u64> {
    let stale: Vec<u64> = (0..index.blocks.len() as u64)
        .filter(|&block| index.blocks[block as usize] == BlockDigest::Unknown)
        .collect();
    let digests = map_blocks(memory, &stale, |bytes| {
        bytes.map_or(BlockDigest::Hole, BlockDigest::of)
    })?;
    for (&block, digest) in stale.iter().zip(digests) {
        index.blocks[block as usize] = digest;
    }
    Ok(stale.len() as u64)
}

/// A machine's RAM base, in `<vm data>/ram-base`.
#[derive(Clone, Debug)]
pub(crate) struct RamBase {
    dir: PathBuf,
}

impl RamBase {
    pub fn of(vm_data: &Path) -> Self {
        Self {
            dir: vm_data.join(RAM_BASE_DIR),
        }
    }

    pub fn memory_path(&self) -> PathBuf {
        self.dir.join(MEMORY)
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join(INDEX)
    }

    /// The index, or `None` when there is no base.
    pub fn load(&self) -> Result<Option<RamIndex>> {
        match std::fs::read(self.index_path()) {
            Ok(bytes) => RamIndex::decode(&bytes).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// The index of a base a delta can write into: clean, of this version,
    /// with a protected image of the length it describes. Anything else is
    /// `None`, and the pause writes the image in full.
    pub fn usable(&self) -> Option<RamIndex> {
        let index = match self.load() {
            Ok(Some(index)) => index,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(%error, base = %self.dir.display(), "the RAM base index is unreadable; the pause saves in full");
                return None;
            }
        };
        if index.state != IndexState::Clean {
            tracing::warn!(base = %self.dir.display(), "the RAM base was being written when its writer stopped; the pause saves in full");
            return None;
        }
        match self.check_memory(index.image_len) {
            Ok(()) => Some(index),
            Err(error) => {
                tracing::warn!(%error, base = %self.dir.display(), "the RAM base is not usable; the pause saves in full");
                None
            }
        }
    }

    fn check_memory(&self, len: u64) -> Result<()> {
        let directory = std::fs::symlink_metadata(&self.dir)?;
        let memory = std::fs::symlink_metadata(self.memory_path())?;
        let euid = unsafe { libc::geteuid() };
        if !directory.is_dir() || directory.uid() != euid || directory.mode() & 0o077 != 0 {
            return Err(invalid(
                "the RAM base directory must be a private service directory",
            ));
        }
        if !memory.is_file() || memory.uid() != euid || memory.mode() & 0o222 != 0 {
            return Err(invalid(
                "the RAM base image must be a protected regular file",
            ));
        }
        if memory.len() != len {
            return Err(invalid(
                "the RAM base image does not have its index's length",
            ));
        }
        Ok(())
    }

    /// Open the image for a delta to write into, and to hash it again.
    pub fn open_for_writing(&self) -> Result<File> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.memory_path())?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(invalid(
                "the RAM base image must be a regular service-owned file",
            ));
        }
        Ok(file)
    }

    /// Write `index` in place of the current one, durably.
    pub fn write_index(&self, index: &RamIndex) -> Result<()> {
        let partial = self.dir.join(format!(".{INDEX}.partial"));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&partial)?;
        file.write_all(&index.encode())?;
        file.sync_data()?;
        std::fs::rename(&partial, self.index_path())?;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Mark `index`, the clean index of this base, `applying`, in place.
    /// Returns the index's bytes as they now are on disk.
    pub fn mark_applying(&self, index: &mut RamIndex) -> Result<Vec<u8>> {
        let on_disk = std::fs::read(self.index_path())?;
        index.state = IndexState::Applying;
        index.generation += 1;
        self.update_index(&on_disk, index)
    }

    /// Write `index` over `on_disk`, the index's bytes on disk, durably.
    /// Only the 4 KiB pages that differ are written, and the header page,
    /// which holds the state, last; an index of another length is written in
    /// full. Returns the bytes now on disk.
    pub fn update_index(&self, on_disk: &[u8], index: &RamIndex) -> Result<Vec<u8>> {
        let encoded = index.encode();
        if encoded.len() != on_disk.len() {
            self.write_index(index)?;
            return Ok(encoded);
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.index_path())?;
        if file.metadata()?.len() != on_disk.len() as u64 {
            drop(file);
            self.write_index(index)?;
            return Ok(encoded);
        }
        let page = PAGE as usize;
        let mut wrote = false;
        let mut at = page;
        while at < encoded.len() {
            let end = (at + page).min(encoded.len());
            if encoded[at..end] != on_disk[at..end] {
                let mut run_end = end;
                while run_end < encoded.len() {
                    let next = (run_end + page).min(encoded.len());
                    if encoded[run_end..next] == on_disk[run_end..next] {
                        break;
                    }
                    run_end = next;
                }
                file.write_all_at(&encoded[at..run_end], at as u64)?;
                wrote = true;
                at = run_end;
            } else {
                at = end;
            }
        }
        if wrote {
            file.sync_data()?;
        }
        if encoded[..page] != on_disk[..page] {
            file.write_all_at(&encoded[..page], 0)?;
            file.sync_data()?;
        }
        Ok(encoded)
    }

    /// Make `image`, a sealed RAM image, the base, described by `index`.
    pub fn install(&self, image: &Path, index: &RamIndex) -> Result<()> {
        self.create_dir()?;
        // Without an index there is no base, so a crash between the steps
        // leaves none rather than an index of another image.
        match std::fs::remove_file(self.index_path()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let partial = self.dir.join(format!(".{MEMORY}.partial"));
        match std::fs::remove_file(&partial) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::fs::hard_link(image, &partial)?;
        std::fs::rename(&partial, self.memory_path())?;
        self.check_memory(index.image_len)?;
        self.write_index(index)
    }

    fn create_dir(&self) -> Result<()> {
        match std::fs::create_dir(&self.dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    /// Remove the base. The next pause writes the image in full.
    pub fn remove(&self) {
        match std::fs::remove_dir_all(&self.dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, base = %self.dir.display(), "could not remove the RAM base")
            }
        }
    }

    /// Remove a base whose writer stopped while it was `applying`, or whose
    /// index cannot be read, for example because it has another version.
    pub fn drop_if_applying(&self) {
        if matches!(
            self.load(),
            Err(_)
                | Ok(Some(RamIndex {
                    state: IndexState::Applying,
                    ..
                }))
        ) {
            tracing::info!(base = %self.dir.display(), "removed a RAM base left half written or unreadable");
            self.remove();
        }
    }

    /// Bytes the base takes on disk.
    pub fn allocated_bytes(&self) -> u64 {
        [self.memory_path(), self.index_path()]
            .iter()
            .filter_map(|path| std::fs::symlink_metadata(path).ok())
            .map(|metadata| metadata.blocks() * 512)
            .sum()
    }
}

/// What a delta stream did to the base.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Applied {
    /// Blocks the VMM sent a frame for.
    pub changed_blocks: u64,
    /// Pages the VMM sent, with data or as zeros.
    pub changed_pages: u64,
    /// Bytes of RAM data written to the base: the data pages sent, without
    /// the zero pages punched as holes.
    pub written_bytes: u64,
}

/// How a delta stream ended.
#[derive(Debug)]
pub(crate) enum StreamEnd {
    /// Every page is in the base; the VMM's reply line follows.
    Complete,
    /// The VMM aborted the save; its reply line follows.
    Aborted,
}

fn read_u64(stream: &mut impl Read) -> std::io::Result<u64> {
    let mut bytes = [0_u8; 8];
    stream.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn bit(map: &[u8], page: usize) -> bool {
    map[page / 8] & (1 << (page % 8)) != 0
}

/// Read a delta stream whose magic was already read and write each frame's
/// pages into `memory`, updating `index` as each frame lands: the pages'
/// entries from the bytes written, and the block's digest as unknown, for
/// [`refresh_digests`]. `applied` counts what was written, also when this
/// fails part way. An image of another length than the index's resizes the
/// base and forgets every page, which the VMM then sends.
pub(crate) fn apply_delta(
    memory: &File,
    index: &mut RamIndex,
    stream: &mut impl Read,
    max_image: u64,
    applied: &mut Applied,
) -> Result<StreamEnd> {
    let protocol = |reason: &str| Error::agent("apply RAM delta", reason.to_string());
    if read_u64(stream)? != BLOCK || read_u64(stream)? != PAGE {
        return Err(protocol("the VMM streamed another block or page size"));
    }
    let image_len = read_u64(stream)?;
    let count = read_u64(stream)?;
    if image_len == 0 || image_len > max_image || count != image_len.div_ceil(BLOCK) {
        return Err(protocol(
            "the VMM streamed an image of an impossible length",
        ));
    }
    if image_len != index.image_len {
        tracing::info!(
            from = index.image_len,
            to = image_len,
            "the RAM image changed length; rewriting the base"
        );
        index.blocks = vec![BlockDigest::Unknown; count as usize];
        index.pages = vec![PageEntry::UNKNOWN; image_len.div_ceil(PAGE) as usize];
        index.image_len = image_len;
        memory.set_len(image_len)?;
    }
    let mut seen = vec![false; count as usize];
    let mut data_bytes = 0_u64;
    let mut maps = [0_u8; 2 * BITMAP];
    let mut buffer = vec![0_u8; BLOCK as usize];
    loop {
        let mut tag = [0_u8];
        stream.read_exact(&mut tag)?;
        match tag[0] {
            FRAME_PAGES => {
                let block = read_u64(stream)?;
                if block >= count {
                    return Err(protocol("the VMM streamed a block past the image"));
                }
                if std::mem::replace(&mut seen[block as usize], true) {
                    return Err(protocol("the VMM streamed a block twice"));
                }
                stream.read_exact(&mut maps)?;
                let (changed, data) = maps.split_at(BITMAP);
                let start = block * BLOCK;
                let len = (image_len - start).min(BLOCK);
                let pages = len.div_ceil(PAGE) as usize;
                let page_len = |page: usize| (len - page as u64 * PAGE).min(PAGE) as usize;
                let mut frame_bytes = 0;
                let mut any = false;
                for page in 0..BLOCK_PAGES {
                    let (is_changed, is_data) = (bit(changed, page), bit(data, page));
                    if is_data && !is_changed {
                        return Err(protocol("the VMM sent data for an unchanged page"));
                    }
                    if is_changed && page >= pages {
                        return Err(protocol("the VMM streamed a page past the image"));
                    }
                    any |= is_changed;
                    if is_data {
                        frame_bytes += page_len(page);
                    }
                }
                if !any {
                    return Err(protocol("the VMM streamed a block with no changed page"));
                }
                stream.read_exact(&mut buffer[..frame_bytes])?;
                data_bytes += frame_bytes as u64;
                index.blocks[block as usize] = BlockDigest::Unknown;
                let first = (start / PAGE) as usize;
                let (written, sent) = write_pages(
                    memory,
                    start,
                    (0..pages).filter(|&page| bit(changed, page)).map(|page| {
                        index.pages[first + page] = PageEntry::UNKNOWN;
                        (page, page_len(page), bit(data, page))
                    }),
                    &buffer[..frame_bytes],
                )?;
                applied.written_bytes += written;
                let mut at = 0;
                for page in (0..pages).filter(|&page| bit(changed, page)) {
                    let len = page_len(page);
                    index.pages[first + page] = if bit(data, page) {
                        at += len;
                        PageEntry::of(&buffer[at - len..at], index.seed)
                    } else {
                        PageEntry::HOLE
                    };
                }
                applied.changed_blocks += 1;
                applied.changed_pages += sent;
            }
            FRAME_END => {
                let totals = [
                    read_u64(stream)?,
                    read_u64(stream)?,
                    read_u64(stream)?,
                    read_u64(stream)?,
                ];
                if totals
                    != [
                        count,
                        applied.changed_blocks,
                        applied.changed_pages,
                        data_bytes,
                    ]
                {
                    return Err(protocol("the VMM's totals do not match its frames"));
                }
                if index
                    .pages
                    .iter()
                    .any(|page| page.state == PageState::Unknown)
                {
                    return Err(protocol("the VMM did not send every page the base lacks"));
                }
                return Ok(StreamEnd::Complete);
            }
            FRAME_ABORT => return Ok(StreamEnd::Aborted),
            _ => return Err(protocol("the VMM streamed an unknown frame")),
        }
    }
}

/// Write a block's changed `pages` (page, length, holds data) at `start`:
/// the data pages from `data`, in order, the others and the data pages of
/// zeros as holes. Adjacent pages of one kind are written in one call.
/// Returns the data bytes written and the pages.
fn write_pages(
    memory: &File,
    start: u64,
    pages: impl Iterator<Item = (usize, usize, bool)>,
    data: &[u8],
) -> Result<(u64, u64)> {
    // A run of pages: its offset in the block, its length, and where its
    // bytes start in `data` when it is written rather than punched.
    let mut run: Option<(u64, u64, Option<usize>)> = None;
    let flush = |run: (u64, u64, Option<usize>)| -> Result<u64> {
        let (offset, len, from) = run;
        match from {
            Some(from) => {
                memory.write_all_at(&data[from..from + len as usize], start + offset)?;
                Ok(len)
            }
            None => {
                punch_hole(memory, start + offset, len)?;
                Ok(0)
            }
        }
    };
    let (mut written, mut sent, mut at) = (0, 0, 0);
    for (page, len, holds_data) in pages {
        let offset = page as u64 * PAGE;
        let from = if holds_data {
            at += len;
            Some(at - len).filter(|&from| !is_zero(&data[from..at]))
        } else {
            None
        };
        sent += 1;
        run = match run {
            Some((run_at, run_len, run_from))
                if run_at + run_len == offset
                    && match (run_from, from) {
                        (Some(run_from), Some(from)) => run_from + run_len as usize == from,
                        (None, None) => true,
                        _ => false,
                    } =>
            {
                Some((run_at, run_len + len as u64, run_from))
            }
            Some(done) => {
                written += flush(done)?;
                Some((offset, len as u64, from))
            }
            None => Some((offset, len as u64, from)),
        };
    }
    if let Some(done) = run {
        written += flush(done)?;
    }
    Ok((written, sent))
}

fn punch_hole(memory: &File, offset: u64, len: u64) -> Result<()> {
    let result = unsafe {
        libc::fallocate(
            memory.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset as libc::off_t,
            len as libc::off_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const MIB: usize = 1 << 20;
    const P: usize = PAGE as usize;
    const FRAME: usize = 1 + 8 + 2 * BITMAP;
    const HEADER: usize = 8 + 4 * 8;
    const END: usize = 1 + 4 * 8;

    /// A delta stream, as the VMM writes it, of `image` against the page
    /// `table` of a `FINISH_SAVE_DELTA` request.
    pub(crate) fn delta_stream(image: &[u8], table: &[u8]) -> Vec<u8> {
        assert_eq!(&table[..8], TABLE_MAGIC);
        let table_len = le_u64(table, 24);
        let seed = le_u64(table, 32);
        let entries = &table[TABLE_HEADER..];
        let count = (image.len() as u64).div_ceil(BLOCK);
        let mut stream = Vec::new();
        stream.extend_from_slice(STREAM_MAGIC);
        for value in [BLOCK, PAGE, image.len() as u64, count] {
            stream.extend_from_slice(&value.to_le_bytes());
        }
        let (mut blocks, mut pages, mut data_bytes) = (0, 0, 0);
        for (block, bytes) in image.chunks(BLOCK as usize).enumerate() {
            let mut maps = [0_u8; 2 * BITMAP];
            let mut data = Vec::new();
            for (page, page_bytes) in bytes.chunks(P).enumerate() {
                let now = PageEntry::of(page_bytes, seed);
                if table_len == image.len() as u64 {
                    let at = (block * BLOCK_PAGES + page) * PAGE_ENTRY;
                    let entry = &entries[at..at + PAGE_ENTRY];
                    let hash = u128::from_le_bytes(entry[1..].try_into().unwrap());
                    let same = match entry[0] {
                        1 => now.state == PageState::Hole,
                        2 => now.state == PageState::Data && now.xxh3 == hash,
                        _ => false,
                    };
                    if same {
                        continue;
                    }
                }
                maps[page / 8] |= 1 << (page % 8);
                pages += 1;
                if now.state == PageState::Data {
                    maps[BITMAP + page / 8] |= 1 << (page % 8);
                    data.extend_from_slice(page_bytes);
                }
            }
            if maps[..BITMAP].iter().all(|&byte| byte == 0) {
                continue;
            }
            blocks += 1;
            data_bytes += data.len() as u64;
            stream.push(FRAME_PAGES);
            stream.extend_from_slice(&(block as u64).to_le_bytes());
            stream.extend_from_slice(&maps);
            stream.extend_from_slice(&data);
        }
        stream.push(FRAME_END);
        for value in [count, blocks, pages, data_bytes] {
            stream.extend_from_slice(&value.to_le_bytes());
        }
        stream
    }

    fn image(len: usize, pages: &[(usize, u8)]) -> Vec<u8> {
        let mut image = vec![0; len];
        for &(page, byte) in pages {
            image[page * P..((page + 1) * P).min(len)].fill(byte);
        }
        image
    }

    fn allocated(file: &File) -> u64 {
        file.metadata().unwrap().blocks() * 512
    }

    fn base_with(dir: &Path, bytes: &[u8], seed: u64) -> (RamBase, RamIndex) {
        let image = dir.join("image.bin");
        let file = File::create(&image).unwrap();
        file.set_len(bytes.len() as u64).unwrap();
        for (page, data) in bytes.chunks(P).enumerate() {
            if !is_zero(data) {
                file.write_all_at(data, (page * P) as u64).unwrap();
            }
        }
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o444)).unwrap();
        let hashes = hash_image(&File::open(&image).unwrap(), seed).unwrap();
        let index = RamIndex::new(bytes.len() as u64, seed, [7; 32], hashes);
        let base = RamBase::of(dir);
        base.install(&image, &index).unwrap();
        (base, index)
    }

    /// Apply `stream` to the base and hash the blocks it wrote again.
    fn apply(
        base: &RamBase,
        index: &mut RamIndex,
        stream: &[u8],
    ) -> (Result<StreamEnd>, Applied, File) {
        let memory = base.open_for_writing().unwrap();
        let mut applied = Applied::default();
        let mut reader = &stream[8..];
        let end = apply_delta(&memory, index, &mut reader, 1 << 40, &mut applied);
        if end.is_ok() {
            assert!(reader.is_empty(), "the whole stream is read");
        }
        refresh_digests(&memory, index).unwrap();
        (end, applied, memory)
    }

    /// The index describes the base on disk exactly.
    fn assert_true(base: &RamBase, index: &RamIndex) {
        let on_disk = hash_image(&File::open(base.memory_path()).unwrap(), index.seed).unwrap();
        assert_eq!(
            index.blocks, on_disk.blocks,
            "block digests describe the disk"
        );
        assert_eq!(index.pages, on_disk.pages, "page entries describe the disk");
    }

    #[test]
    fn an_index_round_trips_and_damage_is_refused() {
        let bytes = image(3 * MIB + 8192, &[(0, 1), (600, 2)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.bin");
        std::fs::write(&path, &bytes).unwrap();
        let mut index = RamIndex::new(
            bytes.len() as u64,
            99,
            [3; 32],
            hash_image(&File::open(&path).unwrap(), 99).unwrap(),
        );
        index.generation = 5;
        index.state = IndexState::Applying;
        index.blocks[1] = BlockDigest::Unknown;
        index.pages[3] = PageEntry::UNKNOWN;
        let encoded = index.encode();
        assert_eq!(
            encoded.len(),
            INDEX_HEADER + 2 * BLOCK_ENTRY + (768 + 2) * PAGE_ENTRY
        );
        assert_eq!(RamIndex::decode(&encoded).unwrap(), index);
        assert_eq!(index.pages[0].state, PageState::Data);
        assert_eq!(index.pages[1], PageEntry::HOLE);
        assert!(matches!(index.blocks[0], BlockDigest::Data(_)));
        assert!(RamIndex::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut wrong = encoded.clone();
        wrong[32..40].copy_from_slice(&(20 * BLOCK).to_le_bytes());
        assert!(RamIndex::decode(&wrong).is_err());
        let mut wrong = encoded.clone();
        wrong[INDEX_HEADER] = 7;
        assert!(RamIndex::decode(&wrong).is_err());
        let mut wrong = encoded.clone();
        wrong[INDEX_HEADER + 2 * BLOCK_ENTRY] = 7;
        assert!(RamIndex::decode(&wrong).is_err());
        let mut wrong = encoded;
        wrong[24..32].copy_from_slice(&(64 * 1024_u64).to_le_bytes());
        assert!(RamIndex::decode(&wrong).is_err());
        // The table carries the page states and change hashes only.
        let table = index.table();
        assert_eq!(&table[..8], TABLE_MAGIC);
        assert_eq!(table.len(), TABLE_HEADER + 770 * PAGE_ENTRY);
        assert_eq!(table[TABLE_HEADER], 2, "a data page");
        assert_eq!(table[TABLE_HEADER + PAGE_ENTRY], 1, "a hole");
        assert_eq!(table[TABLE_HEADER + 3 * PAGE_ENTRY], 0, "an unknown page");
    }

    #[test]
    fn an_index_of_the_old_version_is_unusable_and_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _) = base_with(dir.path(), &image(BLOCK as usize, &[(1, 1)]), 3);
        assert!(base.usable().is_some());
        // A version 1 index: 2 MiB entries only.
        let mut old = Vec::new();
        old.extend_from_slice(INDEX_MAGIC);
        old.extend_from_slice(&1_u32.to_le_bytes());
        old.extend_from_slice(&0_u32.to_le_bytes());
        for value in [BLOCK, BLOCK, 3, 1] {
            old.extend_from_slice(&value.to_le_bytes());
        }
        old.extend_from_slice(&[7; 32]);
        old.extend_from_slice(&1_u64.to_le_bytes());
        old.push(2);
        old.extend_from_slice(&[1; 48]);
        std::fs::write(base.index_path(), &old).unwrap();
        let error = base.load().unwrap_err().to_string();
        assert!(error.contains("version"), "{error}");
        assert!(base.usable().is_none(), "the next pause saves in full");
        base.drop_if_applying();
        assert!(!base.memory_path().exists());
    }

    #[test]
    fn hashing_an_image_skips_holes_and_finds_zero_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.bin");
        let file = File::create(&path).unwrap();
        file.set_len(5 * BLOCK + 100).unwrap();
        file.write_all_at(&[9; P], BLOCK + PAGE).unwrap();
        file.write_all_at(&[0; P], 3 * BLOCK).unwrap();
        file.write_all_at(&[1; 10], 5 * BLOCK + 50).unwrap();
        let hashes = hash_image(&File::open(&path).unwrap(), 1).unwrap();
        use BlockDigest::Hole;
        assert_eq!(hashes.blocks[0], Hole);
        assert!(matches!(hashes.blocks[1], BlockDigest::Data(_)));
        assert_eq!(hashes.blocks[2..5], [Hole, Hole, Hole]);
        assert!(matches!(hashes.blocks[5], BlockDigest::Data(_)));
        assert_eq!(hashes.pages.len(), 5 * BLOCK_PAGES + 1);
        let data: Vec<usize> = (0..hashes.pages.len())
            .filter(|&page| hashes.pages[page].state == PageState::Data)
            .collect();
        assert_eq!(data, [BLOCK_PAGES + 1, 5 * BLOCK_PAGES]);
        assert!(hashes
            .pages
            .iter()
            .all(|page| page.state != PageState::Unknown));
        let mut short = vec![0; 100];
        short[50..60].fill(1);
        assert_eq!(hashes.pages[5 * BLOCK_PAGES], PageEntry::of(&short, 1));
        assert_eq!(hashes.blocks[5], BlockDigest::of(&short));
        assert_eq!(
            block_digests(&File::open(&path).unwrap()).unwrap(),
            hashes.blocks
        );
    }

    #[test]
    fn a_delta_makes_the_base_the_new_image_and_keeps_it_sparse() {
        let dir = tempfile::tempdir().unwrap();
        let len = 3 * BLOCK as usize + 3 * P;
        let old = image(
            len,
            &[
                (0, 1),
                (1, 1),
                (511, 2),
                (512, 3),
                (1024 + 5, 4),
                (1536 + 2, 5),
            ],
        );
        let (base, mut index) = base_with(dir.path(), &old, 42);
        let mut new = old.clone();
        // Block 0's pages become holes; in block 1 one page becomes a hole and
        // a hole becomes data; block 2 is unchanged; a page of the short last
        // block changes.
        new[..BLOCK as usize].fill(0);
        new[512 * P..513 * P].fill(0);
        new[700 * P..701 * P].fill(6);
        new[(1536 + 2) * P..(1536 + 3) * P].fill(7);
        let stream = delta_stream(&new, &index.table());
        assert_eq!(
            stream.len(),
            HEADER + 3 * FRAME + 2 * P + END,
            "only changed pages are sent, and only data pages carry bytes"
        );
        let (end, applied, memory) = apply(&base, &mut index, &stream);
        assert!(matches!(end.unwrap(), StreamEnd::Complete));
        assert_eq!(
            applied,
            Applied {
                changed_blocks: 3,
                changed_pages: 6,
                written_bytes: 2 * PAGE,
            }
        );
        memory.sync_data().unwrap();
        assert_eq!(std::fs::read(base.memory_path()).unwrap(), new);
        assert_true(&base, &index);
        assert_eq!(index.blocks[0], BlockDigest::Hole);
        assert_eq!(
            allocated(&memory),
            3 * PAGE,
            "only the pages holding data are allocated"
        );
        // Against the updated index the image has no delta.
        assert_eq!(delta_stream(&new, &index.table()).len(), HEADER + END);
    }

    #[test]
    fn a_block_with_one_changed_page_writes_only_that_page() {
        let dir = tempfile::tempdir().unwrap();
        let old: Vec<u8> = (0..2 * BLOCK as usize)
            .map(|at| (at / P) as u8 | 1)
            .collect();
        let (base, mut index) = base_with(dir.path(), &old, 11);
        let mut new = old.clone();
        new[BLOCK as usize + 300 * P + 17] ^= 0xff;
        let stream = delta_stream(&new, &index.table());
        assert_eq!(stream.len(), HEADER + FRAME + P + END);
        let block0 = index.blocks[0];
        let (end, applied, _) = apply(&base, &mut index, &stream);
        end.unwrap();
        assert_eq!(applied.changed_pages, 1);
        assert_eq!(applied.written_bytes, PAGE);
        assert_eq!(
            index.blocks[0], block0,
            "an unchanged block keeps its digest"
        );
        assert_eq!(std::fs::read(base.memory_path()).unwrap(), new);
        assert_true(&base, &index);
    }

    #[test]
    fn a_block_with_every_page_changed_is_written_whole() {
        let dir = tempfile::tempdir().unwrap();
        let old = vec![0x10; BLOCK as usize + 2 * P];
        let (base, mut index) = base_with(dir.path(), &old, 12);
        let mut new = vec![0x20; BLOCK as usize + 2 * P];
        new[BLOCK as usize..BLOCK as usize + P].fill(0);
        let stream = delta_stream(&new, &index.table());
        let (end, applied, _) = apply(&base, &mut index, &stream);
        end.unwrap();
        assert_eq!(applied.changed_blocks, 2);
        assert_eq!(applied.changed_pages, BLOCK_PAGES as u64 + 2);
        assert_eq!(applied.written_bytes, BLOCK + PAGE);
        assert_eq!(std::fs::read(base.memory_path()).unwrap(), new);
        assert_true(&base, &index);
    }

    #[test]
    fn a_short_final_page_is_written_short() {
        let dir = tempfile::tempdir().unwrap();
        let len = BLOCK as usize + P + 100;
        let (base, mut index) = base_with(dir.path(), &image(len, &[(512, 1)]), 13);
        let mut new = image(len, &[]);
        new[len - 100..].fill(0x33);
        let stream = delta_stream(&new, &index.table());
        let (end, applied, memory) = apply(&base, &mut index, &stream);
        end.unwrap();
        assert_eq!(applied.changed_pages, 2);
        assert_eq!(applied.written_bytes, 100);
        assert_eq!(memory.metadata().unwrap().len(), len as u64);
        assert_eq!(std::fs::read(base.memory_path()).unwrap(), new);
        assert_true(&base, &index);
    }

    #[test]
    fn a_stream_cut_short_leaves_an_index_true_for_what_was_written() {
        let dir = tempfile::tempdir().unwrap();
        let len = 4 * BLOCK as usize;
        let old = image(len, &[(0, 1), (512, 2), (1024, 3), (1536, 4)]);
        let (base, mut index) = base_with(dir.path(), &old, 5);
        let new = image(len, &[(0, 11), (512, 12), (1024, 13), (1536, 14)]);
        let stream = delta_stream(&new, &index.table());
        // Two whole frames, and part of the third.
        let cut = &stream[..HEADER + 2 * (FRAME + P) + 1000];
        let (end, applied, _) = apply(&base, &mut index, cut);
        assert!(end.is_err());
        assert_eq!(applied.changed_blocks, 2);
        assert_true(&base, &index);
        base.write_index(&index).unwrap();
        // The next delta against that index completes the base.
        let mut index = base.usable().unwrap();
        let stream = delta_stream(&new, &index.table());
        assert_eq!(stream.len(), HEADER + 2 * (FRAME + P) + END);
        let (end, _, _) = apply(&base, &mut index, &stream);
        assert!(matches!(end.unwrap(), StreamEnd::Complete));
        assert_eq!(std::fs::read(base.memory_path()).unwrap(), new);
        assert_true(&base, &index);
    }

    #[test]
    fn a_new_image_length_rewrites_the_whole_base() {
        let dir = tempfile::tempdir().unwrap();
        let old = image(2 * BLOCK as usize, &[(0, 1), (600, 2)]);
        let (base, mut index) = base_with(dir.path(), &old, 8);
        let new = image(3 * BLOCK as usize + P, &[(10, 3), (1536, 4)]);
        let stream = delta_stream(&new, &index.table());
        let (end, applied, _) = apply(&base, &mut index, &stream);
        end.unwrap();
        assert_eq!(applied.changed_blocks, 4);
        assert_eq!(applied.changed_pages, 3 * BLOCK_PAGES as u64 + 1);
        assert_eq!(index.image_len, new.len() as u64);
        assert_eq!(std::fs::read(base.memory_path()).unwrap(), new);
        assert_true(&base, &index);
    }

    #[test]
    fn a_hostile_stream_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        // Two blocks, the second of two pages and 100 bytes.
        let len = BLOCK + 2 * PAGE + 100;
        let old = image(len as usize, &[(0, 1)]);
        let (base, mut index) = base_with(dir.path(), &old, 8);
        let memory = base.open_for_writing().unwrap();
        let mut header = Vec::new();
        for value in [BLOCK, PAGE, len, 2] {
            header.extend_from_slice(&value.to_le_bytes());
        }
        let frame = |block: u64, changed: &[usize], data: &[usize]| {
            let mut frame = vec![FRAME_PAGES];
            frame.extend_from_slice(&block.to_le_bytes());
            let mut maps = [0_u8; 2 * BITMAP];
            for &page in changed {
                maps[page / 8] |= 1 << (page % 8);
            }
            for &page in data {
                maps[BITMAP + page / 8] |= 1 << (page % 8);
            }
            frame.extend_from_slice(&maps);
            frame
        };
        let refused = |index: &mut RamIndex, body: &[u8], max: u64| {
            let mut stream = header.clone();
            stream.extend_from_slice(body);
            apply_delta(
                &memory,
                index,
                &mut &stream[..],
                max,
                &mut Applied::default(),
            )
            .is_err()
        };
        assert!(
            refused(&mut index, &frame(2, &[0], &[]), 1 << 40),
            "a block past the image"
        );
        assert!(
            refused(&mut index, &[], BLOCK),
            "an image above the machine's bound"
        );
        assert!(
            refused(&mut index, &frame(1, &[3], &[]), 1 << 40),
            "a page past the end of a short final block"
        );
        assert!(
            refused(&mut index, &frame(0, &[1], &[1, 2]), 1 << 40),
            "data for an unchanged page"
        );
        assert!(
            refused(&mut index, &frame(0, &[], &[]), 1 << 40),
            "an empty frame"
        );
        let mut twice = frame(1, &[0], &[]);
        twice.extend(frame(1, &[1], &[]));
        assert!(refused(&mut index, &twice, 1 << 40), "a block sent twice");
        let mut short = frame(1, &[2], &[2]);
        short.extend_from_slice(&[5; 101]);
        short.push(FRAME_END);
        for value in [2_u64, 1, 1, 101] {
            short.extend_from_slice(&value.to_le_bytes());
        }
        assert!(
            refused(&mut index, &short, 1 << 40),
            "a short final page carries its own length"
        );
        for totals in [
            [2_u64, 0, 0, 0],
            [2, 1, 2, 100],
            [2, 1, 1, 99],
            [3, 1, 1, 100],
        ] {
            let mut lying = frame(1, &[2], &[2]);
            lying.extend_from_slice(&[5; 100]);
            lying.push(FRAME_END);
            for value in totals {
                lying.extend_from_slice(&value.to_le_bytes());
            }
            assert!(refused(&mut index, &lying, 1 << 40), "totals {totals:?}");
        }
        let mut wrong_page = Vec::new();
        for value in [BLOCK, 65536, len, 2] {
            wrong_page.extend_from_slice(&value.to_le_bytes());
        }
        wrong_page.push(FRAME_END);
        assert!(
            apply_delta(
                &memory,
                &mut index,
                &mut &wrong_page[..],
                1 << 40,
                &mut Applied::default()
            )
            .is_err(),
            "another page size"
        );
        // Only the frame of page 2 of block 1 held data, at its offset.
        let mut expected = old;
        expected[(BLOCK + 2 * PAGE) as usize..].fill(5);
        assert_eq!(std::fs::read(base.memory_path()).unwrap(), expected);
    }

    #[test]
    fn an_index_is_updated_in_place_with_its_header_last() {
        let dir = tempfile::tempdir().unwrap();
        let len = 64 * BLOCK as usize;
        let (base, mut index) = base_with(dir.path(), &image(len, &[(1, 1)]), 4);
        let inode = std::fs::metadata(base.index_path()).unwrap().ino();
        let on_disk = base.mark_applying(&mut index).unwrap();
        assert_eq!(base.load().unwrap().unwrap().state, IndexState::Applying);
        assert!(base.usable().is_none());
        index.pages[40 * BLOCK_PAGES] = PageEntry::of(&[1; P], index.seed);
        index.blocks[40] = BlockDigest::Unknown;
        index.state = IndexState::Clean;
        index.generation += 1;
        let written = base.update_index(&on_disk, &index).unwrap();
        assert_eq!(std::fs::read(base.index_path()).unwrap(), written);
        assert_eq!(base.usable().unwrap(), index);
        assert_eq!(
            std::fs::metadata(base.index_path()).unwrap().ino(),
            inode,
            "written in place"
        );
        // An index of another length is written anew.
        index.image_len += BLOCK;
        index.blocks.push(BlockDigest::Hole);
        index
            .pages
            .extend(std::iter::repeat_n(PageEntry::HOLE, BLOCK_PAGES));
        base.update_index(&written, &index).unwrap();
        assert_eq!(base.load().unwrap().unwrap(), index);
    }

    #[test]
    fn a_base_left_applying_is_unusable_and_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (base, mut index) = base_with(dir.path(), &image(BLOCK as usize, &[(1, 1)]), 3);
        assert!(base.usable().is_some());
        assert!(base.allocated_bytes() >= PAGE);
        index.state = IndexState::Applying;
        base.write_index(&index).unwrap();
        assert!(base.usable().is_none());
        base.drop_if_applying();
        assert!(!base.memory_path().exists());
        assert!(base.usable().is_none());
        assert_eq!(base.allocated_bytes(), 0);
    }

    #[test]
    fn a_base_with_a_damaged_index_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _) = base_with(dir.path(), &image(BLOCK as usize, &[(1, 1)]), 3);
        std::fs::write(base.index_path(), b"damaged").unwrap();
        assert!(base.usable().is_none());
        base.drop_if_applying();
        assert!(!base.memory_path().exists());
        assert_eq!(base.allocated_bytes(), 0);
    }

    #[test]
    fn a_base_that_is_not_protected_is_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _) = base_with(dir.path(), &image(BLOCK as usize, &[(1, 1)]), 3);
        std::fs::set_permissions(base.memory_path(), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(base.usable().is_none());
        std::fs::set_permissions(base.memory_path(), std::fs::Permissions::from_mode(0o444))
            .unwrap();
        assert!(base.usable().is_some());
        std::fs::set_permissions(&base.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(base.usable().is_none());
    }
}
