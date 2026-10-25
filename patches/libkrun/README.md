# libkrun patches for smolvm-pods

`0001-anonymous-restore.patch`, `0002-readonly-input.patch`, `0003-delta-save.patch` and
`0004-clock-follow.patch` apply, in that order, to the `libkrun`
submodule's commit, the libkrun of the smolvm v1.31.4 Linux release.
They make the libkrun that runs pod VMs inside a smolvm-pods node: Floci's
`tools/smolvm-pods/node/libkrun/build.sh` fetches that commit, applies them in name order and
builds `libkrun.so`, which the node image ships in place of the release's `lib/libkrun.so`. They
change only Linux code paths, and the smolvm code that uses them is on this branch.

## Anonymous restore

On a stock resume, libkrun maps a pod VM's guest RAM as a shared mapping of the checkpoint
file `memory.bin`. That mapping gets no transparent huge pages, and in a nested VM every 4 KiB
page is slow to map, so memory stays slow after a resume.

`0001-anonymous-restore.patch` changes only the Linux restore path that is neither forkable
nor layered. It maps guest RAM as new anonymous memory, 2 MiB aligned, with `MADV_HUGEPAGE`, and
reads `memory.bin` into it with parallel `pread` calls before any vCPU runs. Holes in the file
are skipped. The restored RAM then has the same shape as a cold-booted VM's, so the next pause
saves it the same way. A unit test checks the copy is exact, has no file backing and is aligned.

Measured in a nested node on the Mac with [the huge-page node kernel](https://github.com/elliots/floci/blob/feat/smolvm-floci/tools/smolvm-pods/node/kernel/README.md), with
this patch alone. Each of these resumes also unpacked a packed checkpoint and made smolvm's private
copy of the RAM image, about 1 s that the node does not spend: it pauses to an unpacked
[local checkpoint](https://github.com/elliots/floci/blob/feat/smolvm-floci/tools/smolvm-pods/docs/architecture.md#pause) and has the patches. With them, the
[timings](https://github.com/elliots/floci/blob/feat/smolvm-floci/tools/smolvm-pods/docs/architecture.md#wake) are 0.21 s from the start of a resume to PetClinic's
first answer, and a warm request median of 4.0 ms.

| After a resume | Stock libkrun | Patched |
| --- | --- | --- |
| Read 1 GiB | 7.66 s | 0.43 s |
| Random 8-byte read | 137 µs | 9.6 ns |
| PetClinic, resume start to first answer | 4.55 s | 1.30 s |
| PetClinic, warm request median | 1,369 ms | 5.1 ms |

The copy of 1.19 GB takes 22 to 32 ms, and memory hashes match after every resume.

Cost: a resumed pod's memory is resident at once (about 780 MiB for PetClinic right after a
resume, against about 340 MiB lazily with the stock library).

## Read-only RAM input

With `0001-anonymous-restore.patch`, the restore only reads `memory.bin`.
`0002-readonly-input.patch` makes it accept a read-only file and exports
`krun_restore_reads_memory`. smolvm checks for that function and then skips its private copy and
fsync of the RAM image, which takes 0.3 to 0.7 s per resume. With any other libkrun, smolvm makes
the copy. The smolvm side is in the smolvm commit that `scripts/build.sh` pins.

## Delta saves

`0003-delta-save.patch` adds two control commands, Linux only. `SAVE_DELTA_CAPABILITIES`
answers `OK delta-v2`. `FINISH_SAVE_DELTA DIR LENGTH`, followed by LENGTH bytes of a page table,
finishes a prepared save as a delta: the table gives, for each 4 KiB page of the caller's RAM
base, whether it reads as zeros, holds data with a seeded XXH3-128, or is unknown. The VM process
reads and hashes guest RAM on four threads, with the readers a full save uses, and streams one
frame per 2 MiB block with a changed page: the block, a bitmap of its changed pages, a bitmap of
those that hold data, and the bytes of only those. It then publishes `checkpoint.bin` and
`manifest.bin` without a memory image. smolvm writes the blocks into the base; the VM process never gets a descriptor of
it. A table for an image of another length is ignored, so every page is sent. The unit tests
check that a delta applied to its base gives the new image exactly, with pages that become holes,
blocks that span two regions, a block with one changed page, a block with every page changed and
a short final page, and a delta over real anonymous guest
memory through the held save. [Pause](https://github.com/elliots/floci/blob/feat/smolvm-floci/tools/smolvm-pods/docs/architecture.md#pause) describes the whole
pause.

## Guest clock

On arm64, KVM gives a guest its time through the generic timer's virtual counter, and libkrun
wrote the counter of a checkpoint or a pause back at the restore or resume, so a guest's clocks
stood still while it was saved and its wall clock fell behind by that long. An x86 guest's kvmclock
moves on by the host's time instead. `0004-clock-follow.patch` does the same on arm64: a vCPU's saved
state records the host's `CLOCK_REALTIME` when its counter was read, and a restore moves the counter
on by the time since, before the vCPUs run; an in-process pause and resume moves it on by the time
paused. The guest's monotonic and wall clocks then show the time gone by, as if it had run through
it. The record is a trailer of the vCPU state, which a checkpoint without it lacks; such a checkpoint
restores with its clock as saved. A unit test checks the trailer and the move.

## Upstreaming

The patches are not upstream. To go upstream the restore patches need:

- a setting that chooses this eager restore or the stock lazy mapping, instead of replacing the
  mapping;
- reading the checkpoint without filling the page cache;
- a huge-page policy that also works when the host's memory is full;
- an integration test of restore, run, pause and restore with a memory hash check.
