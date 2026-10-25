//! Guest wall-clock sync from the host over a vsock DGRAM (port 123).
//!
//! On hypervisors without a guest-readable paravirt clock (macOS/HVF and
//! Windows/WHP), libkrun's host-side `TimesyncThread` pushes the host's
//! `CLOCK_REALTIME` to the guest — at boot, every 60s, and (critically) as soon
//! as it detects the host was suspended (lid closed / sleep). During host sleep
//! the VM is frozen, so the guest clock stops; without a receiver it falls
//! behind by the accumulated sleep and eventually breaks TLS / signed package
//! indexes inside the guest (issue #521). The agent runs as PID-1 with
//! `CAP_SYS_TIME`, so — unlike the unprivileged container — it can apply the fix.
//!
//! Each host datagram is an 8-byte little-endian u64: host `CLOCK_REALTIME` in
//! nanoseconds (see libkrun `vsock/timesync.rs::write_time_sync`). Mirrors
//! libkrun's own guest reader (`init/src/timesync.rs`), but as a thread since
//! the agent is long-lived (it never `exec`s away, so it needs no `fork`).

use std::mem;

const AF_VSOCK: libc::c_int = 40;
const VMADDR_CID_ANY: u32 = u32::MAX;
const TSYNC_PORT: u32 = 123;
const NANOS_IN_SECOND: u64 = 1_000_000_000;
/// Ignore sub-100ms drift — matches libkrun's guest reader.
const DELTA_SYNC_NS: u64 = 100_000_000;

#[repr(C)]
struct sockaddr_vm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

/// Spawn the host→guest clock-sync receiver as a background thread. Best-effort:
/// on any setup error the thread exits and the boot-seeded clock stands.
pub fn spawn() {
    let _ = std::thread::Builder::new()
        .name("timesync".into())
        .spawn(run);
}

fn run() {
    // AF_VSOCK DGRAM bound to port 123 — the port libkrun's TimesyncThread sends
    // to. VMADDR_CID_ANY: accept from the host CID.
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return;
    }
    let addr = sockaddr_vm {
        svm_family: AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: TSYNC_PORT,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const sockaddr_vm as *const libc::sockaddr,
            mem::size_of::<sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return;
    }

    let mut buf = [0u8; 8];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            break; // socket error — give up (the boot clock stands)
        }
        if n != 8 {
            continue; // malformed datagram — ignore
        }

        let host_ns = u64::from_le_bytes(buf);
        if host_ns.abs_diff(current_realtime_ns()) > DELTA_SYNC_NS {
            let _ = set_realtime_ns(host_ns);
        }
    }
    unsafe { libc::close(fd) };
}

/// A guest further behind the host than this is stepped by [`set_clock`].
const MAX_BEHIND_NS: i64 = 50_000_000;
/// A guest further ahead of the host than this is stepped by [`set_clock`].
const MAX_AHEAD_NS: i64 = 5_000_000_000;

/// With `exact`, a guest further off than this, either way, is stepped.
const MAX_EXACT_SKEW_NS: i64 = 1_000_000;

/// Step the wall clock to the host's `host_ns` when the guest is more than
/// 50 ms behind it or more than 5 s ahead. Small forward drift is left to the
/// guest, so that a host whose timestamp is a little stale never moves the
/// clock back. With `exact`, step it whenever it is more than 1 ms off, as a
/// host does right after a boot.
pub fn set_clock(host_ns: u64, exact: bool) -> std::io::Result<smolvm_protocol::ClockStep> {
    let skew_ns = skew_ns(current_realtime_ns(), host_ns);
    let stepped = steps(skew_ns, exact);
    if stepped {
        set_realtime_ns(host_ns)?;
    }
    Ok(smolvm_protocol::ClockStep { skew_ns, stepped })
}

/// Whether [`set_clock`] steps a guest `skew_ns` off the host.
fn steps(skew_ns: i64, exact: bool) -> bool {
    if exact {
        skew_ns.unsigned_abs() > MAX_EXACT_SKEW_NS as u64
    } else {
        !(-MAX_BEHIND_NS..=MAX_AHEAD_NS).contains(&skew_ns)
    }
}

fn skew_ns(guest_ns: u64, host_ns: u64) -> i64 {
    (i128::from(guest_ns) - i128::from(host_ns)).clamp(i64::MIN.into(), i64::MAX.into()) as i64
}

fn set_realtime_ns(ns: u64) -> std::io::Result<()> {
    let ts = libc::timespec {
        tv_sec: (ns / NANOS_IN_SECOND) as libc::time_t,
        tv_nsec: (ns % NANOS_IN_SECOND) as libc::c_long,
    };
    // SAFETY: ts is a valid timespec; the agent is PID-1 with CAP_SYS_TIME.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn current_realtime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, writable timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    ts.tv_sec as u64 * NANOS_IN_SECOND + ts.tv_nsec as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skew_is_guest_minus_host() {
        assert_eq!(skew_ns(10, 3), 7);
        assert_eq!(skew_ns(3, 10), -7);
        assert_eq!(skew_ns(u64::MAX, 0), i64::MAX);
        assert_eq!(skew_ns(0, u64::MAX), i64::MIN);
    }

    #[test]
    fn exact_steps_any_skew_over_a_millisecond_either_way() {
        assert!(!steps(1_000_000, true));
        assert!(!steps(-1_000_000, true));
        assert!(steps(1_000_001, true));
        assert!(steps(-1_000_001, true));
        assert!(steps(400_000_000, true), "a guest ahead is stepped back");
        assert!(!steps(400_000_000, false), "without exact a guest ahead is left");
        assert!(steps(-60_000_000, false));
        assert!(steps(i64::MIN, true));
    }

    // A host time inside the gate never steps the clock, so this needs no
    // CAP_SYS_TIME.
    #[test]
    fn a_clock_inside_the_gate_is_left_alone() {
        let now = current_realtime_ns();
        let behind = set_clock(now + 40_000_000, false).unwrap();
        assert!(!behind.stepped, "{behind:?}");
        assert!(
            behind.skew_ns < 0 && behind.skew_ns >= -MAX_BEHIND_NS,
            "{behind:?}"
        );
        let ahead = set_clock(now - 4_000_000_000, false).unwrap();
        assert!(!ahead.stepped, "{ahead:?}");
        assert!(ahead.skew_ns > 3_900_000_000, "{ahead:?}");
    }
}
