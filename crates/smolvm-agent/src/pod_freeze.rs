//! `PodFreeze` and `PodThaw`: a pod's containers are frozen before its VM
//! pauses, and its TCP connections that leave the guest are closed, so that
//! no peer keeps a connection to a sleeping pod.
//!
//! The containers freeze first, through the cgroup freezer of the pod-cgroup
//! parent that every container's cgroup is under, so that no app reacts to
//! the closed connections, or opens new ones, before the pause. Each
//! connection then closes with `SOCK_DESTROY` over `sock_diag`: the kernel
//! resets it to its peer with the right sequence numbers, and fails it for
//! the app. Listening sockets stay, and so do connections within the guest.
//! A watcher thaws the containers as soon as the guest runs again after the
//! pause, which it sees as a jump of the monotonic clock, since the VM's
//! clocks move on by the time it was paused; the apps then find their
//! connections closed and reconnect. `PodThaw` thaws them too, for a pause
//! that did not happen.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smolvm_protocol::{PodFreezeReply, PreservedTcpPeer};

/// The pod-cgroup parent that every pod container's cgroup is under.
const POD_CGROUP: &str = "/sys/fs/cgroup/smolvm";
/// How long a freeze may take before it fails.
const FREEZE_TIMEOUT: Duration = Duration::from_secs(2);
/// The watcher's tick, and the gap between two ticks that only a pause of
/// the VM makes.
const WATCH_TICK: Duration = Duration::from_millis(5);
const WATCH_GAP: Duration = Duration::from_millis(250);

/// The stop flag of the running thaw watcher, if any.
static WATCHER: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);

/// `PodFreeze`.
pub fn freeze(keep: &[PreservedTcpPeer]) -> Result<PodFreezeReply, String> {
    if keep
        .iter()
        .any(|peer| peer.first_port == 0 || peer.first_port > peer.last_port)
    {
        return Err("a preserved TCP peer must have a nonempty port range".into());
    }
    let frozen = has_pod_cgroup();
    if frozen {
        // Before the freeze, so that a freeze that fails part way still
        // thaws after the pause.
        watch_for_resume();
        set_frozen(true)?;
    }
    let reset = reset_connections(keep)?;
    tracing::info!(frozen, reset, "pod frozen for a pause");
    Ok(PodFreezeReply { frozen, reset })
}

/// `PodThaw`.
pub fn thaw() -> Result<(), String> {
    if let Some(stop) = WATCHER.lock().unwrap().take() {
        stop.store(true, Ordering::Release);
    }
    if has_pod_cgroup() {
        set_frozen(false)?;
    }
    Ok(())
}

/// Whether the guest has the pod-cgroup parent. It has none when crun runs
/// containers without cgroups.
fn has_pod_cgroup() -> bool {
    Path::new(POD_CGROUP).join("cgroup.freeze").exists()
}

/// Freezes or thaws the pod containers' cgroups. A freeze waits until they
/// are frozen.
fn set_frozen(frozen: bool) -> Result<(), String> {
    let dir = Path::new(POD_CGROUP);
    let control = dir.join("cgroup.freeze");
    std::fs::write(&control, if frozen { "1" } else { "0" })
        .map_err(|e| format!("write {}: {e}", control.display()))?;
    if !frozen {
        return Ok(());
    }
    let events = dir.join("cgroup.events");
    let deadline = Instant::now() + FREEZE_TIMEOUT;
    loop {
        let text = std::fs::read_to_string(&events)
            .map_err(|e| format!("read {}: {e}", events.display()))?;
        if text.lines().any(|line| line == "frozen 1") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the pod containers did not freeze within {FREEZE_TIMEOUT:?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Starts the thread that thaws the containers once the guest runs again
/// after a pause, replacing any earlier one.
fn watch_for_resume() {
    let stop = Arc::new(AtomicBool::new(false));
    if let Some(old) = WATCHER.lock().unwrap().replace(stop.clone()) {
        old.store(true, Ordering::Release);
    }
    let spawned = std::thread::Builder::new()
        .name("pod-thaw-watch".into())
        .spawn(move || {
            let mut last = Instant::now();
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(WATCH_TICK);
                let now = Instant::now();
                if now.duration_since(last) >= WATCH_GAP {
                    if let Err(e) = set_frozen(false) {
                        tracing::warn!(error = %e, "thaw the pod after its pause");
                    }
                    return;
                }
                last = now;
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "start the pod thaw watcher; the host thaws the pod");
    }
}

#[cfg(target_os = "linux")]
use diag::reset_connections;

#[cfg(not(target_os = "linux"))]
fn reset_connections(_keep: &[PreservedTcpPeer]) -> Result<u32, String> {
    Ok(0)
}

/// `sock_diag` over netlink: the dump of the guest's TCP sockets and their
/// `SOCK_DESTROY`.
#[cfg(target_os = "linux")]
mod diag {
    use smolvm_protocol::PreservedTcpPeer;
    use std::io;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const NETLINK_SOCK_DIAG: libc::c_int = 4;
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const SOCK_DESTROY: u16 = 21;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_ACK: u16 = 0x4;
    const NLM_F_DUMP: u16 = 0x300;
    const NLMSG_HDRLEN: usize = 16;
    /// `struct inet_diag_sockid`.
    const SOCKID_LEN: usize = 48;
    /// `struct inet_diag_req_v2`.
    const REQ_LEN: usize = 8 + SOCKID_LEN;
    /// `struct inet_diag_msg`, up to and with its socket id.
    const MSG_ID_END: usize = 4 + SOCKID_LEN;
    const TCP_LISTEN: u8 = 10;
    const TCP_TIME_WAIT: u8 = 6;
    const TCP_CLOSE: u8 = 7;
    /// Every TCP state with a peer to reset: not `LISTEN`, `TIME_WAIT` or
    /// `CLOSE`.
    const STATES: u32 = ((1 << 12) - 2) & !(1 << TCP_LISTEN | 1 << TCP_TIME_WAIT | 1 << TCP_CLOSE);

    /// A TCP socket of the dump: its family, state and `inet_diag_sockid`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Sock {
        pub family: u8,
        pub state: u8,
        pub id: [u8; SOCKID_LEN],
    }

    impl Sock {
        fn is_preserved(&self, keep: &[PreservedTcpPeer]) -> bool {
            let port = u16::from_be_bytes([self.id[2], self.id[3]]);
            let address = match self.family as libc::c_int {
                libc::AF_INET => std::net::IpAddr::V4(v4(&self.id[20..24]).unwrap()),
                _ => {
                    let ip =
                        std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&self.id[20..36]).unwrap());
                    ip.to_ipv4_mapped()
                        .map(std::net::IpAddr::V4)
                        .unwrap_or(std::net::IpAddr::V6(ip))
                }
            };
            keep.iter().any(|peer| {
                peer.address == address && (peer.first_port..=peer.last_port).contains(&port)
            })
        }

        /// Whether both ends are in the guest: the peer is a loopback
        /// address, or the guest's own address.
        pub fn is_internal(&self) -> bool {
            let (src, dst) = match self.family as libc::c_int {
                libc::AF_INET => (v4(&self.id[4..8]), v4(&self.id[20..24])),
                _ => (v6_as_v4(&self.id[4..20]), v6_as_v4(&self.id[20..36])),
            };
            match (src, dst) {
                (Some(src), Some(dst)) => dst.is_loopback() || dst == src,
                // An IPv6 peer: only ::1 is internal, as the pod has no
                // other IPv6 address.
                _ => self.id[20..36] == std::net::Ipv6Addr::LOCALHOST.octets(),
            }
        }
    }

    fn v4(bytes: &[u8]) -> Option<Ipv4Addr> {
        let octets: [u8; 4] = bytes.try_into().ok()?;
        Some(Ipv4Addr::from(octets))
    }

    fn v6_as_v4(bytes: &[u8]) -> Option<Ipv4Addr> {
        let octets: [u8; 16] = bytes.try_into().ok()?;
        std::net::Ipv6Addr::from(octets).to_ipv4_mapped()
    }

    /// A `sock_diag` request for TCP sockets of `family` in `states`, for
    /// the socket `id` or, with `NLM_F_DUMP`, all.
    pub(super) fn request(
        kind: u16,
        flags: u16,
        seq: u32,
        family: u8,
        states: u32,
        id: &[u8; SOCKID_LEN],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(NLMSG_HDRLEN + REQ_LEN);
        msg.extend_from_slice(&((NLMSG_HDRLEN + REQ_LEN) as u32).to_ne_bytes());
        msg.extend_from_slice(&kind.to_ne_bytes());
        msg.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&[family, libc::IPPROTO_TCP as u8, 0, 0]);
        msg.extend_from_slice(&states.to_ne_bytes());
        msg.extend_from_slice(id);
        msg
    }

    /// The netlink messages in `buf`: their type and payload.
    pub(super) fn messages(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
        let mut out = Vec::new();
        while buf.len() >= NLMSG_HDRLEN {
            let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
            if len < NLMSG_HDRLEN || len > buf.len() {
                break;
            }
            let kind = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
            out.push((kind, &buf[NLMSG_HDRLEN..len]));
            buf = &buf[len.next_multiple_of(4).min(buf.len())..];
        }
        out
    }

    /// The socket in an `inet_diag_msg` payload.
    pub(super) fn sock(payload: &[u8]) -> Option<Sock> {
        let id = payload.get(4..MSG_ID_END)?.try_into().ok()?;
        Some(Sock {
            family: payload[0],
            state: payload[1],
            id,
        })
    }

    /// The error of an `NLMSG_ERROR` payload, or none for an ack.
    fn error(payload: &[u8]) -> Option<i32> {
        let code = i32::from_ne_bytes(payload.get(0..4)?.try_into().ok()?);
        (code != 0).then_some(-code)
    }

    fn socket() -> io::Result<OwnedFd> {
        // SAFETY: plain socket call; the result is checked.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a new descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn send(fd: &OwnedFd, msg: &[u8]) -> io::Result<()> {
        // SAFETY: sends `msg` to the kernel, whose address is the default.
        if unsafe { libc::send(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: reads into `buf`, of the length passed.
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// The guest's TCP sockets of `family` that have a peer.
    fn dump(fd: &OwnedFd, family: u8) -> Result<Vec<Sock>, String> {
        send(
            fd,
            &request(
                SOCK_DIAG_BY_FAMILY,
                NLM_F_DUMP,
                1,
                family,
                STATES,
                &[0; SOCKID_LEN],
            ),
        )
        .map_err(|e| format!("dump the TCP sockets: {e}"))?;
        let mut socks = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = recv(fd, &mut buf).map_err(|e| format!("read the TCP sockets: {e}"))?;
            for (kind, payload) in messages(&buf[..n]) {
                match kind {
                    NLMSG_DONE => return Ok(socks),
                    NLMSG_ERROR => match error(payload) {
                        Some(code) => {
                            return Err(format!(
                                "dump the TCP sockets: {}",
                                io::Error::from_raw_os_error(code)
                            ))
                        }
                        None => return Ok(socks),
                    },
                    SOCK_DIAG_BY_FAMILY => socks.extend(sock(payload)),
                    _ => {}
                }
            }
            if n == 0 {
                return Ok(socks);
            }
        }
    }

    /// Destroys `sock`: the kernel resets the connection to its peer.
    fn destroy(fd: &OwnedFd, seq: u32, sock: &Sock) -> io::Result<()> {
        send(
            fd,
            &request(
                SOCK_DESTROY,
                NLM_F_ACK,
                seq,
                sock.family,
                1 << sock.state,
                &sock.id,
            ),
        )?;
        let mut buf = [0u8; 512];
        let n = recv(fd, &mut buf)?;
        for (kind, payload) in messages(&buf[..n]) {
            if kind == NLMSG_ERROR {
                return match error(payload) {
                    // A socket closed since the dump is not an error.
                    Some(libc::ENOENT) | None => Ok(()),
                    Some(code) => Err(io::Error::from_raw_os_error(code)),
                };
            }
        }
        Ok(())
    }

    /// Closes every TCP connection that leaves the guest, and returns how
    /// many it closed.
    pub fn reset_connections(keep: &[PreservedTcpPeer]) -> Result<u32, String> {
        let fd = socket().map_err(|e| format!("open sock_diag: {e}"))?;
        let mut reset = 0;
        let mut seq = 2;
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            for sock in dump(&fd, family)? {
                if sock.is_internal() || sock.is_preserved(keep) {
                    continue;
                }
                seq += 1;
                match destroy(&fd, seq, &sock) {
                    Ok(()) => reset += 1,
                    Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                        return Err(
                            "the guest kernel cannot close sockets (CONFIG_INET_DIAG_DESTROY)"
                                .into(),
                        );
                    }
                    Err(e) => tracing::warn!(error = %e, "close a TCP connection for a pause"),
                }
            }
        }
        Ok(reset)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn sockid(src: [u8; 16], dst: [u8; 16]) -> [u8; SOCKID_LEN] {
            let mut id = [0u8; SOCKID_LEN];
            id[0..2].copy_from_slice(&40000u16.to_be_bytes());
            id[2..4].copy_from_slice(&443u16.to_be_bytes());
            id[4..20].copy_from_slice(&src);
            id[20..36].copy_from_slice(&dst);
            id
        }

        fn v4_id(src: [u8; 4], dst: [u8; 4]) -> [u8; SOCKID_LEN] {
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s[..4].copy_from_slice(&src);
            d[..4].copy_from_slice(&dst);
            sockid(s, d)
        }

        fn mapped(ip: [u8; 4]) -> [u8; 16] {
            Ipv4Addr::from(ip).to_ipv6_mapped().octets()
        }

        #[test]
        fn the_states_leave_out_listening_and_closed_sockets() {
            for state in [TCP_LISTEN, TCP_TIME_WAIT, TCP_CLOSE] {
                assert_eq!(STATES & 1 << state, 0, "state {state}");
            }
            // ESTABLISHED, SYN_SENT, CLOSE_WAIT.
            for state in [1, 2, 8] {
                assert_ne!(STATES & 1 << state, 0, "state {state}");
            }
        }

        #[test]
        fn only_connections_that_leave_the_guest_are_closed() {
            let pod = [10, 42, 0, 17];
            let sock = |family, id| Sock {
                family,
                state: 1,
                id,
            };
            let v4 = libc::AF_INET as u8;
            let v6 = libc::AF_INET6 as u8;
            assert!(!sock(v4, v4_id(pod, [10, 42, 0, 9])).is_internal());
            assert!(!sock(v4, v4_id(pod, [169, 254, 53, 1])).is_internal());
            assert!(sock(v4, v4_id([127, 0, 0, 1], [127, 0, 0, 1])).is_internal());
            assert!(sock(v4, v4_id(pod, pod)).is_internal());
            // A Java or Node socket: IPv4 on IPv6.
            assert!(!sock(v6, sockid(mapped(pod), mapped([10, 43, 0, 10]))).is_internal());
            assert!(sock(v6, sockid(mapped(pod), mapped([127, 0, 0, 1]))).is_internal());
            let localhost = std::net::Ipv6Addr::LOCALHOST.octets();
            assert!(sock(v6, sockid(localhost, localhost)).is_internal());
        }

        #[test]
        fn only_the_named_destination_and_port_range_are_preserved() {
            let pod = [10, 42, 0, 17];
            let destination = [169, 254, 53, 1];
            let peer = PreservedTcpPeer {
                address: Ipv4Addr::from(destination).into(),
                first_port: 12000,
                last_port: 12499,
            };
            for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
                for (port, expected) in [
                    (11999u16, false),
                    (12000, true),
                    (12499, true),
                    (12500, false),
                ] {
                    let mut id = if family == libc::AF_INET as u8 {
                        v4_id(pod, destination)
                    } else {
                        sockid(mapped(pod), mapped(destination))
                    };
                    id[2..4].copy_from_slice(&port.to_be_bytes());
                    let sock = Sock {
                        family,
                        state: 1,
                        id,
                    };
                    assert_eq!(sock.is_preserved(std::slice::from_ref(&peer)), expected);
                    let mut other = peer.clone();
                    other.address = Ipv4Addr::new(169, 254, 53, 2).into();
                    assert!(!sock.is_preserved(&[other]));
                }
            }
        }

        #[test]
        fn a_destroy_request_names_the_socket_and_its_state() {
            let id = v4_id([10, 42, 0, 17], [10, 42, 0, 9]);
            let msg = request(SOCK_DESTROY, NLM_F_ACK, 7, libc::AF_INET as u8, 1 << 1, &id);
            assert_eq!(msg.len(), NLMSG_HDRLEN + REQ_LEN);
            assert_eq!(
                u32::from_ne_bytes(msg[0..4].try_into().unwrap()) as usize,
                msg.len()
            );
            assert_eq!(
                u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
                SOCK_DESTROY
            );
            assert_eq!(
                u16::from_ne_bytes(msg[6..8].try_into().unwrap()),
                NLM_F_REQUEST | NLM_F_ACK
            );
            assert_eq!(msg[16], libc::AF_INET as u8);
            assert_eq!(msg[17], libc::IPPROTO_TCP as u8);
            assert_eq!(u32::from_ne_bytes(msg[20..24].try_into().unwrap()), 1 << 1);
            assert_eq!(&msg[24..], &id);
        }

        #[test]
        fn a_dump_reply_gives_each_socket() {
            let id = v4_id([10, 42, 0, 17], [10, 42, 0, 9]);
            let mut payload = vec![libc::AF_INET as u8, 1, 0, 0];
            payload.extend_from_slice(&id);
            payload.extend_from_slice(&[0u8; 20]);
            let mut buf = Vec::new();
            for kind in [SOCK_DIAG_BY_FAMILY, NLMSG_DONE] {
                let body: &[u8] = if kind == NLMSG_DONE {
                    &[0; 4]
                } else {
                    &payload
                };
                buf.extend_from_slice(&((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
                buf.extend_from_slice(&kind.to_ne_bytes());
                buf.extend_from_slice(&[0u8; 10]);
                buf.extend_from_slice(body);
            }
            let msgs = messages(&buf);
            assert_eq!(msgs.len(), 2);
            assert_eq!(msgs[0].0, SOCK_DIAG_BY_FAMILY);
            assert_eq!(
                sock(msgs[0].1),
                Some(Sock {
                    family: libc::AF_INET as u8,
                    state: 1,
                    id
                })
            );
            assert_eq!(msgs[1].0, NLMSG_DONE);
        }
    }
}
