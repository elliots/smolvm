//! Pod processes that outlive host connections. `PodStart` runs a process in
//! a session that journals its output frames, up to 8 MiB, and `PodAttach`
//! streams them again from a cursor. A session takes no input from the host.
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use smolvm_protocol::{error_codes, AgentRequest, AgentResponse};

const MAX_JOURNAL_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
struct Journal {
    frames: VecDeque<(AgentResponse, usize)>,
    first: u64,
    bytes: usize,
    complete: bool,
    failure: Option<String>,
}

impl Journal {
    fn push(&mut self, frame: AgentResponse, size: usize) {
        self.frames.push_back((frame, size));
        self.bytes += size;
        while self.bytes > MAX_JOURNAL_BYTES && self.frames.len() > 1 {
            let (_, removed) = self.frames.pop_front().unwrap();
            self.bytes -= removed;
            self.first += 1;
        }
    }

    /// Why `cursor` cannot be replayed, if it cannot. A cursor older than the
    /// journal gets an answer that names the oldest one it still holds, so
    /// that a client can report the gap and go on from there.
    fn refuse(&self, cursor: u64) -> Option<AgentResponse> {
        if cursor < self.first {
            Some(AgentResponse::cursor_expired(cursor, self.first))
        } else if cursor > self.first + self.frames.len() as u64 {
            Some(AgentResponse::error(
                "pod replay cursor is past the end of the journal",
                error_codes::INVALID_REQUEST,
            ))
        } else {
            None
        }
    }
}

struct Session {
    journal: Mutex<Journal>,
    changed: Condvar,
    // Holds the collector's end of the pump's stream open for the session's
    // life, so that the pump never reads the end of its input.
    _input: UnixStream,
}

/// Sessions by container id and exec id.
type Sessions = Mutex<HashMap<(String, Option<String>), Arc<Session>>>;

fn sessions() -> &'static Sessions {
    static SESSIONS: OnceLock<Sessions> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn remove(id: &str, exec_id: Option<&str>) {
    sessions().lock().unwrap().retain(|(container, exec), _| {
        container != id || exec_id.is_some_and(|wanted| exec.as_deref() != Some(wanted))
    });
}

fn collect(mut peer: UnixStream, session: Arc<Session>) {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let mut size = [0; 4];
            peer.read_exact(&mut size)?;
            let size = u32::from_be_bytes(size) as usize;
            if size > MAX_JOURNAL_BYTES {
                return Err("pod output frame exceeds journal bound".into());
            }
            let mut payload = vec![0; size];
            peer.read_exact(&mut payload)?;
            let response: AgentResponse = serde_json::from_slice(&payload)?;
            let complete = matches!(
                response,
                AgentResponse::Exited { .. } | AgentResponse::Error { .. }
            );
            let mut journal = session.journal.lock().unwrap();
            journal.push(response, size);
            journal.complete = complete;
            session.changed.notify_all();
            if complete {
                return Ok(());
            }
        }
    })();
    if let Err(error) = result {
        let mut journal = session.journal.lock().unwrap();
        journal.failure = Some(error.to_string());
        journal.complete = true;
        session.changed.notify_all();
    }
}

pub fn handle(
    stream: &mut impl crate::ReadWrite,
    request: AgentRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let (id, exec_id, mut cursor, attach) = match &request {
        AgentRequest::PodStart { id, exec_id } => (id.clone(), exec_id.clone(), 0, false),
        AgentRequest::PodAttach {
            id,
            exec_id,
            cursor,
        } => (id.clone(), exec_id.clone(), *cursor, true),
        _ => return Err("expected PodStart or PodAttach".into()),
    };
    let key = (id, exec_id);
    let session = {
        let mut entries = sessions().lock().unwrap();
        if attach {
            match entries.get(&key) {
                Some(session) => session.clone(),
                None => {
                    crate::send_response(
                        stream,
                        &AgentResponse::error("unknown pod session", error_codes::NOT_FOUND),
                    )?;
                    return Ok(());
                }
            }
        } else {
            if entries.contains_key(&key) {
                crate::send_response(
                    stream,
                    &AgentResponse::error(
                        "session already started; use PodAttach",
                        error_codes::INVALID_REQUEST,
                    ),
                )?;
                return Ok(());
            }
            let (mut child_peer, collector_peer) = UnixStream::pair()?;
            let session = Arc::new(Session {
                journal: Mutex::new(Journal::default()),
                changed: Condvar::new(),
                _input: collector_peer.try_clone()?,
            });
            entries.insert(key, session.clone());
            let collector_session = session.clone();
            std::thread::spawn(move || collect(collector_peer, collector_session));
            std::thread::spawn(move || {
                if let Err(error) = crate::pod::handle_pod_start(&mut child_peer, request) {
                    tracing::warn!(error = %error, "supervised pod process failed");
                }
            });
            session
        }
    };
    if attach {
        let refused = session.journal.lock().unwrap().refuse(cursor);
        if let Some(refused) = refused {
            crate::send_response(stream, &refused)?;
            return Ok(());
        }
        crate::send_response(
            stream,
            &AgentResponse::ok(Some(
                serde_json::json!({"attached": true, "cursor": cursor}),
            )),
        )?;
    }
    loop {
        let response = {
            let mut journal = session.journal.lock().unwrap();
            loop {
                // A cursor the journal has dropped gets CURSOR_EXPIRED.
                if let Some(refused) = journal.refuse(cursor) {
                    break Some(refused);
                }
                if let Some((frame, _)) = journal.frames.get((cursor - journal.first) as usize) {
                    cursor += 1;
                    break Some(frame.clone());
                }
                if let Some(failure) = &journal.failure {
                    break Some(AgentResponse::error(
                        failure.clone(),
                        error_codes::INTERNAL_ERROR,
                    ));
                }
                if journal.complete {
                    break None;
                }
                journal = session
                    .changed
                    .wait_timeout(journal, std::time::Duration::from_millis(250))
                    .unwrap()
                    .0;
                let mut poll = libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: poll points at one initialized descriptor; zero timeout.
                if unsafe { libc::poll(&mut poll, 1, 0) } > 0 {
                    if poll.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                        return Err("pod subscription disconnected".into());
                    }
                    if poll.revents & libc::POLLIN != 0 {
                        let mut byte = [0u8; 1];
                        let count = unsafe {
                            libc::recv(
                                stream.as_raw_fd(),
                                byte.as_mut_ptr().cast(),
                                1,
                                libc::MSG_PEEK | libc::MSG_DONTWAIT,
                            )
                        };
                        if count == 0 {
                            return Err("pod subscription disconnected".into());
                        }
                        if count > 0 {
                            return Err("a pod session takes no input from the host".into());
                        }
                    }
                }
            }
        };
        let Some(response) = response else {
            return Ok(());
        };
        let complete = matches!(
            response,
            AgentResponse::Exited { .. } | AgentResponse::Error { .. }
        );
        // A disconnected host terminates this subscription, never the process.
        crate::send_response(stream, &response)?;
        if complete {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(bytes: usize) -> AgentResponse {
        AgentResponse::Stdout {
            data: vec![b'x'; bytes],
        }
    }

    #[test]
    fn a_full_journal_drops_its_oldest_frames() {
        let mut journal = Journal::default();
        journal.push(AgentResponse::Started, 16);
        for _ in 0..8 {
            journal.push(output(0), 1024 * 1024);
        }
        assert_eq!(journal.first, 1);
        assert_eq!(journal.frames.len(), 8);
        assert!(journal.bytes <= MAX_JOURNAL_BYTES);
    }

    #[test]
    fn a_cursor_older_than_the_journal_names_the_oldest_one_it_holds() {
        let mut journal = Journal::default();
        for _ in 0..12 {
            journal.push(output(0), 1024 * 1024);
        }
        assert_eq!(journal.first, 4);
        let refused = journal.refuse(1).expect("cursor 1 was dropped");
        assert_eq!(refused.expired_cursor_oldest(), Some(4));
        assert!(journal.refuse(4).is_none());
        assert!(journal.refuse(12).is_none(), "a caught-up cursor waits");
        let past = journal.refuse(13).expect("cursor 13 does not exist yet");
        assert_eq!(past.expired_cursor_oldest(), None);
    }

    fn read_frame(stream: &mut UnixStream) -> AgentResponse {
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let mut payload = vec![0; u32::from_be_bytes(size) as usize];
        stream.read_exact(&mut payload).unwrap();
        serde_json::from_slice(&payload).unwrap()
    }

    // A host that fell behind learns where the journal now starts, attaches
    // there, and gets every frame from it on.
    #[test]
    fn an_attach_past_a_gap_goes_on_from_the_oldest_frame() {
        let mut journal = Journal::default();
        for _ in 0..12 {
            journal.push(output(0), 1024 * 1024);
        }
        journal.complete = true;
        let (input, _process) = UnixStream::pair().unwrap();
        sessions().lock().unwrap().insert(
            ("gap".into(), None),
            Arc::new(Session {
                journal: Mutex::new(journal),
                changed: Condvar::new(),
                _input: input,
            }),
        );
        let attach = |cursor| AgentRequest::PodAttach {
            id: "gap".into(),
            exec_id: None,
            cursor,
        };
        let (mut host, mut agent) = UnixStream::pair().unwrap();

        handle(&mut agent, attach(1)).unwrap();
        let refused = read_frame(&mut host);
        assert_eq!(refused.expired_cursor_oldest(), Some(4), "{refused:?}");

        handle(&mut agent, attach(4)).unwrap();
        assert!(matches!(read_frame(&mut host), AgentResponse::Ok { .. }));
        for _ in 4..12 {
            assert!(matches!(
                read_frame(&mut host),
                AgentResponse::Stdout { .. }
            ));
        }
        remove("gap", None);
    }
}
