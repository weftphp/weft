//! Messages between workers.
//!
//! Process-mode workers each own the receiving end of a Unix datagram socket pair created
//! before forking; every worker holds the sending ends of all of them. Thread-mode workers
//! post closures to each other's reactors instead.

use std::cell::Cell;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use super::ConnId;
use crate::core::{Error, ErrorKind, Result};
use crate::network::{Socket, SocketType};
use crate::protocol::message_bus::{self, Reassembler};
use crate::reactor::Remote;

/// Identifies a task submitted with [`Context::task`](super::Context::task).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId(pub u64);

/// Something one worker asks of another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Envelope {
    /// A user message for `on_pipe_message`.
    Message { from: usize, data: Vec<u8> },
    /// Send data on a connection owned by the receiving worker.
    Send { conn: ConnId, data: Vec<u8> },
    /// Close a connection owned by the receiving worker.
    Close { conn: ConnId },
    /// A task worker's answer.
    TaskResult { task: TaskId, data: Vec<u8> },
    /// Stop gracefully.
    Stop,
}

const KIND_MESSAGE: u8 = 1;
const KIND_SEND: u8 = 2;
const KIND_CLOSE: u8 = 3;
const KIND_TASK_RESULT: u8 = 4;
const KIND_STOP: u8 = 5;

impl Envelope {
    fn encode(&self) -> (u8, Vec<u8>) {
        let with_prefix = |prefix: &[u8], data: &[u8]| {
            let mut out = prefix.to_vec();
            out.extend_from_slice(data);
            out
        };
        match self {
            Envelope::Message { from, data } => (
                KIND_MESSAGE,
                with_prefix(&(*from as u32).to_be_bytes(), data),
            ),
            Envelope::Send { conn, data } => (KIND_SEND, with_prefix(&conn.0.to_be_bytes(), data)),
            Envelope::Close { conn } => (KIND_CLOSE, conn.0.to_be_bytes().to_vec()),
            Envelope::TaskResult { task, data } => {
                (KIND_TASK_RESULT, with_prefix(&task.0.to_be_bytes(), data))
            }
            Envelope::Stop => (KIND_STOP, Vec::new()),
        }
    }

    fn decode(kind: u8, payload: Vec<u8>) -> Result<Envelope> {
        let bad = || Error::new(ErrorKind::Protocol, "malformed worker message");
        let u64_at = |p: &[u8]| -> Result<u64> {
            Ok(u64::from_be_bytes(
                p.get(..8).ok_or_else(bad)?.try_into().map_err(|_| bad())?,
            ))
        };
        Ok(match kind {
            KIND_MESSAGE => {
                let from = u32::from_be_bytes(
                    payload
                        .get(..4)
                        .ok_or_else(bad)?
                        .try_into()
                        .map_err(|_| bad())?,
                );
                Envelope::Message {
                    from: from as usize,
                    data: payload[4..].to_vec(),
                }
            }
            KIND_SEND => Envelope::Send {
                conn: ConnId(u64_at(&payload)?),
                data: payload[8..].to_vec(),
            },
            KIND_CLOSE => Envelope::Close {
                conn: ConnId(u64_at(&payload)?),
            },
            KIND_TASK_RESULT => Envelope::TaskResult {
                task: TaskId(u64_at(&payload)?),
                data: payload[8..].to_vec(),
            },
            KIND_STOP => Envelope::Stop,
            _ => return Err(bad()),
        })
    }
}

/// Delivers envelopes to workers by index.
pub(crate) trait Peers {
    fn deliver(&self, worker: usize, envelope: Envelope) -> Result<()>;
}

/// Largest datagram written; macOS caps Unix datagrams at 2 KiB by default.
#[cfg(any(target_os = "macos", target_os = "ios"))]
const MAX_DATAGRAM: usize = 2048;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
const MAX_DATAGRAM: usize = 64 * 1024;

/// How long a sender keeps retrying a full inbox before giving up.
const SEND_PATIENCE: Duration = Duration::from_secs(2);

/// Socket pairs for every worker, created before forking.
pub(crate) struct Mailboxes {
    /// Sending ends, indexed by worker.
    outboxes: Vec<Socket>,
    /// Receiving ends, indexed by worker; each worker keeps only its own.
    inboxes: Vec<Option<Socket>>,
}

impl Mailboxes {
    pub fn new(workers: usize) -> Result<Mailboxes> {
        let mut outboxes = Vec::with_capacity(workers);
        let mut inboxes = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (rx, tx) = Socket::pair(SocketType::Datagram)?;
            // Larger buffers absorb bursts; the kernel clamps to its own maximum.
            let _ = rx.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = tx.set_send_buffer_size(4 * 1024 * 1024);
            outboxes.push(tx);
            inboxes.push(Some(rx));
        }
        Ok(Mailboxes { outboxes, inboxes })
    }

    /// Handles for `worker`: its own inbox (if it is an event worker) and senders to all.
    /// Descriptors are duplicated, so this can be called once per (re)started worker.
    pub fn for_worker(&self, worker: usize) -> Result<(Option<Inbox>, ProcessPeers)> {
        let inbox = match self.inboxes.get(worker) {
            Some(Some(socket)) => Some(Inbox {
                socket: socket.try_clone()?,
                reassembler: Reassembler::new(256 * 1024 * 1024, 1024),
            }),
            _ => None,
        };
        let outboxes = self
            .outboxes
            .iter()
            .map(Socket::try_clone)
            .collect::<io::Result<Vec<_>>>()?;
        Ok((
            inbox,
            ProcessPeers {
                outboxes,
                next_id: Cell::new(0),
                sender: worker,
            },
        ))
    }
}

/// [`Peers`] over datagram sockets.
pub(crate) struct ProcessPeers {
    outboxes: Vec<Socket>,
    next_id: Cell<u64>,
    sender: usize,
}

impl Peers for ProcessPeers {
    fn deliver(&self, worker: usize, envelope: Envelope) -> Result<()> {
        let outbox = self
            .outboxes
            .get(worker)
            .ok_or_else(|| Error::new(ErrorKind::InvalidArgument, format!("no worker {worker}")))?;
        let (kind, payload) = envelope.encode();
        // Ids only need to be unique per sender while pieces interleave.
        let id = (self.sender as u64) << 48 | self.next_id.replace(self.next_id.get() + 1);
        for datagram in message_bus::split(id, kind, &payload, MAX_DATAGRAM)? {
            let deadline = Instant::now() + SEND_PATIENCE;
            loop {
                match outbox.send(&datagram) {
                    Ok(_) => break,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                    {
                        let mut pfd = libc::pollfd {
                            fd: outbox.as_raw_fd(),
                            events: libc::POLLOUT,
                            revents: 0,
                        };
                        // SAFETY: one valid pollfd.
                        unsafe { libc::poll(&mut pfd, 1, 10) };
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }
}

/// A worker's receiving end.
pub(crate) struct Inbox {
    pub socket: Socket,
    reassembler: Reassembler,
}

impl Inbox {
    /// Reads every pending datagram and returns the completed envelopes.
    pub fn drain(&mut self) -> Vec<Envelope> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            match self.socket.recv(&mut buf) {
                Ok(n) => match self.reassembler.push(&buf[..n]) {
                    Ok(Some(message)) => {
                        if let Ok(env) = Envelope::decode(message.kind, message.payload) {
                            out.push(env);
                        }
                    }
                    Ok(None) => {}
                    Err(_) => self.reassembler.reset(),
                },
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        out
    }
}

/// [`Peers`] between threads: each worker publishes its reactor's [`Remote`] once running.
#[derive(Clone, Default)]
pub(crate) struct ThreadPeers {
    pub remotes: Arc<Vec<OnceLock<Remote>>>,
}

impl ThreadPeers {
    pub fn new(workers: usize) -> ThreadPeers {
        ThreadPeers {
            remotes: Arc::new((0..workers).map(|_| OnceLock::new()).collect()),
        }
    }
}

impl Peers for ThreadPeers {
    fn deliver(&self, worker: usize, envelope: Envelope) -> Result<()> {
        let remote = self
            .remotes
            .get(worker)
            .and_then(OnceLock::get)
            .ok_or_else(|| {
                Error::new(ErrorKind::NotFound, format!("worker {worker} not running"))
            })?;
        remote.post(move |reactor| super::worker::deliver_local(reactor, envelope))
    }
}

/// A task as queued for task workers: id, originating worker, payload.
pub(crate) fn encode_task(task: TaskId, from: usize, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + data.len());
    out.extend_from_slice(&task.0.to_be_bytes());
    out.extend_from_slice(&(from as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

pub(crate) fn decode_task(message: &[u8]) -> Option<(TaskId, usize, &[u8])> {
    let task = u64::from_be_bytes(message.get(..8)?.try_into().ok()?);
    let from = u32::from_be_bytes(message.get(8..12)?.try_into().ok()?);
    Some((TaskId(task), from as usize, &message[12..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_roundtrip_through_mailboxes() {
        let envelopes = vec![
            Envelope::Message {
                from: 3,
                data: vec![7; 10_000],
            },
            Envelope::Send {
                conn: ConnId(42),
                data: b"hi".to_vec(),
            },
            Envelope::Close { conn: ConnId(9) },
            Envelope::TaskResult {
                task: TaskId(5),
                data: vec![],
            },
            Envelope::Stop,
        ];
        let boxes = Mailboxes::new(2).unwrap();
        let (inbox, peers) = boxes.for_worker(1).unwrap();
        let mut inbox = inbox.unwrap();
        for env in &envelopes {
            peers.deliver(1, env.clone()).unwrap();
        }
        assert_eq!(inbox.drain(), envelopes);
        assert!(peers.deliver(9, Envelope::Stop).is_err());

        let task = encode_task(TaskId(77), 2, b"job");
        assert_eq!(decode_task(&task), Some((TaskId(77), 2, &b"job"[..])));
        assert_eq!(decode_task(&[1, 2]), None);
    }
}
