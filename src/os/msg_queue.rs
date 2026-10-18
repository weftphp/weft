//! System V message queues (Linux only): a kernel-buffered channel between related processes
//! that survives either side restarting.

use std::io;

use crate::os::fd::{check, check_len, retry};

/// Largest payload accepted by [`MessageQueue::send`]; Linux's default `msgmax` is 8 KiB.
pub const MAX_PAYLOAD: usize = 8192;

/// A System V message queue.
#[derive(Debug)]
pub struct MessageQueue {
    id: libc::c_int,
    blocking: bool,
}

#[repr(C)]
struct RawMessage {
    kind: libc::c_long,
    data: [u8; MAX_PAYLOAD],
}

impl MessageQueue {
    /// Opens (creating if needed) the queue identified by `key`, with permissions `mode`.
    pub fn open(key: i32, mode: u32) -> io::Result<Self> {
        // SAFETY: msgget has no memory-safety preconditions.
        let id = check(unsafe { libc::msgget(key, libc::IPC_CREAT | (mode & 0o777) as i32) })?;
        Ok(MessageQueue { id, blocking: true })
    }

    /// Creates a private queue, usable by this process and children forked afterwards.
    pub fn private() -> io::Result<Self> {
        Self::open(libc::IPC_PRIVATE, 0o600)
    }

    /// Chooses whether send/receive wait (`true`, the default) or fail with `WouldBlock`.
    pub fn set_blocking(&mut self, blocking: bool) {
        self.blocking = blocking;
    }

    fn flags(&self) -> libc::c_int {
        if self.blocking { 0 } else { libc::IPC_NOWAIT }
    }

    /// Sends `data` tagged with `kind` (which must be positive).
    pub fn send(&self, kind: libc::c_long, data: &[u8]) -> io::Result<()> {
        if kind <= 0 || data.len() > MAX_PAYLOAD {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let mut message = Box::new(RawMessage {
            kind,
            data: [0; MAX_PAYLOAD],
        });
        message.data[..data.len()].copy_from_slice(data);
        retry(|| {
            // SAFETY: `message` is a valid msgbuf-shaped struct with `data.len()` payload bytes.
            check(unsafe {
                libc::msgsnd(
                    self.id,
                    (&raw const *message).cast(),
                    data.len(),
                    self.flags(),
                )
            })
        })
        .map(drop)
    }

    /// Receives the next message. `kind == 0` takes any message; a positive `kind` takes the
    /// first message of that kind. Returns `(kind, payload)`.
    pub fn recv(&self, kind: libc::c_long) -> io::Result<(libc::c_long, Vec<u8>)> {
        let mut message = Box::new(RawMessage {
            kind: 0,
            data: [0; MAX_PAYLOAD],
        });
        let len = retry(|| {
            // SAFETY: `message` has room for MAX_PAYLOAD payload bytes, which we pass as msgsz.
            check_len(unsafe {
                libc::msgrcv(
                    self.id,
                    (&raw mut *message).cast(),
                    MAX_PAYLOAD,
                    kind,
                    self.flags(),
                )
            })
        })?;
        Ok((message.kind, message.data[..len].to_vec()))
    }

    /// Number of messages currently queued.
    pub fn len(&self) -> io::Result<usize> {
        // SAFETY: `info` is a valid out-pointer for IPC_STAT.
        unsafe {
            let mut info: libc::msqid_ds = std::mem::zeroed();
            check(libc::msgctl(self.id, libc::IPC_STAT, &mut info))?;
            Ok(info.msg_qnum as usize)
        }
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Deletes the queue from the system. Other holders' operations then fail.
    pub fn remove(self) -> io::Result<()> {
        // SAFETY: IPC_RMID takes no buffer.
        check(unsafe { libc::msgctl(self.id, libc::IPC_RMID, std::ptr::null_mut()) }).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_and_select_by_kind() {
        let mut queue = MessageQueue::private().unwrap();
        queue.send(1, b"one").unwrap();
        queue.send(2, b"two").unwrap();
        assert_eq!(queue.len().unwrap(), 2);
        assert_eq!(queue.recv(2).unwrap(), (2, b"two".to_vec()));
        assert_eq!(queue.recv(0).unwrap(), (1, b"one".to_vec()));

        queue.set_blocking(false);
        let err = queue.recv(0).unwrap_err();
        assert!(matches!(err.raw_os_error(), Some(libc::ENOMSG)));
        assert!(queue.send(0, b"x").is_err());
        queue.remove().unwrap();
    }
}
