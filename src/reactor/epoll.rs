//! Linux backend on epoll, level-triggered.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use super::poller::{Event, Interest, Poller, Readiness, timeout_millis};
use crate::os::fd::check;

const BATCH: usize = 256;

pub struct Epoll {
    epfd: OwnedFd,
    buffer: Vec<libc::epoll_event>,
}

impl Epoll {
    pub fn new() -> io::Result<Self> {
        // SAFETY: epoll_create1 has no memory-safety preconditions.
        let fd = check(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })?;
        Ok(Epoll {
            // SAFETY: the descriptor was just created and is owned by nobody else.
            epfd: unsafe { OwnedFd::from_raw_fd(fd) },
            buffer: vec![libc::epoll_event { events: 0, u64: 0 }; BATCH],
        })
    }

    fn control(&self, op: libc::c_int, fd: RawFd, key: u64, interest: Interest) -> io::Result<()> {
        // A muted registration asks for nothing, so the kernel can only report HUP/ERR for it,
        // which `poll` then filters out.
        let mut flags = if interest == Interest::NONE {
            0
        } else {
            libc::EPOLLRDHUP
        };
        if interest.is_readable() {
            flags |= libc::EPOLLIN;
        }
        if interest.is_writable() {
            flags |= libc::EPOLLOUT;
        }
        let mut event = libc::epoll_event {
            events: flags as u32,
            u64: key,
        };
        // SAFETY: `event` is a valid epoll_event for the duration of the call.
        check(unsafe { libc::epoll_ctl(self.epfd.as_raw_fd(), op, fd, &mut event) }).map(drop)
    }
}

impl Poller for Epoll {
    fn name(&self) -> &'static str {
        "epoll"
    }

    fn register(&mut self, fd: RawFd, key: u64, interest: Interest) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_ADD, fd, key, interest)
    }

    fn reregister(&mut self, fd: RawFd, key: u64, _old: Interest, new: Interest) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_MOD, fd, key, new)
    }

    fn deregister(&mut self, fd: RawFd, _interest: Interest) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_DEL, fd, 0, Interest::NONE)
    }

    fn poll(&mut self, events: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()> {
        // SAFETY: `buffer` has room for `buffer.len()` events.
        let n = unsafe {
            libc::epoll_wait(
                self.epfd.as_raw_fd(),
                self.buffer.as_mut_ptr(),
                self.buffer.len() as libc::c_int,
                timeout_millis(timeout),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(err)
            };
        }
        for raw in &self.buffer[..n as usize] {
            let bits = raw.events as libc::c_int;
            if bits & (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLRDHUP) == 0 {
                continue;
            }
            let hangup = bits & (libc::EPOLLHUP | libc::EPOLLRDHUP) != 0;
            events.push(Event {
                key: raw.u64,
                readiness: Readiness {
                    readable: bits & libc::EPOLLIN != 0 || hangup,
                    writable: bits & libc::EPOLLOUT != 0,
                    hangup,
                    error: bits & libc::EPOLLERR != 0,
                },
            });
        }
        // A full batch suggests more are waiting; grow so the next wait sees them at once.
        if n as usize == self.buffer.len() && self.buffer.len() < 16 * BATCH {
            let grown = self.buffer.len() * 2;
            self.buffer
                .resize(grown, libc::epoll_event { events: 0, u64: 0 });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn conformance() {
        super::super::poller::tests::conformance(Box::new(super::Epoll::new().unwrap()));
    }
}
