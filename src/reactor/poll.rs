//! Portable backend on `poll(2)`. O(n) per wait, so mainly a fallback and a test oracle.

use std::collections::HashMap;
use std::io;
use std::os::fd::RawFd;
use std::time::Duration;

use super::poller::{Event, Interest, Poller, Readiness, timeout_millis};

#[derive(Default)]
pub struct PollPoller {
    fds: Vec<libc::pollfd>,
    keys: Vec<u64>,
    /// Descriptor to its index in `fds`/`keys`.
    index: HashMap<RawFd, usize>,
}

impl PollPoller {
    pub fn new() -> Self {
        Self::default()
    }
}

fn mask(interest: Interest) -> libc::c_short {
    let mut events = 0;
    if interest.is_readable() {
        events |= libc::POLLIN;
    }
    if interest.is_writable() {
        events |= libc::POLLOUT;
    }
    events
}

fn not_registered() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}

impl Poller for PollPoller {
    fn name(&self) -> &'static str {
        "poll"
    }

    fn register(&mut self, fd: RawFd, key: u64, interest: Interest) -> io::Result<()> {
        if self.index.contains_key(&fd) {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        self.index.insert(fd, self.fds.len());
        self.fds.push(libc::pollfd {
            fd,
            events: mask(interest),
            revents: 0,
        });
        self.keys.push(key);
        Ok(())
    }

    fn reregister(&mut self, fd: RawFd, key: u64, _old: Interest, new: Interest) -> io::Result<()> {
        let &i = self.index.get(&fd).ok_or_else(not_registered)?;
        self.fds[i].events = mask(new);
        self.keys[i] = key;
        Ok(())
    }

    fn deregister(&mut self, fd: RawFd, _interest: Interest) -> io::Result<()> {
        let i = self.index.remove(&fd).ok_or_else(not_registered)?;
        self.fds.swap_remove(i);
        self.keys.swap_remove(i);
        if let Some(moved) = self.fds.get(i) {
            self.index.insert(moved.fd, i);
        }
        Ok(())
    }

    fn poll(&mut self, events: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()> {
        // SAFETY: `fds` is a valid array of `fds.len()` pollfd structs.
        let ret = unsafe {
            libc::poll(
                self.fds.as_mut_ptr(),
                self.fds.len() as libc::nfds_t,
                timeout_millis(timeout),
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(err)
            };
        }
        for (pfd, &key) in self.fds.iter().zip(&self.keys) {
            let r = pfd.revents;
            // A muted registration may still get POLLHUP/POLLERR, which poll always reports.
            if r == 0 || pfd.events == 0 {
                continue;
            }
            events.push(Event {
                key,
                readiness: Readiness {
                    readable: r & (libc::POLLIN | libc::POLLHUP) != 0,
                    writable: r & libc::POLLOUT != 0,
                    hangup: r & libc::POLLHUP != 0,
                    error: r & (libc::POLLERR | libc::POLLNVAL) != 0,
                },
            });
        }
        Ok(())
    }
}
