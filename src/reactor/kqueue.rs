//! BSD/macOS backend on kqueue. Read and write readiness are separate filters, so a
//! descriptor ready both ways yields two events with the same key.

// kevent field and constant types differ between BSDs, so casts that are no-ops on one
// platform are needed on another.
#![allow(clippy::unnecessary_cast)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use super::poller::{Event, Interest, Poller, Readiness};
use crate::os::fd::check;

const BATCH: usize = 256;

pub struct Kqueue {
    kq: OwnedFd,
    buffer: Vec<libc::kevent>,
}

// SAFETY: the only non-Send part is `kevent::udata`, a pointer-typed field that weft uses solely
// to carry an integer key and never dereferences.
unsafe impl Send for Kqueue {}

fn change(fd: RawFd, filter: i16, flags: u16, key: u64) -> libc::kevent {
    // SAFETY: kevent is plain old data; every field the kernel reads is set below.
    let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
    ev.ident = fd as libc::uintptr_t;
    ev.filter = filter as _;
    ev.flags = flags as _;
    ev.udata = key as usize as _;
    ev
}

impl Kqueue {
    pub fn new() -> io::Result<Self> {
        // SAFETY: kqueue has no memory-safety preconditions.
        let fd = check(unsafe { libc::kqueue() })?;
        // SAFETY: the descriptor was just created and is owned by nobody else.
        let kq = unsafe { OwnedFd::from_raw_fd(fd) };
        crate::os::fd::set_cloexec(std::os::fd::AsFd::as_fd(&kq), true)?;
        Ok(Kqueue {
            kq,
            // SAFETY: as in `change`, a zeroed kevent is a valid value.
            buffer: vec![unsafe { std::mem::zeroed() }; BATCH],
        })
    }

    fn apply(&self, changes: &[libc::kevent]) -> io::Result<()> {
        if changes.is_empty() {
            return Ok(());
        }
        // SAFETY: `changes` holds `changes.len()` initialised kevents; no event list is
        // requested and the zero timeout is not used.
        check(unsafe {
            libc::kevent(
                self.kq.as_raw_fd(),
                changes.as_ptr(),
                changes.len() as libc::c_int,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        })
        .map(drop)
    }

    /// Adds the filters in `add`, deletes those in `remove`.
    fn update(&self, fd: RawFd, key: u64, add: Interest, remove: Interest) -> io::Result<()> {
        let mut changes = Vec::with_capacity(4);
        let add_flags = (libc::EV_ADD | libc::EV_ENABLE) as u16;
        if add.is_readable() {
            changes.push(change(fd, libc::EVFILT_READ as i16, add_flags, key));
        }
        if add.is_writable() {
            changes.push(change(fd, libc::EVFILT_WRITE as i16, add_flags, key));
        }
        if remove.is_readable() {
            changes.push(change(
                fd,
                libc::EVFILT_READ as i16,
                libc::EV_DELETE as u16,
                0,
            ));
        }
        if remove.is_writable() {
            changes.push(change(
                fd,
                libc::EVFILT_WRITE as i16,
                libc::EV_DELETE as u16,
                0,
            ));
        }
        self.apply(&changes)
    }
}

impl Poller for Kqueue {
    fn name(&self) -> &'static str {
        "kqueue"
    }

    fn register(&mut self, fd: RawFd, key: u64, interest: Interest) -> io::Result<()> {
        self.update(fd, key, interest, Interest::NONE)
    }

    fn reregister(&mut self, fd: RawFd, key: u64, old: Interest, new: Interest) -> io::Result<()> {
        // EV_ADD on an existing filter just updates its udata, so re-adding `new` in full
        // also moves surviving filters to the new key.
        self.update(fd, key, new, old.without(new))
    }

    fn deregister(&mut self, fd: RawFd, interest: Interest) -> io::Result<()> {
        self.update(fd, 0, Interest::NONE, interest)
    }

    fn poll(&mut self, events: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()> {
        let spec = timeout.map(|t| libc::timespec {
            tv_sec: t.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
            tv_nsec: t.subsec_nanos() as _,
        });
        let spec_ptr = spec.as_ref().map_or(std::ptr::null(), |s| s as *const _);
        // SAFETY: `buffer` has room for `buffer.len()` kevents; `spec_ptr` is null or points
        // at a timespec that outlives the call.
        let n = unsafe {
            libc::kevent(
                self.kq.as_raw_fd(),
                std::ptr::null(),
                0,
                self.buffer.as_mut_ptr(),
                self.buffer.len() as libc::c_int,
                spec_ptr,
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
        for ev in &self.buffer[..n as usize] {
            let flags = ev.flags as u32;
            let filter = ev.filter as i32;
            let error = flags & libc::EV_ERROR as u32 != 0;
            let hangup = flags & libc::EV_EOF as u32 != 0;
            events.push(Event {
                key: ev.udata as usize as u64,
                readiness: Readiness {
                    readable: filter == libc::EVFILT_READ as i32,
                    writable: filter == libc::EVFILT_WRITE as i32,
                    hangup,
                    // With EV_EOF, `fflags` carries the socket error, if any.
                    error: error || (hangup && ev.fflags != 0),
                },
            });
        }
        if n as usize == self.buffer.len() && self.buffer.len() < 16 * BATCH {
            let grown = self.buffer.len() * 2;
            // SAFETY: as in `new`.
            self.buffer.resize(grown, unsafe { std::mem::zeroed() });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn conformance() {
        super::super::poller::tests::conformance(Box::new(super::Kqueue::new().unwrap()));
    }
}
