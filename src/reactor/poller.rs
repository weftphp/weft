//! The readiness-polling interface each OS backend implements.

use std::io;
use std::ops::BitOr;
use std::os::fd::RawFd;
use std::time::Duration;

/// Which readiness a registration wants to hear about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Interest(u8);

impl Interest {
    /// Registered but muted: no events are reported.
    pub const NONE: Interest = Interest(0);
    pub const READABLE: Interest = Interest(1);
    pub const WRITABLE: Interest = Interest(2);
    pub const BOTH: Interest = Interest(3);

    pub fn is_readable(self) -> bool {
        self.0 & Self::READABLE.0 != 0
    }

    pub fn is_writable(self) -> bool {
        self.0 & Self::WRITABLE.0 != 0
    }

    /// `self` with `other`'s bits removed.
    pub fn without(self, other: Interest) -> Interest {
        Interest(self.0 & !other.0)
    }
}

impl BitOr for Interest {
    type Output = Interest;

    fn bitor(self, rhs: Interest) -> Interest {
        Interest(self.0 | rhs.0)
    }
}

/// What a backend observed on one descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
    /// The peer closed its end (reads will hit EOF once buffered data is consumed).
    pub hangup: bool,
    /// The descriptor has a pending error (see `SO_ERROR`).
    pub error: bool,
}

/// One readiness report from [`Poller::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub key: u64,
    pub readiness: Readiness,
}

/// A level-triggered readiness poller.
///
/// Registrations are identified by an opaque `key` chosen by the caller and reported back in
/// each [`Event`]. A descriptor must be deregistered before it is closed.
pub trait Poller: Send {
    /// Short backend name, for diagnostics.
    fn name(&self) -> &'static str;

    fn register(&mut self, fd: RawFd, key: u64, interest: Interest) -> io::Result<()>;

    /// Changes the interest (and key) of a registered descriptor. `old` is the interest it was
    /// last registered with.
    fn reregister(&mut self, fd: RawFd, key: u64, old: Interest, new: Interest) -> io::Result<()>;

    fn deregister(&mut self, fd: RawFd, interest: Interest) -> io::Result<()>;

    /// Waits up to `timeout` (forever if `None`) and appends ready descriptors to `events`.
    /// Returns early, with no events, if interrupted by a signal.
    fn poll(&mut self, events: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()>;
}

/// Selects the polling backend of a [`Reactor`](super::Reactor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// The best one for this OS: epoll on Linux, kqueue on BSD/macOS, otherwise `poll(2)`.
    #[default]
    Auto,
    /// Portable `poll(2)`.
    Poll,
}

/// Creates a poller for `backend`.
pub fn new_poller(backend: Backend) -> io::Result<Box<dyn Poller>> {
    match backend {
        Backend::Poll => Ok(Box::new(super::poll::PollPoller::new())),
        Backend::Auto => native(),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn native() -> io::Result<Box<dyn Poller>> {
    Ok(Box::new(super::epoll::Epoll::new()?))
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn native() -> io::Result<Box<dyn Poller>> {
    Ok(Box::new(super::kqueue::Kqueue::new()?))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
fn native() -> io::Result<Box<dyn Poller>> {
    Ok(Box::new(super::poll::PollPoller::new()))
}

/// Converts a timeout to whole milliseconds for `poll`/`epoll_wait`, rounding up so a
/// sub-millisecond wait does not turn into a busy loop. `-1` means forever.
pub(crate) fn timeout_millis(timeout: Option<Duration>) -> libc::c_int {
    match timeout {
        None => -1,
        Some(t) => {
            let ms = t.as_nanos().div_ceil(1_000_000);
            ms.min(libc::c_int::MAX as u128) as libc::c_int
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    /// Behaviour every backend must share.
    pub fn conformance(mut poller: Box<dyn Poller>) {
        let (mut a, b) = UnixStream::pair().unwrap();
        let mut events = Vec::new();

        poller
            .register(b.as_raw_fd(), 7, Interest::READABLE)
            .unwrap();
        let start = Instant::now();
        poller
            .poll(&mut events, Some(Duration::from_millis(20)))
            .unwrap();
        assert!(events.is_empty());
        assert!(
            start.elapsed() >= Duration::from_millis(15),
            "honours timeout"
        );

        a.write_all(b"x").unwrap();
        poller.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].key, 7);
        assert!(events[0].readiness.readable);

        // Level-triggered: still readable because nothing was read.
        events.clear();
        poller.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.iter().any(|e| e.key == 7 && e.readiness.readable));

        events.clear();
        poller
            .reregister(b.as_raw_fd(), 8, Interest::READABLE, Interest::WRITABLE)
            .unwrap();
        poller.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.iter().all(|e| e.key == 8 && !e.readiness.readable));
        assert!(events.iter().any(|e| e.readiness.writable));

        events.clear();
        poller
            .reregister(b.as_raw_fd(), 9, Interest::WRITABLE, Interest::NONE)
            .unwrap();
        poller.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.is_empty(), "muted registration reports nothing");

        poller
            .reregister(b.as_raw_fd(), 9, Interest::NONE, Interest::READABLE)
            .unwrap();
        drop(a);
        poller.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.iter().any(|e| e.key == 9 && e.readiness.hangup));

        events.clear();
        poller
            .deregister(b.as_raw_fd(), Interest::READABLE)
            .unwrap();
        poller.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.is_empty());

        // A pipe whose writer closed must wake its reader (epoll reports only HUP here),
        // and must stay silent while muted.
        let (r, w) = crate::os::fd::pipe(true).unwrap();
        poller
            .register(r.as_raw_fd(), 10, Interest::READABLE)
            .unwrap();
        drop(w);
        poller
            .poll(&mut events, Some(Duration::from_secs(5)))
            .unwrap();
        assert!(events.iter().any(|e| e.key == 10 && e.readiness.readable));
        events.clear();
        poller
            .reregister(r.as_raw_fd(), 10, Interest::READABLE, Interest::NONE)
            .unwrap();
        poller.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.is_empty(), "muted hung-up pipe reports nothing");
        poller.deregister(r.as_raw_fd(), Interest::NONE).unwrap();
    }

    #[test]
    fn auto_backend() {
        conformance(new_poller(Backend::Auto).unwrap());
    }

    #[test]
    fn poll_backend() {
        conformance(new_poller(Backend::Poll).unwrap());
    }

    #[test]
    fn millisecond_rounding() {
        assert_eq!(timeout_millis(None), -1);
        assert_eq!(timeout_millis(Some(Duration::ZERO)), 0);
        assert_eq!(timeout_millis(Some(Duration::from_micros(10))), 1);
        assert_eq!(timeout_millis(Some(Duration::from_millis(5))), 5);
    }
}
