//! Moving signal delivery out of signal-handler context.
//!
//! A handler may only do async-signal-safe work, so weft's handler just marks the signal as
//! pending and writes one byte to a process-wide pipe. An event loop watches that pipe's read
//! end ([`notifier`]) and, once it is readable, calls [`take_pending`] from ordinary code.
//!
//! Pending signals are flags, not a queue: two deliveries of the same signal before the loop
//! catches up are reported once. A full pipe is harmless for the same reason.

use std::io;
use std::os::fd::{BorrowedFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Mutex, Once};

use crate::os::fd;

/// One past the largest signal number tracked (Linux realtime signals end at 64).
const SIGNAL_LIMIT: usize = 65;

static PENDING: [AtomicBool; SIGNAL_LIMIT] = [const { AtomicBool::new(false) }; SIGNAL_LIMIT];
/// Ends of the notification pipe, or -1 before the first [`watch`].
static NOTIFY_READ: AtomicI32 = AtomicI32::new(-1);
static NOTIFY_WRITE: AtomicI32 = AtomicI32::new(-1);
static CREATE: Mutex<()> = Mutex::new(());
static ATFORK: Once = Once::new();

fn ensure_pipe() -> io::Result<RawFd> {
    let fd = NOTIFY_READ.load(Ordering::Acquire);
    if fd >= 0 {
        return Ok(fd);
    }
    let _guard = CREATE.lock().unwrap_or_else(|e| e.into_inner());
    let fd = NOTIFY_READ.load(Ordering::Acquire);
    if fd >= 0 {
        return Ok(fd);
    }
    ATFORK.call_once(|| {
        // SAFETY: registering a child handler has no preconditions; the handler only does
        // async-signal-safe work.
        unsafe { libc::pthread_atfork(None, None, Some(after_fork_in_child)) };
    });
    let (read, write) = fd::pipe(true)?;
    let (read, write) = (read.into_raw_fd(), write.into_raw_fd());
    NOTIFY_WRITE.store(write, Ordering::Release);
    NOTIFY_READ.store(read, Ordering::Release);
    Ok(read)
}

/// A forked child must not share its parent's pipe, or each would consume the other's
/// notifications. Forget it here; the child's next [`watch`] creates its own.
extern "C" fn after_fork_in_child() {
    for end in [&NOTIFY_READ, &NOTIFY_WRITE] {
        let fd = end.swap(-1, Ordering::AcqRel);
        if fd >= 0 {
            // SAFETY: closing a descriptor this module owns; close is async-signal-safe.
            unsafe { libc::close(fd) };
        }
    }
    for flag in &PENDING {
        flag.store(false, Ordering::Relaxed);
    }
}

/// The read end of the notification pipe. It becomes readable whenever a watched signal
/// arrives. In a forked child this is a different pipe than in the parent.
pub fn notifier() -> io::Result<BorrowedFd<'static>> {
    let fd = ensure_pipe()?;
    // SAFETY: the pipe stays open for the life of the process; it is only replaced in a
    // freshly forked child, where the parent's borrowers are not meant to be used.
    Ok(unsafe { BorrowedFd::borrow_raw(fd) })
}

fn validate(signal: i32) -> io::Result<usize> {
    match usize::try_from(signal) {
        Ok(n) if (1..SIGNAL_LIMIT).contains(&n) => Ok(n),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("signal {signal} is out of range"),
        )),
    }
}

fn install(signal: i32, handler: libc::sighandler_t) -> io::Result<()> {
    validate(signal)?;
    // SAFETY: a zeroed sigaction is a valid starting value; we then set every field the
    // kernel reads. `handler` is SIG_DFL, SIG_IGN or `on_signal`, all valid dispositions.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        fd::check(libc::sigaction(signal, &action, std::ptr::null_mut()))?;
    }
    Ok(())
}

/// Starts routing `signal` through the notification pipe.
pub fn watch(signal: i32) -> io::Result<()> {
    ensure_pipe()?;
    install(
        signal,
        on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
    )
}

/// Ignores `signal` (for example `SIGPIPE`, so a closed peer surfaces as `EPIPE`).
pub fn ignore(signal: i32) -> io::Result<()> {
    install(signal, libc::SIG_IGN)
}

/// Restores the default disposition of `signal`.
pub fn reset(signal: i32) -> io::Result<()> {
    install(signal, libc::SIG_DFL)?;
    PENDING[validate(signal)?].store(false, Ordering::Relaxed);
    Ok(())
}

/// Drains the notification pipe and returns the signals that arrived since the last call,
/// in ascending order.
pub fn take_pending() -> Vec<i32> {
    let reader = NOTIFY_READ.load(Ordering::Acquire);
    if reader >= 0 {
        // SAFETY: the pipe is open (see `notifier`).
        let reader = unsafe { BorrowedFd::borrow_raw(reader) };
        let mut sink = [0u8; 64];
        while matches!(fd::read(reader, &mut sink), Ok(n) if n > 0) {}
    }
    (1..SIGNAL_LIMIT)
        .filter(|&n| PENDING[n].swap(false, Ordering::AcqRel))
        .map(|n| n as i32)
        .collect()
}

fn change_mask(how: libc::c_int, signals: &[i32]) -> io::Result<()> {
    // SAFETY: the set is initialised by sigemptyset before use, and pthread_sigmask only
    // reads it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &signal in signals {
            validate(signal)?;
            libc::sigaddset(&mut set, signal);
        }
        match libc::pthread_sigmask(how, &set, std::ptr::null_mut()) {
            0 => Ok(()),
            err => Err(io::Error::from_raw_os_error(err)),
        }
    }
}

/// Blocks `signals` for the calling thread (they stay pending until unblocked).
pub fn block(signals: &[i32]) -> io::Result<()> {
    change_mask(libc::SIG_BLOCK, signals)
}

/// Unblocks `signals` for the calling thread.
pub fn unblock(signals: &[i32]) -> io::Result<()> {
    change_mask(libc::SIG_UNBLOCK, signals)
}

extern "C" fn on_signal(signal: libc::c_int) {
    let saved = errno::get();
    if let Some(flag) = PENDING.get(signal as usize) {
        flag.store(true, Ordering::Release);
    }
    let fd = NOTIFY_WRITE.load(Ordering::Acquire);
    if fd >= 0 {
        let byte = 1u8;
        // SAFETY: write(2) is async-signal-safe and `byte` outlives the call. The pipe is
        // never closed once created. Failure (a full pipe) is fine: the flag is already set.
        unsafe { libc::write(fd, (&raw const byte).cast(), 1) };
    }
    errno::set(saved);
}

/// Handlers must leave `errno` as they found it.
mod errno {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn location() -> *mut libc::c_int {
        // SAFETY: always returns the calling thread's errno slot.
        unsafe { libc::__errno_location() }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn location() -> *mut libc::c_int {
        // SAFETY: always returns the calling thread's errno slot.
        unsafe { libc::__error() }
    }

    pub fn get() -> libc::c_int {
        // SAFETY: the slot is valid for the lifetime of the thread.
        unsafe { *location() }
    }

    pub fn set(value: libc::c_int) {
        // SAFETY: as above.
        unsafe { *location() = value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivers_through_pipe() {
        watch(libc::SIGUSR1).unwrap();
        // SAFETY: raise only delivers the signal, now handled by `on_signal`.
        assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
        assert!(take_pending().contains(&libc::SIGUSR1));
        assert!(!take_pending().contains(&libc::SIGUSR1));
        reset(libc::SIGUSR1).unwrap();
    }

    #[test]
    fn rejects_bad_numbers() {
        assert!(watch(0).is_err());
        assert!(watch(SIGNAL_LIMIT as i32).is_err());
        assert!(watch(libc::SIGKILL).is_err());
    }
}
