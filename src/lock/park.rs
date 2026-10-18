//! Waiting on a shared 32-bit word, across processes.
//!
//! On Linux this is a (non-private) futex, so waiters sleep in the kernel until woken. Other
//! systems have no portable cross-process equivalent, so waiters back off with short sleeps
//! and `wake_*` does nothing; callers must re-check their condition after every return.

use std::sync::atomic::AtomicU32;
use std::time::Duration;

/// Blocks while `*word == expected`, for at most `timeout`. May return spuriously.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn wait(word: &AtomicU32, expected: u32, timeout: Option<Duration>) {
    let spec = timeout.map(|t| libc::timespec {
        tv_sec: t.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
        tv_nsec: t.subsec_nanos() as _,
    });
    let spec_ptr = spec.as_ref().map_or(std::ptr::null(), |s| s as *const _);
    // SAFETY: `word` is a live, aligned 32-bit atomic; FUTEX_WAIT only reads it and sleeps.
    // The shared (non-private) variant is required because waiters may be in other processes.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word.as_ptr(),
            libc::FUTEX_WAIT,
            expected,
            spec_ptr,
            std::ptr::null::<u32>(),
            0,
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn wake(word: &AtomicU32, count: i32) {
    // SAFETY: FUTEX_WAKE only uses the address as a key.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word.as_ptr(),
            libc::FUTEX_WAKE,
            count,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0,
        );
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn wait(word: &AtomicU32, expected: u32, timeout: Option<Duration>) {
    use std::sync::atomic::Ordering;
    // Without a wake-up mechanism, sleep briefly and let the caller re-check.
    let nap = Duration::from_micros(200);
    let nap = timeout.map_or(nap, |t| t.min(nap));
    if word.load(Ordering::Acquire) == expected {
        std::thread::sleep(nap);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn wake(_word: &AtomicU32, _count: i32) {}

/// Wakes one waiter on `word`.
pub(crate) fn wake_one(word: &AtomicU32) {
    wake(word, 1);
}

/// Wakes every waiter on `word`.
pub(crate) fn wake_all(word: &AtomicU32) {
    wake(word, i32::MAX);
}
