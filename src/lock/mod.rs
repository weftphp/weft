//! Locks that work across processes as well as threads.
//!
//! Each lock is a small `#[repr(C)]` struct of atomics that implements
//! [`ShmSafe`](crate::memory::ShmSafe), so it can be placed in
//! [`Shared`](crate::memory::Shared) memory before forking and used by every process.
//! All of them also work as ordinary in-process locks.
//!
//! - [`ProcessMutex`]: a sleeping mutex that recovers when its holder dies.
//! - [`SpinLock`]: for very short critical sections.
//! - [`RwLock`]: many readers or one writer, writer-preferring.
//! - [`Barrier`]: lets a fixed number of participants wait for each other.

mod barrier;
mod mutex;
mod park;
mod rwlock;
mod spin;

pub use barrier::Barrier;
pub use mutex::{MutexGuard, ProcessMutex};
pub use rwlock::{ReadGuard, RwLock, WriteGuard};
pub use spin::{SpinGuard, SpinLock};

/// Sleeps while `*word == seen`, for at most `timeout` (spurious wake-ups possible). For
/// building other cross-process waits on a shared counter.
pub fn park_wait(word: &std::sync::atomic::AtomicU32, seen: u32, timeout: std::time::Duration) {
    park::wait(word, seen, Some(timeout));
}

/// Wakes every [`park_wait`]er on `word`.
pub fn park_wake_all(word: &std::sync::atomic::AtomicU32) {
    park::wake_all(word);
}
