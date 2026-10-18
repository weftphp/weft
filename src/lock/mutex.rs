use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use super::park;
use crate::memory::ShmSafe;
use crate::os::process::{self, Pid};

const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;
/// Locked, and someone may be sleeping on it.
const CONTENDED: u32 = 2;

/// How often a waiter checks whether the holder process died.
const LIVENESS_CHECK: Duration = Duration::from_millis(50);

/// A sleeping mutex usable across processes.
///
/// If the process holding it dies, the next waiter takes it over and its guard reports
/// [`recovered`](MutexGuard::recovered), so the protected data can be checked or rebuilt.
/// (Death of a *thread* holding it is not detected; release locks before a thread exits.)
#[repr(C)]
#[derive(Debug, Default)]
pub struct ProcessMutex {
    state: AtomicU32,
    /// Pid of the holding process, 0 when unlocked.
    owner: AtomicI32,
}

// SAFETY: two atomic words, valid when zeroed (unlocked, no owner).
unsafe impl ShmSafe for ProcessMutex {}

impl ProcessMutex {
    pub const fn new() -> ProcessMutex {
        ProcessMutex {
            state: AtomicU32::new(UNLOCKED),
            owner: AtomicI32::new(0),
        }
    }

    fn acquired(&self, recovered: bool) -> MutexGuard<'_> {
        self.owner.store(Pid::current().0, Ordering::Relaxed);
        MutexGuard {
            mutex: self,
            recovered,
        }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_>> {
        self.state
            .compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| self.acquired(false))
    }

    /// Blocks until the lock is acquired.
    pub fn lock(&self) -> MutexGuard<'_> {
        match self.lock_until(None) {
            Some(guard) => guard,
            // Without a deadline lock_until only returns once acquired.
            None => self.lock(),
        }
    }

    /// Waits at most `timeout`.
    pub fn lock_timeout(&self, timeout: Duration) -> Option<MutexGuard<'_>> {
        self.lock_until(Some(Instant::now() + timeout))
    }

    fn lock_until(&self, deadline: Option<Instant>) -> Option<MutexGuard<'_>> {
        if let Some(guard) = self.try_lock() {
            return Some(guard);
        }
        for _ in 0..100 {
            std::hint::spin_loop();
            if self.state.load(Ordering::Relaxed) == UNLOCKED
                && let Some(guard) = self.try_lock()
            {
                return Some(guard);
            }
        }
        loop {
            // Marking the lock contended before sleeping makes the holder wake us.
            if self.state.swap(CONTENDED, Ordering::Acquire) == UNLOCKED {
                return Some(self.acquired(false));
            }
            if let Some(guard) = self.take_from_dead_owner() {
                return Some(guard);
            }
            let mut nap = LIVENESS_CHECK;
            if let Some(deadline) = deadline {
                let left = deadline.checked_duration_since(Instant::now())?;
                nap = nap.min(left);
                if nap.is_zero() {
                    return None;
                }
            }
            park::wait(&self.state, CONTENDED, Some(nap));
        }
    }

    fn take_from_dead_owner(&self) -> Option<MutexGuard<'_>> {
        let owner = self.owner.load(Ordering::Relaxed);
        if owner == 0 || owner == Pid::current().0 || process::exists(Pid(owner)) {
            return None;
        }
        // Only one waiter wins the ownership transfer; the lock word stays held.
        self.owner
            .compare_exchange(owner, Pid::current().0, Ordering::AcqRel, Ordering::Relaxed)
            .ok()
            .map(|_| self.acquired(true))
    }

    pub fn is_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) != UNLOCKED
    }
}

/// Releases the [`ProcessMutex`] when dropped.
#[derive(Debug)]
pub struct MutexGuard<'a> {
    mutex: &'a ProcessMutex,
    recovered: bool,
}

impl MutexGuard<'_> {
    /// Whether the lock was taken over from a process that died while holding it, leaving
    /// the protected data possibly half-updated.
    pub fn recovered(&self) -> bool {
        self.recovered
    }
}

impl Drop for MutexGuard<'_> {
    fn drop(&mut self) {
        self.mutex.owner.store(0, Ordering::Relaxed);
        if self.mutex.state.swap(UNLOCKED, Ordering::Release) == CONTENDED {
            park::wake_one(&self.mutex.state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn mutual_exclusion_between_threads() {
        let mutex = ProcessMutex::new();
        let counter = AtomicU64::new(0);
        let inside = AtomicU32::new(0);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..500 {
                        let guard = mutex.lock();
                        assert!(!guard.recovered());
                        assert_eq!(inside.fetch_add(1, Ordering::Relaxed), 0);
                        counter.fetch_add(1, Ordering::Relaxed);
                        inside.fetch_sub(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(counter.load(Ordering::Relaxed), 2000);
        assert!(!mutex.is_locked());
    }

    #[test]
    fn timeout_and_dead_owner_recovery() {
        let mutex = ProcessMutex::new();
        let held = mutex.lock();
        assert!(mutex.try_lock().is_none());
        let start = Instant::now();
        assert!(mutex.lock_timeout(Duration::from_millis(30)).is_none());
        assert!(start.elapsed() >= Duration::from_millis(25));
        // Pretend the holder was a process that has since exited.
        std::mem::forget(held);
        mutex.owner.store(i32::MAX - 7, Ordering::Relaxed);
        let guard = mutex.lock_timeout(Duration::from_secs(5)).unwrap();
        assert!(guard.recovered());
        drop(guard);
        assert!(mutex.try_lock().is_some());
    }
}
