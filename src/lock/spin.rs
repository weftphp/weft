use std::hint;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::memory::ShmSafe;

/// A test-and-test-and-set spinlock. Yields the CPU after a burst of spinning, so it degrades
/// gracefully when the holder is descheduled, but critical sections should stay tiny.
#[repr(C)]
#[derive(Debug, Default)]
pub struct SpinLock {
    locked: AtomicU32,
}

// SAFETY: one atomic word, valid when zeroed (unlocked).
unsafe impl ShmSafe for SpinLock {}

impl SpinLock {
    pub const fn new() -> SpinLock {
        SpinLock {
            locked: AtomicU32::new(0),
        }
    }

    pub fn lock(&self) -> SpinGuard<'_> {
        let mut spins = 0u32;
        loop {
            if self.locked.load(Ordering::Relaxed) == 0
                && self
                    .locked
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return SpinGuard { lock: self };
            }
            spins += 1;
            if spins < 64 {
                hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
    }

    pub fn try_lock(&self) -> Option<SpinGuard<'_>> {
        self.locked
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinGuard { lock: self })
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed) != 0
    }
}

/// Releases the [`SpinLock`] when dropped.
#[derive(Debug)]
pub struct SpinGuard<'a> {
    lock: &'a SpinLock,
}

impl Drop for SpinGuard<'_> {
    fn drop(&mut self) {
        self.lock.locked.store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn excludes_concurrent_holders() {
        let lock = SpinLock::new();
        let inside = AtomicU64::new(0);
        let total = AtomicU64::new(0);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..2000 {
                        let _g = lock.lock();
                        assert_eq!(inside.fetch_add(1, Ordering::Relaxed), 0);
                        total.fetch_add(1, Ordering::Relaxed);
                        inside.fetch_sub(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(total.load(Ordering::Relaxed), 8000);
        let g = lock.try_lock().unwrap();
        assert!(lock.try_lock().is_none());
        drop(g);
        assert!(!lock.is_locked());
    }
}
