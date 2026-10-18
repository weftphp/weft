use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::park;
use crate::memory::ShmSafe;

const WRITER: u32 = 1 << 31;
/// A writer is waiting; new readers hold back so writers are not starved.
const WRITER_WAITING: u32 = 1 << 30;
const READERS: u32 = WRITER_WAITING - 1;

const NAP: Duration = Duration::from_millis(50);

/// A reader-writer lock usable across processes. Writer-preferring.
#[repr(C)]
#[derive(Debug, Default)]
pub struct RwLock {
    state: AtomicU32,
}

// SAFETY: one atomic word, valid when zeroed (unlocked).
unsafe impl ShmSafe for RwLock {}

impl RwLock {
    pub const fn new() -> RwLock {
        RwLock {
            state: AtomicU32::new(0),
        }
    }

    pub fn try_read(&self) -> Option<ReadGuard<'_>> {
        let s = self.state.load(Ordering::Relaxed);
        if s & (WRITER | WRITER_WAITING) != 0 || s & READERS == READERS {
            return None;
        }
        self.state
            .compare_exchange(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| ReadGuard { lock: self })
    }

    pub fn read(&self) -> ReadGuard<'_> {
        loop {
            if let Some(guard) = self.try_read() {
                return guard;
            }
            let s = self.state.load(Ordering::Relaxed);
            if s & (WRITER | WRITER_WAITING) != 0 {
                park::wait(&self.state, s, Some(NAP));
            } else {
                std::hint::spin_loop();
            }
        }
    }

    pub fn try_write(&self) -> Option<WriteGuard<'_>> {
        let s = self.state.load(Ordering::Relaxed);
        if s & (WRITER | READERS) != 0 {
            return None;
        }
        // Keeps nothing else: the waiting flag is re-set by any writer still waiting.
        self.state
            .compare_exchange(s, WRITER, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| WriteGuard { lock: self })
    }

    pub fn write(&self) -> WriteGuard<'_> {
        loop {
            if let Some(guard) = self.try_write() {
                return guard;
            }
            let s = self.state.fetch_or(WRITER_WAITING, Ordering::Relaxed) | WRITER_WAITING;
            if s & (WRITER | READERS) != 0 {
                park::wait(&self.state, s, Some(NAP));
            }
        }
    }
}

/// Shared access to an [`RwLock`], released on drop.
#[derive(Debug)]
pub struct ReadGuard<'a> {
    lock: &'a RwLock,
}

impl Drop for ReadGuard<'_> {
    fn drop(&mut self) {
        let before = self.lock.state.fetch_sub(1, Ordering::Release);
        if before & READERS == 1 && before & WRITER_WAITING != 0 {
            park::wake_all(&self.lock.state);
        }
    }
}

/// Exclusive access to an [`RwLock`], released on drop.
#[derive(Debug)]
pub struct WriteGuard<'a> {
    lock: &'a RwLock,
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
        park::wake_all(&self.lock.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn readers_share_writers_exclude() {
        let lock = RwLock::new();
        let r1 = lock.read();
        let r2 = lock.try_read().unwrap();
        assert!(lock.try_write().is_none());
        drop((r1, r2));
        let w = lock.write();
        assert!(lock.try_read().is_none());
        drop(w);

        // Two counters that writers keep equal; readers must never see them differ.
        let a = AtomicU64::new(0);
        let b = AtomicU64::new(0);
        std::thread::scope(|s| {
            for _ in 0..2 {
                s.spawn(|| {
                    for _ in 0..300 {
                        let _w = lock.write();
                        a.fetch_add(1, Ordering::Relaxed);
                        b.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
            for _ in 0..3 {
                s.spawn(|| {
                    for _ in 0..300 {
                        let _r = lock.read();
                        assert_eq!(a.load(Ordering::Relaxed), b.load(Ordering::Relaxed));
                    }
                });
            }
        });
        assert_eq!(a.load(Ordering::Relaxed), 600);
    }
}
