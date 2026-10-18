use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::park;
use crate::memory::ShmSafe;

/// Blocks participants until `parties` of them have arrived, then releases them together.
/// Reusable: each release starts a new generation.
#[repr(C)]
#[derive(Debug, Default)]
pub struct Barrier {
    parties: AtomicU32,
    arrived: AtomicU32,
    generation: AtomicU32,
}

// SAFETY: three atomic words, valid when zeroed (configured with `set_parties` before use).
unsafe impl ShmSafe for Barrier {}

impl Barrier {
    pub fn new(parties: u32) -> Barrier {
        let barrier = Barrier::default();
        barrier.set_parties(parties);
        barrier
    }

    /// Sets the number of participants. Call before anyone waits (for example, before
    /// forking the processes that will use it).
    pub fn set_parties(&self, parties: u32) {
        self.parties.store(parties.max(1), Ordering::Relaxed);
    }

    /// Waits for every participant. Returns `true` in exactly one of them per generation.
    pub fn wait(&self) -> bool {
        let generation = self.generation.load(Ordering::Acquire);
        let arrived = self.arrived.fetch_add(1, Ordering::AcqRel) + 1;
        if arrived >= self.parties.load(Ordering::Relaxed) {
            self.arrived.store(0, Ordering::Relaxed);
            self.generation.fetch_add(1, Ordering::Release);
            park::wake_all(&self.generation);
            return true;
        }
        while self.generation.load(Ordering::Acquire) == generation {
            park::wait(
                &self.generation,
                generation,
                Some(Duration::from_millis(50)),
            );
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn releases_all_together_repeatedly() {
        let barrier = Barrier::new(4);
        let leaders = AtomicUsize::new(0);
        let phase = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for round in 0..3 {
                        assert!(phase.load(Ordering::SeqCst) >= round * 4);
                        phase.fetch_add(1, Ordering::SeqCst);
                        if barrier.wait() {
                            leaders.fetch_add(1, Ordering::SeqCst);
                        }
                        assert!(phase.load(Ordering::SeqCst) >= (round + 1) * 4);
                        barrier.wait();
                    }
                });
            }
        });
        assert_eq!(leaders.load(Ordering::SeqCst), 3);
    }
}
