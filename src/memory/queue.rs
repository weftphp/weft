//! A bounded queue of byte messages in shared memory, for passing work between processes.
//!
//! Messages are stored back to back in a ring of bytes, each prefixed with its length.
//! Senders block (or time out) while the ring is full and receivers while it is empty.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::shared::Mapping;
use crate::core::{Error, ErrorKind, Result};
use crate::lock::{MutexGuard, ProcessMutex};

#[repr(C)]
struct Header {
    lock: ProcessMutex,
    /// Total bytes ever consumed and produced; their difference is the bytes in use.
    head: AtomicU64,
    tail: AtomicU64,
    messages: AtomicU64,
    /// Bumped whenever data is added or space is freed; waiters sleep on them.
    pushed: AtomicU32,
    popped: AtomicU32,
    closed: AtomicU32,
}

const LEN_PREFIX: usize = 4;
const NAP: Duration = Duration::from_millis(20);

/// See the [module documentation](self).
pub struct SharedQueue {
    map: Mapping,
    capacity: usize,
    max_message: usize,
    data_offset: usize,
}

impl SharedQueue {
    /// A queue holding up to `capacity` bytes of messages (plus 4 bytes of framing each).
    pub fn new(capacity: usize, max_message: usize) -> Result<SharedQueue> {
        if capacity == 0 || max_message == 0 || max_message + LEN_PREFIX > capacity {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "need 0 < max_message and max_message + 4 <= capacity",
            ));
        }
        let data_offset = std::mem::size_of::<Header>().next_multiple_of(64);
        Ok(SharedQueue {
            map: Mapping::new(data_offset + capacity)?,
            capacity,
            max_message,
            data_offset,
        })
    }

    fn header(&self) -> &Header {
        // SAFETY: the mapping starts with a zeroed (valid) Header made of ShmSafe parts.
        unsafe { &*self.map.as_ptr().cast::<Header>() }
    }

    fn data(&self) -> *mut u8 {
        // SAFETY: the ring follows the header inside the mapping.
        unsafe { self.map.as_ptr().add(self.data_offset) }
    }

    /// Copies `bytes` into the ring at logical position `pos`. Caller holds the lock.
    fn copy_in(&self, pos: u64, bytes: &[u8]) {
        let start = (pos % self.capacity as u64) as usize;
        let first = bytes.len().min(self.capacity - start);
        // SAFETY: both pieces stay inside the ring; the queue lock gives exclusive access to
        // the free region being written.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.data().add(start), first);
            std::ptr::copy_nonoverlapping(
                bytes[first..].as_ptr(),
                self.data(),
                bytes.len() - first,
            );
        }
    }

    /// Copies out of the ring at logical position `pos`. Caller holds the lock.
    fn copy_out(&self, pos: u64, out: &mut [u8]) {
        let start = (pos % self.capacity as u64) as usize;
        let first = out.len().min(self.capacity - start);
        // SAFETY: as in `copy_in`, for the occupied region.
        unsafe {
            std::ptr::copy_nonoverlapping(self.data().add(start), out.as_mut_ptr(), first);
            let rest = out.len() - first;
            std::ptr::copy_nonoverlapping(self.data(), out[first..].as_mut_ptr(), rest);
        }
    }

    fn deadline(timeout: Option<Duration>) -> Option<Instant> {
        timeout.map(|t| Instant::now() + t)
    }

    /// Sleeps on `word` until it changes, the deadline passes, or a nap elapses.
    fn sleep(
        word: &AtomicU32,
        seen: u32,
        guard: MutexGuard<'_>,
        deadline: Option<Instant>,
    ) -> bool {
        drop(guard);
        let nap = match deadline {
            Some(d) => match d.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => left.min(NAP),
                _ => return false,
            },
            None => NAP,
        };
        crate::lock::park_wait(word, seen, nap);
        true
    }

    /// Appends a message, waiting up to `timeout` (forever if `None`) for room. Fails with
    /// [`ErrorKind::Full`] on timeout, [`ErrorKind::Closed`] after [`close`](Self::close).
    pub fn push(&self, message: &[u8], timeout: Option<Duration>) -> Result<()> {
        if message.len() > self.max_message {
            return Err(Error::new(
                ErrorKind::TooLarge,
                format!(
                    "message of {} bytes exceeds {}",
                    message.len(),
                    self.max_message
                ),
            ));
        }
        let h = self.header();
        let need = (LEN_PREFIX + message.len()) as u64;
        let deadline = Self::deadline(timeout);
        loop {
            let guard = h.lock.lock();
            if h.closed.load(Ordering::Relaxed) != 0 {
                return Err(ErrorKind::Closed.into());
            }
            let head = h.head.load(Ordering::Relaxed);
            let tail = h.tail.load(Ordering::Relaxed);
            if tail - head + need <= self.capacity as u64 {
                self.copy_in(tail, &(message.len() as u32).to_le_bytes());
                self.copy_in(tail + LEN_PREFIX as u64, message);
                h.tail.store(tail + need, Ordering::Relaxed);
                h.messages.fetch_add(1, Ordering::Relaxed);
                h.pushed.fetch_add(1, Ordering::Release);
                drop(guard);
                crate::lock::park_wake_all(&h.pushed);
                return Ok(());
            }
            let seen = h.popped.load(Ordering::Acquire);
            if !Self::sleep(&h.popped, seen, guard, deadline) {
                return Err(ErrorKind::Full.into());
            }
        }
    }

    pub fn try_push(&self, message: &[u8]) -> Result<()> {
        self.push(message, Some(Duration::ZERO))
    }

    /// Removes the oldest message, waiting up to `timeout` (forever if `None`). Returns
    /// `None` on timeout, or once the queue is closed and drained.
    pub fn pop(&self, timeout: Option<Duration>) -> Option<Vec<u8>> {
        let h = self.header();
        let deadline = Self::deadline(timeout);
        loop {
            let guard = h.lock.lock();
            if h.messages.load(Ordering::Relaxed) > 0 {
                let head = h.head.load(Ordering::Relaxed);
                let mut len = [0u8; LEN_PREFIX];
                self.copy_out(head, &mut len);
                let len = u32::from_le_bytes(len) as usize;
                let mut message = vec![0u8; len];
                self.copy_out(head + LEN_PREFIX as u64, &mut message);
                h.head
                    .store(head + (LEN_PREFIX + len) as u64, Ordering::Relaxed);
                h.messages.fetch_sub(1, Ordering::Relaxed);
                h.popped.fetch_add(1, Ordering::Release);
                drop(guard);
                crate::lock::park_wake_all(&h.popped);
                return Some(message);
            }
            if h.closed.load(Ordering::Relaxed) != 0 {
                return None;
            }
            let seen = h.pushed.load(Ordering::Acquire);
            if !Self::sleep(&h.pushed, seen, guard, deadline) {
                return None;
            }
        }
    }

    pub fn try_pop(&self) -> Option<Vec<u8>> {
        self.pop(Some(Duration::ZERO))
    }

    /// Rejects further pushes and wakes every waiter; queued messages remain poppable.
    pub fn close(&self) {
        let h = self.header();
        h.closed.store(1, Ordering::Relaxed);
        h.pushed.fetch_add(1, Ordering::Release);
        h.popped.fetch_add(1, Ordering::Release);
        crate::lock::park_wake_all(&h.pushed);
        crate::lock::park_wake_all(&h.popped);
    }

    pub fn len(&self) -> usize {
        self.header().messages.load(Ordering::Relaxed) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes in use, framing included.
    pub fn bytes(&self) -> usize {
        let h = self.header();
        (h.tail.load(Ordering::Relaxed) - h.head.load(Ordering::Relaxed)) as usize
    }
}

impl std::fmt::Debug for SharedQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedQueue")
            .field("len", &self.len())
            .field("bytes", &self.bytes())
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_around_and_blocks_when_full() {
        let q = SharedQueue::new(32, 16).unwrap();
        for round in 0..50u32 {
            q.try_push(&round.to_le_bytes()).unwrap();
            q.try_push(b"0123456789ab").unwrap();
            assert_eq!(q.try_pop().unwrap(), round.to_le_bytes());
            assert_eq!(q.try_pop().unwrap(), b"0123456789ab");
        }
        q.try_push(&[1; 16]).unwrap();
        assert_eq!(q.try_push(&[2; 9]).unwrap_err().kind(), ErrorKind::Full);
        assert_eq!(
            q.try_push(&[0; 17]).unwrap_err().kind(),
            ErrorKind::TooLarge
        );
        assert_eq!(q.bytes(), 20);
        q.close();
        assert_eq!(q.try_push(b"x").unwrap_err().kind(), ErrorKind::Closed);
        assert_eq!(q.pop(None).unwrap(), [1; 16]);
        assert_eq!(q.pop(None), None);
    }

    #[test]
    fn producers_and_consumers_on_threads() {
        let q = SharedQueue::new(64, 8).unwrap();
        let received = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for p in 0..2u32 {
                let q = &q;
                s.spawn(move || {
                    for i in 0..200u32 {
                        q.push(&(p * 1000 + i).to_le_bytes(), Some(Duration::from_secs(5)))
                            .unwrap();
                    }
                });
            }
            for _ in 0..2 {
                s.spawn(|| {
                    while let Some(m) = q.pop(Some(Duration::from_millis(500))) {
                        received
                            .lock()
                            .unwrap()
                            .push(u32::from_le_bytes(m.try_into().unwrap()));
                    }
                });
            }
        });
        let mut got = received.into_inner().unwrap();
        got.sort_unstable();
        let mut expected: Vec<u32> = (0..200).chain(1000..1200).collect();
        expected.sort_unstable();
        assert_eq!(got, expected);
    }
}
