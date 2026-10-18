//! Bounded queues of byte messages.
//!
//! [`Channel`] is a plain single-owner queue. [`SyncChannel`] shares one between threads,
//! with blocking send/receive and an explicit close.
//!
//! Both are bounded by total payload bytes rather than message count, so a queue of large
//! messages cannot grow without limit.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::core::error::{Error, ErrorKind, Result};

/// Single-owner FIFO of byte messages with a byte budget.
#[derive(Debug, Clone)]
pub struct Channel {
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    capacity: usize,
    max_message: usize,
}

impl Channel {
    /// Creates a channel holding at most `capacity` payload bytes, with no message larger
    /// than `max_message` bytes.
    pub fn new(capacity: usize, max_message: usize) -> Result<Self> {
        if capacity == 0 || max_message == 0 || max_message > capacity {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                format!("need 0 < max_message ({max_message}) <= capacity ({capacity})"),
            ));
        }
        Ok(Channel {
            queue: VecDeque::new(),
            bytes: 0,
            capacity,
            max_message,
        })
    }

    /// Number of queued messages.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Payload bytes currently queued.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn max_message(&self) -> usize {
        self.max_message
    }

    /// Whether a message of `len` bytes would fit right now.
    pub fn has_room_for(&self, len: usize) -> bool {
        len <= self.max_message && self.bytes + len <= self.capacity
    }

    /// Appends a message. Fails with [`ErrorKind::TooLarge`] if it exceeds `max_message`,
    /// or [`ErrorKind::Full`] if the byte budget is used up.
    pub fn push(&mut self, message: &[u8]) -> Result<()> {
        if message.len() > self.max_message {
            return Err(Error::new(
                ErrorKind::TooLarge,
                format!(
                    "message is {} bytes, limit is {}",
                    message.len(),
                    self.max_message
                ),
            ));
        }
        if !self.has_room_for(message.len()) {
            return Err(ErrorKind::Full.into());
        }
        self.bytes += message.len();
        self.queue.push_back(message.to_vec());
        Ok(())
    }

    /// Removes and returns the oldest message.
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let message = self.queue.pop_front()?;
        self.bytes -= message.len();
        Some(message)
    }

    /// The oldest message, without removing it.
    pub fn peek(&self) -> Option<&[u8]> {
        self.queue.front().map(Vec::as_slice)
    }
}

#[derive(Debug)]
struct Shared {
    channel: Channel,
    closed: bool,
}

/// Thread-safe [`Channel`] with blocking operations.
///
/// After [`close`](Self::close), sends fail with [`ErrorKind::Closed`] while receivers can
/// still drain the messages already queued.
#[derive(Debug)]
pub struct SyncChannel {
    shared: Mutex<Shared>,
    not_empty: Condvar,
    not_full: Condvar,
}

impl SyncChannel {
    pub fn new(capacity: usize, max_message: usize) -> Result<Self> {
        Ok(SyncChannel {
            shared: Mutex::new(Shared {
                channel: Channel::new(capacity, max_message)?,
                closed: false,
            }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        // The queue stays consistent even if a holder panicked, so poisoning is ignored.
        self.shared.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sends without blocking.
    pub fn try_send(&self, message: &[u8]) -> Result<()> {
        let mut shared = self.lock();
        if shared.closed {
            return Err(ErrorKind::Closed.into());
        }
        shared.channel.push(message)?;
        drop(shared);
        self.not_empty.notify_one();
        Ok(())
    }

    /// Sends, waiting up to `timeout` (forever if `None`) for room. Fails with
    /// [`ErrorKind::Full`] on timeout.
    pub fn send(&self, message: &[u8], timeout: Option<Duration>) -> Result<()> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut shared = self.lock();
        loop {
            if shared.closed {
                return Err(ErrorKind::Closed.into());
            }
            if shared.channel.has_room_for(message.len())
                || message.len() > shared.channel.max_message()
            {
                // Either it fits, or `push` reports TooLarge, which waiting cannot fix.
                shared.channel.push(message)?;
                drop(shared);
                self.not_empty.notify_one();
                return Ok(());
            }
            shared = match wait(&self.not_full, shared, deadline) {
                Some(guard) => guard,
                None => return Err(ErrorKind::Full.into()),
            };
        }
    }

    /// Receives without blocking.
    pub fn try_recv(&self) -> Option<Vec<u8>> {
        let message = self.lock().channel.pop()?;
        self.not_full.notify_all();
        Some(message)
    }

    /// Receives, waiting up to `timeout` (forever if `None`). Returns `None` on timeout, or
    /// once the channel is closed and drained.
    pub fn recv(&self, timeout: Option<Duration>) -> Option<Vec<u8>> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut shared = self.lock();
        loop {
            if let Some(message) = shared.channel.pop() {
                drop(shared);
                self.not_full.notify_all();
                return Some(message);
            }
            if shared.closed {
                return None;
            }
            shared = wait(&self.not_empty, shared, deadline)?;
        }
    }

    /// Rejects further sends and wakes every waiter.
    pub fn close(&self) {
        self.lock().closed = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    pub fn len(&self) -> usize {
        self.lock().channel.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().channel.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.lock().channel.bytes()
    }
}

/// Waits on `condvar` until notified or `deadline` passes. `None` means the deadline passed.
fn wait<'a>(
    condvar: &Condvar,
    guard: MutexGuard<'a, Shared>,
    deadline: Option<Instant>,
) -> Option<MutexGuard<'a, Shared>> {
    match deadline {
        None => Some(condvar.wait(guard).unwrap_or_else(|e| e.into_inner())),
        Some(deadline) => {
            let left = deadline.checked_duration_since(Instant::now())?;
            let (guard, _) = condvar
                .wait_timeout(guard, left)
                .unwrap_or_else(|e| e.into_inner());
            Some(guard)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn byte_budget_and_limits() {
        assert!(Channel::new(4, 8).is_err());
        let mut ch = Channel::new(10, 4).unwrap();
        ch.push(b"abcd").unwrap();
        ch.push(b"efgh").unwrap();
        assert_eq!(ch.push(b"ijk").unwrap_err().kind(), ErrorKind::Full);
        assert_eq!(ch.push(b"toolong").unwrap_err().kind(), ErrorKind::TooLarge);
        ch.push(b"ij").unwrap();
        assert_eq!((ch.len(), ch.bytes()), (3, 10));
        assert_eq!(ch.peek(), Some(&b"abcd"[..]));
        assert_eq!(ch.pop().unwrap(), b"abcd");
        assert_eq!(ch.bytes(), 6);
    }

    #[test]
    fn blocking_send_and_recv_across_threads() {
        let ch = Arc::new(SyncChannel::new(8, 4).unwrap());
        let producer = {
            let ch = Arc::clone(&ch);
            std::thread::spawn(move || {
                for i in 0..100u32 {
                    ch.send(&i.to_le_bytes(), None).unwrap();
                }
                ch.close();
            })
        };
        let mut received = Vec::new();
        while let Some(msg) = ch.recv(Some(Duration::from_secs(5))) {
            received.push(u32::from_le_bytes(msg.try_into().unwrap()));
        }
        producer.join().unwrap();
        assert_eq!(received, (0..100).collect::<Vec<_>>());
    }

    #[test]
    fn timeouts_and_close() {
        let ch = SyncChannel::new(4, 4).unwrap();
        assert_eq!(ch.recv(Some(Duration::from_millis(5))), None);
        ch.try_send(b"full").unwrap();
        let err = ch.send(b"x", Some(Duration::from_millis(5))).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Full);

        ch.close();
        assert_eq!(ch.try_send(b"x").unwrap_err().kind(), ErrorKind::Closed);
        assert_eq!(ch.recv(None).unwrap(), b"full");
        assert_eq!(ch.recv(None), None);
    }
}
