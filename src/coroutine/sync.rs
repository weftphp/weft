//! Synchronization between coroutines of one thread: [`Channel`], [`Mutex`] and
//! [`WaitGroup`].
//!
//! These suspend the calling coroutine instead of blocking the thread. Waiters are woken at
//! the end of the current loop iteration (not immediately), so a sender is never preempted
//! by the receiver it wakes.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::rc::Rc;
use std::time::Duration;

use super::runtime::{Waiter, Wake, with_reactor};
use crate::core::{Error, ErrorKind, Result};

fn wake_first(waiters: &mut VecDeque<Waiter>) -> Result<()> {
    // Skip stale entries left by waits that timed out.
    while let Some(w) = waiters.pop_front() {
        if w.is_pending() {
            return with_reactor(|r| w.wake_later(r, Wake::Done));
        }
    }
    Ok(())
}

fn wake_all(waiters: &mut VecDeque<Waiter>, wake: Wake) -> Result<()> {
    let list: Vec<Waiter> = waiters.drain(..).collect();
    with_reactor(|r| {
        for w in list {
            w.wake_later(r, wake);
        }
    })
}

fn wait_error(wake: Wake, what: &str) -> Error {
    match wake {
        Wake::Timeout => Error::new(ErrorKind::TimedOut, format!("{what} timed out")),
        Wake::Cancelled => Error::new(ErrorKind::Closed, format!("{what} cancelled")),
        _ => Error::new(ErrorKind::Closed, format!("{what}: channel closed")),
    }
}

struct ChannelState<T> {
    queue: VecDeque<T>,
    capacity: usize,
    closed: bool,
    receivers: VecDeque<Waiter>,
    senders: VecDeque<Waiter>,
}

/// A bounded multi-producer, multi-consumer queue between coroutines. Clones share it.
pub struct Channel<T> {
    state: Rc<RefCell<ChannelState<T>>>,
}

impl<T> Clone for Channel<T> {
    fn clone(&self) -> Self {
        Channel {
            state: Rc::clone(&self.state),
        }
    }
}

/// A failed [`Channel::push`], returning the value.
pub struct PushError<T> {
    pub value: T,
    pub error: Error,
}

impl<T> fmt::Debug for PushError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<T> Channel<T> {
    /// A channel buffering up to `capacity` values (at least one).
    pub fn new(capacity: usize) -> Channel<T> {
        Channel {
            state: Rc::new(RefCell::new(ChannelState {
                queue: VecDeque::new(),
                capacity: capacity.max(1),
                closed: false,
                receivers: VecDeque::new(),
                senders: VecDeque::new(),
            })),
        }
    }

    /// Sends `value`, waiting up to `timeout` (forever if `None`) for room.
    pub fn push(&self, value: T, timeout: Option<Duration>) -> Result<(), PushError<T>> {
        loop {
            let waiter = {
                let mut state = self.state.borrow_mut();
                if state.closed {
                    return Err(PushError {
                        value,
                        error: Error::new(ErrorKind::Closed, "channel closed"),
                    });
                }
                if state.queue.len() < state.capacity {
                    state.queue.push_back(value);
                    if let Err(error) = wake_first(&mut state.receivers) {
                        let value = state.queue.pop_back();
                        return match value {
                            Some(value) => Err(PushError { value, error }),
                            None => Ok(()),
                        };
                    }
                    return Ok(());
                }
                match Waiter::new() {
                    Ok(w) => {
                        state.senders.push_back(w);
                        w
                    }
                    Err(error) => return Err(PushError { value, error }),
                }
            };
            match waiter.wait(timeout) {
                Ok(Wake::Done) | Ok(Wake::Resumed) => {}
                Ok(wake) => {
                    let mut state = self.state.borrow_mut();
                    state.senders.retain(|w| *w != waiter);
                    // We may have been picked just as we timed out; pass the turn on.
                    if state.queue.len() < state.capacity {
                        let _ = wake_first(&mut state.senders);
                    }
                    drop(state);
                    return Err(PushError {
                        value,
                        error: wait_error(wake, "push"),
                    });
                }
                Err(error) => return Err(PushError { value, error }),
            }
        }
    }

    /// Receives a value, waiting up to `timeout` (forever if `None`). Fails with
    /// [`ErrorKind::TimedOut`], or [`ErrorKind::Closed`] once closed and drained.
    pub fn pop(&self, timeout: Option<Duration>) -> Result<T> {
        loop {
            let waiter = {
                let mut state = self.state.borrow_mut();
                if let Some(value) = state.queue.pop_front() {
                    wake_first(&mut state.senders)?;
                    return Ok(value);
                }
                if state.closed {
                    return Err(Error::new(ErrorKind::Closed, "channel closed"));
                }
                let w = Waiter::new()?;
                state.receivers.push_back(w);
                w
            };
            match waiter.wait(timeout)? {
                Wake::Done | Wake::Resumed => {}
                Wake::Closed => {}
                wake => {
                    let mut state = self.state.borrow_mut();
                    state.receivers.retain(|w| *w != waiter);
                    // We may have been picked just as we timed out; pass the turn on.
                    if !state.queue.is_empty() {
                        let _ = wake_first(&mut state.receivers);
                    }
                    return Err(wait_error(wake, "pop"));
                }
            }
        }
    }

    /// Takes a value without waiting.
    pub fn try_pop(&self) -> Option<T> {
        let mut state = self.state.borrow_mut();
        let value = state.queue.pop_front()?;
        let _ = wake_first(&mut state.senders);
        Some(value)
    }

    /// Rejects further pushes and wakes every waiter. Buffered values stay poppable.
    pub fn close(&self) -> Result<()> {
        let mut state = self.state.borrow_mut();
        state.closed = true;
        wake_all(&mut state.receivers, Wake::Closed)?;
        wake_all(&mut state.senders, Wake::Closed)
    }

    pub fn is_closed(&self) -> bool {
        self.state.borrow().closed
    }

    pub fn len(&self) -> usize {
        self.state.borrow().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.borrow().queue.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.state.borrow().capacity
    }

    /// Coroutines waiting to receive / to send.
    pub fn waiting(&self) -> (usize, usize) {
        let state = self.state.borrow();
        (state.receivers.len(), state.senders.len())
    }
}

/// A mutual-exclusion lock between coroutines, handed to waiters in arrival order.
#[derive(Clone, Default)]
pub struct Mutex {
    state: Rc<RefCell<MutexState>>,
}

#[derive(Default)]
struct MutexState {
    locked: bool,
    waiters: VecDeque<Waiter>,
    /// The waiter the lock was handed to, until it wakes up and takes it.
    handoff: Option<Waiter>,
}

/// Releases the [`Mutex`] when dropped.
pub struct MutexGuard {
    state: Rc<RefCell<MutexState>>,
}

impl Mutex {
    pub fn new() -> Mutex {
        Mutex::default()
    }

    pub fn try_lock(&self) -> Option<MutexGuard> {
        let mut state = self.state.borrow_mut();
        if state.locked {
            return None;
        }
        state.locked = true;
        Some(MutexGuard {
            state: Rc::clone(&self.state),
        })
    }

    /// Waits up to `timeout` (forever if `None`) for the lock.
    pub fn lock(&self, timeout: Option<Duration>) -> Result<MutexGuard> {
        loop {
            if let Some(guard) = self.try_lock() {
                return Ok(guard);
            }
            let waiter = Waiter::new()?;
            self.state.borrow_mut().waiters.push_back(waiter);
            match waiter.wait(timeout)? {
                // The releaser handed the lock over: `locked` stayed true for us.
                Wake::Done => {
                    self.state.borrow_mut().handoff = None;
                    return Ok(MutexGuard {
                        state: Rc::clone(&self.state),
                    });
                }
                Wake::Resumed => {}
                wake => {
                    let handed_to_us = {
                        let mut state = self.state.borrow_mut();
                        state.waiters.retain(|w| *w != waiter);
                        state.handoff == Some(waiter)
                    };
                    if handed_to_us {
                        // The lock reached us as we gave up: pass it on.
                        self.state.borrow_mut().handoff = None;
                        drop(MutexGuard {
                            state: Rc::clone(&self.state),
                        });
                    }
                    return Err(wait_error(wake, "lock"));
                }
            }
        }
    }

    pub fn is_locked(&self) -> bool {
        self.state.borrow().locked
    }
}

impl Drop for MutexGuard {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        // Hand the lock directly to the next live waiter, or release it.
        while let Some(w) = state.waiters.pop_front() {
            if w.is_pending() && with_reactor(|r| w.wake_later(r, Wake::Done)).is_ok() {
                state.handoff = Some(w);
                return;
            }
        }
        state.handoff = None;
        state.locked = false;
    }
}

/// Waits for a set of coroutines to finish: `add` before starting each, `done` when each
/// ends, `wait` until the count reaches zero.
#[derive(Clone, Default)]
pub struct WaitGroup {
    state: Rc<RefCell<(usize, VecDeque<Waiter>)>>,
}

impl WaitGroup {
    pub fn new() -> WaitGroup {
        WaitGroup::default()
    }

    pub fn add(&self, n: usize) {
        self.state.borrow_mut().0 += n;
    }

    /// Marks one participant finished.
    pub fn done(&self) -> Result<()> {
        let mut state = self.state.borrow_mut();
        state.0 = state
            .0
            .checked_sub(1)
            .ok_or_else(|| Error::new(ErrorKind::InvalidState, "done called too many times"))?;
        if state.0 == 0 {
            wake_all(&mut state.1, Wake::Done)?;
        }
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.state.borrow().0
    }

    /// Waits up to `timeout` (forever if `None`) for the count to reach zero.
    pub fn wait(&self, timeout: Option<Duration>) -> Result<()> {
        loop {
            if self.state.borrow().0 == 0 {
                return Ok(());
            }
            let waiter = Waiter::new()?;
            self.state.borrow_mut().1.push_back(waiter);
            match waiter.wait(timeout)? {
                Wake::Done | Wake::Resumed => {}
                wake => {
                    self.state.borrow_mut().1.retain(|w| *w != waiter);
                    return Err(wait_error(wake, "wait group"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::runtime::{run, sleep, spawn};
    use super::*;
    use std::cell::Cell;

    #[test]
    fn producer_consumer_with_backpressure() {
        let received = Rc::new(RefCell::new(Vec::new()));
        let r = Rc::clone(&received);
        run(move || {
            let ch = Channel::new(2);
            let tx = ch.clone();
            spawn(move || {
                for i in 0..10 {
                    tx.push(i, None).unwrap();
                }
                tx.close().unwrap();
            })
            .unwrap();
            assert!(
                ch.waiting().1 > 0 || ch.len() == 2,
                "producer blocked on a full channel"
            );
            loop {
                match ch.pop(Some(Duration::from_secs(5))) {
                    Ok(v) => r.borrow_mut().push(v),
                    Err(e) => {
                        assert_eq!(e.kind(), ErrorKind::Closed);
                        break;
                    }
                }
            }
        })
        .unwrap();
        assert_eq!(*received.borrow(), (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn timeouts_return_values() {
        run(|| {
            let ch: Channel<u8> = Channel::new(1);
            let err = ch.pop(Some(Duration::from_millis(5))).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::TimedOut);
            ch.push(1, None).unwrap();
            let failed = ch.push(2, Some(Duration::from_millis(5))).unwrap_err();
            assert_eq!(failed.value, 2);
            assert_eq!(failed.error.kind(), ErrorKind::TimedOut);
            assert_eq!(ch.waiting(), (0, 0), "timed-out waiters are removed");
            assert_eq!(ch.try_pop(), Some(1));
        })
        .unwrap();
    }

    #[test]
    fn mutex_serializes_critical_sections() {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let t = Rc::clone(&trace);
        run(move || {
            let mutex = Mutex::new();
            let wg = WaitGroup::new();
            for id in 0..3 {
                let (mutex, wg, t) = (mutex.clone(), wg.clone(), Rc::clone(&t));
                wg.add(1);
                spawn(move || {
                    let _guard = mutex.lock(None).unwrap();
                    t.borrow_mut().push((id, "in"));
                    sleep(Duration::from_millis(2)).unwrap();
                    t.borrow_mut().push((id, "out"));
                    drop(_guard);
                    wg.done().unwrap();
                })
                .unwrap();
            }
            wg.wait(Some(Duration::from_secs(5))).unwrap();
            assert!(!mutex.is_locked());
        })
        .unwrap();
        let trace = trace.borrow();
        for pair in trace.chunks(2) {
            assert_eq!(pair[0].0, pair[1].0, "no interleaving: {trace:?}");
        }
        assert_eq!(trace.len(), 6);
    }

    #[test]
    fn wait_group_counts() {
        let finished = Rc::new(Cell::new(0));
        let f = Rc::clone(&finished);
        run(move || {
            let wg = WaitGroup::new();
            for ms in [3u64, 1, 2] {
                wg.add(1);
                let (wg, f) = (wg.clone(), Rc::clone(&f));
                spawn(move || {
                    sleep(Duration::from_millis(ms)).unwrap();
                    f.set(f.get() + 1);
                    wg.done().unwrap();
                })
                .unwrap();
            }
            wg.wait(None).unwrap();
            assert_eq!(f.get(), 3);
            assert!(wg.done().is_err());
        })
        .unwrap();
    }
}
