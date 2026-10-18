//! One-shot and repeating timers, driven by the owner's event loop.
//!
//! [`Timer`] never sleeps or spawns threads. The event loop asks [`Timer::timeout`] how long
//! it may block, then calls [`Timer::poll`] to run whatever is due.
//!
//! Each poll first takes a snapshot of the due timers and only runs those. Timers created or
//! rescheduled by a callback therefore wait for the next poll, so a callback that keeps
//! scheduling zero-delay timers cannot trap the loop.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::time::{Duration, Instant};

use crate::core::error::{Error, ErrorKind, Result};

/// Identifies a timer within one [`Timer`]. Never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerId(u64);

impl TimerId {
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for TimerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Code run when a timer fires. Receives the timer set so it can schedule or cancel timers,
/// including its own.
pub type TimerCallback = Box<dyn FnMut(&mut Timer, TimerId)>;

struct Entry {
    deadline: Instant,
    /// `Some` for repeating timers.
    period: Option<Duration>,
    runs: u64,
    callback: TimerCallback,
}

/// The timer currently executing its callback.
struct Running {
    id: TimerId,
    cancelled: bool,
}

/// A set of timers ordered by deadline.
#[derive(Default)]
pub struct Timer {
    entries: HashMap<TimerId, Entry>,
    /// Deadlines in firing order; ties fire in creation order.
    queue: BTreeSet<(Instant, TimerId)>,
    last_id: u64,
    running: Option<Running>,
}

impl Timer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `callback` once, `delay` from now.
    pub fn after(
        &mut self,
        delay: Duration,
        callback: impl FnMut(&mut Timer, TimerId) + 'static,
    ) -> TimerId {
        self.insert(Instant::now() + delay, None, Box::new(callback))
    }

    /// Runs `callback` every `period`, starting one period from now.
    ///
    /// Ticks are scheduled at fixed multiples of `period`. If the loop falls behind, missed
    /// ticks are skipped rather than run back to back.
    pub fn every(
        &mut self,
        period: Duration,
        callback: impl FnMut(&mut Timer, TimerId) + 'static,
    ) -> Result<TimerId> {
        if period.is_zero() {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "period must be non-zero",
            ));
        }
        Ok(self.insert(Instant::now() + period, Some(period), Box::new(callback)))
    }

    fn insert(
        &mut self,
        deadline: Instant,
        period: Option<Duration>,
        callback: TimerCallback,
    ) -> TimerId {
        self.last_id += 1;
        let id = TimerId(self.last_id);
        self.entries.insert(
            id,
            Entry {
                deadline,
                period,
                runs: 0,
                callback,
            },
        );
        self.queue.insert((deadline, id));
        id
    }

    /// Cancels a timer. Returns `false` if it already finished or was cancelled.
    ///
    /// A repeating timer may cancel itself from inside its callback.
    pub fn cancel(&mut self, id: TimerId) -> bool {
        if let Some(running) = &mut self.running
            && running.id == id
        {
            return !std::mem::replace(&mut running.cancelled, true);
        }
        match self.entries.remove(&id) {
            Some(entry) => {
                self.queue.remove(&(entry.deadline, id));
                true
            }
            None => false,
        }
    }

    /// Moves a pending timer's next run to `delay` from now. Returns `false` if the timer is
    /// unknown or is the one currently running.
    pub fn reschedule(&mut self, id: TimerId, delay: Duration) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else {
            return false;
        };
        self.queue.remove(&(entry.deadline, id));
        entry.deadline = Instant::now() + delay;
        self.queue.insert((entry.deadline, id));
        true
    }

    /// Whether `id` is still scheduled.
    pub fn contains(&self, id: TimerId) -> bool {
        self.entries.contains_key(&id)
    }

    /// When `id` next fires.
    pub fn deadline(&self, id: TimerId) -> Option<Instant> {
        self.entries.get(&id).map(|e| e.deadline)
    }

    /// How many times `id` has fired so far.
    pub fn runs(&self, id: TimerId) -> Option<u64> {
        self.entries.get(&id).map(|e| e.runs)
    }

    /// Number of scheduled timers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Earliest deadline among scheduled timers.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.queue.first().map(|&(deadline, _)| deadline)
    }

    /// How long the event loop may block before the next timer is due; `None` if no timer
    /// is scheduled.
    pub fn timeout(&self) -> Option<Duration> {
        self.next_deadline()
            .map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// Runs every timer due now. Returns how many callbacks ran.
    pub fn poll(&mut self) -> usize {
        self.poll_at(Instant::now())
    }

    /// Runs every timer due at `now`. Returns how many callbacks ran.
    pub fn poll_at(&mut self, now: Instant) -> usize {
        let due: Vec<TimerId> = self
            .queue
            .iter()
            .take_while(|&&(deadline, _)| deadline <= now)
            .map(|&(_, id)| id)
            .collect();

        let mut ran = 0;
        for id in due {
            // An earlier callback in this batch may have cancelled or rescheduled it.
            match self.entries.get(&id) {
                Some(entry) if entry.deadline <= now => {}
                _ => continue,
            }
            let Some(mut entry) = self.entries.remove(&id) else {
                continue;
            };
            self.queue.remove(&(entry.deadline, id));

            self.running = Some(Running {
                id,
                cancelled: false,
            });
            (entry.callback)(self, id);
            ran += 1;
            let cancelled = self.running.take().is_some_and(|r| r.cancelled);

            if let Some(period) = entry.period
                && !cancelled
            {
                entry.runs += 1;
                entry.deadline = next_tick(entry.deadline, period, now);
                self.queue.insert((entry.deadline, id));
                self.entries.insert(id, entry);
            }
        }
        ran
    }
}

/// First tick after `now` on the grid `last + k * period`.
fn next_tick(last: Instant, period: Duration, now: Instant) -> Instant {
    let behind = now.saturating_duration_since(last).as_nanos();
    let steps = behind / period.as_nanos() + 1;
    let advance = steps
        .saturating_mul(period.as_nanos())
        .min(u64::MAX as u128) as u64;
    last + Duration::from_nanos(advance)
}

impl fmt::Debug for Timer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Timer")
            .field("len", &self.entries.len())
            .field("next_deadline", &self.next_deadline())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    const MS: Duration = Duration::from_millis(1);

    type Log = Rc<RefCell<Vec<TimerId>>>;

    fn record(log: &Log) -> impl FnMut(&mut Timer, TimerId) + 'static {
        let log = Rc::clone(log);
        move |_, id| log.borrow_mut().push(id)
    }

    #[test]
    fn one_shots_fire_in_deadline_order() {
        let log = Log::default();
        let mut timer = Timer::new();
        let start = Instant::now();
        let late = timer.after(30 * MS, record(&log));
        let early = timer.after(10 * MS, record(&log));
        assert_eq!(timer.next_deadline(), timer.deadline(early));

        assert_eq!(timer.poll_at(start), 0);
        assert_eq!(timer.poll_at(start + 60 * MS), 2);
        assert_eq!(*log.borrow(), vec![early, late]);
        assert!(timer.is_empty());
        assert_eq!(timer.timeout(), None);
    }

    #[test]
    fn repeating_timer_keeps_its_grid_and_skips_missed_ticks() {
        let log = Log::default();
        let mut timer = Timer::new();
        let id = timer.every(10 * MS, record(&log)).unwrap();
        let first = timer.deadline(id).unwrap();

        timer.poll_at(first);
        assert_eq!(timer.deadline(id), Some(first + 10 * MS));
        // Fall 35ms behind: one run, then the next tick on the grid.
        timer.poll_at(first + 45 * MS);
        assert_eq!(log.borrow().len(), 2);
        assert_eq!(timer.runs(id), Some(2));
        assert_eq!(timer.deadline(id), Some(first + 50 * MS));
        assert!(timer.every(Duration::ZERO, |_, _| {}).is_err());
    }

    #[test]
    fn cancel_from_outside_and_from_own_callback() {
        let log = Log::default();
        let mut timer = Timer::new();
        let a = timer.after(MS, record(&log));
        assert!(timer.cancel(a));
        assert!(!timer.cancel(a));

        let runs = Rc::new(RefCell::new(0));
        let r = Rc::clone(&runs);
        let b = timer
            .every(MS, move |t, id| {
                *r.borrow_mut() += 1;
                assert!(t.cancel(id));
                assert!(!t.cancel(id));
            })
            .unwrap();
        let far = Instant::now() + 100 * MS;
        timer.poll_at(far);
        timer.poll_at(far + 100 * MS);
        assert_eq!(*runs.borrow(), 1);
        assert!(!timer.contains(b));
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn callbacks_can_cancel_later_timers_in_the_same_batch() {
        let log = Log::default();
        let mut timer = Timer::new();
        let victim = Rc::new(RefCell::new(None));
        let v = Rc::clone(&victim);
        timer.after(MS, move |t, _| {
            if let Some(id) = v.borrow_mut().take() {
                t.cancel(id);
            }
        });
        *victim.borrow_mut() = Some(timer.after(2 * MS, record(&log)));
        assert_eq!(timer.poll_at(Instant::now() + 50 * MS), 1);
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn timers_created_by_callbacks_wait_for_next_poll() {
        let log = Log::default();
        let mut timer = Timer::new();
        let child_log = Rc::clone(&log);
        timer.after(Duration::ZERO, move |t, _| {
            t.after(Duration::ZERO, record(&child_log));
        });
        let now = Instant::now() + MS;
        assert_eq!(timer.poll_at(now), 1);
        assert!(log.borrow().is_empty());
        assert_eq!(timer.poll_at(now + MS), 1);
        assert_eq!(log.borrow().len(), 1);
    }

    #[test]
    fn reschedule_moves_deadline() {
        let log = Log::default();
        let mut timer = Timer::new();
        let id = timer.after(MS, record(&log));
        assert!(timer.reschedule(id, Duration::from_secs(60)));
        timer.poll_at(Instant::now() + 100 * MS);
        assert!(log.borrow().is_empty());
        assert!(timer.timeout().unwrap() > Duration::from_secs(59));
    }

    #[test]
    fn real_clock() {
        let log = Log::default();
        let mut timer = Timer::new();
        timer.after(MS, record(&log));
        std::thread::sleep(5 * MS);
        assert_eq!(timer.poll(), 1);
    }
}
