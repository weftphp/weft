//! A thread pool for blocking work (file I/O, DNS, CPU-heavy calls) that must not stall an
//! event loop.
//!
//! The owner submits closures and later collects [`Completion`]s. After every completion the
//! pool calls a notifier, typically one that wakes the owner's event loop, so nothing has to
//! poll. The pool grows on demand up to `max_threads` and lets idle threads beyond
//! `min_threads` exit after `idle_timeout`.

use std::any::Any;
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::core::{Error, ErrorKind, Result};

/// Identifies a submitted task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId(u64);

impl TaskId {
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// What a task returned, boxed; downcast it to the type the closure produced.
pub type Output = Box<dyn Any + Send>;

/// A finished task. `result` is `Err` with the panic payload if the task panicked.
#[derive(Debug)]
pub struct Completion {
    pub id: TaskId,
    pub result: thread::Result<Output>,
}

/// Sizing of a [`BlockingPool`].
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub min_threads: usize,
    pub max_threads: usize,
    pub idle_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        let cpus = thread::available_parallelism().map_or(4, |n| n.get());
        PoolConfig {
            min_threads: 0,
            max_threads: cpus * 2,
            idle_timeout: Duration::from_secs(10),
        }
    }
}

type Job = Box<dyn FnOnce() -> Output + Send>;
type Notify = Box<dyn Fn() + Send + Sync>;

struct State {
    queue: VecDeque<(TaskId, Job)>,
    threads: usize,
    idle: usize,
    in_flight: usize,
    shutdown: bool,
    handles: Vec<JoinHandle<()>>,
}

struct Shared {
    config: PoolConfig,
    state: Mutex<State>,
    work: Condvar,
    done: Mutex<Vec<Completion>>,
    notify: Notify,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// See the [module documentation](self).
pub struct BlockingPool {
    shared: Arc<Shared>,
    last_id: u64,
}

impl BlockingPool {
    /// Creates a pool; `notify` runs on a worker thread after each completion.
    pub fn new(config: PoolConfig, notify: impl Fn() + Send + Sync + 'static) -> Result<Self> {
        if config.max_threads == 0 || config.min_threads > config.max_threads {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "need min_threads <= max_threads and max_threads > 0",
            ));
        }
        let pool = BlockingPool {
            shared: Arc::new(Shared {
                config,
                state: Mutex::new(State {
                    queue: VecDeque::new(),
                    threads: 0,
                    idle: 0,
                    in_flight: 0,
                    shutdown: false,
                    handles: Vec::new(),
                }),
                work: Condvar::new(),
                done: Mutex::new(Vec::new()),
                notify: Box::new(notify),
            }),
            last_id: 0,
        };
        let mut state = pool.shared.state();
        for _ in 0..pool.shared.config.min_threads {
            spawn_worker(&pool.shared, &mut state)?;
        }
        drop(state);
        Ok(pool)
    }

    /// Queues `task`. Its return value arrives later in [`take_completed`](Self::take_completed).
    pub fn submit<T: Send + 'static>(
        &mut self,
        task: impl FnOnce() -> T + Send + 'static,
    ) -> Result<TaskId> {
        self.last_id += 1;
        let id = TaskId(self.last_id);
        let mut state = self.shared.state();
        if state.idle == 0 && state.threads < self.shared.config.max_threads {
            // With at least one live thread the queue still drains, so a failed spawn is
            // only fatal when there is none.
            if let Err(err) = spawn_worker(&self.shared, &mut state)
                && state.threads == 0
            {
                return Err(err);
            }
        }
        state
            .queue
            .push_back((id, Box::new(move || Box::new(task()) as Output)));
        state.in_flight += 1;
        drop(state);
        self.shared.work.notify_one();
        Ok(id)
    }

    /// Removes and returns every completion collected so far.
    pub fn take_completed(&self) -> Vec<Completion> {
        std::mem::take(&mut *self.shared.done.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Tasks submitted but not yet completed.
    pub fn in_flight(&self) -> usize {
        self.shared.state().in_flight
    }

    /// Live worker threads.
    pub fn threads(&self) -> usize {
        self.shared.state().threads
    }
}

impl Drop for BlockingPool {
    /// Lets queued tasks finish, then joins every worker.
    fn drop(&mut self) {
        let handles = {
            let mut state = self.shared.state();
            state.shutdown = true;
            std::mem::take(&mut state.handles)
        };
        self.shared.work.notify_all();
        for handle in handles {
            let _ = handle.join();
        }
    }
}

fn spawn_worker(shared: &Arc<Shared>, state: &mut State) -> Result<()> {
    let worker = Arc::clone(shared);
    let handle = thread::Builder::new()
        .name("weft-blocking".into())
        .spawn(move || run_worker(&worker))?;
    state.threads += 1;
    state.handles.retain(|h| !h.is_finished());
    state.handles.push(handle);
    Ok(())
}

fn run_worker(shared: &Shared) {
    let mut state = shared.state();
    loop {
        if let Some((id, job)) = state.queue.pop_front() {
            drop(state);
            let result = catch_unwind(AssertUnwindSafe(job));
            shared
                .done
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(Completion { id, result });
            state = shared.state();
            state.in_flight -= 1;
            drop(state);
            (shared.notify)();
            state = shared.state();
            continue;
        }
        if state.shutdown {
            break;
        }
        state.idle += 1;
        let (guard, timeout) = shared
            .work
            .wait_timeout(state, shared.config.idle_timeout)
            .unwrap_or_else(|e| e.into_inner());
        state = guard;
        state.idle -= 1;
        if timeout.timed_out()
            && state.queue.is_empty()
            && state.threads > shared.config.min_threads
        {
            break;
        }
    }
    state.threads -= 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    fn wait_for(pool: &BlockingPool, count: usize) -> Vec<Completion> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut all = Vec::new();
        while all.len() < count && Instant::now() < deadline {
            all.extend(pool.take_completed());
            thread::sleep(Duration::from_millis(1));
        }
        all
    }

    #[test]
    fn runs_tasks_and_notifies() {
        let notified = Arc::new(AtomicUsize::new(0));
        let n = Arc::clone(&notified);
        let mut pool = BlockingPool::new(PoolConfig::default(), move || {
            n.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();

        let ids: Vec<_> = (0..20u64)
            .map(|i| pool.submit(move || i * i).unwrap())
            .collect();
        let mut done = wait_for(&pool, 20);
        done.sort_by_key(|c| c.id);
        assert_eq!(done.len(), 20);
        for (i, (completion, id)) in done.into_iter().zip(ids).enumerate() {
            assert_eq!(completion.id, id);
            let value = completion.result.unwrap().downcast::<u64>().unwrap();
            assert_eq!(*value, (i * i) as u64);
        }
        assert_eq!(notified.load(Ordering::SeqCst), 20);
        assert_eq!(pool.in_flight(), 0);
    }

    #[test]
    fn panics_are_reported_not_propagated() {
        let mut pool = BlockingPool::new(PoolConfig::default(), || {}).unwrap();
        pool.submit(|| -> () { panic!("boom") }).unwrap();
        let done = wait_for(&pool, 1);
        assert!(done[0].result.is_err());
        pool.submit(|| 1).unwrap();
        assert!(
            wait_for(&pool, 1)[0].result.is_ok(),
            "pool survives a panic"
        );
    }

    #[test]
    fn idle_threads_shrink_to_minimum() {
        let config = PoolConfig {
            min_threads: 1,
            max_threads: 4,
            idle_timeout: Duration::from_millis(20),
        };
        let mut pool = BlockingPool::new(config, || {}).unwrap();
        for _ in 0..4 {
            pool.submit(|| thread::sleep(Duration::from_millis(30)))
                .unwrap();
        }
        wait_for(&pool, 4);
        let deadline = Instant::now() + Duration::from_secs(5);
        while pool.threads() > 1 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(pool.threads(), 1);
        assert!(
            BlockingPool::new(
                PoolConfig {
                    min_threads: 2,
                    max_threads: 1,
                    idle_timeout: Duration::ZERO
                },
                || {}
            )
            .is_err()
        );
    }
}
