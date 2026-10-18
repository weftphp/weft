//! A supervised group of worker processes.
//!
//! The pool forks `workers` children that each run the same entry function with their
//! index, restarts any that exit while the pool is running, replaces them one at a time on
//! [`reload`](ProcessPool::reload), and terminates them on [`stop`](ProcessPool::stop),
//! escalating to `SIGKILL` after a grace period.
//!
//! [`ProcessPool::run`] drives all of that from signals (`SIGCHLD`, `SIGTERM`/`SIGINT` to
//! stop, `SIGUSR1` to reload). The individual steps are public too, for a supervisor that
//! has its own event loop.

use std::collections::VecDeque;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::core::{Error, ErrorKind, Result};
use crate::os::process::{self, ExitStatus, Fork, Pid};
use crate::os::signal;

/// Pool behaviour.
#[derive(Debug, Clone)]
pub struct PoolOptions {
    pub workers: usize,
    /// How long stopped workers get to exit before `SIGKILL`.
    pub stop_timeout: Duration,
    /// A worker that dies sooner than this after starting is restarted only after this delay,
    /// so a crashing worker cannot fork in a tight loop.
    pub min_lifetime: Duration,
}

impl Default for PoolOptions {
    fn default() -> Self {
        PoolOptions {
            workers: 1,
            stop_timeout: Duration::from_secs(10),
            min_lifetime: Duration::from_secs(1),
        }
    }
}

/// A running worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInfo {
    pub index: usize,
    pub pid: Pid,
    pub started: Instant,
    /// Times this slot has been restarted.
    pub restarts: u32,
}

type ExitHook = Box<dyn FnMut(&WorkerInfo, ExitStatus)>;

/// See the [module documentation](self).
pub struct ProcessPool {
    options: PoolOptions,
    main: Rc<dyn Fn(usize) -> i32>,
    slots: Vec<Option<WorkerInfo>>,
    restarts: Vec<u32>,
    /// Slots waiting to be restarted, and when.
    respawn: Vec<(usize, Instant)>,
    stopping: Option<Instant>,
    killed: bool,
    /// Slots still to be replaced by the reload in progress.
    reload_queue: VecDeque<usize>,
    reloading: Option<usize>,
    on_exit: Option<ExitHook>,
}

/// Signals a worker should not inherit the supervisor's handling of.
const WORKER_RESET: [i32; 5] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGCHLD,
];

impl ProcessPool {
    /// `main` runs in each child with the worker index; its return value is the exit code.
    pub fn new(options: PoolOptions, main: impl Fn(usize) -> i32 + 'static) -> Result<Self> {
        if options.workers == 0 {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "a pool needs workers",
            ));
        }
        Ok(ProcessPool {
            slots: vec![None; options.workers],
            restarts: vec![0; options.workers],
            options,
            main: Rc::new(main),
            respawn: Vec::new(),
            stopping: None,
            killed: false,
            reload_queue: VecDeque::new(),
            reloading: None,
            on_exit: None,
        })
    }

    /// Called in the supervisor whenever a worker exits.
    pub fn on_exit(&mut self, hook: impl FnMut(&WorkerInfo, ExitStatus) + 'static) {
        self.on_exit = Some(Box::new(hook));
    }

    /// Forks every worker.
    pub fn start(&mut self) -> Result<()> {
        for index in 0..self.slots.len() {
            if self.slots[index].is_none() {
                self.spawn(index)?;
            }
        }
        Ok(())
    }

    fn spawn(&mut self, index: usize) -> Result<()> {
        // SAFETY: the child resets signal state, runs the worker entry and leaves with
        // `exit_now`, never returning into the supervisor's code.
        match unsafe { process::fork() }? {
            Fork::Child => {
                for sig in WORKER_RESET {
                    let _ = signal::reset(sig);
                }
                let _ = signal::unblock(&WORKER_RESET);
                let main = Rc::clone(&self.main);
                let code = catch_unwind(AssertUnwindSafe(|| main(index))).unwrap_or(101);
                process::exit_now(code)
            }
            Fork::Parent(pid) => {
                self.slots[index] = Some(WorkerInfo {
                    index,
                    pid,
                    started: Instant::now(),
                    restarts: self.restarts[index],
                });
                Ok(())
            }
        }
    }

    /// Live workers.
    pub fn workers(&self) -> Vec<WorkerInfo> {
        self.slots.iter().flatten().cloned().collect()
    }

    pub fn alive(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Reaps exited workers and schedules restarts. Returns how many were reaped.
    pub fn reap(&mut self) -> Result<usize> {
        let mut reaped = 0;
        // Wait only for our own pids: the process may have other children (and other
        // threads waiting on them) that a wildcard wait would steal.
        let exited: Vec<(usize, ExitStatus)> = self
            .slots
            .iter()
            .flatten()
            .filter_map(|w| match process::wait(Some(w.pid), false) {
                Ok(Some((_, status))) => Some((w.index, status)),
                _ => None,
            })
            .collect();
        for (index, status) in exited {
            reaped += 1;
            let Some(info) = self.slots[index].take() else {
                continue;
            };
            if let Some(hook) = &mut self.on_exit {
                hook(&info, status);
            }
            if self.stopping.is_some() {
                continue;
            }
            self.restarts[index] += 1;
            let lived = info.started.elapsed();
            let at = if self.reloading == Some(index) || lived >= self.options.min_lifetime {
                Instant::now()
            } else {
                Instant::now() + (self.options.min_lifetime - lived)
            };
            self.respawn.push((index, at));
        }
        self.tick()?;
        Ok(reaped)
    }

    /// Performs due restarts, reload steps and stop escalation. Call periodically (and after
    /// [`reap`](Self::reap), which does so itself).
    pub fn tick(&mut self) -> Result<()> {
        let now = Instant::now();
        if let Some(since) = self.stopping {
            if !self.killed && now.duration_since(since) >= self.options.stop_timeout {
                self.killed = true;
                for w in self.slots.iter().flatten() {
                    let _ = process::kill(w.pid, libc::SIGKILL);
                }
            }
            return Ok(());
        }
        let due: Vec<usize> = self
            .respawn
            .iter()
            .filter(|(_, at)| *at <= now)
            .map(|(i, _)| *i)
            .collect();
        self.respawn.retain(|(_, at)| *at > now);
        for index in due {
            self.spawn(index)?;
            if self.reloading == Some(index) {
                self.reloading = None;
            }
        }
        if self.reloading.is_none()
            && let Some(next) = self.reload_queue.pop_front()
        {
            // A slot that is empty is already restarting on its own; skip it.
            if let Some(worker) = &self.slots[next] {
                self.reloading = Some(next);
                process::kill(worker.pid, libc::SIGTERM)?;
            }
        }
        Ok(())
    }

    /// Replaces every worker, one at a time, waiting for each replacement to start before
    /// stopping the next.
    pub fn reload(&mut self) {
        if self.stopping.is_none() && self.reload_queue.is_empty() && self.reloading.is_none() {
            self.reload_queue = (0..self.slots.len()).collect();
        }
    }

    /// Asks every worker to exit (`SIGTERM`) and stops restarting them.
    pub fn stop(&mut self) {
        if self.stopping.is_some() {
            return;
        }
        self.stopping = Some(Instant::now());
        self.respawn.clear();
        self.reload_queue.clear();
        for w in self.slots.iter().flatten() {
            let _ = process::kill(w.pid, libc::SIGTERM);
        }
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.is_some()
    }

    /// Whether the pool was stopped and every worker has exited.
    pub fn is_finished(&self) -> bool {
        self.stopping.is_some() && self.alive() == 0
    }

    /// Starts the workers and supervises them until stopped by `SIGTERM` or `SIGINT` (or until
    /// `until` returns `true`), reloading on `SIGUSR1`.
    pub fn run(mut self, mut until: impl FnMut(&ProcessPool) -> bool) -> Result<()> {
        for sig in [libc::SIGCHLD, libc::SIGTERM, libc::SIGINT, libc::SIGUSR1] {
            signal::watch(sig)?;
        }
        self.start()?;
        let notifier = signal::notifier()?;
        loop {
            for sig in signal::take_pending() {
                match sig {
                    libc::SIGTERM | libc::SIGINT => self.stop(),
                    libc::SIGUSR1 => self.reload(),
                    _ => {}
                }
            }
            self.reap()?;
            if until(&self) {
                self.stop();
            }
            if self.is_finished() {
                break;
            }
            // Wake for the next signal, or periodically for timers (restarts, escalation).
            let mut pfd = libc::pollfd {
                fd: std::os::fd::AsRawFd::as_raw_fd(&notifier),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(&mut pfd, 1, 100) };
        }
        for sig in [libc::SIGCHLD, libc::SIGTERM, libc::SIGINT, libc::SIGUSR1] {
            let _ = signal::reset(sig);
        }
        Ok(())
    }
}

impl fmt::Debug for ProcessPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessPool")
            .field("workers", &self.workers())
            .field("stopping", &self.stopping.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_until(pool: &mut ProcessPool, mut done: impl FnMut(&ProcessPool) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done(pool) {
            assert!(Instant::now() < deadline, "timed out: {pool:?}");
            pool.reap().unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn restarts_exiting_workers_until_stopped() {
        let options = PoolOptions {
            workers: 2,
            stop_timeout: Duration::from_secs(5),
            min_lifetime: Duration::ZERO,
        };
        // Workers exit right away with their index as the code.
        let mut pool = ProcessPool::new(options, |index| index as i32).unwrap();
        let exits = Rc::new(std::cell::RefCell::new(Vec::new()));
        let e = Rc::clone(&exits);
        pool.on_exit(move |info, status| e.borrow_mut().push((info.index, status)));
        pool.start().unwrap();
        wait_until(&mut pool, |_| exits.borrow().len() >= 6);
        pool.stop();
        wait_until(&mut pool, ProcessPool::is_finished);
        let exits = exits.borrow();
        assert!(
            exits
                .iter()
                .all(|(i, s)| *s == ExitStatus::Exited(*i as i32))
        );
        assert!(exits.iter().any(|(i, _)| *i == 1));
    }

    #[test]
    fn stop_terminates_and_escalates() {
        let options = PoolOptions {
            workers: 2,
            stop_timeout: Duration::from_millis(100),
            min_lifetime: Duration::ZERO,
        };
        let mut pool = ProcessPool::new(options, |index| {
            if index == 1 {
                // Ignore SIGTERM so the pool has to escalate.
                let _ = signal::ignore(libc::SIGTERM);
            }
            loop {
                // SAFETY: pause has no preconditions.
                unsafe { libc::pause() };
            }
        })
        .unwrap();
        let exits = Rc::new(std::cell::RefCell::new(Vec::new()));
        let e = Rc::clone(&exits);
        pool.on_exit(move |info, status| e.borrow_mut().push((info.index, status)));
        pool.start().unwrap();
        assert_eq!(pool.alive(), 2);
        // Give worker 1 time to install its SIG_IGN.
        std::thread::sleep(Duration::from_millis(50));
        pool.stop();
        wait_until(&mut pool, ProcessPool::is_finished);
        let mut exits = exits.borrow().clone();
        exits.sort_by_key(|(i, _)| *i);
        assert_eq!(
            exits,
            [
                (
                    0,
                    ExitStatus::Signaled {
                        signal: libc::SIGTERM,
                        core_dumped: false
                    }
                ),
                (
                    1,
                    ExitStatus::Signaled {
                        signal: libc::SIGKILL,
                        core_dumped: false
                    }
                ),
            ]
        );
    }

    #[test]
    fn rolling_reload_replaces_each_worker() {
        let options = PoolOptions {
            workers: 3,
            stop_timeout: Duration::from_secs(5),
            min_lifetime: Duration::ZERO,
        };
        let mut pool = ProcessPool::new(options, |_| {
            loop {
                // SAFETY: pause has no preconditions.
                unsafe { libc::pause() };
            }
        })
        .unwrap();
        pool.start().unwrap();
        let before: Vec<Pid> = pool.workers().iter().map(|w| w.pid).collect();
        pool.reload();
        wait_until(&mut pool, |p| {
            p.alive() == 3
                && p.reload_queue.is_empty()
                && p.reloading.is_none()
                && p.workers().iter().all(|w| w.restarts == 1)
        });
        let after: Vec<Pid> = pool.workers().iter().map(|w| w.pid).collect();
        assert!(before.iter().all(|pid| !after.contains(pid)));
        pool.stop();
        wait_until(&mut pool, ProcessPool::is_finished);
    }
}
