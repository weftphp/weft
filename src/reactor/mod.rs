//! A single-threaded event loop.
//!
//! A [`Reactor`] multiplexes four kinds of work, each delivered as a callback that receives
//! `&mut Reactor` so it can register or cancel further work:
//!
//! - **I/O readiness** on registered descriptors ([`Reactor::add`]), level-triggered.
//! - **Timers** ([`Reactor::after`], [`Reactor::every`]).
//! - **Deferred tasks** ([`Reactor::defer`]) that run at the end of the current iteration.
//! - **Remote tasks** posted from other threads through a [`Remote`] handle.
//!
//! It can also turn POSIX signals into callbacks ([`Reactor::on_signal`]).
//!
//! [`Reactor::run`] loops until [`Reactor::stop`] is called or nothing is left that could ever
//! produce a callback (no descriptors, timers, deferred tasks or [`Reactor::hold`]s).
//!
//! A reactor is deliberately `!Send`: one loop per thread, and callbacks need not be `Send`.

pub mod current;
mod poller;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod epoll;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
mod kqueue;
mod poll;

pub use poller::{Backend, Interest, Readiness};

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::core::timer::{Timer, TimerId};
use crate::core::{Error, ErrorKind, Result};
use crate::os::{fd, signal};
use poller::{Event, Poller};

/// Identifies a descriptor registration. Tokens are never reused within one reactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Token(u64);

impl Token {
    fn new(index: u32, generation: u32) -> Token {
        Token(u64::from(generation) << 32 | u64::from(index))
    }

    fn index(self) -> usize {
        (self.0 & u64::from(u32::MAX)) as usize
    }

    fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.index(), self.generation())
    }
}

type IoHandler = Box<dyn FnMut(&mut Reactor, Token, Readiness)>;
type TimerHandler = Box<dyn FnMut(&mut Reactor, TimerId)>;
type SignalHandler = Box<dyn FnMut(&mut Reactor, i32)>;
type Task = Box<dyn FnOnce(&mut Reactor)>;
type RemoteTask = Box<dyn FnOnce(&mut Reactor) + Send>;

/// Keys reserved for the reactor's own descriptors. User tokens never reach them because
/// generations start at 1 and stay below `u32::MAX`.
const WAKE_KEY: u64 = u64::MAX;
const SIGNAL_KEY: u64 = u64::MAX - 1;

struct Source {
    fd: RawFd,
    interest: Interest,
    /// Taken out while the handler runs.
    handler: Option<IoHandler>,
}

#[derive(Default)]
struct Slot {
    generation: u32,
    source: Option<Source>,
}

struct RemoteInner {
    tasks: Mutex<Vec<RemoteTask>>,
    wake_tx: OwnedFd,
    closed: AtomicBool,
}

impl RemoteInner {
    fn wake(&self) {
        // A full pipe means a wakeup is already pending, so the error is irrelevant.
        let _ = fd::write(self.wake_tx.as_fd(), &[1]);
    }
}

/// A `Send + Sync` handle for handing work to a [`Reactor`] from other threads.
#[derive(Clone)]
pub struct Remote {
    inner: Arc<RemoteInner>,
}

impl Remote {
    /// Queues `task` to run on the reactor's thread and wakes the reactor. Fails with
    /// [`ErrorKind::Closed`] once the reactor has been dropped.
    pub fn post(&self, task: impl FnOnce(&mut Reactor) + Send + 'static) -> Result<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(ErrorKind::Closed.into());
        }
        self.inner
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Box::new(task));
        self.inner.wake();
        Ok(())
    }

    /// Interrupts the reactor's current wait without queueing anything.
    pub fn wake(&self) {
        self.inner.wake();
    }
}

impl fmt::Debug for Remote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Remote").finish_non_exhaustive()
    }
}

/// See the [module documentation](self).
pub struct Reactor {
    poller: Box<dyn Poller>,
    slots: Vec<Slot>,
    free: Vec<u32>,
    sources: usize,
    events: Vec<Event>,

    timer: Timer,
    fired: Rc<RefCell<Vec<TimerId>>>,
    timer_handlers: HashMap<TimerId, Option<TimerHandler>>,

    deferred: VecDeque<Task>,
    remote: Arc<RemoteInner>,
    wake_rx: OwnedFd,

    signal_handlers: HashMap<i32, Option<SignalHandler>>,
    signal_registered: bool,

    holds: usize,
    stopped: bool,
}

impl Reactor {
    /// Creates a reactor on the best backend for this OS.
    pub fn new() -> Result<Self> {
        Self::with_backend(Backend::Auto)
    }

    pub fn with_backend(backend: Backend) -> Result<Self> {
        let mut poller = poller::new_poller(backend)?;
        let (wake_rx, wake_tx) = fd::pipe(true)?;
        poller.register(wake_rx.as_raw_fd(), WAKE_KEY, Interest::READABLE)?;
        Ok(Reactor {
            poller,
            slots: Vec::new(),
            free: Vec::new(),
            sources: 0,
            events: Vec::with_capacity(64),
            timer: Timer::new(),
            fired: Rc::default(),
            timer_handlers: HashMap::new(),
            deferred: VecDeque::new(),
            remote: Arc::new(RemoteInner {
                tasks: Mutex::new(Vec::new()),
                wake_tx,
                closed: AtomicBool::new(false),
            }),
            wake_rx,
            signal_handlers: HashMap::new(),
            signal_registered: false,
            holds: 0,
            stopped: false,
        })
    }

    /// Name of the polling backend in use (`epoll`, `kqueue` or `poll`).
    pub fn backend_name(&self) -> &'static str {
        self.poller.name()
    }

    // ----- descriptors -----

    /// Watches `fd` for `interest` and calls `handler` whenever it is ready.
    ///
    /// The reactor does not own `fd`; [`remove`](Self::remove) the registration before the
    /// descriptor is closed.
    pub fn add(
        &mut self,
        fd: RawFd,
        interest: Interest,
        handler: impl FnMut(&mut Reactor, Token, Readiness) + 'static,
    ) -> Result<Token> {
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                let index = u32::try_from(self.slots.len())
                    .map_err(|_| Error::new(ErrorKind::Full, "too many registrations"))?;
                self.slots.push(Slot::default());
                index
            }
        };
        let slot = &mut self.slots[index as usize];
        // Wrapping skips 0 and the reserved high generations.
        slot.generation = match slot.generation.wrapping_add(1) {
            g if g == 0 || g >= u32::MAX - 1 => 1,
            g => g,
        };
        let token = Token::new(index, slot.generation);
        if let Err(err) = self.poller.register(fd, token.0, interest) {
            self.free.push(index);
            return Err(err.into());
        }
        self.slots[index as usize].source = Some(Source {
            fd,
            interest,
            handler: Some(Box::new(handler)),
        });
        self.sources += 1;
        Ok(token)
    }

    fn source(&self, token: Token) -> Option<&Source> {
        self.slots
            .get(token.index())
            .filter(|slot| slot.generation == token.generation())
            .and_then(|slot| slot.source.as_ref())
    }

    fn source_mut(&mut self, token: Token) -> Option<&mut Source> {
        self.slots
            .get_mut(token.index())
            .filter(|slot| slot.generation == token.generation())
            .and_then(|slot| slot.source.as_mut())
    }

    fn unknown(token: Token) -> Error {
        Error::new(ErrorKind::InvalidArgument, format!("unknown token {token}"))
    }

    /// Changes what `token` is watched for. [`Interest::NONE`] mutes it without removing it.
    pub fn set_interest(&mut self, token: Token, interest: Interest) -> Result<()> {
        let source = self.source(token).ok_or_else(|| Self::unknown(token))?;
        let (fd, old) = (source.fd, source.interest);
        if old != interest {
            self.poller.reregister(fd, token.0, old, interest)?;
            if let Some(source) = self.source_mut(token) {
                source.interest = interest;
            }
        }
        Ok(())
    }

    /// The current interest of `token`.
    pub fn interest(&self, token: Token) -> Option<Interest> {
        self.source(token).map(|s| s.interest)
    }

    /// The descriptor registered under `token`.
    pub fn fd(&self, token: Token) -> Option<RawFd> {
        self.source(token).map(|s| s.fd)
    }

    pub fn contains(&self, token: Token) -> bool {
        self.source(token).is_some()
    }

    /// Stops watching `token`. Safe to call from the token's own handler.
    pub fn remove(&mut self, token: Token) -> Result<()> {
        let source = self
            .slots
            .get_mut(token.index())
            .filter(|slot| slot.generation == token.generation())
            .and_then(|slot| slot.source.take())
            .ok_or_else(|| Self::unknown(token))?;
        self.free.push(token.index() as u32);
        self.sources -= 1;
        match self.poller.deregister(source.fd, source.interest) {
            // Already gone from the kernel's set (for example, closed early): nothing to undo.
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::EBADF)) => Ok(()),
            other => other.map_err(Error::from),
        }
    }

    // ----- timers -----

    /// Runs `callback` once after `delay`.
    pub fn after(
        &mut self,
        delay: Duration,
        callback: impl FnOnce(&mut Reactor) + 'static,
    ) -> TimerId {
        let fired = Rc::clone(&self.fired);
        let id = self
            .timer
            .after(delay, move |_, id| fired.borrow_mut().push(id));
        let mut callback = Some(callback);
        self.timer_handlers.insert(
            id,
            Some(Box::new(move |reactor, _| {
                if let Some(callback) = callback.take() {
                    callback(reactor);
                }
            })),
        );
        id
    }

    /// Runs `callback` every `period` until cancelled (see [`Timer::every`] for how missed
    /// ticks are handled).
    pub fn every(
        &mut self,
        period: Duration,
        callback: impl FnMut(&mut Reactor, TimerId) + 'static,
    ) -> Result<TimerId> {
        let fired = Rc::clone(&self.fired);
        let id = self
            .timer
            .every(period, move |_, id| fired.borrow_mut().push(id))?;
        self.timer_handlers.insert(id, Some(Box::new(callback)));
        Ok(id)
    }

    /// Cancels a timer. Returns `false` if it already finished or was cancelled.
    pub fn cancel_timer(&mut self, id: TimerId) -> bool {
        self.timer.cancel(id);
        self.timer_handlers.remove(&id).is_some()
    }

    /// Moves a pending timer's next run to `delay` from now.
    pub fn reschedule_timer(&mut self, id: TimerId, delay: Duration) -> bool {
        self.timer.reschedule(id, delay)
    }

    /// Whether timer `id` is still scheduled.
    pub fn timer_exists(&self, id: TimerId) -> bool {
        self.timer_handlers.contains_key(&id)
    }

    /// Ids of all live timers.
    pub fn timer_ids(&self) -> Vec<TimerId> {
        self.timer_handlers.keys().copied().collect()
    }

    /// Number of live timers.
    pub fn timers(&self) -> usize {
        self.timer_handlers.len()
    }

    // ----- tasks -----

    /// Runs `task` at the end of the current loop iteration (or the next one, if the loop is
    /// not running). Tasks deferred by a deferred task wait for the following iteration.
    pub fn defer(&mut self, task: impl FnOnce(&mut Reactor) + 'static) {
        self.deferred.push_back(Box::new(task));
    }

    /// A handle for posting work from other threads.
    pub fn remote(&self) -> Remote {
        Remote {
            inner: Arc::clone(&self.remote),
        }
    }

    /// Keeps [`run`](Self::run) going even with nothing registered, for example while waiting
    /// for a [`Remote`] post. Undo with [`release`](Self::release).
    pub fn hold(&mut self) {
        self.holds += 1;
    }

    pub fn release(&mut self) {
        self.holds = self.holds.saturating_sub(1);
    }

    // ----- signals -----

    /// Calls `handler` from the loop whenever `signal` arrives.
    ///
    /// Signal dispositions are process-wide, so only one reactor per process should handle
    /// signals. Signal handlers alone do not keep [`run`](Self::run) going.
    pub fn on_signal(
        &mut self,
        signal: i32,
        handler: impl FnMut(&mut Reactor, i32) + 'static,
    ) -> Result<()> {
        signal::watch(signal)?;
        if !self.signal_registered {
            let notifier = signal::notifier()?.as_raw_fd();
            self.poller
                .register(notifier, SIGNAL_KEY, Interest::READABLE)?;
            self.signal_registered = true;
        }
        self.signal_handlers.insert(signal, Some(Box::new(handler)));
        Ok(())
    }

    /// Stops handling `signal` and restores its default disposition.
    pub fn remove_signal(&mut self, signal: i32) -> Result<bool> {
        let existed = self.signal_handlers.remove(&signal).is_some();
        if existed {
            signal::reset(signal)?;
        }
        Ok(existed)
    }

    // ----- running -----

    /// Makes [`run`](Self::run) return after the current iteration.
    pub fn stop(&mut self) {
        self.stopped = true;
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Whether anything could still produce a callback.
    pub fn has_work(&self) -> bool {
        self.sources > 0 || !self.timer_handlers.is_empty() || !self.deferred.is_empty() || {
            self.holds > 0
        }
    }

    /// Runs until [`stop`](Self::stop) is called or no work remains.
    pub fn run(&mut self) -> Result<()> {
        self.stopped = false;
        while !self.stopped && self.has_work() {
            self.run_once(None)?;
        }
        Ok(())
    }

    /// One iteration: waits for I/O (at most `max_wait`, and never past the next timer),
    /// then dispatches I/O events, due timers and deferred tasks, in that order.
    pub fn run_once(&mut self, max_wait: Option<Duration>) -> Result<()> {
        let mut wait = self.timer.timeout();
        if let Some(cap) = max_wait {
            wait = Some(wait.map_or(cap, |w| w.min(cap)));
        }
        if !self.deferred.is_empty() || self.stopped {
            wait = Some(Duration::ZERO);
        }

        let mut events = std::mem::take(&mut self.events);
        events.clear();
        let polled = self.poller.poll(&mut events, wait);
        if let Err(err) = polled {
            self.events = events;
            return Err(err.into());
        }
        for event in &events {
            match event.key {
                WAKE_KEY => self.run_remote(),
                SIGNAL_KEY => self.dispatch_signals(),
                key => self.dispatch_io(Token(key), event.readiness),
            }
        }
        self.events = events;

        self.dispatch_timers();

        for _ in 0..self.deferred.len() {
            match self.deferred.pop_front() {
                Some(task) => task(self),
                None => break,
            }
        }
        Ok(())
    }

    fn dispatch_io(&mut self, token: Token, readiness: Readiness) {
        let Some(mut handler) = self.source_mut(token).and_then(|s| s.handler.take()) else {
            // Removed by an earlier callback in this batch.
            return;
        };
        handler(self, token, readiness);
        if let Some(source) = self.source_mut(token)
            && source.handler.is_none()
        {
            source.handler = Some(handler);
        }
    }

    fn dispatch_timers(&mut self) {
        self.timer.poll();
        let fired = std::mem::take(&mut *self.fired.borrow_mut());
        for id in fired {
            let Some(mut handler) = self.timer_handlers.get_mut(&id).and_then(Option::take) else {
                continue;
            };
            handler(self, id);
            if self.timer.contains(id) {
                if let Some(slot @ None) = self.timer_handlers.get_mut(&id) {
                    *slot = Some(handler);
                }
            } else {
                self.timer_handlers.remove(&id);
            }
        }
    }

    fn run_remote(&mut self) {
        let mut sink = [0u8; 64];
        while matches!(fd::read(self.wake_rx.as_fd(), &mut sink), Ok(n) if n > 0) {}
        let tasks =
            std::mem::take(&mut *self.remote.tasks.lock().unwrap_or_else(|e| e.into_inner()));
        for task in tasks {
            task(self);
        }
    }

    fn dispatch_signals(&mut self) {
        for sig in signal::take_pending() {
            let Some(mut handler) = self.signal_handlers.get_mut(&sig).and_then(Option::take)
            else {
                continue;
            };
            handler(self, sig);
            if let Some(slot @ None) = self.signal_handlers.get_mut(&sig) {
                *slot = Some(handler);
            }
        }
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        self.remote.closed.store(true, Ordering::Release);
        if self.signal_registered
            && let Ok(notifier) = signal::notifier()
        {
            let _ = self
                .poller
                .deregister(notifier.as_raw_fd(), Interest::READABLE);
        }
    }
}

impl fmt::Debug for Reactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reactor")
            .field("backend", &self.poller.name())
            .field("sources", &self.sources)
            .field("timers", &self.timer_handlers.len())
            .field("deferred", &self.deferred.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    fn backends() -> [Backend; 2] {
        [Backend::Auto, Backend::Poll]
    }

    #[test]
    fn echoes_until_peer_closes() {
        for backend in backends() {
            let mut reactor = Reactor::with_backend(backend).unwrap();
            let (mut client, server) = UnixStream::pair().unwrap();
            server.set_nonblocking(true).unwrap();
            let server = Rc::new(RefCell::new(server));

            let s = Rc::clone(&server);
            let fd = server.borrow().as_raw_fd();
            reactor
                .add(fd, Interest::READABLE, move |r, token, _| {
                    let mut buf = [0u8; 64];
                    let read = s.borrow_mut().read(&mut buf);
                    match read {
                        Ok(0) => r.remove(token).unwrap(),
                        Ok(n) => s.borrow_mut().write_all(&buf[..n]).unwrap(),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => panic!("{e}"),
                    }
                })
                .unwrap();

            client.write_all(b"hello").unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            reactor.run().unwrap();
            drop(server);
            let mut echoed = Vec::new();
            client.read_to_end(&mut echoed).unwrap_or_default();
            assert_eq!(echoed, b"hello", "{}", reactor.backend_name());
            assert!(!reactor.has_work());
        }
    }

    #[test]
    fn timers_and_deferred_tasks_run_in_order() {
        let mut reactor = Reactor::new().unwrap();
        let log = Rc::new(RefCell::new(Vec::new()));

        let l = Rc::clone(&log);
        reactor.after(Duration::from_millis(20), move |_| {
            l.borrow_mut().push("late")
        });
        let l = Rc::clone(&log);
        reactor.after(Duration::from_millis(5), move |r| {
            l.borrow_mut().push("early");
            let l = Rc::clone(&l);
            r.defer(move |_| l.borrow_mut().push("deferred"));
        });
        let l = Rc::clone(&log);
        let ticks = Rc::new(Cell::new(0));
        let t = Rc::clone(&ticks);
        reactor
            .every(Duration::from_millis(2), move |r, id| {
                t.set(t.get() + 1);
                if t.get() == 3 {
                    l.borrow_mut().push("ticked");
                    assert!(r.cancel_timer(id));
                }
            })
            .unwrap();

        let start = Instant::now();
        reactor.run().unwrap();
        assert!(start.elapsed() >= Duration::from_millis(20));
        assert_eq!(ticks.get(), 3);
        let log = log.borrow();
        assert_eq!(log.iter().filter(|&&e| e == "ticked").count(), 1);
        let order: Vec<_> = log.iter().filter(|&&e| e != "ticked").copied().collect();
        assert_eq!(order, ["early", "deferred", "late"]);
        assert_eq!(reactor.timers(), 0);
    }

    #[test]
    fn remote_posts_wake_the_loop() {
        let mut reactor = Reactor::new().unwrap();
        let remote = reactor.remote();
        reactor.hold();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            remote
                .post(|r| {
                    r.release();
                    r.defer(|r| r.stop());
                })
                .unwrap();
        });
        let start = Instant::now();
        reactor.run().unwrap();
        worker.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));

        let remote = reactor.remote();
        drop(reactor);
        assert_eq!(remote.post(|_| {}).unwrap_err().kind(), ErrorKind::Closed);
    }

    #[test]
    fn handler_may_remove_and_re_add() {
        let mut reactor = Reactor::new().unwrap();
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"x").unwrap();
        let fd = b.as_raw_fd();
        let calls = Rc::new(Cell::new(0));
        let c = Rc::clone(&calls);
        let first = reactor
            .add(fd, Interest::READABLE, move |r, token, _| {
                c.set(c.get() + 1);
                r.remove(token).unwrap();
                let c = Rc::clone(&c);
                let again = r
                    .add(fd, Interest::READABLE, move |r, token, _| {
                        c.set(c.get() + 10);
                        r.remove(token).unwrap();
                    })
                    .unwrap();
                assert_ne!(again, token, "tokens are not reused");
            })
            .unwrap();
        reactor.run().unwrap();
        assert_eq!(calls.get(), 11);
        assert!(!reactor.contains(first));
        assert!(reactor.remove(first).is_err());
    }

    #[test]
    fn muting_interest() {
        let mut reactor = Reactor::new().unwrap();
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"x").unwrap();
        let calls = Rc::new(Cell::new(0));
        let c = Rc::clone(&calls);
        let token = reactor
            .add(b.as_raw_fd(), Interest::NONE, move |_, _, _| {
                c.set(c.get() + 1)
            })
            .unwrap();
        reactor.run_once(Some(Duration::from_millis(5))).unwrap();
        assert_eq!(calls.get(), 0);
        reactor.set_interest(token, Interest::READABLE).unwrap();
        assert_eq!(reactor.interest(token), Some(Interest::READABLE));
        reactor.run_once(Some(Duration::from_millis(5))).unwrap();
        assert_eq!(calls.get(), 1);
        reactor.remove(token).unwrap();
    }

    #[test]
    fn signals_become_callbacks() {
        let mut reactor = Reactor::new().unwrap();
        let got = Rc::new(Cell::new(0));
        let g = Rc::clone(&got);
        reactor
            .on_signal(libc::SIGUSR2, move |r, sig| {
                g.set(sig);
                r.stop();
            })
            .unwrap();
        reactor.hold();
        // SAFETY: SIGUSR2 is now handled by the self-pipe handler.
        unsafe { libc::raise(libc::SIGUSR2) };
        reactor.run().unwrap();
        assert_eq!(got.get(), libc::SIGUSR2);
        assert!(reactor.remove_signal(libc::SIGUSR2).unwrap());
    }
}
