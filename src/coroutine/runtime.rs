//! The per-thread coroutine scheduler.
//!
//! Each thread has its own set of coroutines and a "main" context (the thread's original
//! stack). [`resume`] switches into a coroutine and returns once it suspends or finishes;
//! [`suspend`] switches back to whoever resumed the current coroutine. A finished
//! coroutine's stack is recycled by the context that resumed it, never by the coroutine
//! itself.
//!
//! Coroutines that wait for events do so through a [`Waiter`]: a handle naming one specific
//! wait of one coroutine. Waking a stale waiter (one whose coroutine has since moved on) is a
//! harmless no-op, which makes timeouts and cancellation race-free.
//!
//! When resumed from a reactor callback with [`resume_in`], a coroutine can use that
//! reactor through [`with_reactor`] until it suspends again.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt;
use std::os::fd::RawFd;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::rc::Rc;
use std::time::Duration;

use super::context::{self, Stack};
use crate::core::timer::TimerId;
use crate::core::{Error, ErrorKind, Result};
use crate::reactor::{Interest, Reactor, Readiness, Token, current};

/// Identifies a coroutine within its thread. Never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CoId(u64);

impl CoId {
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for CoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Why a waiting coroutine was resumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// Plain resumption without a reason.
    Resumed,
    /// The awaited descriptor is ready.
    Ready(Readiness),
    /// The wait's deadline passed.
    Timeout,
    /// [`cancel`] was called on the coroutine.
    Cancelled,
    /// The awaited resource was closed.
    Closed,
    /// The awaited event happened.
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Created, never run.
    Ready,
    /// On the active chain (running, or blocked inside a `resume` of another coroutine).
    Running,
    Suspended,
    Finished,
}

/// Called on every switch with (from, to); `None` is the thread's main context. A language
/// runtime embedding weft uses it to swap its own per-coroutine state.
pub type SwitchHook = Rc<dyn Fn(Option<CoId>, Option<CoId>)>;

struct Co {
    sp: *mut u8,
    stack: Option<Stack>,
    origin: Option<CoId>,
    state: State,
    entry: Option<Box<dyn FnOnce()>>,
    panic: Option<Box<dyn Any + Send>>,
    wake: Option<Wake>,
    /// Identifies the coroutine's current wait; bumped by every [`Waiter`] creation.
    wait_seq: u64,
    waiting: bool,
    locals: HashMap<std::any::TypeId, Box<dyn Any>>,
}

/// Interest of one descriptor shared by the coroutines waiting on it.
struct FdWaits {
    token: Token,
    reader: Option<Waiter>,
    writer: Option<Waiter>,
}

struct Scheduler {
    coroutines: HashMap<CoId, Box<Co>>,
    current: Option<CoId>,
    /// Saved stack pointer of the thread's main context. Boxed for a stable address.
    main_sp: Box<Cell<*mut u8>>,
    last_id: u64,
    stack_size: usize,
    spare_stacks: Vec<Stack>,
    hook: Option<SwitchHook>,
    fd_waits: HashMap<RawFd, FdWaits>,
}

/// Stacks kept for reuse instead of being unmapped.
const SPARE_STACKS: usize = 64;

/// Default usable stack size per coroutine.
pub const DEFAULT_STACK_SIZE: usize = 256 * 1024;

thread_local! {
    static SCHEDULER: RefCell<Scheduler> = RefCell::new(Scheduler {
        coroutines: HashMap::new(),
        current: None,
        main_sp: Box::new(Cell::new(std::ptr::null_mut())),
        last_id: 0,
        stack_size: DEFAULT_STACK_SIZE,
        spare_stacks: Vec::new(),
        hook: None,
        fd_waits: HashMap::new(),
    });
}

fn with<R>(f: impl FnOnce(&mut Scheduler) -> R) -> R {
    SCHEDULER.with(|s| f(&mut s.borrow_mut()))
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidState, msg)
}

/// The running coroutine, or `None` on the main context.
pub fn current() -> Option<CoId> {
    with(|s| s.current)
}

/// Whether the caller runs inside a coroutine.
pub fn in_coroutine() -> bool {
    current().is_some()
}

/// Number of coroutines that exist (started or not, but not finished).
pub fn count() -> usize {
    with(|s| s.coroutines.len())
}

/// Ids of every live coroutine.
pub fn list() -> Vec<CoId> {
    with(|s| s.coroutines.keys().copied().collect())
}

/// Whether `id` exists and has not finished.
pub fn exists(id: CoId) -> bool {
    with(|s| s.coroutines.contains_key(&id))
}

/// The coroutine that most recently resumed `id`, if it is still blocked in that resume.
pub fn origin(id: CoId) -> Option<CoId> {
    with(|s| s.coroutines.get(&id).and_then(|c| c.origin))
}

/// Sets the stack size for coroutines created from now on.
pub fn set_stack_size(bytes: usize) {
    with(|s| {
        s.stack_size = bytes.max(context::MIN_STACK);
        s.spare_stacks.clear();
    });
}

/// Installs (or removes) the switch hook for this thread.
pub fn set_switch_hook(hook: Option<SwitchHook>) {
    with(|s| s.hook = hook);
}

fn run_hook(from: Option<CoId>, to: Option<CoId>) {
    if let Some(hook) = with(|s| s.hook.clone()) {
        hook(from, to);
    }
}

/// Creates a coroutine without running it. Start it with [`resume`].
pub fn create(f: impl FnOnce() + 'static) -> Result<CoId> {
    let (id, size, stack) = with(|s| {
        s.last_id += 1;
        (CoId(s.last_id), s.stack_size, s.spare_stacks.pop())
    });
    let mut stack = match stack {
        Some(stack) => stack,
        None => Stack::new(size)?,
    };
    // SAFETY: `coroutine_main` decodes `data` back into this id, which is a plain integer.
    let sp = unsafe { stack.prepare(coroutine_main, id.0 as usize as *mut ()) };
    with(|s| {
        s.coroutines.insert(
            id,
            Box::new(Co {
                sp,
                stack: Some(stack),
                origin: None,
                state: State::Ready,
                entry: Some(Box::new(f)),
                panic: None,
                wake: None,
                wait_seq: 0,
                waiting: false,
                locals: HashMap::new(),
            }),
        )
    });
    Ok(id)
}

/// Creates a coroutine and runs it until it first suspends or finishes.
pub fn spawn(f: impl FnOnce() + 'static) -> Result<CoId> {
    let id = create(f)?;
    resume(id)?;
    Ok(id)
}

/// Switches into `id` until it suspends or finishes. If it finished by panicking, the panic
/// continues in the caller.
pub fn resume(id: CoId) -> Result<()> {
    if current::is_lent() {
        return Err(invalid("cannot switch coroutines inside with_reactor"));
    }
    let (save, to, from) = with(|s| -> Result<_> {
        let from = s.current;
        let save: *mut *mut u8 = match from {
            None => s.main_sp.as_ptr(),
            Some(cur) => match s.coroutines.get_mut(&cur) {
                Some(co) => &raw mut co.sp,
                None => return Err(invalid("current coroutine vanished")),
            },
        };
        let target = s
            .coroutines
            .get_mut(&id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no coroutine {id}")))?;
        match target.state {
            State::Ready | State::Suspended => {}
            State::Running => return Err(invalid(format!("coroutine {id} is already running"))),
            State::Finished => return Err(invalid(format!("coroutine {id} has finished"))),
        }
        target.state = State::Running;
        target.origin = from;
        target.waiting = false;
        let to = target.sp;
        s.current = Some(id);
        Ok((save, to, from))
    })?;
    run_hook(from, Some(id));
    // SAFETY: `save` points into a boxed Co or the boxed main slot, both stable while this
    // context is blocked here; `to` was prepared or saved for `id`, which is not running.
    // No RefCell borrow is held across the switch.
    unsafe { context::switch(save, to, 0) };

    // Back here because `id` suspended or finished (or a coroutine it resumed did and the
    // chain unwound to us).
    let finished = with(|s| {
        let done = s
            .coroutines
            .get(&id)
            .is_some_and(|c| c.state == State::Finished);
        if !done {
            return None;
        }
        let mut co = s.coroutines.remove(&id)?;
        if let Some(stack) = co.stack.take()
            && s.spare_stacks.len() < SPARE_STACKS
        {
            s.spare_stacks.push(stack);
        }
        Some(co.panic.take())
    });
    if let Some(Some(panic)) = finished {
        resume_unwind(panic);
    }
    Ok(())
}

/// Switches from the current coroutine back to whoever resumed it, and returns the reason it
/// was later resumed.
pub fn suspend() -> Result<Wake> {
    if current::is_lent() {
        return Err(invalid("cannot suspend inside with_reactor"));
    }
    let (save, to, me, origin) = with(|s| -> Result<_> {
        let me = s
            .current
            .ok_or_else(|| invalid("suspend called outside a coroutine"))?;
        let origin = {
            let co = s
                .coroutines
                .get_mut(&me)
                .ok_or_else(|| invalid("current coroutine vanished"))?;
            co.state = State::Suspended;
            co.origin.take()
        };
        let to = match origin {
            None => s.main_sp.get(),
            Some(o) => s.coroutines.get(&o).map_or(std::ptr::null_mut(), |c| c.sp),
        };
        let save: *mut *mut u8 = match s.coroutines.get_mut(&me) {
            Some(co) => &raw mut co.sp,
            None => return Err(invalid("current coroutine vanished")),
        };
        s.current = origin;
        Ok((save, to, me, origin))
    })?;
    run_hook(Some(me), origin);
    // SAFETY: as in `resume`; `to` is the saved stack pointer of the context blocked in the
    // `resume` that started us.
    unsafe { context::switch(save, to, 0) };
    Ok(with(|s| {
        s.coroutines
            .get_mut(&me)
            .and_then(|co| co.wake.take())
            .unwrap_or(Wake::Resumed)
    }))
}

/// First function run on every coroutine stack.
unsafe extern "C" fn coroutine_main(data: *mut (), _arg: usize) -> ! {
    let id = CoId(data as usize as u64);
    {
        let entry = with(|s| s.coroutines.get_mut(&id).and_then(|c| c.entry.take()));
        let outcome = match entry {
            Some(f) => catch_unwind(AssertUnwindSafe(f)).err(),
            None => None,
        };
        with(|s| {
            if let Some(co) = s.coroutines.get_mut(&id) {
                co.panic = outcome;
                co.state = State::Finished;
                co.locals.clear();
            }
        });
    }
    // Every value owned by this frame has been dropped; leave for good.
    let (save, to, origin) = with(|s| {
        let origin = s.coroutines.get_mut(&id).and_then(|c| c.origin.take());
        let to = match origin {
            None => s.main_sp.get(),
            Some(o) => s.coroutines.get(&o).map_or(std::ptr::null_mut(), |c| c.sp),
        };
        let save: *mut *mut u8 = match s.coroutines.get_mut(&id) {
            Some(co) => &raw mut co.sp,
            None => s.main_sp.as_ptr(),
        };
        s.current = origin;
        (save, to, origin)
    });
    run_hook(Some(id), origin);
    // SAFETY: switching to the context blocked in the `resume` that ran us; it frees this
    // stack only after the switch completes. This context is never resumed again.
    unsafe { context::switch(save, to, 0) };
    // A finished coroutine is never resumed, so this is unreachable.
    std::process::abort()
}

// ----- coroutine-local storage -----

/// Stores a value of type `T` local to the current coroutine (dropped when it finishes).
pub fn set_local<T: 'static>(value: T) -> Result<()> {
    with(|s| {
        let id = s.current.ok_or_else(|| invalid("not in a coroutine"))?;
        let co = s
            .coroutines
            .get_mut(&id)
            .ok_or_else(|| invalid("current coroutine vanished"))?;
        co.locals
            .insert(std::any::TypeId::of::<T>(), Box::new(value));
        Ok(())
    })
}

/// Runs `f` on the current coroutine's `T`, if set.
pub fn with_local<T: 'static, R>(f: impl FnOnce(&mut T) -> R) -> Option<R> {
    // Take the value out so `f` may use the scheduler freely, then put it back.
    let (id, mut value) = with(|s| {
        let id = s.current?;
        let value = s
            .coroutines
            .get_mut(&id)?
            .locals
            .remove(&std::any::TypeId::of::<T>())?;
        Some((id, value))
    })?;
    let out = value.downcast_mut::<T>().map(f);
    with(|s| {
        if let Some(co) = s.coroutines.get_mut(&id) {
            co.locals.insert(std::any::TypeId::of::<T>(), value);
        }
    });
    out
}

// ----- reactor access -----

/// Resumes `id` from inside a reactor callback, giving it access to `reactor` through
/// [`with_reactor`] while it runs.
pub fn resume_in(reactor: &mut Reactor, id: CoId) -> Result<()> {
    current::scope(reactor, || resume(id))
}

/// Creates a coroutine and runs it immediately with access to `reactor`.
pub fn spawn_in(reactor: &mut Reactor, f: impl FnOnce() + 'static) -> Result<CoId> {
    let id = create(f)?;
    resume_in(reactor, id)?;
    Ok(id)
}

/// Runs `f` with the current event loop: the one whose callback resumed this coroutine, or
/// the thread's idle global loop. `f` must not suspend or switch coroutines.
pub fn with_reactor<R>(f: impl FnOnce(&mut Reactor) -> R) -> Result<R> {
    current::with(f)
}

/// Whether [`with_reactor`] would succeed.
pub fn has_reactor() -> bool {
    current::available()
}

// ----- waiting -----

/// One specific wait of one coroutine. Cheap to copy into callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waiter {
    pub id: CoId,
    seq: u64,
}

impl Waiter {
    /// Starts a new wait for the current coroutine. Any older waiter becomes stale.
    pub fn new() -> Result<Waiter> {
        with(|s| {
            let id = s
                .current
                .ok_or_else(|| invalid("waiting requires a coroutine"))?;
            let co = s
                .coroutines
                .get_mut(&id)
                .ok_or_else(|| invalid("current coroutine vanished"))?;
            co.wait_seq += 1;
            Ok(Waiter {
                id,
                seq: co.wait_seq,
            })
        })
    }

    /// Whether the coroutine is still suspended in this exact wait.
    pub fn is_pending(&self) -> bool {
        with(|s| {
            s.coroutines
                .get(&self.id)
                .is_some_and(|c| c.waiting && c.wait_seq == self.seq && c.state == State::Suspended)
        })
    }

    /// Resumes the coroutine with `wake` if it is still in this wait. Returns whether it was.
    pub fn wake(&self, reactor: &mut Reactor, wake: Wake) -> bool {
        let pending = with(|s| match s.coroutines.get_mut(&self.id) {
            Some(c) if c.waiting && c.wait_seq == self.seq && c.state == State::Suspended => {
                c.wake = Some(wake);
                c.waiting = false;
                true
            }
            _ => false,
        });
        if pending {
            // Errors here mean the coroutine vanished in between; nothing to do.
            let _ = resume_in(reactor, self.id);
        }
        pending
    }

    /// Wakes the coroutine at the end of the current loop iteration instead of immediately.
    pub fn wake_later(self, reactor: &mut Reactor, wake: Wake) {
        reactor.defer(move |r| {
            self.wake(r, wake);
        });
    }

    /// Suspends until woken, with an optional deadline after which it wakes with
    /// [`Wake::Timeout`].
    pub fn wait(self, timeout: Option<Duration>) -> Result<Wake> {
        let timer = match timeout {
            Some(delay) => Some(with_reactor(|r| {
                r.after(delay, move |r| {
                    self.wake(r, Wake::Timeout);
                })
            })?),
            None => None,
        };
        with(|s| -> Result<()> {
            let co = s
                .coroutines
                .get_mut(&self.id)
                .ok_or_else(|| invalid("current coroutine vanished"))?;
            if co.wait_seq != self.seq || s.current != Some(self.id) {
                return Err(invalid("stale waiter"));
            }
            co.waiting = true;
            Ok(())
        })?;
        let wake = suspend();
        with(|s| {
            if let Some(co) = s.coroutines.get_mut(&self.id) {
                co.waiting = false;
            }
        });
        if let Some(timer) = timer {
            cancel_timer(timer);
        }
        wake
    }
}

fn cancel_timer(timer: TimerId) {
    let _ = with_reactor(|r| r.cancel_timer(timer));
}

/// Wakes `id` with [`Wake::Cancelled`] if it is waiting. Returns whether it was.
pub fn cancel(reactor: &mut Reactor, id: CoId) -> bool {
    let waiter = with(|s| {
        s.coroutines
            .get(&id)
            .filter(|c| c.waiting && c.state == State::Suspended)
            .map(|c| Waiter {
                id,
                seq: c.wait_seq,
            })
    });
    waiter.is_some_and(|w| w.wake(reactor, Wake::Cancelled))
}

/// Suspends for `duration`. Returns early with an error if cancelled.
pub fn sleep(duration: Duration) -> Result<()> {
    match Waiter::new()?.wait(Some(duration))? {
        Wake::Timeout => Ok(()),
        Wake::Cancelled => Err(Error::new(ErrorKind::Closed, "sleep cancelled")),
        _ => Ok(()),
    }
}

/// Gives other ready work (I/O callbacks, deferred wake-ups) a turn, then continues.
pub fn yield_now() -> Result<()> {
    let waiter = Waiter::new()?;
    with_reactor(|r| waiter.wake_later(r, Wake::Resumed))?;
    waiter.wait(None).map(drop)
}

// ----- descriptor readiness -----

fn fd_interest(entry: &FdWaits) -> Interest {
    let mut interest = Interest::NONE;
    if entry.reader.is_some() {
        interest = interest | Interest::READABLE;
    }
    if entry.writer.is_some() {
        interest = interest | Interest::WRITABLE;
    }
    interest
}

/// Called by the reactor when a watched descriptor is ready.
fn on_fd_ready(r: &mut Reactor, fd: RawFd, readiness: Readiness) {
    let (reader, writer) = with(|s| match s.fd_waits.get(&fd) {
        Some(entry) => {
            let reader = (readiness.readable || readiness.hangup || readiness.error)
                .then_some(entry.reader)
                .flatten();
            let writer = (readiness.writable || readiness.hangup || readiness.error)
                .then_some(entry.writer)
                .flatten();
            (reader, writer)
        }
        None => (None, None),
    });
    if let Some(w) = reader {
        w.wake(r, Wake::Ready(readiness));
    }
    if let Some(w) = writer {
        w.wake(r, Wake::Ready(readiness));
    }
}

/// Updates the reactor registration of `fd` after its waiter set changed.
fn sync_registration(r: &mut Reactor, fd: RawFd) -> Result<()> {
    let action = with(|s| match s.fd_waits.get(&fd) {
        Some(entry) if entry.reader.is_none() && entry.writer.is_none() => {
            let token = entry.token;
            s.fd_waits.remove(&fd);
            Some((token, None))
        }
        Some(entry) => Some((entry.token, Some(fd_interest(entry)))),
        None => None,
    });
    match action {
        Some((token, None)) => {
            let _ = r.remove(token);
            Ok(())
        }
        Some((token, Some(interest))) => r.set_interest(token, interest),
        None => Ok(()),
    }
}

/// Suspends until `fd` is ready for `interest` (readable or writable, not both), or the
/// timeout passes. Only one coroutine may wait per direction on a descriptor.
pub fn wait_fd(fd: RawFd, interest: Interest, timeout: Option<Duration>) -> Result<Readiness> {
    let reading = interest.is_readable();
    if reading == interest.is_writable() {
        return Err(Error::new(
            ErrorKind::InvalidArgument,
            "wait for exactly one of readable or writable",
        ));
    }
    let waiter = Waiter::new()?;
    with_reactor(|r| -> Result<()> {
        let exists = with(|s| -> Result<bool> {
            let Some(entry) = s.fd_waits.get(&fd) else {
                return Ok(false);
            };
            let existing = if reading { entry.reader } else { entry.writer };
            if existing.is_some_and(|w| w.is_pending_unlocked(s)) {
                return Err(invalid(format!(
                    "descriptor {fd} already has a {} coroutine",
                    if reading { "reading" } else { "writing" }
                )));
            }
            if let Some(entry) = s.fd_waits.get_mut(&fd) {
                if reading {
                    entry.reader = Some(waiter);
                } else {
                    entry.writer = Some(waiter);
                }
            }
            Ok(true)
        })?;
        if exists {
            return sync_registration(r, fd);
        }
        let token = r.add(fd, interest, move |r, _, readiness| {
            on_fd_ready(r, fd, readiness)
        })?;
        with(|s| {
            s.fd_waits.insert(
                fd,
                FdWaits {
                    token,
                    reader: reading.then_some(waiter),
                    writer: (!reading).then_some(waiter),
                },
            )
        });
        Ok(())
    })??;

    let wake = waiter.wait(timeout);
    // Remove our interest whatever happened.
    let _ = with_reactor(|r| {
        with(|s| {
            if let Some(entry) = s.fd_waits.get_mut(&fd) {
                let slot = if reading {
                    &mut entry.reader
                } else {
                    &mut entry.writer
                };
                if *slot == Some(waiter) {
                    *slot = None;
                }
            }
        });
        sync_registration(r, fd)
    });
    match wake? {
        Wake::Ready(readiness) => Ok(readiness),
        Wake::Timeout => Err(Error::new(ErrorKind::TimedOut, "timed out waiting for I/O")),
        Wake::Cancelled => Err(Error::new(ErrorKind::Closed, "wait cancelled")),
        Wake::Closed => Err(Error::new(ErrorKind::Closed, "descriptor closed")),
        Wake::Resumed | Wake::Done => Err(invalid("unexpected wake-up")),
    }
}

impl Waiter {
    /// [`Waiter::is_pending`] for callers that already hold the scheduler.
    fn is_pending_unlocked(&self, s: &Scheduler) -> bool {
        s.coroutines
            .get(&self.id)
            .is_some_and(|c| c.waiting && c.wait_seq == self.seq)
    }
}

/// Wakes every coroutine waiting on `fd` with [`Wake::Closed`] and drops the registration.
/// Call before closing a descriptor that coroutines may be waiting on.
pub fn release_fd(fd: RawFd) {
    let Some(entry) = with(|s| s.fd_waits.remove(&fd)) else {
        return;
    };
    let _ = with_reactor(|r| {
        let _ = r.remove(entry.token);
        for waiter in [entry.reader, entry.writer].into_iter().flatten() {
            waiter.wake_later(r, Wake::Closed);
        }
    });
}

/// Runs `main` as a coroutine on the thread's global event loop and returns when the loop
/// has no work left. Fails if coroutines remain blocked with nothing left that could wake
/// them (a deadlock).
pub fn run(main: impl FnOnce() + 'static) -> Result<()> {
    if in_coroutine() {
        return Err(invalid("run cannot be nested inside a coroutine"));
    }
    let started = Rc::new(Cell::new(None));
    let s = Rc::clone(&started);
    current::with(move |r| r.defer(move |r| s.set(Some(spawn_in(r, main)))))?;
    current::run_global()?;
    if let Some(Err(err)) = started.take() {
        return Err(err);
    }
    let stuck = count();
    if stuck > 0 {
        return Err(invalid(format!(
            "deadlock: {stuck} coroutine(s) still waiting with nothing left to wake them"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn spawn_runs_until_first_suspend() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let l = Rc::clone(&log);
        let id = spawn(move || {
            l.borrow_mut().push(1);
            suspend().unwrap();
            l.borrow_mut().push(3);
        })
        .unwrap();
        log.borrow_mut().push(2);
        assert!(exists(id));
        resume(id).unwrap();
        assert_eq!(*log.borrow(), [1, 2, 3]);
        assert!(!exists(id));
        assert!(resume(id).is_err());
        assert!(suspend().is_err(), "main context cannot suspend");
    }

    #[test]
    fn nested_coroutines_return_to_their_resumer() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let l = Rc::clone(&log);
        let outer = spawn(move || {
            let me = current().unwrap();
            let l2 = Rc::clone(&l);
            let inner = spawn(move || {
                l2.borrow_mut().push("inner start");
                assert_eq!(origin(current().unwrap()), Some(me));
                suspend().unwrap();
                l2.borrow_mut().push("inner end");
            })
            .unwrap();
            l.borrow_mut().push("outer after spawn");
            assert!(resume(me).is_err(), "cannot resume a running coroutine");
            resume(inner).unwrap();
            l.borrow_mut().push("outer end");
        })
        .unwrap();
        assert!(!exists(outer));
        assert_eq!(
            *log.borrow(),
            ["inner start", "outer after spawn", "inner end", "outer end"]
        );
    }

    #[test]
    fn panics_propagate_to_the_resumer() {
        let result = std::panic::catch_unwind(|| {
            spawn(|| panic!("inside")).unwrap();
        });
        assert!(result.is_err());
        assert!(current().is_none());
        // The scheduler is still usable.
        spawn(|| {}).unwrap();
    }

    #[test]
    fn locals_and_hooks() {
        let switches = Rc::new(Cell::new(0));
        let s = Rc::clone(&switches);
        set_switch_hook(Some(Rc::new(move |_, _| s.set(s.get() + 1))));
        let id = spawn(|| {
            set_local(41u32).unwrap();
            suspend().unwrap();
            assert_eq!(with_local(|v: &mut u32| *v + 1), Some(42));
        })
        .unwrap();
        resume(id).unwrap();
        set_switch_hook(None);
        assert_eq!(switches.get(), 4);
        assert_eq!(with_local(|v: &mut u32| *v), None);
    }

    #[test]
    fn many_coroutines_reuse_stacks() {
        let total = Rc::new(Cell::new(0));
        for _ in 0..1000 {
            let t = Rc::clone(&total);
            spawn(move || t.set(t.get() + 1)).unwrap();
        }
        assert_eq!(total.get(), 1000);
        assert_eq!(count(), 0);
    }

    #[test]
    fn run_with_sleep_and_timeouts() {
        let order = Rc::new(RefCell::new(Vec::new()));
        let o = Rc::clone(&order);
        run(move || {
            let o2 = Rc::clone(&o);
            let a = spawn(move || {
                sleep(Duration::from_millis(20)).unwrap();
                o2.borrow_mut().push("slow");
            })
            .unwrap();
            let o3 = Rc::clone(&o);
            spawn(move || {
                sleep(Duration::from_millis(5)).unwrap();
                o3.borrow_mut().push("fast");
            })
            .unwrap();
            yield_now().unwrap();
            o.borrow_mut().push("main");
            let w = Waiter::new().unwrap();
            assert_eq!(
                w.wait(Some(Duration::from_millis(1))).unwrap(),
                Wake::Timeout
            );
            let _ = a;
        })
        .unwrap();
        assert_eq!(*order.borrow(), ["main", "fast", "slow"]);
    }

    #[test]
    fn cancel_and_deadlock_detection() {
        run(|| {
            let sleeper = spawn(|| {
                let err = sleep(Duration::from_secs(60)).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::Closed);
            })
            .unwrap();
            with_reactor(|r| r.defer(move |r| assert!(cancel(r, sleeper)))).unwrap();
        })
        .unwrap();

        let err = run(|| {
            Waiter::new().unwrap().wait(None).unwrap();
        })
        .unwrap_err();
        assert!(err.to_string().contains("deadlock"));
        // Clean up the stuck coroutine so later tests on this thread start fresh.
        for id in list() {
            with(|s| s.coroutines.remove(&id));
        }
    }

    #[test]
    fn full_duplex_waits_on_one_descriptor() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        let a = Rc::new(a);
        let got = Rc::new(RefCell::new(Vec::new()));
        let g = Rc::clone(&got);
        run(move || {
            let fd = a.as_raw_fd();
            let reader_sock = Rc::clone(&a);
            spawn(move || {
                wait_fd(fd, Interest::READABLE, Some(Duration::from_secs(5))).unwrap();
                let mut buf = [0u8; 16];
                let n = (&*reader_sock).read(&mut buf).unwrap();
                g.borrow_mut().extend_from_slice(&buf[..n]);
            })
            .unwrap();
            // The same descriptor is writable meanwhile.
            wait_fd(fd, Interest::WRITABLE, Some(Duration::from_secs(5))).unwrap();
            (&*a).write_all(b"to peer").unwrap();
            let mut b = b;
            let mut buf = [0u8; 16];
            let mut tries = 0;
            let n = loop {
                match b.read(&mut buf) {
                    Ok(n) => break n,
                    Err(_) if tries < 100 => {
                        tries += 1;
                        sleep(Duration::from_millis(1)).unwrap();
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            b.write_all(&buf[..n]).unwrap();
        })
        .unwrap();
        assert_eq!(*got.borrow(), b"to peer");
    }
}
