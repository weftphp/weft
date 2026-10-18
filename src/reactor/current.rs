//! Access to "the" event loop of the current thread, for code that is not handed a
//! `&mut Reactor` (coroutines, embedding layers).
//!
//! Two sources, tried in order:
//!
//! 1. The reactor of the callback currently running, installed with [`scope`] by the code
//!    that received it.
//! 2. The thread's global reactor (created on demand) while it is idle. [`run_global`] runs
//!    it; while it runs, access goes through the scopes its callbacks install.
//!
//! [`with`] lends the reactor to a closure, which must not call [`with`] again (that fails
//! with [`ErrorKind::InvalidState`] rather than aliasing).

use std::cell::{Cell, RefCell};

use super::Reactor;
use crate::core::{Error, ErrorKind, Result};

thread_local! {
    static SCOPED: Cell<*mut Reactor> = const { Cell::new(std::ptr::null_mut()) };
    static LENT: Cell<bool> = const { Cell::new(false) };
    static GLOBAL: RefCell<Option<Box<Reactor>>> = const { RefCell::new(None) };
    static GLOBAL_RUNNING: Cell<bool> = const { Cell::new(false) };
}

fn invalid(msg: &str) -> Error {
    Error::new(ErrorKind::InvalidState, msg)
}

/// Makes `reactor` the current one while `f` runs. Call it from a reactor callback with the
/// `&mut Reactor` the callback received, and do not touch that reference inside `f`.
pub fn scope<R>(reactor: &mut Reactor, f: impl FnOnce() -> R) -> R {
    struct Restore(*mut Reactor, bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            SCOPED.with(|s| s.set(self.0));
            LENT.with(|l| l.set(self.1));
        }
    }
    let previous = SCOPED.with(|s| s.replace(reactor as *mut Reactor));
    let lent = LENT.with(|l| l.replace(false));
    let _restore = Restore(previous, lent);
    f()
}

/// Whether [`with`] would find a reactor.
pub fn available() -> bool {
    if LENT.with(Cell::get) {
        return false;
    }
    !SCOPED.with(Cell::get).is_null() || !GLOBAL_RUNNING.with(Cell::get)
}

/// Lends the current reactor to `f`.
pub fn with<R>(f: impl FnOnce(&mut Reactor) -> R) -> Result<R> {
    if LENT.with(Cell::get) {
        return Err(invalid("the current reactor is already lent out"));
    }
    let scoped = SCOPED.with(Cell::get);
    if !scoped.is_null() {
        LENT.with(|l| l.set(true));
        struct Unlend;
        impl Drop for Unlend {
            fn drop(&mut self) {
                LENT.with(|l| l.set(false));
            }
        }
        let _unlend = Unlend;
        // SAFETY: `scope` installed this pointer from a live `&mut Reactor` whose owner does
        // not use it until `scope` returns, and LENT ensures only one borrow exists at a time.
        return Ok(f(unsafe { &mut *scoped }));
    }
    if GLOBAL_RUNNING.with(Cell::get) {
        return Err(invalid(
            "the global loop is running; use it from its callbacks",
        ));
    }
    GLOBAL.with(|g| -> Result<R> {
        let mut slot = g
            .try_borrow_mut()
            .map_err(|_| invalid("the global reactor is busy"))?;
        if slot.is_none() {
            *slot = Some(Box::new(Reactor::new()?));
        }
        let reactor = slot
            .as_mut()
            .ok_or_else(|| invalid("global reactor missing"))?;
        LENT.with(|l| l.set(true));
        let out = f(reactor);
        LENT.with(|l| l.set(false));
        Ok(out)
    })
}

/// Runs the thread's global reactor until it has no more work or is stopped. Callbacks see
/// it as the current reactor. Returns immediately if it was never created.
pub fn run_global() -> Result<()> {
    if GLOBAL_RUNNING.with(Cell::get) {
        return Err(invalid("the global loop is already running"));
    }
    let Some(mut reactor) = GLOBAL.with(|g| g.borrow_mut().take()) else {
        return Ok(());
    };
    GLOBAL_RUNNING.with(|r| r.set(true));
    let result = reactor.run();
    GLOBAL_RUNNING.with(|r| r.set(false));
    GLOBAL.with(|g| {
        let mut slot = g.borrow_mut();
        if slot.is_none() {
            *slot = Some(reactor);
        }
    });
    result
}

/// Runs one iteration of the global reactor (waiting at most `max_wait`).
pub fn run_global_once(max_wait: Option<std::time::Duration>) -> Result<()> {
    if GLOBAL_RUNNING.with(Cell::get) {
        return Err(invalid("the global loop is already running"));
    }
    let Some(mut reactor) = GLOBAL.with(|g| g.borrow_mut().take()) else {
        return Ok(());
    };
    GLOBAL_RUNNING.with(|r| r.set(true));
    let result = reactor.run_once(max_wait);
    GLOBAL_RUNNING.with(|r| r.set(false));
    GLOBAL.with(|g| *g.borrow_mut() = Some(reactor));
    result
}

/// Whether a [`with`] borrow is active (code inside it must not switch coroutines).
pub fn is_lent() -> bool {
    LENT.with(Cell::get)
}

/// Whether the global reactor is running on this thread.
pub fn global_running() -> bool {
    GLOBAL_RUNNING.with(Cell::get)
}

/// Drops the thread's global reactor (and everything registered on it).
pub fn reset_global() -> Result<()> {
    if GLOBAL_RUNNING.with(Cell::get) {
        return Err(invalid("cannot reset a running loop"));
    }
    GLOBAL.with(|g| g.borrow_mut().take());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn scoped_then_global() {
        let mut local = Reactor::new().unwrap();
        let backend = local.backend_name();
        scope(&mut local, || {
            assert!(available());
            let name = with(|r| r.backend_name()).unwrap();
            assert_eq!(name, backend);
            // Not reentrant.
            let nested = with(|_| with(|_| ()).is_err()).unwrap();
            assert!(nested);
        });

        // Outside any scope the idle global reactor is used, and run later.
        let fired = std::rc::Rc::new(Cell::new(false));
        let f = std::rc::Rc::clone(&fired);
        with(|r| {
            r.after(Duration::from_millis(1), move |r| {
                // Inside the global loop, callbacks reach it through scope.
                scope(r, || {
                    assert!(global_running());
                    assert!(with(|_| ()).is_ok());
                });
                f.set(true);
            });
        })
        .unwrap();
        run_global().unwrap();
        assert!(fired.get());
        reset_global().unwrap();
    }
}
