//! Descriptor watching and loop control on the thread's global event loop.

use std::cell::RefCell;
use std::collections::HashMap;
use std::os::fd::RawFd;
use std::time::Duration;

use crate::core::{Error, ErrorKind, Result};
use crate::reactor::{Interest, Readiness, Token, current};

thread_local! {
    static WATCHED: RefCell<HashMap<RawFd, Token>> = RefCell::new(HashMap::new());
}

/// Calls `f` whenever `fd` is ready for `interest`. Each descriptor can be added once;
/// [`del`] it before closing it.
pub fn add(fd: RawFd, interest: Interest, mut f: impl FnMut(Readiness) + 'static) -> Result<()> {
    if exists(fd) {
        return Err(Error::new(
            ErrorKind::InvalidState,
            format!("descriptor {fd} is already watched"),
        ));
    }
    let token = current::with(|r| {
        r.add(fd, interest, move |r, _, readiness| {
            current::scope(r, || f(readiness))
        })
    })??;
    WATCHED.with(|w| w.borrow_mut().insert(fd, token));
    Ok(())
}

/// Changes what `fd` is watched for.
pub fn set(fd: RawFd, interest: Interest) -> Result<()> {
    let token = token(fd)?;
    current::with(|r| r.set_interest(token, interest))?
}

/// Stops watching `fd`. Returns whether it was watched.
pub fn del(fd: RawFd) -> Result<bool> {
    let Some(token) = WATCHED.with(|w| w.borrow_mut().remove(&fd)) else {
        return Ok(false);
    };
    current::with(|r| r.remove(token))??;
    Ok(true)
}

pub fn exists(fd: RawFd) -> bool {
    WATCHED.with(|w| w.borrow().contains_key(&fd))
}

fn token(fd: RawFd) -> Result<Token> {
    WATCHED
        .with(|w| w.borrow().get(&fd).copied())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                format!("descriptor {fd} is not watched"),
            )
        })
}

/// Runs `f` at the end of the current (or next) loop iteration.
pub fn defer(f: impl FnOnce() + 'static) -> Result<()> {
    current::with(|r| r.defer(move |r| current::scope(r, f)))
}

/// Runs the global loop until nothing is left to wait for, or [`exit`] is called.
pub fn wait() -> Result<()> {
    current::run_global()
}

/// Runs one iteration of the global loop, waiting at most `max_wait` for events.
pub fn dispatch(max_wait: Option<Duration>) -> Result<()> {
    current::run_global_once(max_wait)
}

/// Makes [`wait`] return after the current iteration.
pub fn exit() -> Result<()> {
    current::with(|r| r.stop())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::fd;
    use std::cell::Cell;
    use std::os::fd::{AsFd, AsRawFd};
    use std::rc::Rc;

    #[test]
    fn watch_a_pipe_then_exit() {
        let (r, w) = fd::pipe(true).unwrap();
        let rfd = r.as_raw_fd();
        let got = Rc::new(RefCell::new(Vec::new()));
        let g = Rc::clone(&got);
        let reader = Rc::new(r);
        let rr = Rc::clone(&reader);
        add(rfd, Interest::READABLE, move |_| {
            let mut buf = [0u8; 16];
            let n = fd::read(rr.as_fd(), &mut buf).unwrap();
            g.borrow_mut().extend_from_slice(&buf[..n]);
            del(rfd).unwrap();
            exit().unwrap();
        })
        .unwrap();
        assert!(exists(rfd));
        assert!(add(rfd, Interest::READABLE, |_| {}).is_err());

        let deferred = Rc::new(Cell::new(false));
        let d = Rc::clone(&deferred);
        defer(move || {
            d.set(true);
            fd::write(w.as_fd(), b"ping").unwrap();
        })
        .unwrap();
        wait().unwrap();
        assert!(deferred.get());
        assert_eq!(*got.borrow(), b"ping");
        assert!(!exists(rfd));
        assert!(set(rfd, Interest::WRITABLE).is_err());
    }

    #[test]
    fn coroutines_started_outside_a_loop_park_on_it() {
        let done = Rc::new(Cell::new(false));
        let d = Rc::clone(&done);
        crate::coroutine::spawn(move || {
            crate::coroutine::sleep(Duration::from_millis(5)).unwrap();
            d.set(true);
        })
        .unwrap();
        assert!(!done.get());
        wait().unwrap();
        assert!(done.get());
    }
}
