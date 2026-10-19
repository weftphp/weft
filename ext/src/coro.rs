//! Coroutine functions: `Weft\run`, `Weft\go`, `Weft\sleep` and friends.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use weft::coroutine::{self, CoId};

use crate::php::{
    Boxed, Callable, PhpError, PhpResult, exception_pending, fail, handler, register_function,
};
use crate::{sys, vm};

thread_local! {
    /// Live coroutines by the integer id PHP sees.
    static LIVE: RefCell<HashMap<u64, CoId>> = RefCell::new(HashMap::new());
}

fn lookup(cid: i64) -> Option<CoId> {
    LIVE.with(|l| l.borrow().get(&(cid as u64)).copied())
}

/// Called when a coroutine's callable returns, with whether it ended by throwing.
pub type Finish = Box<dyn FnOnce(bool)>;

/// Runs a PHP callable as the body of a coroutine. With a `finish` hook, an uncaught
/// exception is reported as a warning and handed to the hook instead of being stashed for
/// `run` to rethrow.
fn body(callback: Rc<Callable>, args: Vec<Boxed>, finish: Option<Finish>) {
    vm::enter_coroutine();
    let me = coroutine::current();
    if let Some(me) = me {
        LIVE.with(|l| l.borrow_mut().insert(me.as_u64(), me));
    }
    callback.call(&args);
    let threw = exception_pending();
    if threw {
        // SAFETY: both only touch the pending exception of the loaded executor state.
        unsafe {
            if finish.is_some() {
                sys::weft_exception_report();
            } else {
                sys::weft_exception_stash();
            }
        }
    }
    if let Some(finish) = finish {
        finish(threw);
    }
    // Release PHP values while this coroutine's executor state is still loaded.
    drop(callback);
    drop(args);
    if coroutine::runtime::count() <= 1 {
        crate::timer::cancel_idle_ticks();
    }
    if let Some(me) = me {
        LIVE.with(|l| l.borrow_mut().remove(&me.as_u64()));
        vm::leave_coroutine(me);
    }
}

/// Starts a coroutine from the current context (a coroutine, or a reactor callback via `r`).
pub fn spawn(callback: Rc<Callable>, args: Vec<Boxed>) -> PhpResult<CoId> {
    Ok(coroutine::spawn(move || body(callback, args, None))?)
}

/// Starts a coroutine from inside a reactor callback.
pub fn spawn_in(
    reactor: &mut weft::reactor::Reactor,
    callback: Rc<Callable>,
    args: Vec<Boxed>,
    finish: Option<Finish>,
) -> PhpResult<CoId> {
    Ok(coroutine::runtime::spawn_in(reactor, move || {
        body(callback, args, finish)
    })?)
}

handler!(fn run(args, ret) {
    args.check(1, 1)?;
    if coroutine::in_coroutine() {
        return fail("run() cannot be called from inside a coroutine");
    }
    let callback = Callable::new(args.require(0)?)?;
    vm::install();
    let result = coroutine::run(move || body(Rc::new(callback), Vec::new(), None));
    vm::uninstall();
    crate::timer::clear_all();
    // SAFETY: reads the stash set by finished coroutines.
    if unsafe { sys::weft_exception_stashed() } != 0 {
        // SAFETY: rethrows in the main context, which is current again.
        unsafe { sys::weft_exception_rethrow() };
        return Err(PhpError::Thrown);
    }
    result?;
    ret.null();
    Ok(())
});

handler!(fn go(args, ret) {
    args.check(1, usize::MAX)?;
    if !coroutine::in_coroutine() {
        return fail("go() must be called inside Weft\\run()");
    }
    let callback = Callable::new(args.require(0)?)?;
    let rest = (1..args.len()).filter_map(|i| args.get(i)).map(|z| z.to_owned()).collect();
    let id = spawn(Rc::new(callback), rest)?;
    ret.long(id.as_u64() as i64);
    Ok(())
});

handler!(fn sleep(args, ret) {
    args.check(1, 1)?;
    if !coroutine::in_coroutine() {
        return fail("sleep() must be called inside a coroutine");
    }
    let secs = args.double(0, 0.0).max(0.0);
    coroutine::sleep(Duration::from_secs_f64(secs))?;
    ret.null();
    Ok(())
});

handler!(fn yield_now(args, ret) {
    args.check(0, 0)?;
    if !coroutine::in_coroutine() {
        return fail("pass() must be called inside a coroutine");
    }
    coroutine::yield_now()?;
    ret.null();
    Ok(())
});

handler!(fn cid(args, ret) {
    args.check(0, 0)?;
    ret.long(coroutine::current().map_or(-1, |c| c.as_u64() as i64));
    Ok(())
});

handler!(fn exists(args, ret) {
    args.check(1, 1)?;
    ret.bool(lookup(args.long(0, -1)).is_some_and(coroutine::exists));
    Ok(())
});

handler!(fn count(args, ret) {
    args.check(0, 0)?;
    ret.long(coroutine::runtime::count() as i64);
    Ok(())
});

handler!(fn suspend(args, ret) {
    args.check(0, 0)?;
    if !coroutine::in_coroutine() {
        return fail("suspend() must be called inside a coroutine");
    }
    coroutine::suspend()?;
    ret.null();
    Ok(())
});

handler!(fn resume(args, ret) {
    args.check(1, 1)?;
    match lookup(args.long(0, -1)) {
        Some(id) => {
            coroutine::resume(id)?;
            ret.bool(true);
        }
        None => ret.bool(false),
    }
    Ok(())
});

pub fn register() -> bool {
    register_function("Weft\\run", run, 1, 1)
        && register_function("Weft\\go", go, 1, usize::MAX)
        && register_function("Weft\\sleep", sleep, 1, 1)
        && register_function("Weft\\pass", yield_now, 0, 0)
        && register_function("Weft\\cid", cid, 0, 0)
        && register_function("Weft\\exists", exists, 1, 1)
        && register_function("Weft\\count", count, 0, 0)
        && register_function("Weft\\suspend", suspend, 0, 0)
        && register_function("Weft\\resume", resume, 1, 1)
}
