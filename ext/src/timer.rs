//! `Weft\after`, `Weft\tick` and `Weft\clear`. Each firing runs its callback in a new
//! coroutine.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use weft::core::timer::TimerId;
use weft::coroutine;

use crate::coro;
use crate::php::{Callable, PhpResult, fail, handler, register_function};

/// Recurring timers do not keep `run` alive by themselves: once no coroutine is left they are
/// cancelled, while one-shot timers still fire first.
pub fn cancel_idle_ticks() {
    let ticks: Vec<(i64, TimerId)> = TIMERS.with(|t| {
        let mut t = t.borrow_mut();
        let ids: Vec<i64> = t
            .keys()
            .filter(|id| TICKS.with(|k| k.borrow().contains(id)))
            .copied()
            .collect();
        ids.into_iter()
            .filter_map(|id| t.remove(&id).map(|v| (id, v)))
            .collect()
    });
    let _ = coroutine::with_reactor(|r| {
        for (_, timer) in &ticks {
            r.cancel_timer(*timer);
        }
    });
    TICKS.with(|k| k.borrow_mut().clear());
}

thread_local! {
    static TICKS: RefCell<std::collections::HashSet<i64>> = RefCell::new(std::collections::HashSet::new());
    static TIMERS: RefCell<HashMap<i64, TimerId>> = RefCell::new(HashMap::new());
    static NEXT: Cell<i64> = const { Cell::new(1) };
}

fn next_id() -> i64 {
    NEXT.with(|n| {
        let id = n.get();
        n.set(id + 1);
        id
    })
}

fn delay(secs: f64) -> PhpResult<Duration> {
    if !secs.is_finite() || secs < 0.0 {
        return fail("the delay must be a non-negative number of seconds");
    }
    Ok(Duration::from_secs_f64(secs.max(0.001)))
}

/// Cancels every timer; called when `run` returns so none outlives its callbacks' world.
pub fn clear_all() {
    let all: Vec<TimerId> = TIMERS.with(|t| t.borrow_mut().drain().map(|(_, v)| v).collect());
    TICKS.with(|k| k.borrow_mut().clear());
    let _ = coroutine::with_reactor(|r| {
        for id in all {
            r.cancel_timer(id);
        }
    });
}

handler!(fn after(args, ret) {
    args.check(2, 2)?;
    let wait = delay(args.double(0, 0.0))?;
    let callback = Rc::new(Callable::new(args.require(1)?)?);
    let id = next_id();
    let timer = coroutine::with_reactor(|r| {
        r.after(wait, move |r| {
            TIMERS.with(|t| t.borrow_mut().remove(&id));
            let _ = coro::spawn_in(r, callback, Vec::new(), None);
        })
    })?;
    TIMERS.with(|t| t.borrow_mut().insert(id, timer));
    ret.long(id);
    Ok(())
});

handler!(fn tick(args, ret) {
    args.check(2, 2)?;
    let period = delay(args.double(0, 0.0))?;
    let callback = Rc::new(Callable::new(args.require(1)?)?);
    let id = next_id();
    let timer = coroutine::with_reactor(|r| {
        r.every(period, move |r, _| {
            let _ = coro::spawn_in(r, Rc::clone(&callback), Vec::new(), None);
        })
    })??;
    TIMERS.with(|t| t.borrow_mut().insert(id, timer));
    TICKS.with(|k| k.borrow_mut().insert(id));
    ret.long(id);
    Ok(())
});

handler!(fn clear(args, ret) {
    args.check(1, 1)?;
    let id = args.long(0, 0);
    let timer = TIMERS.with(|t| t.borrow_mut().remove(&id));
    TICKS.with(|k| k.borrow_mut().remove(&id));
    let cleared = match timer {
        Some(timer) => coroutine::with_reactor(|r| r.cancel_timer(timer))?,
        None => false,
    };
    ret.bool(cleared);
    Ok(())
});

pub fn register() -> bool {
    register_function("Weft\\after", after, 2, 2)
        && register_function("Weft\\tick", tick, 2, 2)
        && register_function("Weft\\clear", clear, 1, 1)
}
