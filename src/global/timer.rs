//! Timers on the thread's global event loop.

use std::time::Duration;

use crate::core::Result;
use crate::core::timer::TimerId;
use crate::reactor::current;

/// Runs `f` once after `delay`.
pub fn after(delay: Duration, f: impl FnOnce() + 'static) -> Result<TimerId> {
    current::with(|r| r.after(delay, move |r| current::scope(r, f)))
}

/// Runs `f` every `period` until [`clear`]ed (also from inside `f`).
pub fn tick(period: Duration, mut f: impl FnMut(TimerId) + 'static) -> Result<TimerId> {
    current::with(|r| r.every(period, move |r, id| current::scope(r, || f(id))))?
}

/// Cancels a timer. Returns whether it was still scheduled.
pub fn clear(id: TimerId) -> bool {
    current::with(|r| r.cancel_timer(id)).unwrap_or(false)
}

pub fn exists(id: TimerId) -> bool {
    current::with(|r| r.timer_exists(id)).unwrap_or(false)
}

/// Ids of every scheduled timer.
pub fn list() -> Vec<TimerId> {
    current::with(|r| r.timer_ids()).unwrap_or_default()
}

/// Cancels every timer.
pub fn clear_all() {
    let _ = current::with(|r| {
        for id in r.timer_ids() {
            r.cancel_timer(id);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::event;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    #[test]
    fn nested_timers_on_the_global_loop() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let l = Rc::clone(&log);
        after(Duration::from_millis(5), move || {
            l.borrow_mut().push("outer");
            let l2 = Rc::clone(&l);
            after(Duration::from_millis(1), move || {
                l2.borrow_mut().push("inner")
            })
            .unwrap();
        })
        .unwrap();
        let ticks = Rc::new(Cell::new(0));
        let t = Rc::clone(&ticks);
        let id = tick(Duration::from_millis(2), move |id| {
            t.set(t.get() + 1);
            if t.get() == 3 {
                assert!(clear(id));
            }
        })
        .unwrap();
        assert!(exists(id));
        let doomed = after(Duration::from_secs(60), || panic!("cancelled timer ran")).unwrap();
        assert!(clear(doomed));
        event::wait().unwrap();
        assert_eq!(*log.borrow(), ["outer", "inner"]);
        assert_eq!(ticks.get(), 3);
        assert!(list().is_empty());
    }
}
