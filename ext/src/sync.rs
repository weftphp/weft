//! `Weft\Channel`, `Weft\Mutex` and `Weft\WaitGroup`.

use std::cell::RefCell;
use std::sync::OnceLock;

use weft::coroutine::sync::{Channel, Mutex, MutexGuard, WaitGroup};

use crate::php::{Boxed, Class, ClassBuilder, PhpResult, fail, handler};

static CHANNEL: OnceLock<Class> = OnceLock::new();

fn in_coroutine() -> PhpResult {
    if weft::coroutine::in_coroutine() {
        Ok(())
    } else {
        fail("this operation must run inside a coroutine")
    }
}

// ----- Channel -----

handler!(fn channel_new(args, ret) {
    args.check(0, 1)?;
    let capacity = args.long(0, 1).max(1) as usize;
    args.set_this(Channel::<Boxed>::new(capacity));
    ret.null();
    Ok(())
});

handler!(fn channel_push(args, ret) {
    args.check(1, 2)?;
    in_coroutine()?;
    let ch = args.this::<Channel<Boxed>>()?;
    let value = args.require(0)?.to_owned();
    ret.bool(ch.push(value, args.timeout(1)).is_ok());
    Ok(())
});

handler!(fn channel_pop(args, ret) {
    args.check(0, 1)?;
    in_coroutine()?;
    let ch = args.this::<Channel<Boxed>>()?;
    match ch.pop(args.timeout(0)) {
        Ok(v) => ret.value(&v),
        Err(_) => ret.null(),
    }
    Ok(())
});

handler!(fn channel_close(args, ret) {
    args.check(0, 0)?;
    in_coroutine()?;
    args.this::<Channel<Boxed>>()?.close()?;
    ret.null();
    Ok(())
});

handler!(fn channel_is_closed(args, ret) {
    args.check(0, 0)?;
    ret.bool(args.this::<Channel<Boxed>>()?.is_closed());
    Ok(())
});

handler!(fn channel_length(args, ret) {
    args.check(0, 0)?;
    ret.long(args.this::<Channel<Boxed>>()?.len() as i64);
    Ok(())
});

handler!(fn channel_capacity(args, ret) {
    args.check(0, 0)?;
    ret.long(args.this::<Channel<Boxed>>()?.capacity() as i64);
    Ok(())
});

// ----- Mutex -----

struct PhpMutex {
    mutex: Mutex,
    held: RefCell<Option<MutexGuard>>,
}

handler!(fn mutex_new(args, ret) {
    args.check(0, 0)?;
    args.set_this(PhpMutex { mutex: Mutex::new(), held: RefCell::new(None) });
    ret.null();
    Ok(())
});

handler!(fn mutex_lock(args, ret) {
    args.check(0, 1)?;
    in_coroutine()?;
    let m = args.this::<PhpMutex>()?;
    match m.mutex.lock(args.timeout(0)) {
        Ok(guard) => {
            *m.held.borrow_mut() = Some(guard);
            ret.bool(true);
        }
        Err(_) => ret.bool(false),
    }
    Ok(())
});

handler!(fn mutex_try_lock(args, ret) {
    args.check(0, 0)?;
    let m = args.this::<PhpMutex>()?;
    match m.mutex.try_lock() {
        Some(guard) => {
            *m.held.borrow_mut() = Some(guard);
            ret.bool(true);
        }
        None => ret.bool(false),
    }
    Ok(())
});

handler!(fn mutex_unlock(args, ret) {
    args.check(0, 0)?;
    let m = args.this::<PhpMutex>()?;
    let guard = m.held.borrow_mut().take();
    if guard.is_none() {
        return fail("the mutex is not locked");
    }
    drop(guard);
    ret.null();
    Ok(())
});

handler!(fn mutex_is_locked(args, ret) {
    args.check(0, 0)?;
    ret.bool(args.this::<PhpMutex>()?.mutex.is_locked());
    Ok(())
});

// ----- WaitGroup -----

handler!(fn wg_new(args, ret) {
    args.check(0, 0)?;
    args.set_this(WaitGroup::new());
    ret.null();
    Ok(())
});

handler!(fn wg_add(args, ret) {
    args.check(0, 1)?;
    args.this::<WaitGroup>()?.add(args.long(0, 1).max(0) as usize);
    ret.null();
    Ok(())
});

handler!(fn wg_done(args, ret) {
    args.check(0, 0)?;
    args.this::<WaitGroup>()?.done()?;
    ret.null();
    Ok(())
});

handler!(fn wg_wait(args, ret) {
    args.check(0, 1)?;
    in_coroutine()?;
    ret.bool(args.this::<WaitGroup>()?.wait(args.timeout(0)).is_ok());
    Ok(())
});

handler!(fn wg_count(args, ret) {
    args.check(0, 0)?;
    ret.long(args.this::<WaitGroup>()?.count() as i64);
    Ok(())
});

pub fn register() -> bool {
    let channel = ClassBuilder::new("Weft\\Channel")
        .method("__construct", channel_new, 0, 1)
        .method("push", channel_push, 1, 2)
        .method("pop", channel_pop, 0, 1)
        .method("close", channel_close, 0, 0)
        .method("isClosed", channel_is_closed, 0, 0)
        .method("length", channel_length, 0, 0)
        .method("capacity", channel_capacity, 0, 0)
        .register();
    let mutex = ClassBuilder::new("Weft\\Mutex")
        .method("__construct", mutex_new, 0, 0)
        .method("lock", mutex_lock, 0, 1)
        .method("tryLock", mutex_try_lock, 0, 0)
        .method("unlock", mutex_unlock, 0, 0)
        .method("isLocked", mutex_is_locked, 0, 0)
        .register();
    let wg = ClassBuilder::new("Weft\\WaitGroup")
        .method("__construct", wg_new, 0, 0)
        .method("add", wg_add, 0, 1)
        .method("done", wg_done, 0, 0)
        .method("wait", wg_wait, 0, 1)
        .method("count", wg_count, 0, 0)
        .register();
    if let Some(c) = channel {
        let _ = CHANNEL.set(c);
    }
    channel.is_some() && mutex.is_some() && wg.is_some()
}
