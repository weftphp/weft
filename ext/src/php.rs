//! Safe-ish wrappers over the shim: arguments, return values, owned values, callables, and
//! registration of functions and classes.

use std::ffi::{CString, c_char, c_int, c_long, c_void};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::sys;

/// Why a PHP-visible function failed.
#[derive(Debug)]
pub enum PhpError {
    /// An exception is already pending on the PHP side (for example from a callback).
    Thrown,
    /// To be thrown as `Weft\Exception`.
    Message(String),
}

impl<E: fmt::Display> From<E> for PhpError {
    fn from(e: E) -> Self {
        PhpError::Message(e.to_string())
    }
}

pub type PhpResult<T = ()> = Result<T, PhpError>;

/// Shorthand for building a [`PhpError::Message`].
pub fn fail<T>(msg: impl Into<String>) -> PhpResult<T> {
    Err(PhpError::Message(msg.into()))
}

/// Throws `Weft\Exception` with `msg`.
pub fn throw(msg: &str) {
    let c = CString::new(msg.replace('\0', " ")).unwrap_or_default();
    // SAFETY: `c` is NUL-terminated and outlives the call, which copies it.
    unsafe { sys::weft_throw(c.as_ptr(), 0) };
}

/// Runs a handler body, turning errors and panics into PHP exceptions.
pub fn guard(body: impl FnOnce() -> PhpResult) {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) | Ok(Err(PhpError::Thrown)) => {}
        Ok(Err(PhpError::Message(m))) => throw(&m),
        Err(_) => throw("internal error in the weft extension"),
    }
}

/// Declares a PHP-callable `extern "C"` handler.
///
/// ```ignore
/// handler!(pub fn name(args, ret) { ... Ok(()) });
/// ```
macro_rules! handler {
    ($vis:vis fn $name:ident($args:ident, $ret:ident) $body:block) => {
        $vis unsafe extern "C" fn $name(
            ed: *mut ::std::ffi::c_void,
            rv: *mut ::std::ffi::c_void,
        ) {
            let $args = $crate::php::Args::new(ed);
            let $ret = $crate::php::Ret::new(rv);
            $crate::php::guard(|| -> $crate::php::PhpResult { $body });
        }
    };
}
pub(crate) use handler;

/// The arguments of the running call.
#[derive(Clone, Copy)]
pub struct Args {
    ed: *mut c_void,
}

impl Args {
    pub fn new(ed: *mut c_void) -> Args {
        Args { ed }
    }

    pub fn len(&self) -> usize {
        // SAFETY: `ed` is the live execute_data of the call being handled.
        unsafe { sys::weft_argc(self.ed) as usize }
    }

    /// Fails with PHP's argument-count error unless `min <= len <= max`.
    pub fn check(&self, min: usize, max: usize) -> PhpResult {
        let n = self.len();
        if n < min || n > max {
            // SAFETY: as above; the shim raises ArgumentCountError.
            unsafe { sys::weft_wrong_argc(self.ed, min as u32, max.min(u32::MAX as usize) as u32) };
            return Err(PhpError::Thrown);
        }
        Ok(())
    }

    pub fn get(&self, i: usize) -> Option<Zval> {
        if i >= self.len() {
            return None;
        }
        // SAFETY: `i` is within the passed argument count.
        Some(Zval(unsafe { sys::weft_arg(self.ed, i as u32) }))
    }

    pub fn require(&self, i: usize) -> PhpResult<Zval> {
        self.get(i)
            .ok_or(PhpError::Message(format!("missing argument {}", i + 1)))
    }

    pub fn long(&self, i: usize, default: i64) -> i64 {
        self.get(i).map_or(default, |z| z.as_long())
    }

    pub fn double(&self, i: usize, default: f64) -> f64 {
        self.get(i).map_or(default, |z| z.as_f64())
    }

    /// A timeout argument in seconds; negative or absent means "no timeout".
    pub fn timeout(&self, i: usize) -> Option<std::time::Duration> {
        let secs = self.double(i, -1.0);
        (secs >= 0.0).then(|| std::time::Duration::from_secs_f64(secs))
    }

    pub fn string(&self, i: usize) -> PhpResult<Vec<u8>> {
        match self.require(i)?.as_bytes() {
            Some(b) => Ok(b.to_vec()),
            None => fail(format!("argument {} must be a string", i + 1)),
        }
    }

    pub fn text(&self, i: usize) -> PhpResult<String> {
        Ok(String::from_utf8_lossy(&self.string(i)?).into_owned())
    }

    /// The Rust value behind `$this`.
    pub fn this<'a, T>(&self) -> PhpResult<&'a T> {
        // SAFETY: `ed` is live; the pointer was stored by `set_this::<T>` for this class.
        let p = unsafe { sys::weft_this_ptr(self.ed) };
        if p.is_null() {
            return fail("object is not initialised");
        }
        // SAFETY: only classes created with `Class::new_object::<T>` / `set_this::<T>` reach
        // their own methods, and the box lives until the PHP object is freed.
        Ok(unsafe { &*p.cast::<T>() })
    }

    /// Stores `value` as the state behind `$this` (for constructors).
    pub fn set_this<T: 'static>(&self, value: T) {
        let p = Box::into_raw(Box::new(value));
        // SAFETY: `ed` is live; the dtor matches the boxed type.
        unsafe { sys::weft_this_set(self.ed, p.cast(), drop_box::<T>) };
    }

    pub fn this_zval(&self, ret: Ret) {
        // SAFETY: both pointers are live for the call.
        unsafe { sys::weft_ret_this(ret.0, self.ed) };
    }
}

unsafe extern "C" fn drop_box<T>(p: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `p` came from `Box::into_raw(Box<T>)` and is released exactly once.
        drop(unsafe { Box::from_raw(p.cast::<T>()) });
    }));
}

type EachCallback<'a> = &'a mut dyn FnMut(Option<&[u8]>, i64, Zval);

/// A borrowed PHP value.
#[derive(Clone, Copy)]
pub struct Zval(pub *mut c_void);

impl Zval {
    pub fn as_long(&self) -> i64 {
        // SAFETY: as above.
        unsafe { sys::weft_zval_long(self.0) as i64 }
    }

    pub fn as_f64(&self) -> f64 {
        // SAFETY: as above.
        unsafe { sys::weft_zval_double(self.0) }
    }

    pub fn as_bool(&self) -> bool {
        // SAFETY: as above.
        unsafe { sys::weft_zval_bool(self.0) != 0 }
    }

    /// The bytes of a PHP string; `None` for other types.
    pub fn as_bytes<'a>(&self) -> Option<&'a [u8]> {
        let mut len = 0usize;
        // SAFETY: as above; the returned pointer is valid for `len` bytes while the zval lives.
        let p = unsafe { sys::weft_zval_str(self.0, &mut len) };
        if p.is_null() {
            return None;
        }
        // SAFETY: `p` points at `len` initialised bytes owned by the PHP string.
        Some(unsafe { std::slice::from_raw_parts(p.cast::<u8>(), len) })
    }

    /// Takes a counted reference that outlives the call.
    pub fn to_owned(self) -> Boxed {
        // SAFETY: as above; the shim adds a reference and boxes the zval.
        Boxed(unsafe { sys::weft_zval_box(self.0) })
    }

    /// Calls `f` for every element of a PHP array: `(string key | None, index, value)`.
    pub fn each(&self, mut f: impl FnMut(Option<&[u8]>, i64, Zval)) {
        unsafe extern "C" fn trampoline(
            ctx: *mut c_void,
            key: *const c_char,
            klen: usize,
            is_str: c_int,
            idx: c_long,
            val: *mut c_void,
        ) {
            // SAFETY: `ctx` is the `&mut dyn FnMut` passed below, alive for the whole call.
            let f = unsafe { &mut *ctx.cast::<EachCallback<'_>>() };
            let key = (is_str != 0).then(|| {
                // SAFETY: the key string is valid for `klen` bytes during the callback.
                unsafe { std::slice::from_raw_parts(key.cast::<u8>(), klen) }
            });
            f(key, idx, Zval(val));
        }
        let mut dynf: EachCallback<'_> = &mut f;
        // SAFETY: `trampoline` only dereferences `ctx` during this call.
        unsafe {
            sys::weft_arr_each(self.0, trampoline, (&raw mut dynf).cast());
        }
    }
}

/// A PHP value owned by Rust (one counted reference). Dropping releases it.
pub struct Boxed(*mut c_void);

impl Drop for Boxed {
    fn drop(&mut self) {
        // SAFETY: created by `weft_zval_box`, released once.
        unsafe { sys::weft_zval_release(self.0) };
    }
}

/// A PHP callable kept alive across calls.
pub struct Callable(*mut c_void);

impl Callable {
    pub fn new(z: Zval) -> PhpResult<Callable> {
        // SAFETY: `z` is live; the shim validates and retains the callable.
        let p = unsafe { sys::weft_callable_new(z.0) };
        if p.is_null() {
            return fail("argument is not a valid callback");
        }
        Ok(Callable(p))
    }

    /// Calls with `args`; returns whether the call ran. PHP exceptions stay pending in the
    /// engine for the caller to deal with.
    pub fn call(&self, args: &[Boxed]) -> bool {
        self.call_ret(args).is_some()
    }

    /// Like [`call`](Self::call): `None` if the call did not run, else its result (if any).
    pub fn call_ret(&self, args: &[Boxed]) -> Option<Option<Boxed>> {
        // SAFETY: querying a constant.
        let size = unsafe { sys::weft_zval_size() };
        // u64 slots keep the zvals 8-byte aligned.
        let mut buf = vec![0u64; (size / 8) * (args.len() + 1)];
        let base = buf.as_mut_ptr().cast::<u8>();
        for (i, a) in args.iter().enumerate() {
            // SAFETY: slot `i` lies inside `buf`; the source box is live.
            unsafe { sys::weft_zval_copy_to(base.add(i * size).cast(), a.0) };
        }
        // SAFETY: the last slot of `buf` is scratch space for the return value.
        let ret = unsafe { base.add(args.len() * size) }.cast::<c_void>();
        // SAFETY: `base` holds `args.len()` initialised zvals followed by the return slot.
        let ok =
            unsafe { sys::weft_callable_call(self.0, args.len() as u32, base.cast(), ret) } == 0;
        // SAFETY: each argument slot was filled above; the return slot is UNDEF or a value.
        unsafe {
            for i in 0..args.len() {
                sys::weft_zval_dtor(base.add(i * size).cast());
            }
            let kind = sys::weft_zval_type(ret);
            let out = (ok && kind != 0).then(|| Boxed(sys::weft_zval_box(ret)));
            if kind != 0 {
                sys::weft_zval_dtor(ret);
            }
            ok.then_some(out)
        }
    }
}

impl Drop for Callable {
    fn drop(&mut self) {
        // SAFETY: created by `weft_callable_new`, released once.
        unsafe { sys::weft_callable_free(self.0) };
    }
}

/// Whether a PHP exception is pending.
pub fn exception_pending() -> bool {
    // SAFETY: reads engine state on the PHP thread.
    unsafe { sys::weft_exception_pending() != 0 }
}

/// The return value slot of the running call.
#[derive(Clone, Copy)]
pub struct Ret(*mut c_void);

impl Ret {
    pub fn new(rv: *mut c_void) -> Ret {
        Ret(rv)
    }

    pub fn null(self) {
        // SAFETY: `rv` is live for the call.
        unsafe { sys::weft_ret_null(self.0) };
    }

    pub fn bool(self, v: bool) {
        // SAFETY: as above.
        unsafe { sys::weft_ret_bool(self.0, v as c_int) };
    }

    pub fn long(self, v: i64) {
        // SAFETY: as above.
        unsafe { sys::weft_ret_long(self.0, v as c_long) };
    }

    pub fn bytes(self, v: &[u8]) {
        // SAFETY: as above; the shim copies the bytes.
        unsafe { sys::weft_ret_str(self.0, v.as_ptr().cast(), v.len()) };
    }

    pub fn str(self, v: &str) {
        self.bytes(v.as_bytes());
    }

    pub fn value(self, v: &Boxed) {
        // SAFETY: as above; adds a reference.
        unsafe { sys::weft_ret_copy(self.0, v.0) };
    }

    /// Returns a new array and gives a builder for it.
    pub fn array(self) -> Array {
        // SAFETY: as above.
        unsafe { sys::weft_arr_init(self.0) };
        Array(self.0)
    }

    /// Creates an instance of `class` that owns `value`.
    pub fn object<T: 'static>(self, class: Class, value: T) {
        let p = Box::into_raw(Box::new(value));
        // SAFETY: as above; the dtor matches the boxed type.
        unsafe { sys::weft_object_init(class.0, self.0, p.cast(), drop_box::<T>) };
    }
}

/// Builder over an array being returned.
#[derive(Clone, Copy)]
pub struct Array(*mut c_void);

impl Array {
    pub fn set_bytes(&self, key: &str, v: &[u8]) {
        // SAFETY: the array is live; the shim copies key and value.
        unsafe {
            sys::weft_arr_set_str(
                self.0,
                key.as_ptr().cast(),
                key.len(),
                v.as_ptr().cast(),
                v.len(),
            )
        };
    }

    pub fn set_long(&self, key: &str, v: i64) {
        // SAFETY: as above.
        unsafe { sys::weft_arr_set_long(self.0, key.as_ptr().cast(), key.len(), v as c_long) };
    }

    /// Adds an empty array under `key` and returns a builder for it.
    pub fn child(&self, key: &str) -> Array {
        // SAFETY: as above; the returned zval lives inside `self`.
        Array(unsafe { sys::weft_arr_child(self.0, key.as_ptr().cast(), key.len()) })
    }
}

/// A registered PHP class.
#[derive(Clone, Copy)]
pub struct Class(*mut c_void);

// SAFETY: the pointer names an immutable registry entry created at module init and only read
// afterwards; PHP builds supported here are non-threaded.
unsafe impl Send for Class {}
unsafe impl Sync for Class {}

impl Class {
    /// Creates an instance that owns `value` and returns a counted reference to it.
    pub fn make_object<T: 'static>(self, value: T) -> Boxed {
        let p = Box::into_raw(Box::new(value));
        // SAFETY: querying a constant.
        let size = unsafe { sys::weft_zval_size() };
        let mut slot = vec![0u64; size / 8];
        let zv = slot.as_mut_ptr().cast::<c_void>();
        // SAFETY: `zv` is a zeroed zval-sized buffer; the dtor matches the boxed type. The
        // box takes its own reference, so the temporary is released afterwards.
        unsafe {
            sys::weft_object_init(self.0, zv, p.cast(), drop_box::<T>);
            let boxed = Boxed(sys::weft_zval_box(zv));
            sys::weft_zval_dtor(zv);
            boxed
        }
    }
}

pub struct ClassBuilder(*mut c_void);

impl ClassBuilder {
    pub fn new(name: &str) -> ClassBuilder {
        let c = CString::new(name).unwrap_or_default();
        // SAFETY: the shim copies the name.
        ClassBuilder(unsafe { sys::weft_class_new(c.as_ptr()) })
    }

    /// Adds a public method taking between `min` and `max` arguments (`usize::MAX` = variadic).
    pub fn method(self, name: &str, h: sys::Handler, min: usize, max: usize) -> Self {
        self.add(name, h, min, max, false)
    }

    pub fn static_method(self, name: &str, h: sys::Handler, min: usize, max: usize) -> Self {
        self.add(name, h, min, max, true)
    }

    fn add(self, name: &str, h: sys::Handler, min: usize, max: usize, is_static: bool) -> Self {
        let c = CString::new(name).unwrap_or_default();
        let variadic = max == usize::MAX;
        let total = if variadic { min + 1 } else { max };
        // SAFETY: the shim copies the name and builds its own arginfo.
        unsafe {
            sys::weft_class_method(
                self.0,
                c.as_ptr(),
                h,
                min as u32,
                total as u32,
                variadic as c_int,
                is_static as c_int,
            );
        }
        self
    }

    pub fn register(self) -> Option<Class> {
        // SAFETY: called during module init with a builder created above.
        (unsafe { sys::weft_class_register(self.0) } == 0).then_some(Class(self.0))
    }
}

/// Registers a global function (`name` may contain a namespace).
pub fn register_function(name: &str, h: sys::Handler, min: usize, max: usize) -> bool {
    let c = CString::new(name).unwrap_or_default();
    let variadic = max == usize::MAX;
    let total = if variadic { min + 1 } else { max };
    // SAFETY: called during module init; the shim copies the name.
    unsafe {
        sys::weft_register_function(c.as_ptr(), h, min as u32, total as u32, variadic as c_int) == 0
    }
}
