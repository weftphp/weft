//! The weft PHP extension: PHP bindings for the weft engine.
//!
//! - `shim/shim.c` is the only C: Zend macros, table construction and executor-state swaps.
//! - [`php`] wraps the shim in a small safe API; [`vm`] swaps PHP state between coroutines.
//! - The remaining modules register the PHP-visible functions and classes.

mod coro;
mod http;
mod php;
mod socket;
mod sync;
mod sys;
mod timer;
mod vm;

unsafe extern "C" {
    fn weft_module() -> *mut std::ffi::c_void;
}

/// Entry point PHP looks up when loading the shared object.
#[unsafe(no_mangle)]
pub extern "C" fn get_module() -> *mut std::ffi::c_void {
    // SAFETY: returns the address of the static module entry defined in the shim.
    unsafe { weft_module() }
}

/// Called by the shim during module initialisation.
#[unsafe(no_mangle)]
pub extern "C" fn weft_rs_minit() -> i32 {
    let ok = std::panic::catch_unwind(|| {
        coro::register()
            && sync::register()
            && timer::register()
            && http::register()
            && socket::register()
    })
    .unwrap_or(false);
    if ok { 0 } else { -1 }
}

/// Called by the shim at the end of every request.
#[unsafe(no_mangle)]
pub extern "C" fn weft_rs_rshutdown() {
    let _ = std::panic::catch_unwind(vm::uninstall);
}
