//! Raw declarations of the C shim. Pointers are opaque: `ed` is a `zend_execute_data*`, `zv`
//! and `rv` are `zval*`.

use std::ffi::{c_char, c_int, c_long, c_void};

/// A PHP-callable entry point: `(execute_data, return_value)`.
pub type Handler = unsafe extern "C" fn(*mut c_void, *mut c_void);
pub type Dtor = unsafe extern "C" fn(*mut c_void);
pub type EachFn =
    unsafe extern "C" fn(*mut c_void, *const c_char, usize, c_int, c_long, *mut c_void);

// SAFETY (all declarations): implemented in `shim/shim.c`, which links into this crate.
unsafe extern "C" {
    pub fn weft_throw(message: *const c_char, code: c_long);
    pub fn weft_exception_pending() -> c_int;
    pub fn weft_exception_stash();
    pub fn weft_exception_report();
    pub fn weft_exception_stashed() -> c_int;
    pub fn weft_exception_rethrow();

    pub fn weft_this_ptr(ed: *mut c_void) -> *mut c_void;
    pub fn weft_this_set(ed: *mut c_void, ptr: *mut c_void, dtor: Dtor);
    pub fn weft_class_new(name: *const c_char) -> *mut c_void;
    pub fn weft_class_method(
        class: *mut c_void,
        name: *const c_char,
        handler: Handler,
        required: u32,
        total: u32,
        variadic: c_int,
        is_static: c_int,
    ) -> c_int;
    pub fn weft_class_register(class: *mut c_void) -> c_int;
    pub fn weft_object_init(class: *mut c_void, rv: *mut c_void, ptr: *mut c_void, dtor: Dtor);
    pub fn weft_register_function(
        name: *const c_char,
        handler: Handler,
        required: u32,
        total: u32,
        variadic: c_int,
    ) -> c_int;

    pub fn weft_argc(ed: *mut c_void) -> u32;
    pub fn weft_arg(ed: *mut c_void, i: u32) -> *mut c_void;
    pub fn weft_wrong_argc(ed: *mut c_void, min: u32, max: u32);
    pub fn weft_zval_type(zv: *mut c_void) -> c_int;
    pub fn weft_zval_long(zv: *mut c_void) -> c_long;
    pub fn weft_zval_double(zv: *mut c_void) -> f64;
    pub fn weft_zval_bool(zv: *mut c_void) -> c_int;
    pub fn weft_zval_str(zv: *mut c_void, len: *mut usize) -> *const c_char;
    pub fn weft_zval_box(zv: *mut c_void) -> *mut c_void;
    pub fn weft_zval_release(zv: *mut c_void);
    pub fn weft_ret_copy(rv: *mut c_void, src: *mut c_void);
    pub fn weft_zval_size() -> usize;
    pub fn weft_zval_copy_to(dst: *mut c_void, src: *mut c_void);
    pub fn weft_zval_dtor(zv: *mut c_void);

    pub fn weft_ret_null(rv: *mut c_void);
    pub fn weft_ret_bool(rv: *mut c_void, v: c_int);
    pub fn weft_ret_long(rv: *mut c_void, v: c_long);
    pub fn weft_ret_str(rv: *mut c_void, p: *const c_char, n: usize);
    pub fn weft_ret_this(rv: *mut c_void, ed: *mut c_void);

    pub fn weft_arr_init(zv: *mut c_void);
    pub fn weft_arr_set_str(
        arr: *mut c_void,
        key: *const c_char,
        klen: usize,
        v: *const c_char,
        vlen: usize,
    );
    pub fn weft_arr_set_long(arr: *mut c_void, key: *const c_char, klen: usize, v: c_long);
    pub fn weft_arr_child(arr: *mut c_void, key: *const c_char, klen: usize) -> *mut c_void;
    pub fn weft_arr_each(zv: *mut c_void, cb: EachFn, ctx: *mut c_void);

    pub fn weft_callable_new(zv: *mut c_void) -> *mut c_void;
    pub fn weft_callable_free(c: *mut c_void);
    pub fn weft_callable_call(
        c: *mut c_void,
        argc: u32,
        argv: *mut c_void,
        ret: *mut c_void,
    ) -> c_int;

    pub fn weft_vm_new() -> *mut c_void;
    pub fn weft_vm_blank() -> *mut c_void;
    pub fn weft_vm_save(vm: *mut c_void);
    pub fn weft_vm_restore(vm: *mut c_void);
    pub fn weft_vm_free(vm: *mut c_void);
    pub fn weft_vm_stack_destroy();
    pub fn weft_vm_set_stack(base: *mut c_void, limit: *mut c_void);
}
