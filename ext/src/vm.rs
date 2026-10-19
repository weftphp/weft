//! Per-coroutine PHP executor state.
//!
//! Every coroutine runs its PHP code on its own VM stack. The engine's switch hook swaps the
//! executor globals (VM stack, current frame, pending exception, stack-overflow bounds)
//! whenever control moves between coroutines.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::rc::Rc;

use weft::coroutine::{self, CoId};

use crate::sys;

/// Machine stack given to each coroutine. PHP-to-PHP calls do not recurse on it, but internal
/// functions that call back into PHP (sorting callbacks, `array_map`) do.
pub const STACK_SIZE: usize = 1024 * 1024;

/// Headroom kept below the PHP recursion limit for native frames.
const RESERVE: usize = 128 * 1024;

struct State(*mut c_void);

thread_local! {
    static STATES: RefCell<HashMap<u64, State>> = RefCell::new(HashMap::new());
    /// The coroutine whose final switch is in flight; its state is freed, not saved.
    static RETIRING: RefCell<Option<u64>> = const { RefCell::new(None) };
}

/// Key of the thread's main context.
const MAIN: u64 = 0;

fn key(id: Option<CoId>) -> u64 {
    id.map_or(MAIN, |c| c.as_u64())
}

/// Installs the switch hook and sizes coroutine stacks. Idempotent.
pub fn install() {
    coroutine::runtime::set_stack_size(STACK_SIZE);
    coroutine::runtime::set_switch_hook(Some(Rc::new(switch)));
}

/// Removes the hook and frees all saved states.
pub fn uninstall() {
    coroutine::runtime::set_switch_hook(None);
    STATES.with(|s| {
        let Ok(mut states) = s.try_borrow_mut() else {
            return;
        };
        for (_, st) in states.drain() {
            // SAFETY: each state was created by the shim and is released once.
            unsafe { sys::weft_vm_free(st.0) };
        }
    });
}

fn switch(from: Option<CoId>, to: Option<CoId>) {
    let (fk, tk) = (key(from), key(to));
    let retiring = RETIRING.with(|r| r.borrow_mut().take()) == Some(fk) && fk != MAIN;
    // Allocate before borrowing: PHP raises a fatal error (which unwinds past Rust frames)
    // when it is out of memory, and must not find the map borrowed.
    let fresh = STATES.with(|s| !s.borrow().contains_key(&tk)).then(|| {
        // SAFETY: allocates a fresh VM stack for a coroutine that has not run yet.
        State(unsafe { sys::weft_vm_new() })
    });
    STATES.with(|states| {
        let mut states = states.borrow_mut();
        if retiring {
            if let Some(st) = states.remove(&fk) {
                // SAFETY: the coroutine is gone; nothing refers to its state anymore.
                unsafe { sys::weft_vm_free(st.0) };
            }
        } else {
            let st = states.entry(fk).or_insert_with(|| {
                // SAFETY: allocates a blank state that the save below fills.
                State(unsafe { sys::weft_vm_blank() })
            });
            // SAFETY: `st` is a shim-allocated state; this runs on the PHP thread.
            unsafe { sys::weft_vm_save(st.0) };
        }
        if let Some(st) = fresh {
            states.insert(tk, st);
        }
        if let Some(st) = states.get(&tk) {
            // SAFETY: as above.
            unsafe { sys::weft_vm_restore(st.0) };
        }
    });
}

/// Called at the top of a coroutine: tells PHP where this coroutine's machine stack ends.
pub fn enter_coroutine() {
    let marker = 0u8;
    let base = &raw const marker as usize;
    let limit = base.saturating_sub(STACK_SIZE - RESERVE);
    // SAFETY: runs on the coroutine with its own state loaded.
    unsafe { sys::weft_vm_set_stack(base as *mut c_void, limit as *mut c_void) };
}

/// Called at the bottom of a coroutine, before it finishes: frees its PHP stack and marks its
/// state for release at the final switch.
pub fn leave_coroutine(id: CoId) {
    // SAFETY: the coroutine's own VM stack is loaded and no PHP frames remain on it.
    unsafe { sys::weft_vm_stack_destroy() };
    RETIRING.with(|r| *r.borrow_mut() = Some(id.as_u64()));
}
