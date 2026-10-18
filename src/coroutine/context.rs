//! Machine-level context switching: separate stacks and a routine that swaps the callee-saved
//! register set between them.
//!
//! A suspended context is just a stack pointer. [`switch`] pushes the current callee-saved
//! registers onto the current stack, records the stack pointer, loads the target's stack
//! pointer and pops its registers, then "returns" on the target stack. A fresh stack is
//! prepared ([`Stack::prepare`]) so that the first switch to it returns into a trampoline
//! that calls an entry function.
//!
//! Supported targets: aarch64 (AAPCS64) and x86_64 (System V).

use std::io;
use std::ptr::NonNull;

/// The smallest stack accepted, guard page excluded.
pub const MIN_STACK: usize = 16 * 1024;

fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 { size as usize } else { 4096 }
}

/// A coroutine stack: an anonymous mapping whose lowest page is inaccessible, so an
/// overflow faults instead of silently corrupting memory.
#[derive(Debug)]
pub struct Stack {
    base: NonNull<u8>,
    len: usize,
}

impl Stack {
    /// Maps a stack with at least `size` usable bytes.
    pub fn new(size: usize) -> io::Result<Stack> {
        let page = page_size();
        let usable = size.max(MIN_STACK).next_multiple_of(page);
        let len = usable + page;
        // SAFETY: an anonymous private mapping with no hint has no preconditions.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `ptr` is the start of the mapping just created; protecting its first page
        // turns it into the guard.
        if unsafe { libc::mprotect(ptr, page, libc::PROT_NONE) } != 0 {
            let err = io::Error::last_os_error();
            // SAFETY: unmapping the mapping we own.
            unsafe { libc::munmap(ptr, len) };
            return Err(err);
        }
        let base = NonNull::new(ptr.cast::<u8>()).ok_or_else(|| io::Error::other("null stack"))?;
        Ok(Stack { base, len })
    }

    /// One past the highest usable address (stacks grow down from here).
    pub fn top(&self) -> *mut u8 {
        // SAFETY: base + len is the end of the mapping.
        unsafe { self.base.as_ptr().add(self.len) }
    }

    /// Usable bytes (guard page excluded).
    pub fn size(&self) -> usize {
        self.len - page_size()
    }

    /// Lays out an initial frame so that the first [`switch`] to the returned stack pointer
    /// calls `entry(data, arg)`, where `arg` is the value passed to that switch. `entry`
    /// must never return.
    ///
    /// # Safety
    ///
    /// `entry` must be prepared to receive `data` (it will be called with it on this stack),
    /// and the stack must not be running.
    pub unsafe fn prepare(&mut self, entry: Entry, data: *mut ()) -> *mut u8 {
        // SAFETY: the frame written by `arch::prepare` fits well within MIN_STACK below the
        // top of a stack we exclusively own; the caller vouches for `entry`/`data`.
        unsafe { arch::prepare(self.top(), entry, data) }
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        // SAFETY: base/len describe the mapping created in `new`.
        unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) };
    }
}

/// Entry point of a fresh context. It receives the `data` given to [`Stack::prepare`] and
/// the `arg` of the first switch, and must never return.
pub type Entry = unsafe extern "C" fn(data: *mut (), arg: usize) -> !;

/// Saves the current context's stack pointer into `*save`, switches to the context whose
/// stack pointer is `to`, and passes it `arg`. Returns the `arg` of the switch that later
/// resumes this context.
///
/// # Safety
///
/// `save` must be valid for writes, and `to` must be a stack pointer produced by
/// [`Stack::prepare`] or saved by a previous `switch`, on a stack that is still alive and not
/// running. The caller must not hold borrows that the other context may invalidate.
pub unsafe fn switch(save: *mut *mut u8, to: *mut u8, arg: usize) -> usize {
    // SAFETY: forwarded to the caller.
    unsafe { arch::weft_context_switch(save, to, arg) }
}

#[cfg(target_arch = "aarch64")]
mod arch {
    use super::Entry;
    use std::arch::naked_asm;

    /// Bytes of saved state: x19-x30 (12 registers) and d8-d15 (8), 8 bytes each.
    const FRAME: usize = 160;

    #[unsafe(naked)]
    pub unsafe extern "C" fn weft_context_switch(
        save: *mut *mut u8,
        to: *mut u8,
        arg: usize,
    ) -> usize {
        naked_asm!(
            "sub sp, sp, #160",
            "stp x19, x20, [sp, #0]",
            "stp x21, x22, [sp, #16]",
            "stp x23, x24, [sp, #32]",
            "stp x25, x26, [sp, #48]",
            "stp x27, x28, [sp, #64]",
            "stp x29, x30, [sp, #80]",
            "stp d8, d9, [sp, #96]",
            "stp d10, d11, [sp, #112]",
            "stp d12, d13, [sp, #128]",
            "stp d14, d15, [sp, #144]",
            "mov x9, sp",
            "str x9, [x0]",
            "mov sp, x1",
            "ldp x19, x20, [sp, #0]",
            "ldp x21, x22, [sp, #16]",
            "ldp x23, x24, [sp, #32]",
            "ldp x25, x26, [sp, #48]",
            "ldp x27, x28, [sp, #64]",
            "ldp x29, x30, [sp, #80]",
            "ldp d8, d9, [sp, #96]",
            "ldp d10, d11, [sp, #112]",
            "ldp d12, d13, [sp, #128]",
            "ldp d14, d15, [sp, #144]",
            "add sp, sp, #160",
            "mov x0, x2",
            "ret",
        )
    }

    /// First code run on a fresh stack: `x0` holds the switch argument, `x19` the entry
    /// function and `x20` its data.
    #[unsafe(naked)]
    unsafe extern "C" fn trampoline() -> ! {
        naked_asm!("mov x1, x0", "mov x0, x20", "blr x19", "brk #1")
    }

    pub unsafe fn prepare(top: *mut u8, entry: Entry, data: *mut ()) -> *mut u8 {
        // Keep 16-byte alignment, with a little headroom above the frame.
        let sp = ((top as usize - 64) & !15) - FRAME;
        let slots = sp as *mut usize;
        // SAFETY: the caller guarantees the frame lies in a stack it owns.
        unsafe {
            for i in 0..FRAME / 8 {
                slots.add(i).write(0);
            }
            slots.write(entry as usize); // x19
            slots.add(1).write(data as usize); // x20
            slots.add(11).write(trampoline as *const () as usize); // x30: where `ret` goes
        }
        sp as *mut u8
    }
}

#[cfg(target_arch = "x86_64")]
mod arch {
    use super::Entry;
    use std::arch::naked_asm;

    #[unsafe(naked)]
    pub unsafe extern "C" fn weft_context_switch(
        save: *mut *mut u8,
        to: *mut u8,
        arg: usize,
    ) -> usize {
        naked_asm!(
            "push rbp",
            "push rbx",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "sub rsp, 8",
            "stmxcsr [rsp]",
            "fnstcw [rsp + 4]",
            "mov [rdi], rsp",
            "mov rsp, rsi",
            "ldmxcsr [rsp]",
            "fldcw [rsp + 4]",
            "add rsp, 8",
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbx",
            "pop rbp",
            "mov rax, rdx",
            "ret",
        )
    }

    /// First code run on a fresh stack: `rax` holds the switch argument, `r12` the entry
    /// function and `r13` its data. `rsp` is 16-byte aligned here, as `call` requires.
    #[unsafe(naked)]
    unsafe extern "C" fn trampoline() -> ! {
        naked_asm!("mov rdi, r13", "mov rsi, rax", "call r12", "ud2")
    }

    pub unsafe fn prepare(top: *mut u8, entry: Entry, data: *mut ()) -> *mut u8 {
        // Frame, from low to high: mxcsr+fpu control word, r15, r14, r13, r12, rbx, rbp,
        // return address. After `ret` pops the return address, rsp must be 16-aligned.
        let after_ret = (top as usize - 64) & !15;
        let sp = after_ret - 8 * 8;
        let slots = sp as *mut u64;
        // SAFETY: the caller guarantees the frame lies in a stack it owns.
        unsafe {
            // Default MXCSR (all exceptions masked) and x87 control word.
            slots.write(0x1F80 | (0x037F << 32));
            slots.add(1).write(0); // r15
            slots.add(2).write(0); // r14
            slots.add(3).write(data as u64); // r13
            slots.add(4).write(entry as usize as u64); // r12
            slots.add(5).write(0); // rbx
            slots.add(6).write(0); // rbp
            slots.add(7).write(trampoline as *const () as usize as u64); // return address
        }
        sp as *mut u8
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("weft coroutines support only aarch64 and x86_64");

#[cfg(test)]
mod tests {
    use super::*;

    struct PingPong {
        main_sp: *mut u8,
        co_sp: *mut u8,
        log: Vec<usize>,
    }

    unsafe extern "C" fn body(data: *mut (), first: usize) -> ! {
        // SAFETY: `data` is the PingPong owned by the test, alive for the whole exchange, and
        // only one context touches it at a time.
        let state = unsafe { &mut *(data as *mut PingPong) };
        let mut value = first;
        loop {
            state.log.push(value);
            // Deep-ish recursion with floats to exercise the stack and saved FP registers.
            let f = fib(10) as f64 * 1.5;
            assert_eq!(f, 82.5);
            // SAFETY: main_sp was saved by the switch that entered this context.
            value = unsafe { switch(&mut state.co_sp, state.main_sp, value * 10) };
        }
    }

    fn fib(n: u32) -> u32 {
        if n < 2 { n } else { fib(n - 1) + fib(n - 2) }
    }

    #[test]
    fn ping_pong_between_stacks() {
        let mut stack = Stack::new(64 * 1024).unwrap();
        assert!(stack.size() >= 64 * 1024);
        let mut state = PingPong {
            main_sp: std::ptr::null_mut(),
            co_sp: std::ptr::null_mut(),
            log: Vec::new(),
        };
        // SAFETY: `body` expects a PingPong, which outlives every switch below.
        state.co_sp = unsafe { stack.prepare(body, (&raw mut state).cast()) };
        let keep = 1.25f64;
        for i in 1..=5 {
            // SAFETY: co_sp is a prepared or saved stack pointer of a live, idle stack.
            let reply = unsafe { switch(&mut state.main_sp, state.co_sp, i) };
            assert_eq!(reply, i * 10);
        }
        assert_eq!(keep * 2.0, 2.5, "callee-saved float survives");
        assert_eq!(state.log, [1, 2, 3, 4, 5]);
    }
}
