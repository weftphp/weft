//! Fixed-size blocks of shared memory handed out by index, so processes can refer to a
//! block by a small integer (for example, inside a queue message).

use std::sync::atomic::{AtomicU32, Ordering};

use super::shared::Mapping;
use crate::core::{Error, ErrorKind, Result};
use crate::lock::SpinLock;

#[repr(C)]
struct Header {
    lock: SpinLock,
    /// Number of entries on the free stack.
    free: AtomicU32,
}

#[repr(C)]
struct SlotHeader {
    lock: SpinLock,
    allocated: AtomicU32,
}

/// See the [module documentation](self).
pub struct FixedPool {
    map: Mapping,
    slots: u32,
    slot_size: usize,
    stack_offset: usize,
    slots_offset: usize,
    stride: usize,
}

impl FixedPool {
    /// Creates `slots` blocks of `slot_size` bytes each, all free.
    pub fn new(slots: u32, slot_size: usize) -> Result<FixedPool> {
        if slots == 0 || slot_size == 0 {
            return Err(Error::new(ErrorKind::InvalidArgument, "empty pool"));
        }
        let stack_offset = std::mem::size_of::<Header>().next_multiple_of(8);
        let slots_offset = (stack_offset + 4 * slots as usize).next_multiple_of(64);
        let stride = (std::mem::size_of::<SlotHeader>() + slot_size).next_multiple_of(8);
        let bytes = (slots as usize)
            .checked_mul(stride)
            .and_then(|n| n.checked_add(slots_offset))
            .ok_or_else(|| Error::new(ErrorKind::TooLarge, "pool too large"))?;
        let pool = FixedPool {
            map: Mapping::new(bytes)?,
            slots,
            slot_size,
            stack_offset,
            slots_offset,
            stride,
        };
        for i in 0..slots {
            pool.stack(i).store(slots - 1 - i, Ordering::Relaxed);
        }
        pool.header().free.store(slots, Ordering::Release);
        Ok(pool)
    }

    fn header(&self) -> &Header {
        // SAFETY: the mapping starts with a zeroed (valid) Header of atomics.
        unsafe { &*self.map.as_ptr().cast::<Header>() }
    }

    fn stack(&self, i: u32) -> &AtomicU32 {
        // SAFETY: entry i < slots lies in the 4-byte-aligned free stack.
        unsafe {
            &*self
                .map
                .as_ptr()
                .add(self.stack_offset + 4 * i as usize)
                .cast::<AtomicU32>()
        }
    }

    fn slot_ptr(&self, id: u32) -> *mut u8 {
        // SAFETY: id < slots, so the slot lies inside the mapping.
        unsafe {
            self.map
                .as_ptr()
                .add(self.slots_offset + id as usize * self.stride)
        }
    }

    fn slot_header(&self, id: u32) -> &SlotHeader {
        // SAFETY: slots start 8-byte aligned with a zeroed (valid) SlotHeader of atomics.
        unsafe { &*self.slot_ptr(id).cast::<SlotHeader>() }
    }

    /// Takes a free block, zero-filled. `None` if all are in use.
    pub fn alloc(&self) -> Option<u32> {
        let header = self.header();
        let _guard = header.lock.lock();
        let free = header.free.load(Ordering::Relaxed);
        if free == 0 {
            return None;
        }
        let id = self.stack(free - 1).load(Ordering::Relaxed);
        header.free.store(free - 1, Ordering::Relaxed);
        let slot = self.slot_header(id);
        let _slot = slot.lock.lock();
        // SAFETY: the slot was free, so nobody else holds its data.
        unsafe {
            std::ptr::write_bytes(
                self.slot_ptr(id).add(std::mem::size_of::<SlotHeader>()),
                0,
                self.slot_size,
            )
        };
        slot.allocated.store(1, Ordering::Release);
        Some(id)
    }

    fn check(&self, id: u32) -> Result<()> {
        if id >= self.slots || self.slot_header(id).allocated.load(Ordering::Acquire) == 0 {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                format!("block {id} is not allocated"),
            ));
        }
        Ok(())
    }

    /// Returns a block to the pool.
    pub fn free(&self, id: u32) -> Result<()> {
        let header = self.header();
        let _guard = header.lock.lock();
        self.check(id)?;
        let slot = self.slot_header(id);
        {
            let _slot = slot.lock.lock();
            slot.allocated.store(0, Ordering::Release);
        }
        let free = header.free.load(Ordering::Relaxed);
        self.stack(free).store(id, Ordering::Relaxed);
        header.free.store(free + 1, Ordering::Relaxed);
        Ok(())
    }

    /// Runs `f` with exclusive access to block `id`'s bytes.
    pub fn with_block<R>(&self, id: u32, f: impl FnOnce(&mut [u8]) -> R) -> Result<R> {
        self.check(id)?;
        let slot = self.slot_header(id);
        let _slot = slot.lock.lock();
        self.check(id)?;
        // SAFETY: the slot lock grants exclusive access to this block's bytes in every
        // process, and the block lies inside the mapping.
        let data = unsafe {
            std::slice::from_raw_parts_mut(
                self.slot_ptr(id).add(std::mem::size_of::<SlotHeader>()),
                self.slot_size,
            )
        };
        Ok(f(data))
    }

    pub fn slot_size(&self) -> usize {
        self.slot_size
    }

    pub fn capacity(&self) -> u32 {
        self.slots
    }

    /// Blocks currently free.
    pub fn available(&self) -> u32 {
        self.header().free.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for FixedPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixedPool")
            .field("slots", &self.slots)
            .field("slot_size", &self.slot_size)
            .field("available", &self.available())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_write_free() {
        let pool = FixedPool::new(3, 10).unwrap();
        let ids: Vec<u32> = (0..3).map(|_| pool.alloc().unwrap()).collect();
        assert_eq!(pool.alloc(), None);
        pool.with_block(ids[1], |b| b[..5].copy_from_slice(b"hello"))
            .unwrap();
        let read = pool.with_block(ids[1], |b| b[..5].to_vec()).unwrap();
        assert_eq!(read, b"hello");

        pool.free(ids[1]).unwrap();
        assert!(pool.free(ids[1]).is_err(), "double free");
        assert!(pool.with_block(ids[1], |_| ()).is_err());
        assert!(pool.free(99).is_err());
        let again = pool.alloc().unwrap();
        assert_eq!(again, ids[1]);
        assert_eq!(
            pool.with_block(again, |b| b[0]).unwrap(),
            0,
            "zeroed on reuse"
        );
        assert_eq!(pool.available(), 0);
    }
}
