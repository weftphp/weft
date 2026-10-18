//! Memory shared between a process and the children it forks.
//!
//! A [`Shared<T>`] is an anonymous `MAP_SHARED` mapping holding one `T`. After `fork`, parent
//! and children see the same `T`, so it must be made of types that are meaningful in every
//! process and are only mutated through atomics: see [`ShmSafe`].

use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU8, AtomicU32, AtomicU64, AtomicUsize};

/// Types that may live in memory shared across processes.
///
/// # Safety
///
/// Implementors must guarantee that:
/// - the all-zero bit pattern is a valid value (mappings start zeroed);
/// - the type holds no pointers, references or handles that are only meaningful in one
///   process (no `Box`, `Vec`, `String`, file descriptors, ...);
/// - all mutation through `&Self` is done with atomics or under a lock that is itself
///   `ShmSafe`, so concurrent access from several processes is sound.
pub unsafe trait ShmSafe: Sync {}

// SAFETY: atomics are valid when zeroed, hold no pointers, and are designed for shared access.
unsafe impl ShmSafe for AtomicU8 {}
// SAFETY: as above.
unsafe impl ShmSafe for AtomicU32 {}
// SAFETY: as above.
unsafe impl ShmSafe for AtomicI32 {}
// SAFETY: as above.
unsafe impl ShmSafe for AtomicU64 {}
// SAFETY: as above.
unsafe impl ShmSafe for AtomicI64 {}
// SAFETY: as above.
unsafe impl ShmSafe for AtomicUsize {}
// SAFETY: an array of ShmSafe values is ShmSafe element-wise.
unsafe impl<T: ShmSafe, const N: usize> ShmSafe for [T; N] {}

/// A raw anonymous shared mapping, zero-filled, unmapped on drop.
pub struct Mapping {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: the mapping is plain memory; what is stored in it decides thread safety, and the
// typed wrappers below only expose `ShmSafe` contents.
unsafe impl Send for Mapping {}
// SAFETY: as above.
unsafe impl Sync for Mapping {}

impl Mapping {
    /// Maps `len` bytes (rounded up to whole pages by the kernel).
    pub fn new(len: usize) -> io::Result<Mapping> {
        if len == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty mapping"));
        }
        // SAFETY: an anonymous mapping with no address hint has no preconditions.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr =
            NonNull::new(ptr.cast::<u8>()).ok_or_else(|| io::Error::other("mmap returned null"))?;
        Ok(Mapping { ptr, len })
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` describe a mapping created by `new` and not yet unmapped.
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

impl fmt::Debug for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mapping").field("len", &self.len).finish()
    }
}

/// One `T` in shared memory. Dereferences to `&T`.
pub struct Shared<T: ShmSafe> {
    map: Mapping,
    _marker: PhantomData<T>,
}

impl<T: ShmSafe> Shared<T> {
    /// Allocates a zeroed `T`.
    pub fn new() -> io::Result<Shared<T>> {
        // mmap returns page-aligned memory, which satisfies any type's alignment.
        let map = Mapping::new(std::mem::size_of::<T>().max(1))?;
        Ok(Shared {
            map,
            _marker: PhantomData,
        })
    }
}

impl<T: ShmSafe> Deref for Shared<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the mapping is large enough and page-aligned for `T`, was zero-filled
        // (a valid `T` per `ShmSafe`), and only shared references are ever handed out.
        unsafe { &*self.map.as_ptr().cast::<T>() }
    }
}

impl<T: ShmSafe + fmt::Debug> fmt::Debug for Shared<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Shared").field(&**self).finish()
    }
}

/// `len` zeroed `T`s in shared memory. Dereferences to `&[T]`.
pub struct SharedSlice<T: ShmSafe> {
    map: Mapping,
    len: usize,
    _marker: PhantomData<T>,
}

impl<T: ShmSafe> SharedSlice<T> {
    pub fn new(len: usize) -> io::Result<SharedSlice<T>> {
        let bytes = std::mem::size_of::<T>()
            .checked_mul(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "size overflow"))?;
        Ok(SharedSlice {
            map: Mapping::new(bytes.max(1))?,
            len,
            _marker: PhantomData,
        })
    }
}

impl<T: ShmSafe> Deref for SharedSlice<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        // SAFETY: as for `Shared`, for `len` consecutive values.
        unsafe { std::slice::from_raw_parts(self.map.as_ptr().cast::<T>(), self.len) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn zeroed_and_shared_between_threads() {
        let counters = SharedSlice::<AtomicU64>::new(4).unwrap();
        assert!(counters.iter().all(|c| c.load(Ordering::Relaxed) == 0));
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for c in counters.iter() {
                        c.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert!(counters.iter().all(|c| c.load(Ordering::Relaxed) == 4));

        let one = Shared::<[AtomicU32; 3]>::new().unwrap();
        one[2].store(7, Ordering::Relaxed);
        assert_eq!(one[2].load(Ordering::Relaxed), 7);
        assert!(Mapping::new(0).is_err());
    }
}
