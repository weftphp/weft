//! Unpredictable bytes from the operating system, for protocol nonces such as DNS query ids
//! and WebSocket masking keys.

use std::io;

/// Fills `buf` with random bytes from the OS.
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    // getentropy accepts at most 256 bytes per call.
    for chunk in buf.chunks_mut(256) {
        os_fill(chunk)?;
    }
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    all(target_os = "linux", target_env = "gnu")
))]
fn os_fill(chunk: &mut [u8]) -> io::Result<()> {
    // SAFETY: `chunk` is valid for `chunk.len()` (<= 256) writable bytes.
    crate::os::fd::check(unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) })
        .map(drop)
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    all(target_os = "linux", target_env = "gnu")
)))]
fn os_fill(chunk: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(chunk)
}

/// A random `u64`.
pub fn u64() -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    fill(&mut bytes)?;
    Ok(u64::from_ne_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_varied_output() {
        let mut a = [0u8; 600];
        let mut b = [0u8; 600];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(u64().unwrap(), u64().unwrap());
    }
}
