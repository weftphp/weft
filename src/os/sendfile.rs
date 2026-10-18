//! Zero-copy file-to-socket transfer, with a read/write fallback.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::FileExt;

use crate::os::fd;

/// Largest chunk moved by one call, so a huge file cannot monopolise the event loop.
pub const MAX_CHUNK: usize = 1 << 20;

/// Copies up to `len` bytes of `file`, starting at `offset`, to `out` (normally a socket).
/// Returns how many bytes were sent; the caller advances its offset by that amount.
///
/// Uses the kernel's `sendfile` where possible and falls back to `pread` + `write` when the
/// descriptor pair is not supported. On a non-blocking `out`, may fail with `WouldBlock`.
pub fn send_file(out: BorrowedFd<'_>, file: &File, offset: u64, len: usize) -> io::Result<usize> {
    let len = len.min(MAX_CHUNK);
    if len == 0 {
        return Ok(0);
    }
    match native(out, file, offset, len) {
        Err(err) if unsupported(&err) => copy(out, file, offset, len),
        other => other,
    }
}

fn unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSOCK | libc::EOPNOTSUPP)
    )
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn native(out: BorrowedFd<'_>, file: &File, offset: u64, len: usize) -> io::Result<usize> {
    let mut off = libc::off_t::try_from(offset)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset too large"))?;
    fd::retry(|| {
        // SAFETY: both descriptors are open for the call and `off` is a valid in/out pointer.
        fd::check_len(unsafe { libc::sendfile(out.as_raw_fd(), file.as_raw_fd(), &mut off, len) })
    })
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn native(out: BorrowedFd<'_>, file: &File, offset: u64, len: usize) -> io::Result<usize> {
    let off = libc::off_t::try_from(offset)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset too large"))?;
    loop {
        let mut sent = len as libc::off_t;
        // SAFETY: both descriptors are open for the call; `sent` is a valid in/out pointer and
        // no header/trailer vector is passed.
        let ret = unsafe {
            libc::sendfile(
                file.as_raw_fd(),
                out.as_raw_fd(),
                off,
                &mut sent,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret == 0 {
            return Ok(sent as usize);
        }
        let err = io::Error::last_os_error();
        // On EAGAIN/EINTR the kernel still reports partial progress through `sent`.
        match err.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted if sent > 0 => {
                return Ok(sent as usize);
            }
            io::ErrorKind::Interrupted => continue,
            _ => return Err(err),
        }
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn native(_out: BorrowedFd<'_>, _file: &File, _offset: u64, _len: usize) -> io::Result<usize> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

fn copy(out: BorrowedFd<'_>, file: &File, offset: u64, len: usize) -> io::Result<usize> {
    let mut chunk = vec![0u8; len.min(64 * 1024)];
    let n = file.read_at(&mut chunk, offset)?;
    if n == 0 {
        return Ok(0);
    }
    // A short write is fine: the unsent tail is read again on the next call.
    fd::write(out, &chunk[..n])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    fn temp_file(contents: &[u8]) -> File {
        let path = std::env::temp_dir().join(format!(
            "weft-sendfile-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file.write_all(contents).unwrap();
        file
    }

    #[test]
    fn sends_a_range_over_a_socket() {
        let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let file = temp_file(&data);
        let (a, mut b) = UnixStream::pair().unwrap();
        // The socket buffer is smaller than the range, so read concurrently.
        let reader = std::thread::spawn(move || {
            let mut got = Vec::new();
            b.read_to_end(&mut got).unwrap();
            got
        });

        let mut offset = 100u64;
        let end = 9_000u64;
        while offset < end {
            let n = send_file(a.as_fd(), &file, offset, (end - offset) as usize).unwrap();
            assert!(n > 0);
            offset += n as u64;
        }
        drop(a);
        assert_eq!(reader.join().unwrap(), &data[100..9_000]);
    }

    #[test]
    fn falls_back_for_pipes() {
        let file = temp_file(b"hello pipe");
        let (r, w) = fd::pipe(false).unwrap();
        let n = send_file(w.as_fd(), &file, 6, 100).unwrap();
        let mut buf = [0u8; 16];
        let got = fd::read(r.as_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..got], &b"pipe"[..n]);
        assert_eq!(send_file(w.as_fd(), &file, 10, 5).unwrap(), 0, "at EOF");
    }
}
