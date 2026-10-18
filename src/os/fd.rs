//! Thin, safe wrappers over file-descriptor syscalls that `std` does not expose.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// Turns a `-1` syscall result into the current `errno`.
pub(crate) fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Like [`check`] for syscalls returning `ssize_t`.
pub(crate) fn check_len(ret: libc::ssize_t) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// Retries `op` while it fails with `EINTR`.
pub(crate) fn retry<T>(mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match op() {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

fn update_flags(
    fd: BorrowedFd<'_>,
    get: libc::c_int,
    set: libc::c_int,
    flag: libc::c_int,
    on: bool,
) -> io::Result<()> {
    // SAFETY: fcntl with F_GET*/F_SET* only reads or writes flag words of a descriptor that
    // `fd` keeps open for the duration of the call.
    unsafe {
        let flags = check(libc::fcntl(fd.as_raw_fd(), get))?;
        let wanted = if on { flags | flag } else { flags & !flag };
        if wanted != flags {
            check(libc::fcntl(fd.as_raw_fd(), set, wanted))?;
        }
    }
    Ok(())
}

/// Switches `O_NONBLOCK` on or off.
pub fn set_nonblocking(fd: BorrowedFd<'_>, on: bool) -> io::Result<()> {
    update_flags(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK, on)
}

/// Whether `O_NONBLOCK` is set.
pub fn is_nonblocking(fd: BorrowedFd<'_>) -> io::Result<bool> {
    // SAFETY: F_GETFL only reads the status flags of an open descriptor.
    let flags = check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) })?;
    Ok(flags & libc::O_NONBLOCK != 0)
}

/// Switches `FD_CLOEXEC` on or off.
pub fn set_cloexec(fd: BorrowedFd<'_>, on: bool) -> io::Result<()> {
    update_flags(fd, libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC, on)
}

/// Reads into `buf`, retrying on `EINTR`.
pub fn read(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    retry(|| {
        // SAFETY: `buf` is valid for `buf.len()` writable bytes.
        check_len(unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) })
    })
}

/// Writes from `buf`, retrying on `EINTR`.
pub fn write(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<usize> {
    retry(|| {
        // SAFETY: `buf` is valid for `buf.len()` readable bytes.
        check_len(unsafe { libc::write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) })
    })
}

/// Creates a pipe whose ends are close-on-exec, and non-blocking if `nonblocking`.
/// Returns `(read_end, write_end)`.
pub fn pipe(nonblocking: bool) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    {
        let flags = libc::O_CLOEXEC | if nonblocking { libc::O_NONBLOCK } else { 0 };
        // SAFETY: `fds` has room for the two descriptors pipe2 writes.
        check(unsafe { libc::pipe2(fds.as_mut_ptr(), flags) })?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
    {
        // SAFETY: `fds` has room for the two descriptors pipe writes.
        check(unsafe { libc::pipe(fds.as_mut_ptr()) })?;
    }
    // SAFETY: pipe succeeded, so both descriptors are open and owned by nobody else.
    let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
    for fd in [&reader, &writer] {
        use std::os::fd::AsFd;
        set_cloexec(fd.as_fd(), true)?;
        set_nonblocking(fd.as_fd(), nonblocking)?;
    }
    Ok((reader, writer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn pipe_roundtrip_and_flags() {
        let (r, w) = pipe(true).unwrap();
        assert!(is_nonblocking(r.as_fd()).unwrap());
        let mut buf = [0u8; 8];
        let err = read(r.as_fd(), &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        assert_eq!(write(w.as_fd(), b"ping").unwrap(), 4);
        assert_eq!(read(r.as_fd(), &mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"ping");

        set_nonblocking(r.as_fd(), false).unwrap();
        assert!(!is_nonblocking(r.as_fd()).unwrap());
        drop(w);
        assert_eq!(
            read(r.as_fd(), &mut buf).unwrap(),
            0,
            "EOF once the writer is gone"
        );
    }
}
