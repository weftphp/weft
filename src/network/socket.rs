//! A non-blocking socket with the operations and options an event loop needs.
//!
//! `std`'s socket types block on connect and hide options such as `SO_REUSEPORT` or the
//! listen backlog. [`Socket`] exposes those directly and converts into the `std` types when
//! a caller prefers them.

use std::io::{self, IoSlice, IoSliceMut};
use std::mem;
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::time::Duration;

use super::address::{Family, SocketAddress};
use crate::core::Result;
use crate::os::fd::{self, check, check_len, retry};

/// Stream (TCP, Unix stream) or datagram (UDP, Unix datagram).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketType {
    Stream,
    Datagram,
}

impl SocketType {
    fn raw(self) -> libc::c_int {
        match self {
            SocketType::Stream => libc::SOCK_STREAM,
            SocketType::Datagram => libc::SOCK_DGRAM,
        }
    }
}

/// Flags for `send`: never raise SIGPIPE on a closed peer where the OS supports it per call.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
const SEND_FLAGS: libc::c_int = 0;

/// See the [module documentation](self).
#[derive(Debug)]
pub struct Socket {
    fd: OwnedFd,
}

impl Socket {
    /// Creates a non-blocking, close-on-exec socket.
    pub fn new(family: Family, kind: SocketType) -> io::Result<Socket> {
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
        let raw = {
            let ty = kind.raw() | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
            // SAFETY: socket has no memory-safety preconditions.
            check(unsafe { libc::socket(family.raw(), ty, 0) })?
        };
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
        // SAFETY: socket has no memory-safety preconditions.
        let raw = check(unsafe { libc::socket(family.raw(), kind.raw(), 0) })?;
        // SAFETY: the descriptor was just created and is owned by nobody else.
        let socket = Socket {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
        };
        socket.prepare()?;
        Ok(socket)
    }

    /// Creates a socket of the right family for `addr`.
    pub fn for_address(addr: &SocketAddress, kind: SocketType) -> io::Result<Socket> {
        Socket::new(addr.family(), kind)
    }

    /// Creates a connected pair of Unix-domain sockets.
    pub fn pair(kind: SocketType) -> io::Result<(Socket, Socket)> {
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
        let ty = kind.raw() | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
        let ty = kind.raw();
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors socketpair writes.
        check(unsafe { libc::socketpair(libc::AF_UNIX, ty, 0, fds.as_mut_ptr()) })?;
        // SAFETY: socketpair succeeded, so both descriptors are open and unowned.
        let (a, b) = unsafe {
            (
                Socket {
                    fd: OwnedFd::from_raw_fd(fds[0]),
                },
                Socket {
                    fd: OwnedFd::from_raw_fd(fds[1]),
                },
            )
        };
        a.prepare()?;
        b.prepare()?;
        Ok((a, b))
    }

    /// Makes a freshly created or accepted socket non-blocking, close-on-exec and (where the
    /// OS needs a socket option for it) SIGPIPE-free.
    fn prepare(&self) -> io::Result<()> {
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
        {
            fd::set_nonblocking(self.fd.as_fd(), true)?;
            fd::set_cloexec(self.fd.as_fd(), true)?;
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        self.set_option(libc::SOL_SOCKET, libc::SO_NOSIGPIPE, 1 as libc::c_int)?;
        Ok(())
    }

    pub fn bind(&self, addr: &SocketAddress) -> Result<()> {
        let (raw, len) = addr.to_raw()?;
        // SAFETY: `raw` holds a valid address of `len` bytes.
        check(unsafe { libc::bind(self.raw(), (&raw const raw).cast(), len) })?;
        Ok(())
    }

    pub fn listen(&self, backlog: i32) -> io::Result<()> {
        // SAFETY: listen has no memory-safety preconditions.
        check(unsafe { libc::listen(self.raw(), backlog) }).map(drop)
    }

    /// Starts connecting. Returns `true` if connected immediately, `false` if the connection
    /// is in progress; wait for writability, then check [`take_error`](Self::take_error).
    pub fn connect(&self, addr: &SocketAddress) -> Result<bool> {
        let (raw, len) = addr.to_raw()?;
        // SAFETY: `raw` holds a valid address of `len` bytes.
        let ret = unsafe { libc::connect(self.raw(), (&raw const raw).cast(), len) };
        if ret == 0 {
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // EINTR also leaves the connect running in the background.
            Some(libc::EINPROGRESS | libc::EINTR) => Ok(false),
            _ => Err(err.into()),
        }
    }

    /// Accepts a connection; the new socket is non-blocking.
    pub fn accept(&self) -> io::Result<(Socket, SocketAddress)> {
        // SAFETY: sockaddr_storage is plain old data, valid when zeroed.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let raw = retry(|| {
            #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
            // SAFETY: `storage` and `len` are valid out-pointers sized for any address.
            let ret = unsafe {
                libc::accept4(
                    self.raw(),
                    (&raw mut storage).cast(),
                    &mut len,
                    libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                )
            };
            #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
            // SAFETY: `storage` and `len` are valid out-pointers sized for any address.
            let ret = unsafe { libc::accept(self.raw(), (&raw mut storage).cast(), &mut len) };
            check(ret)
        })?;
        // SAFETY: accept returned a new descriptor owned by nobody else.
        let socket = Socket {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
        };
        socket.prepare()?;
        Ok((socket, SocketAddress::from_raw(&storage, len)?))
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        retry(|| {
            // SAFETY: `buf` is valid for `buf.len()` writable bytes.
            check_len(unsafe { libc::recv(self.raw(), buf.as_mut_ptr().cast(), buf.len(), 0) })
        })
    }

    /// Reads without consuming.
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        retry(|| {
            // SAFETY: `buf` is valid for `buf.len()` writable bytes.
            check_len(unsafe {
                libc::recv(
                    self.raw(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_PEEK,
                )
            })
        })
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        retry(|| {
            // SAFETY: `buf` is valid for `buf.len()` readable bytes.
            check_len(unsafe { libc::send(self.raw(), buf.as_ptr().cast(), buf.len(), SEND_FLAGS) })
        })
    }

    /// Gathers `bufs` into one send.
    pub fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        // SAFETY: msghdr is plain old data, valid when zeroed.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        // IoSlice is guaranteed ABI-compatible with iovec on Unix.
        msg.msg_iov = bufs.as_ptr() as *mut libc::iovec;
        msg.msg_iovlen = bufs.len().min(1024) as _;
        retry(|| {
            // SAFETY: `msg` points at `msg_iovlen` valid iovecs and no name/control data.
            check_len(unsafe { libc::sendmsg(self.raw(), &msg, SEND_FLAGS) })
        })
    }

    /// Scatters one receive into `bufs`.
    pub fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        // SAFETY: msghdr is plain old data, valid when zeroed.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = bufs.as_mut_ptr().cast();
        msg.msg_iovlen = bufs.len().min(1024) as _;
        retry(|| {
            // SAFETY: `msg` points at `msg_iovlen` valid writable iovecs.
            check_len(unsafe { libc::recvmsg(self.raw(), &mut msg, 0) })
        })
    }

    /// Receives one datagram and its sender.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddress)> {
        // SAFETY: sockaddr_storage is plain old data, valid when zeroed.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let n = retry(|| {
            // SAFETY: `buf`, `storage` and `len` are valid for the sizes passed.
            check_len(unsafe {
                libc::recvfrom(
                    self.raw(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    (&raw mut storage).cast(),
                    &mut len,
                )
            })
        })?;
        Ok((n, SocketAddress::from_raw(&storage, len)?))
    }

    /// Sends one datagram to `addr`.
    pub fn send_to(&self, buf: &[u8], addr: &SocketAddress) -> Result<usize> {
        let (raw, len) = addr.to_raw()?;
        Ok(retry(|| {
            // SAFETY: `buf` and `raw` are valid for the sizes passed.
            check_len(unsafe {
                libc::sendto(
                    self.raw(),
                    buf.as_ptr().cast(),
                    buf.len(),
                    SEND_FLAGS,
                    (&raw const raw).cast(),
                    len,
                )
            })
        })?)
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Both => libc::SHUT_RDWR,
        };
        // SAFETY: shutdown has no memory-safety preconditions.
        check(unsafe { libc::shutdown(self.raw(), how) }).map(drop)
    }

    /// Takes the pending socket error (`SO_ERROR`), for example the outcome of a
    /// non-blocking [`connect`](Self::connect).
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        let code: libc::c_int = self.option(libc::SOL_SOCKET, libc::SO_ERROR)?;
        Ok((code != 0).then(|| io::Error::from_raw_os_error(code)))
    }

    pub fn local_address(&self) -> io::Result<SocketAddress> {
        self.address(libc::getsockname)
    }

    pub fn peer_address(&self) -> io::Result<SocketAddress> {
        self.address(libc::getpeername)
    }

    fn address(
        &self,
        query: unsafe extern "C" fn(
            libc::c_int,
            *mut libc::sockaddr,
            *mut libc::socklen_t,
        ) -> libc::c_int,
    ) -> io::Result<SocketAddress> {
        // SAFETY: sockaddr_storage is plain old data, valid when zeroed.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: `storage` and `len` are valid out-pointers sized for any address.
        check(unsafe { query(self.raw(), (&raw mut storage).cast(), &mut len) })?;
        SocketAddress::from_raw(&storage, len)
    }

    // ----- options -----

    fn set_option<T: Copy>(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: T,
    ) -> io::Result<()> {
        // SAFETY: `value` is a live `T` and its size is passed alongside it.
        check(unsafe {
            libc::setsockopt(
                self.raw(),
                level,
                name,
                (&raw const value).cast(),
                mem::size_of::<T>() as libc::socklen_t,
            )
        })
        .map(drop)
    }

    fn option<T: Copy>(&self, level: libc::c_int, name: libc::c_int) -> io::Result<T> {
        let mut value = mem::MaybeUninit::<T>::zeroed();
        let mut len = mem::size_of::<T>() as libc::socklen_t;
        // SAFETY: `value` has room for a `T`, whose size is passed in `len`.
        check(unsafe {
            libc::getsockopt(self.raw(), level, name, value.as_mut_ptr().cast(), &mut len)
        })?;
        // SAFETY: zero-initialised and then (partly) written by the kernel; every `T` used
        // here is an integer or C struct for which any bit pattern is valid.
        Ok(unsafe { value.assume_init() })
    }

    fn set_flag(&self, level: libc::c_int, name: libc::c_int, on: bool) -> io::Result<()> {
        self.set_option(level, name, libc::c_int::from(on))
    }

    /// `SO_REUSEADDR`: rebind a port that still has connections in `TIME_WAIT`.
    pub fn set_reuse_address(&self, on: bool) -> io::Result<()> {
        self.set_flag(libc::SOL_SOCKET, libc::SO_REUSEADDR, on)
    }

    /// `SO_REUSEPORT`: let several sockets bind the same port (the kernel spreads
    /// connections across them on Linux).
    pub fn set_reuse_port(&self, on: bool) -> io::Result<()> {
        self.set_flag(libc::SOL_SOCKET, libc::SO_REUSEPORT, on)
    }

    /// `TCP_NODELAY`: disable Nagle's algorithm.
    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        self.set_flag(libc::IPPROTO_TCP, libc::TCP_NODELAY, on)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        Ok(self.option::<libc::c_int>(libc::IPPROTO_TCP, libc::TCP_NODELAY)? != 0)
    }

    /// `SO_KEEPALIVE`, plus the idle time before the first probe when `idle` is given.
    pub fn set_keepalive(&self, idle: Option<Duration>) -> io::Result<()> {
        self.set_flag(libc::SOL_SOCKET, libc::SO_KEEPALIVE, idle.is_some())?;
        if let Some(idle) = idle {
            let secs = idle.as_secs().clamp(1, libc::c_int::MAX as u64) as libc::c_int;
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            self.set_option(libc::IPPROTO_TCP, libc::TCP_KEEPALIVE, secs)?;
            #[cfg(not(any(target_os = "macos", target_os = "ios")))]
            self.set_option(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, secs)?;
        }
        Ok(())
    }

    /// `SO_LINGER`. `Some(Duration::ZERO)` makes close send a reset instead of a FIN.
    pub fn set_linger(&self, linger: Option<Duration>) -> io::Result<()> {
        let value = libc::linger {
            l_onoff: libc::c_int::from(linger.is_some()),
            l_linger: linger.map_or(0, |d| d.as_secs().min(libc::c_int::MAX as u64) as _),
        };
        self.set_option(libc::SOL_SOCKET, libc::SO_LINGER, value)
    }

    pub fn set_send_buffer_size(&self, bytes: usize) -> io::Result<()> {
        let bytes = bytes.min(libc::c_int::MAX as usize) as libc::c_int;
        self.set_option(libc::SOL_SOCKET, libc::SO_SNDBUF, bytes)
    }

    pub fn send_buffer_size(&self) -> io::Result<usize> {
        Ok(self.option::<libc::c_int>(libc::SOL_SOCKET, libc::SO_SNDBUF)? as usize)
    }

    pub fn set_recv_buffer_size(&self, bytes: usize) -> io::Result<()> {
        let bytes = bytes.min(libc::c_int::MAX as usize) as libc::c_int;
        self.set_option(libc::SOL_SOCKET, libc::SO_RCVBUF, bytes)
    }

    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        Ok(self.option::<libc::c_int>(libc::SOL_SOCKET, libc::SO_RCVBUF)? as usize)
    }

    /// `SO_BROADCAST` for UDP.
    pub fn set_broadcast(&self, on: bool) -> io::Result<()> {
        self.set_flag(libc::SOL_SOCKET, libc::SO_BROADCAST, on)
    }

    /// `IPV6_V6ONLY`: whether an IPv6 socket refuses IPv4-mapped traffic.
    pub fn set_only_v6(&self, on: bool) -> io::Result<()> {
        self.set_flag(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, on)
    }

    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        fd::set_nonblocking(self.fd.as_fd(), on)
    }

    /// A second handle to the same socket (a duplicated, close-on-exec descriptor).
    pub fn try_clone(&self) -> io::Result<Socket> {
        Ok(Socket {
            fd: self.fd.try_clone()?,
        })
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for Socket {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

impl From<OwnedFd> for Socket {
    fn from(fd: OwnedFd) -> Self {
        Socket { fd }
    }
}

impl From<Socket> for OwnedFd {
    fn from(socket: Socket) -> Self {
        socket.fd
    }
}

macro_rules! std_conversions {
    ($($ty:ty),*) => {$(
        impl From<Socket> for $ty {
            fn from(socket: Socket) -> Self {
                <$ty>::from(socket.fd)
            }
        }
        impl From<$ty> for Socket {
            fn from(sock: $ty) -> Self {
                Socket { fd: OwnedFd::from(sock) }
            }
        }
    )*};
}

std_conversions!(
    std::net::TcpStream,
    std::net::TcpListener,
    std::net::UdpSocket,
    std::os::unix::net::UnixStream,
    std::os::unix::net::UnixListener,
    std::os::unix::net::UnixDatagram
);

impl io::Read for &Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
}

impl io::Write for &Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.send_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
}

impl io::Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.send_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Creates a non-blocking listening socket on `addr` with `SO_REUSEADDR` set (and
/// `SO_REUSEPORT` if `reuse_port`).
pub fn listen(addr: &SocketAddress, backlog: i32, reuse_port: bool) -> Result<Socket> {
    let socket = Socket::for_address(addr, SocketType::Stream)?;
    if addr.family() != Family::Unix {
        socket.set_reuse_address(true)?;
        if reuse_port {
            socket.set_reuse_port(true)?;
        }
    }
    socket.bind(addr)?;
    socket.listen(backlog)?;
    Ok(socket)
}

/// Creates a non-blocking datagram socket bound to `addr`.
pub fn bind_datagram(addr: &SocketAddress) -> Result<Socket> {
    let socket = Socket::for_address(addr, SocketType::Datagram)?;
    socket.bind(addr)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    fn retry_would_block<T>(mut op: impl FnMut() -> io::Result<T>) -> T {
        for _ in 0..1000 {
            match op() {
                Ok(v) => return v,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => sleep(Duration::from_millis(1)),
                Err(e) => panic!("{e}"),
            }
        }
        panic!("timed out");
    }

    #[test]
    fn tcp_nonblocking_connect_accept_and_transfer() {
        let addr: SocketAddress = "127.0.0.1:0".parse().unwrap();
        let listener = listen(&addr, 16, false).unwrap();
        let bound = listener.local_address().unwrap();
        assert_ne!(bound.as_inet().unwrap().port(), 0);

        let client = Socket::for_address(&bound, SocketType::Stream).unwrap();
        let immediate = client.connect(&bound).unwrap();
        let (server, peer) = retry_would_block(|| listener.accept());
        if !immediate {
            retry_would_block(|| match client.peer_address() {
                Ok(_) => Ok(()),
                Err(_) => Err(io::ErrorKind::WouldBlock.into()),
            });
        }
        assert!(client.take_error().unwrap().is_none());
        assert_eq!(peer, client.local_address().unwrap());

        client.set_nodelay(true).unwrap();
        assert!(client.nodelay().unwrap());
        let sent = client
            .send_vectored(&[IoSlice::new(b"hello "), IoSlice::new(b"world")])
            .unwrap();
        assert_eq!(sent, 11);
        let mut buf = [0u8; 32];
        let n = retry_would_block(|| server.recv(&mut buf));
        assert_eq!(&buf[..n], b"hello world");

        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(retry_would_block(|| server.recv(&mut buf)), 0);
    }

    #[test]
    fn connection_refused_surfaces() {
        // Bind then drop to find a port nobody listens on.
        let probe = listen(&"127.0.0.1:0".parse().unwrap(), 1, false).unwrap();
        let addr = probe.local_address().unwrap();
        drop(probe);
        let client = Socket::for_address(&addr, SocketType::Stream).unwrap();
        match client.connect(&addr) {
            Err(e) => assert_eq!(
                e.io_error().map(io::Error::kind),
                Some(io::ErrorKind::ConnectionRefused)
            ),
            Ok(true) => panic!("connected to a closed port"),
            Ok(false) => {
                let err = retry_would_block(|| match client.take_error()? {
                    Some(e) => Ok(e),
                    None => Err(io::ErrorKind::WouldBlock.into()),
                });
                assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
            }
        }
    }

    #[test]
    fn udp_datagrams() {
        let a = bind_datagram(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let b = bind_datagram(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let b_addr = b.local_address().unwrap();
        a.send_to(b"ping", &b_addr).unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = retry_would_block(|| b.recv_from(&mut buf));
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, a.local_address().unwrap());
    }

    #[test]
    fn unix_stream_and_options() {
        let path = std::env::temp_dir().join(format!("weft-sock-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let addr = SocketAddress::unix(&path);
        let listener = listen(&addr, 4, false).unwrap();
        let client = Socket::for_address(&addr, SocketType::Stream).unwrap();
        client.connect(&addr).unwrap();
        let (server, _) = retry_would_block(|| listener.accept());
        assert_eq!(server.local_address().unwrap(), addr);

        server.set_send_buffer_size(64 * 1024).unwrap();
        assert!(server.send_buffer_size().unwrap() > 0);
        let stream: std::os::unix::net::UnixStream = client.into();
        drop(stream);
        let mut buf = [0u8; 4];
        assert_eq!(retry_would_block(|| server.recv(&mut buf)), 0);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn socket_pair() {
        let (a, b) = Socket::pair(SocketType::Datagram).unwrap();
        a.send(b"x").unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(b.peek(&mut buf).unwrap(), 1);
        assert_eq!(b.recv(&mut buf).unwrap(), 1);
        assert_eq!(
            b.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
