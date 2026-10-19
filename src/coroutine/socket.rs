//! Sockets whose blocking operations suspend the calling coroutine instead of the thread.
//!
//! Every operation tries the non-blocking syscall first and only waits for readiness when the
//! kernel says it would block, so a busy connection costs no extra event-loop round trips.
//! One coroutine may read while another writes the same socket.
//!
//! A connected socket can be switched to TLS with [`CoSocket::start_tls_client`] or
//! [`CoSocket::start_tls_server`]; afterwards every stream operation goes through the TLS
//! session transparently.

use std::cell::RefCell;
use std::io::{self, IoSlice};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::time::{Duration, Instant};

use super::runtime::{release_fd, wait_fd};
use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, Result};
use crate::network::tls::{ClientTls, ServerTls, TlsInfo, TlsSession};
use crate::network::{Socket, SocketAddress, SocketType};
use crate::protocol::framing::Decoder;
use crate::reactor::Interest;

/// See the [module documentation](self).
#[derive(Debug)]
pub struct CoSocket {
    // Declared before `socket` so it is dropped first: it does I/O on the socket's descriptor.
    tls: Option<RefCell<TlsSession>>,
    socket: Socket,
    /// Applied to each read-side operation when no explicit timeout is given.
    pub read_timeout: Option<Duration>,
    /// Applied to each write-side operation when no explicit timeout is given.
    pub write_timeout: Option<Duration>,
}

fn remaining(deadline: Option<Instant>) -> Result<Option<Duration>> {
    match deadline {
        None => Ok(None),
        Some(d) => match d.checked_duration_since(Instant::now()) {
            Some(left) if !left.is_zero() => Ok(Some(left)),
            _ => Err(Error::new(ErrorKind::TimedOut, "operation timed out")),
        },
    }
}

impl CoSocket {
    /// Wraps an existing (non-blocking) socket.
    pub fn from_socket(socket: Socket) -> CoSocket {
        CoSocket {
            tls: None,
            socket,
            read_timeout: None,
            write_timeout: None,
        }
    }

    pub fn socket(&self) -> &Socket {
        &self.socket
    }

    /// Unwraps the socket after releasing any coroutine waiting on it. A TLS session is
    /// abandoned without notifying the peer.
    pub fn into_socket(self) -> Socket {
        release_fd(self.socket.as_raw_fd());
        let mut this = std::mem::ManuallyDrop::new(self);
        drop(this.tls.take());
        // SAFETY: `this` is never used or dropped again, so moving the socket out is sound.
        unsafe { std::ptr::read(&this.socket) }
    }

    /// Connects a new stream socket to `addr`.
    pub fn connect(addr: &SocketAddress, timeout: Option<Duration>) -> Result<CoSocket> {
        let socket = Socket::for_address(addr, SocketType::Stream)?;
        if !socket.connect(addr)? {
            wait_fd(socket.as_raw_fd(), Interest::WRITABLE, timeout)?;
            if let Some(err) = socket.take_error()? {
                return Err(err.into());
            }
        }
        Ok(CoSocket::from_socket(socket))
    }

    /// Connects to `addr` and completes a TLS handshake as the client, all within
    /// `timeout`. `server_name` is the host the certificate must name (see
    /// [`start_tls_client`](Self::start_tls_client)).
    pub fn connect_tls(
        addr: &SocketAddress,
        server_name: &str,
        tls: &ClientTls,
        timeout: Option<Duration>,
    ) -> Result<CoSocket> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut socket = CoSocket::connect(addr, timeout)?;
        socket.start_tls_client(tls, server_name, remaining(deadline)?)?;
        Ok(socket)
    }

    /// Switches this connected socket to TLS as the client and completes the handshake.
    /// `server_name` (a host name or IP address) is sent through SNI and, if `tls`
    /// verifies peers, must be named by the server's certificate.
    pub fn start_tls_client(
        &mut self,
        tls: &ClientTls,
        server_name: &str,
        timeout: Option<Duration>,
    ) -> Result<()> {
        self.check_not_tls()?;
        // SAFETY: the session is stored in `self.tls`, which is dropped (or taken) before
        // `self.socket` in every path.
        let session = unsafe { TlsSession::client(tls, server_name, &self.socket) }?;
        self.finish_handshake(session, timeout)
    }

    /// Switches this accepted socket to TLS as the server and completes the handshake.
    pub fn start_tls_server(&mut self, tls: &ServerTls, timeout: Option<Duration>) -> Result<()> {
        self.check_not_tls()?;
        // SAFETY: as in `start_tls_client`.
        let session = unsafe { TlsSession::server(tls, &self.socket) }?;
        self.finish_handshake(session, timeout)
    }

    fn check_not_tls(&self) -> Result<()> {
        if self.tls.is_some() {
            return Err(Error::new(ErrorKind::InvalidState, "TLS is already on"));
        }
        Ok(())
    }

    fn finish_handshake(&mut self, session: TlsSession, timeout: Option<Duration>) -> Result<()> {
        self.tls = Some(RefCell::new(session));
        let result = self.transfer(Interest::READABLE, timeout, |link| match link {
            Link::Tls(session) => session.handshake(),
            Link::Plain(_) => Ok(()),
        });
        if result.is_err() {
            self.tls = None;
        }
        result
    }

    /// Whether stream operations go through TLS.
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// What the TLS handshake negotiated, if this socket uses TLS.
    pub fn tls_info(&self) -> Option<TlsInfo> {
        self.tls
            .as_ref()
            .and_then(|cell| cell.try_borrow().ok()?.info())
    }

    /// A listening socket on `addr`.
    pub fn listen(addr: &SocketAddress, backlog: i32) -> Result<CoSocket> {
        Ok(CoSocket::from_socket(crate::network::socket::listen(
            addr, backlog, false,
        )?))
    }

    /// A datagram socket bound to `addr`.
    pub fn bind_datagram(addr: &SocketAddress) -> Result<CoSocket> {
        Ok(CoSocket::from_socket(
            crate::network::socket::bind_datagram(addr)?,
        ))
    }

    /// Runs a stream operation until it stops reporting `WouldBlock`, waiting for
    /// `interest` in between (or for whatever the TLS session needs, which may differ).
    fn transfer<T>(
        &self,
        interest: Interest,
        timeout: Option<Duration>,
        mut op: impl FnMut(Link<'_>) -> io::Result<T>,
    ) -> Result<T> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            let (result, wait_for) = match &self.tls {
                None => (op(Link::Plain(&self.socket)), interest),
                Some(cell) => {
                    // Coroutines only switch while waiting, and no borrow is held then.
                    let mut session = cell.try_borrow_mut().map_err(|_| {
                        Error::new(ErrorKind::InvalidState, "TLS session is in use")
                    })?;
                    let result = op(Link::Tls(&mut session));
                    if let Err(e) = &result
                        && e.kind() == io::ErrorKind::InvalidData
                    {
                        return Err(Error::new(ErrorKind::Protocol, e.to_string()));
                    }
                    (result, session.wants())
                }
            };
            match result {
                Ok(v) => return Ok(v),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    wait_fd(self.socket.as_raw_fd(), wait_for, remaining(deadline)?)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Runs `op` until it stops reporting `WouldBlock`, waiting for `interest` in between.
    fn retry<T>(
        &self,
        interest: Interest,
        timeout: Option<Duration>,
        mut op: impl FnMut(&Socket) -> io::Result<T>,
    ) -> Result<T> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            match op(&self.socket) {
                Ok(v) => return Ok(v),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    wait_fd(self.socket.as_raw_fd(), interest, remaining(deadline)?)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub fn accept(&self, timeout: Option<Duration>) -> Result<(CoSocket, SocketAddress)> {
        let timeout = timeout.or(self.read_timeout);
        let (socket, peer) = self.retry(Interest::READABLE, timeout, Socket::accept)?;
        Ok((CoSocket::from_socket(socket), peer))
    }

    /// Reads what is available (at least one byte); `Ok(0)` means the peer closed.
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.transfer(Interest::READABLE, self.read_timeout, |mut l| l.recv(buf))
    }

    /// Reads exactly `buf.len()` bytes. Fails with [`ErrorKind::Closed`] if the peer closes
    /// first.
    pub fn recv_exact(&self, buf: &mut [u8]) -> Result<()> {
        let deadline = self.read_timeout.map(|t| Instant::now() + t);
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.transfer(Interest::READABLE, remaining(deadline)?, |mut l| {
                l.recv(&mut buf[filled..])
            })?;
            if n == 0 {
                return Err(Error::new(ErrorKind::Closed, "peer closed mid-message"));
            }
            filled += n;
        }
        Ok(())
    }

    /// Appends whatever arrives (up to `max` bytes) to `buf`. Returns the count; 0 at EOF.
    pub fn recv_into(&self, buf: &mut ByteBuffer, max: usize) -> Result<usize> {
        self.transfer(Interest::READABLE, self.read_timeout, |mut l| {
            buf.fill_with(max, |space| l.recv(space))
        })
    }

    /// Reads until `decoder` yields a message. Returns `None` if the peer closes cleanly
    /// between messages; an EOF inside a message is an error.
    pub fn recv_message<D: Decoder>(
        &self,
        decoder: &mut D,
        buf: &mut ByteBuffer,
    ) -> Result<Option<D::Item>> {
        loop {
            if let Some(item) = decoder.decode(buf)? {
                return Ok(Some(item));
            }
            if self.recv_into(buf, 64 * 1024)? == 0 {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(Error::new(ErrorKind::Closed, "peer closed mid-message"));
            }
        }
    }

    /// Writes some of `data`; returns how much.
    pub fn send(&self, data: &[u8]) -> Result<usize> {
        self.transfer(Interest::WRITABLE, self.write_timeout, |mut l| l.send(data))
    }

    /// Writes all of `data`.
    pub fn send_all(&self, mut data: &[u8]) -> Result<()> {
        let deadline = self.write_timeout.map(|t| Instant::now() + t);
        while !data.is_empty() {
            let n = self.transfer(Interest::WRITABLE, remaining(deadline)?, |mut l| {
                l.send(data)
            })?;
            data = &data[n..];
        }
        Ok(())
    }

    /// Writes all of several buffers with gathered writes.
    pub fn send_all_vectored(&self, parts: &[&[u8]]) -> Result<()> {
        let deadline = self.write_timeout.map(|t| Instant::now() + t);
        let mut parts: Vec<&[u8]> = parts.iter().copied().filter(|p| !p.is_empty()).collect();
        let mut first = 0;
        while first < parts.len() {
            let slices: Vec<IoSlice<'_>> = parts[first..].iter().map(|p| IoSlice::new(p)).collect();
            let mut n = self.transfer(Interest::WRITABLE, remaining(deadline)?, |mut l| {
                l.send_vectored(&slices)
            })?;
            while n > 0 && first < parts.len() {
                let take = n.min(parts[first].len());
                parts[first] = &parts[first][take..];
                n -= take;
                if parts[first].is_empty() {
                    first += 1;
                }
            }
        }
        Ok(())
    }

    /// Streams `len` bytes of `file` from `offset`, zero-copy where possible (not over TLS).
    pub fn send_file(&self, file: &std::fs::File, mut offset: u64, len: u64) -> Result<()> {
        let end = offset + len;
        while offset < end {
            let n = self.transfer(Interest::WRITABLE, self.write_timeout, |mut l| {
                l.send_file(file, offset, (end - offset).min(usize::MAX as u64) as usize)
            })?;
            if n == 0 {
                return Err(Error::new(ErrorKind::Closed, "file ended before the range"));
            }
            offset += n as u64;
        }
        Ok(())
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddress)> {
        self.retry(Interest::READABLE, self.read_timeout, |s| s.recv_from(buf))
    }

    pub fn send_to(&self, data: &[u8], addr: &SocketAddress) -> Result<usize> {
        let deadline = self.write_timeout.map(|t| Instant::now() + t);
        loop {
            match self.socket.send_to(data, addr) {
                Err(e) if e.io_error().map(io::Error::kind) == Some(io::ErrorKind::WouldBlock) => {
                    wait_fd(
                        self.socket.as_raw_fd(),
                        Interest::WRITABLE,
                        remaining(deadline)?,
                    )?;
                }
                other => return other,
            }
        }
    }

    /// Shuts down one or both directions. Over TLS, closing the write side first sends
    /// close_notify (best effort).
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        if how != Shutdown::Read
            && let Some(cell) = &self.tls
            && let Ok(mut session) = cell.try_borrow_mut()
        {
            session.close_notify();
        }
        Ok(self.socket.shutdown(how)?)
    }

    pub fn local_address(&self) -> Result<SocketAddress> {
        Ok(self.socket.local_address()?)
    }

    pub fn peer_address(&self) -> Result<SocketAddress> {
        Ok(self.socket.peer_address()?)
    }

    /// Closes the socket, waking any coroutine blocked on it with [`ErrorKind::Closed`].
    /// A TLS session sends close_notify first (best effort).
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for CoSocket {
    fn drop(&mut self) {
        if let Some(cell) = &mut self.tls {
            cell.get_mut().close_notify();
        }
        release_fd(self.socket.as_raw_fd());
    }
}

/// The transport a stream operation runs on.
enum Link<'a> {
    Plain(&'a Socket),
    Tls(&'a mut TlsSession),
}

impl Link<'_> {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Link::Plain(s) => s.recv(buf),
            Link::Tls(t) => t.read(buf),
        }
    }

    fn send(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            Link::Plain(s) => s.send(data),
            Link::Tls(t) => t.write(data),
        }
    }

    fn send_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Link::Plain(s) => s.send_vectored(bufs),
            Link::Tls(t) => t.write_vectored(bufs),
        }
    }

    fn send_file(&mut self, file: &std::fs::File, offset: u64, len: usize) -> io::Result<usize> {
        match self {
            Link::Plain(s) => crate::os::sendfile::send_file(s.as_fd(), file, offset, len),
            Link::Tls(t) => t.send_file(file, offset, len),
        }
    }
}

impl AsRawFd for CoSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl AsFd for CoSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::super::runtime::{run, spawn};
    use super::*;
    use crate::protocol::framing::{Delimited, LengthPrefixed, Width};
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn tcp_echo_server_and_clients() {
        let replies = Rc::new(RefCell::new(Vec::new()));
        let r = Rc::clone(&replies);
        run(move || {
            let server = CoSocket::listen(&"127.0.0.1:0".parse().unwrap(), 16).unwrap();
            let addr = server.local_address().unwrap();
            spawn(move || {
                for _ in 0..3 {
                    let (conn, _) = server.accept(Some(Duration::from_secs(5))).unwrap();
                    spawn(move || {
                        let mut buf = ByteBuffer::new();
                        let mut lines = Delimited::new(&b"\n"[..], 1024);
                        while let Some(line) = conn.recv_message(&mut lines, &mut buf).unwrap() {
                            let mut reply = line.to_ascii_uppercase();
                            reply.push(b'\n');
                            conn.send_all(&reply).unwrap();
                        }
                    })
                    .unwrap();
                }
            })
            .unwrap();

            let wg = super::super::sync::WaitGroup::new();
            for i in 0..3 {
                wg.add(1);
                let (addr, wg, r) = (addr.clone(), wg.clone(), Rc::clone(&r));
                spawn(move || {
                    let client = CoSocket::connect(&addr, Some(Duration::from_secs(5))).unwrap();
                    client
                        .send_all_vectored(&[b"hello ", format!("{i}\n").as_bytes()])
                        .unwrap();
                    let mut buf = ByteBuffer::new();
                    let mut lines = Delimited::new(&b"\n"[..], 1024);
                    let line = client.recv_message(&mut lines, &mut buf).unwrap().unwrap();
                    r.borrow_mut().push(String::from_utf8(line).unwrap());
                    wg.done().unwrap();
                })
                .unwrap();
            }
            wg.wait(Some(Duration::from_secs(5))).unwrap();
        })
        .unwrap();
        let mut replies = replies.borrow().clone();
        replies.sort();
        assert_eq!(replies, ["HELLO 0", "HELLO 1", "HELLO 2"]);
    }

    #[test]
    fn timeouts_and_close_wake_waiters() {
        run(|| {
            let (a, b) = Socket::pair(SocketType::Stream).unwrap();
            let mut a = CoSocket::from_socket(a);
            a.read_timeout = Some(Duration::from_millis(10));
            let mut buf = [0u8; 4];
            let err = a.recv(&mut buf).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::TimedOut);

            // Framed exchange over the pair.
            let b = CoSocket::from_socket(b);
            let codec = LengthPrefixed::simple(Width::U16, 1024);
            b.send_all(&codec.encode(b"framed").unwrap()).unwrap();
            a.read_timeout = Some(Duration::from_secs(5));
            let mut framed = codec.clone();
            let msg = a.recv_message(&mut framed, &mut ByteBuffer::new()).unwrap();
            assert_eq!(msg.as_deref(), Some(&b"framed"[..]));

            // A coroutine blocked reading `a` is released when `a` is closed.
            a.read_timeout = None;
            let a = Rc::new(RefCell::new(Some(a)));
            let a2 = Rc::clone(&a);
            let reader = spawn(move || {
                let guard = a2.borrow();
                let sock = guard.as_ref().unwrap();
                let fd = sock.as_raw_fd();
                drop(guard);
                let err = wait_fd(fd, Interest::READABLE, None).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::Closed);
            })
            .unwrap();
            a.borrow_mut().take().unwrap().close();
            super::super::runtime::yield_now().unwrap();
            assert!(!super::super::runtime::exists(reader));
            drop(b);
        })
        .unwrap();
    }

    #[test]
    fn tls_echo_file_and_rejection() {
        use crate::network::tls::test_pki;
        let pki = test_pki::generate();
        let server_tls = test_pki::server_options(&pki)
            .with_alpn(["echo/1"])
            .build()
            .unwrap();
        let client_tls = test_pki::client_options(&pki)
            .with_alpn(["echo/1"])
            .build()
            .unwrap();
        let file_path = pki.dir.join("payload.bin");
        let file_data: Vec<u8> = (0..40_000u32).map(|i| (i * 7) as u8).collect();
        std::fs::write(&file_path, &file_data).unwrap();
        let timeout = Some(Duration::from_secs(5));

        run(move || {
            let listener = CoSocket::listen(&"127.0.0.1:0".parse().unwrap(), 8).unwrap();
            let addr = listener.local_address().unwrap();
            spawn(move || {
                // 1: echo until the client half-closes. 2: send a file. 3: a failed handshake.
                for round in 0..3 {
                    let (mut conn, _) = listener.accept(timeout).unwrap();
                    let handshake = conn.start_tls_server(&server_tls, timeout);
                    if round == 2 {
                        assert!(handshake.is_err());
                        continue;
                    }
                    handshake.unwrap();
                    let info = conn.tls_info().unwrap();
                    assert_eq!(info.alpn.as_deref(), Some(&b"echo/1"[..]));
                    if round == 1 {
                        let file = std::fs::File::open(&file_path).unwrap();
                        conn.send_file(&file, 0, 40_000).unwrap();
                        continue;
                    }
                    let mut buf = ByteBuffer::new();
                    while conn.recv_into(&mut buf, 64 * 1024).unwrap() > 0 {
                        conn.send_all(buf.as_slice()).unwrap();
                        buf.clear();
                    }
                }
            })
            .unwrap();

            // A writer coroutine and this reader share one TLS socket.
            let client =
                Rc::new(CoSocket::connect_tls(&addr, "localhost", &client_tls, timeout).unwrap());
            assert!(client.is_tls());
            assert_eq!(client.tls_info().unwrap().version, "TLSv1.3");
            let payload: Rc<Vec<u8>> = Rc::new((0..200_000u32).map(|i| i as u8).collect());
            let (c, p) = (Rc::clone(&client), Rc::clone(&payload));
            spawn(move || {
                c.send_all_vectored(&[&p[..10], &p[10..]]).unwrap();
                c.shutdown(Shutdown::Write).unwrap();
            })
            .unwrap();
            let mut echoed = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = client.recv(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                echoed.extend_from_slice(&buf[..n]);
            }
            assert_eq!(echoed, *payload);

            let file_client =
                CoSocket::connect_tls(&addr, "127.0.0.1", &client_tls, timeout).unwrap();
            let mut received = vec![0u8; 40_000];
            file_client.recv_exact(&mut received).unwrap();
            assert_eq!(received, file_data);

            let err =
                CoSocket::connect_tls(&addr, "example.test", &client_tls, timeout).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Protocol);
        })
        .unwrap();
    }

    #[test]
    fn udp_roundtrip() {
        run(|| {
            let a = CoSocket::bind_datagram(&"127.0.0.1:0".parse().unwrap()).unwrap();
            let b = CoSocket::bind_datagram(&"127.0.0.1:0".parse().unwrap()).unwrap();
            let b_addr = b.local_address().unwrap();
            spawn(move || {
                let mut buf = [0u8; 16];
                let (n, from) = b.recv_from(&mut buf).unwrap();
                b.send_to(&buf[..n], &from).unwrap();
            })
            .unwrap();
            a.send_to(b"ping", &b_addr).unwrap();
            let mut buf = [0u8; 16];
            let (n, _) = a.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"ping");
        })
        .unwrap();
    }
}
