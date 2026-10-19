//! An event-driven stream client: connects without blocking, frames incoming data, buffers
//! outgoing data, and reports everything through [`ClientHandler`] callbacks on a
//! [`Reactor`].
//!
//! With [`ClientOptions::tls`] set, the client runs a TLS handshake after connecting and
//! reports `on_connect` only once it has finished; handlers see plaintext throughout.
//!
//! For sequential code, coroutine sockets ([`crate::coroutine::CoSocket`]) are usually more
//! convenient; this client suits callback-style code and embedding layers.

use std::cell::RefCell;
use std::io;
use std::os::fd::AsRawFd;
use std::rc::Rc;
use std::time::Duration;

use super::tls::{ClientTls, TlsInfo, TlsSession};
use super::{Socket, SocketAddress, SocketType};
use crate::core::buffer::{Segment, WriteQueue};
use crate::core::bytes::ByteBuffer;
use crate::core::timer::TimerId;
use crate::core::{Error, ErrorKind, Result};
use crate::protocol::framing::Decoder;
use crate::reactor::{Interest, Reactor, Readiness, Token};

/// Callbacks of a [`Client`]. All have no-op defaults.
#[allow(unused_variables)]
pub trait ClientHandler: 'static {
    fn on_connect(&mut self, client: &Client, reactor: &mut Reactor) {}
    /// A message (per the decoder), or raw bytes without one.
    fn on_receive(&mut self, client: &Client, reactor: &mut Reactor, data: Vec<u8>) {}
    /// Connecting failed, or the connection broke.
    fn on_error(&mut self, client: &Client, reactor: &mut Reactor, error: Error) {}
    /// The connection is closed (after `on_error`, if any). Called once.
    fn on_close(&mut self, client: &Client, reactor: &mut Reactor) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Connecting,
    /// TCP is up; the TLS handshake is running.
    Handshaking,
    Connected,
    Closed,
}

struct State {
    // Declared before `socket` so it is dropped first: it does I/O on the socket's descriptor.
    tls: Option<TlsSession>,
    /// Context and server name for the session to start once TCP connects.
    tls_pending: Option<(ClientTls, String)>,
    socket: Socket,
    token: Option<Token>,
    phase: Phase,
    input: ByteBuffer,
    output: WriteQueue,
    decoder: Option<Box<dyn Decoder<Item = Vec<u8>>>>,
    interest: Interest,
    close_after_flush: bool,
    connect_timer: Option<TimerId>,
    handler: Option<Box<dyn ClientHandler>>,
    /// Notifications raised while the handler was busy, delivered when it returns.
    notes: Vec<Note>,
    max_output: u64,
}

enum Note {
    Error(Error),
    Close,
}

/// A handle to the client; clones refer to the same connection.
///
/// The reactor owns the connection while it is open, so it keeps running (and calling its
/// handler) after every handle is dropped, until either side closes it. Keep a handle only
/// to send or close from outside the handler's callbacks.
#[derive(Clone)]
pub struct Client {
    state: Rc<RefCell<State>>,
}

/// Options for [`Client::connect`].
pub struct ClientOptions {
    pub connect_timeout: Option<Duration>,
    /// Splits input into messages; `None` delivers raw reads.
    pub decoder: Option<Box<dyn Decoder<Item = Vec<u8>>>>,
    /// Pending output beyond which `send` fails with `Full`.
    pub max_output: usize,
    /// Run TLS over the connection. `connect_timeout` then covers the handshake too.
    pub tls: Option<ClientTls>,
    /// The host the server's certificate must name, also sent through SNI. Defaults to the
    /// IP address connected to; required for TLS over Unix sockets.
    pub server_name: Option<String>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            connect_timeout: Some(Duration::from_secs(10)),
            decoder: None,
            max_output: 8 * 1024 * 1024,
            tls: None,
            server_name: None,
        }
    }
}

/// TLS failures read as protocol errors; everything else keeps its I/O detail.
fn io_failure(e: io::Error) -> Error {
    if e.kind() == io::ErrorKind::InvalidData {
        Error::new(ErrorKind::Protocol, e.to_string())
    } else {
        e.into()
    }
}

impl Client {
    /// Starts connecting to `addr`; `handler` hears about the outcome.
    pub fn connect(
        reactor: &mut Reactor,
        addr: &SocketAddress,
        options: ClientOptions,
        handler: impl ClientHandler,
    ) -> Result<Client> {
        let tls_pending = match options.tls {
            None => None,
            Some(tls) => {
                let name = match (options.server_name, addr.as_inet()) {
                    (Some(name), _) => name,
                    (None, Some(inet)) => inet.ip().to_string(),
                    (None, None) => {
                        return Err(Error::new(
                            ErrorKind::InvalidArgument,
                            "TLS over a Unix socket needs a server_name",
                        ));
                    }
                };
                Some((tls, name))
            }
        };
        let socket = Socket::for_address(addr, SocketType::Stream)?;
        if addr.as_inet().is_some() {
            let _ = socket.set_nodelay(true);
        }
        let connected = socket.connect(addr)?;
        let client = Client {
            state: Rc::new(RefCell::new(State {
                tls: None,
                tls_pending,
                socket,
                token: None,
                phase: Phase::Connecting,
                input: ByteBuffer::new(),
                output: WriteQueue::default(),
                decoder: options.decoder,
                interest: Interest::WRITABLE,
                close_after_flush: false,
                connect_timer: None,
                handler: Some(Box::new(handler)),
                notes: Vec::new(),
                max_output: options.max_output as u64,
            })),
        };
        let fd = client.state.borrow().socket.as_raw_fd();
        // A strong reference: the registration keeps the connection alive, and closing
        // removes the registration, which releases it. With only a weak reference, dropping
        // the last handle would close the socket but leave the registration behind, and
        // `Reactor::run` would never return.
        let state = Rc::clone(&client.state);
        let token = reactor.add(fd, Interest::WRITABLE, move |r, _, readiness| {
            Client {
                state: Rc::clone(&state),
            }
            .on_ready(r, readiness);
        })?;
        client.state.borrow_mut().token = Some(token);
        if let Some(timeout) = options.connect_timeout
            && !connected
        {
            let weak = Rc::downgrade(&client.state);
            let timer = reactor.after(timeout, move |r| {
                if let Some(state) = weak.upgrade() {
                    let c = Client { state };
                    let phase = c.state.borrow().phase;
                    if matches!(phase, Phase::Connecting | Phase::Handshaking) {
                        c.fail(r, Error::new(ErrorKind::TimedOut, "connect timed out"));
                    }
                }
            });
            client.state.borrow_mut().connect_timer = Some(timer);
        }
        Ok(client)
    }

    fn with_handler(
        &self,
        r: &mut Reactor,
        f: impl FnOnce(&mut dyn ClientHandler, &Client, &mut Reactor),
    ) {
        let handler = self.state.borrow_mut().handler.take();
        if let Some(mut handler) = handler {
            f(handler.as_mut(), self, r);
            let mut state = self.state.borrow_mut();
            if state.handler.is_none() {
                state.handler = Some(handler);
            }
        }
        self.deliver_notes(r);
    }

    /// Raises `note` now, or after the callback in progress returns.
    fn notify(&self, r: &mut Reactor, note: Note) {
        self.state.borrow_mut().notes.push(note);
        self.deliver_notes(r);
    }

    fn deliver_notes(&self, r: &mut Reactor) {
        loop {
            let (note, handler) = {
                let mut s = self.state.borrow_mut();
                if s.handler.is_none() || s.notes.is_empty() {
                    return;
                }
                (s.notes.remove(0), s.handler.take())
            };
            if let Some(mut handler) = handler {
                match note {
                    Note::Error(e) => handler.on_error(self, r, e),
                    Note::Close => handler.on_close(self, r),
                }
                let mut s = self.state.borrow_mut();
                if s.handler.is_none() {
                    s.handler = Some(handler);
                }
            }
        }
    }

    fn on_ready(&self, r: &mut Reactor, readiness: Readiness) {
        let phase = self.state.borrow().phase;
        match phase {
            Phase::Connecting => self.finish_connect(r),
            Phase::Handshaking => self.handshake(r),
            Phase::Connected if self.state.borrow().tls.is_some() => {
                // Either readiness can unblock either direction: a TLS read may have to
                // send and a write may have to receive.
                self.flush(r);
                self.read(r);
                self.update_interest(r);
            }
            Phase::Connected => {
                if readiness.writable {
                    self.flush(r);
                }
                if readiness.readable || readiness.hangup || readiness.error {
                    self.read(r);
                }
            }
            Phase::Closed => {}
        }
    }

    fn finish_connect(&self, r: &mut Reactor) {
        let error = self.state.borrow().socket.take_error();
        match error {
            Ok(None) => {
                let started = {
                    let mut s = self.state.borrow_mut();
                    let s = &mut *s;
                    s.tls_pending.take().map(|(tls, name)| {
                        // SAFETY: the session is stored in `State::tls`, declared (and so
                        // dropped) before the socket it uses.
                        let session = unsafe { TlsSession::client(&tls, &name, &s.socket) }?;
                        s.tls = Some(session);
                        s.phase = Phase::Handshaking;
                        Ok(())
                    })
                };
                match started {
                    Some(Ok(())) => self.handshake(r),
                    Some(Err(e)) => self.fail(r, e),
                    None => self.connected(r),
                }
            }
            Ok(Some(err)) | Err(err) => self.fail(r, err.into()),
        }
    }

    fn handshake(&self, r: &mut Reactor) {
        let result = match &mut self.state.borrow_mut().tls {
            Some(session) => session.handshake(),
            None => Ok(()),
        };
        match result {
            Ok(()) => self.connected(r),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.update_interest(r),
            Err(e) => self.fail(r, io_failure(e)),
        }
    }

    fn connected(&self, r: &mut Reactor) {
        let timer = {
            let mut s = self.state.borrow_mut();
            s.phase = Phase::Connected;
            s.connect_timer.take()
        };
        if let Some(timer) = timer {
            r.cancel_timer(timer);
        }
        self.update_interest(r);
        self.with_handler(r, |h, c, r| h.on_connect(c, r));
        self.flush(r);
    }

    fn read(&self, r: &mut Reactor) {
        let mut messages = Vec::new();
        let mut eof = false;
        let mut error = None;
        {
            let mut s = self.state.borrow_mut();
            let s = &mut *s;
            // Reading until the socket would block also drains plaintext OpenSSL holds.
            loop {
                let socket = &s.socket;
                let read = match &mut s.tls {
                    Some(tls) => s.input.fill_with(16 * 1024, |space| tls.read(space)),
                    None => s.input.fill_with(64 * 1024, |space| socket.recv(space)),
                };
                match read {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        error = Some(io_failure(e));
                        break;
                    }
                }
            }
            match &mut s.decoder {
                None => {
                    if !s.input.is_empty() {
                        messages.push(s.input.as_slice().to_vec());
                        s.input.clear();
                    }
                }
                Some(decoder) => loop {
                    match decoder.decode(&mut s.input) {
                        Ok(Some(m)) => messages.push(m),
                        Ok(None) => break,
                        Err(e) => {
                            error = Some(e);
                            break;
                        }
                    }
                },
            }
        }
        for message in messages {
            self.with_handler(r, |h, c, r| h.on_receive(c, r, message));
        }
        if let Some(err) = error {
            self.fail(r, err);
        } else if eof {
            self.close_now(r);
        }
    }

    fn update_interest(&self, r: &mut Reactor) {
        let mut s = self.state.borrow_mut();
        let Some(token) = s.token else { return };
        let mut want = match (s.phase, &s.tls) {
            (Phase::Connecting, _) => Interest::WRITABLE,
            (Phase::Handshaking, Some(tls)) => tls.wants(),
            (Phase::Handshaking, None) | (Phase::Connected, _) => Interest::READABLE,
            (Phase::Closed, _) => return,
        };
        if s.phase == Phase::Connected {
            if !s.output.is_empty() {
                want = want | Interest::WRITABLE;
            }
            // A TLS read that has to send.
            if let Some(tls) = &s.tls
                && tls.wants() == Interest::WRITABLE
            {
                want = want | Interest::WRITABLE;
            }
        }
        if want != s.interest && r.set_interest(token, want).is_ok() {
            s.interest = want;
        }
    }

    fn flush(&self, r: &mut Reactor) {
        let mut failed = None;
        let mut done_closing = false;
        {
            let mut s = self.state.borrow_mut();
            if s.phase != Phase::Connected {
                return;
            }
            while let Some(segment) = s.output.front() {
                if !matches!(segment, Segment::Bytes { .. }) {
                    s.output.pop_front();
                    continue;
                }
                let sent = {
                    let s = &mut *s;
                    let slices = s.output.io_slices(64);
                    match &mut s.tls {
                        Some(tls) => tls.write_vectored(&slices),
                        None => s.socket.send_vectored(&slices),
                    }
                };
                match sent {
                    Ok(n) => {
                        s.output.advance(n as u64);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        failed = Some(io_failure(e));
                        break;
                    }
                }
            }
            if s.output.is_empty() && s.close_after_flush {
                done_closing = true;
            }
        }
        if let Some(err) = failed {
            self.fail(r, err);
        } else if done_closing {
            self.close_now(r);
        } else {
            self.update_interest(r);
        }
    }

    fn fail(&self, r: &mut Reactor, error: Error) {
        if self.state.borrow().phase == Phase::Closed {
            return;
        }
        self.notify(r, Note::Error(error));
        self.close_now(r);
    }

    fn close_now(&self, r: &mut Reactor) {
        let (token, timer) = {
            let mut s = self.state.borrow_mut();
            if s.phase == Phase::Closed {
                return;
            }
            s.phase = Phase::Closed;
            (s.token.take(), s.connect_timer.take())
        };
        if let Some(token) = token {
            let _ = r.remove(token);
        }
        if let Some(timer) = timer {
            r.cancel_timer(timer);
        }
        {
            let mut s = self.state.borrow_mut();
            if let Some(tls) = &mut s.tls {
                tls.close_notify();
            }
            let _ = s.socket.shutdown(std::net::Shutdown::Both);
        }
        self.notify(r, Note::Close);
    }

    /// Queues `data` (sent once connected).
    pub fn send(&self, reactor: &mut Reactor, data: &[u8]) -> Result<()> {
        {
            let mut s = self.state.borrow_mut();
            if s.phase == Phase::Closed || s.close_after_flush {
                return Err(Error::new(ErrorKind::Closed, "client is closed"));
            }
            if s.output.pending() + data.len() as u64 > s.max_output {
                return Err(Error::new(ErrorKind::Full, "output buffer full"));
            }
            s.output.push_bytes(data);
        }
        self.flush(reactor);
        Ok(())
    }

    /// Closes after queued data is sent.
    pub fn close(&self, reactor: &mut Reactor) {
        let empty = {
            let mut s = self.state.borrow_mut();
            s.close_after_flush = true;
            s.output.is_empty() || s.phase != Phase::Connected
        };
        if empty {
            self.close_now(reactor);
        }
    }

    pub fn is_connected(&self) -> bool {
        self.state.borrow().phase == Phase::Connected
    }

    pub fn is_closed(&self) -> bool {
        self.state.borrow().phase == Phase::Closed
    }

    /// What the TLS handshake negotiated, once connected over TLS.
    pub fn tls_info(&self) -> Option<TlsInfo> {
        self.state.borrow().tls.as_ref().and_then(TlsSession::info)
    }

    pub fn local_address(&self) -> Result<SocketAddress> {
        Ok(self.state.borrow().socket.local_address()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::framing::Delimited;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    #[derive(Default)]
    struct Recorder {
        log: Rc<RefCell<Vec<String>>>,
    }

    impl ClientHandler for Recorder {
        fn on_connect(&mut self, client: &Client, r: &mut Reactor) {
            self.log.borrow_mut().push("connect".into());
            client.send(r, b"one\ntwo\n").unwrap();
        }
        fn on_receive(&mut self, client: &Client, r: &mut Reactor, data: Vec<u8>) {
            let line = String::from_utf8(data).unwrap();
            if line == "TWO" {
                client.close(r);
            }
            self.log.borrow_mut().push(line);
        }
        fn on_error(&mut self, _c: &Client, _r: &mut Reactor, error: Error) {
            self.log
                .borrow_mut()
                .push(format!("error {:?}", error.kind()));
        }
        fn on_close(&mut self, _c: &Client, _r: &mut Reactor) {
            self.log.borrow_mut().push("close".into());
        }
    }

    #[test]
    fn connect_exchange_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = SocketAddress::from(listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut writer = s.try_clone().unwrap();
            for line in BufReader::new(s).lines() {
                writer
                    .write_all(format!("{}\n", line.unwrap().to_uppercase()).as_bytes())
                    .unwrap();
            }
        });
        let mut reactor = Reactor::new().unwrap();
        let log = Rc::new(RefCell::new(Vec::new()));
        let options = ClientOptions {
            decoder: Some(Box::new(Delimited::new(&b"\n"[..], 1024))),
            ..ClientOptions::default()
        };
        let client = Client::connect(
            &mut reactor,
            &addr,
            options,
            Recorder {
                log: Rc::clone(&log),
            },
        )
        .unwrap();
        reactor.run().unwrap();
        server.join().unwrap();
        assert_eq!(*log.borrow(), ["connect", "ONE", "TWO", "close"]);
        assert!(client.is_closed());
    }

    #[test]
    fn connection_outlives_dropped_handles() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = SocketAddress::from(listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut writer = s.try_clone().unwrap();
            for line in BufReader::new(s).lines() {
                writer
                    .write_all(format!("{}\n", line.unwrap().to_uppercase()).as_bytes())
                    .unwrap();
            }
        });
        let mut reactor = Reactor::new().unwrap();
        let log = Rc::new(RefCell::new(Vec::new()));
        let options = ClientOptions {
            decoder: Some(Box::new(Delimited::new(&b"\n"[..], 1024))),
            ..ClientOptions::default()
        };
        let recorder = Recorder {
            log: Rc::clone(&log),
        };
        let weak = Rc::downgrade(
            &Client::connect(&mut reactor, &addr, options, recorder)
                .unwrap()
                .state,
        );
        // No handle is kept: the exchange still completes and `run` returns.
        reactor.run().unwrap();
        server.join().unwrap();
        assert_eq!(*log.borrow(), ["connect", "ONE", "TWO", "close"]);
        assert!(weak.upgrade().is_none(), "state freed once closed");
    }

    #[test]
    fn refused_connection_reports_error() {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = SocketAddress::from(probe.local_addr().unwrap());
        drop(probe);
        let mut reactor = Reactor::new().unwrap();
        let log = Rc::new(RefCell::new(Vec::new()));
        match Client::connect(
            &mut reactor,
            &addr,
            ClientOptions::default(),
            Recorder {
                log: Rc::clone(&log),
            },
        ) {
            // Some systems refuse synchronously.
            Err(e) => assert_eq!(
                e.io_error().map(io::Error::kind),
                Some(io::ErrorKind::ConnectionRefused)
            ),
            Ok(_client) => {
                reactor.run().unwrap();
                assert_eq!(*log.borrow(), ["error Io", "close"]);
            }
        }
    }

    /// A blocking TLS server thread: runs `serve` on the first accepted connection.
    fn tls_server(
        pki: &crate::network::tls::test_pki::Pki,
        serve: impl FnOnce(openssl::ssl::SslStream<std::net::TcpStream>) + Send + 'static,
    ) -> (SocketAddress, std::thread::JoinHandle<()>) {
        use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file(&pki.key, SslFiletype::PEM)
            .unwrap();
        acceptor.set_certificate_chain_file(&pki.cert).unwrap();
        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = SocketAddress::from(listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            if let Ok(stream) = acceptor.accept(tcp) {
                serve(stream);
            }
        });
        (addr, thread)
    }

    fn tls_options(pki: &crate::network::tls::test_pki::Pki) -> ClientOptions {
        ClientOptions {
            tls: Some(
                crate::network::tls::test_pki::client_options(pki)
                    .build()
                    .unwrap(),
            ),
            ..ClientOptions::default()
        }
    }

    #[test]
    fn tls_exchange_and_bulk_download() {
        let pki = crate::network::tls::test_pki::generate();
        let (addr, server) = tls_server(&pki, |stream| {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 0 {
                let reply = format!("{}\n", line.trim_end().to_uppercase());
                reader.get_mut().write_all(reply.as_bytes()).unwrap();
                line.clear();
            }
        });
        let mut reactor = Reactor::new().unwrap();
        let log = Rc::new(RefCell::new(Vec::new()));
        let options = ClientOptions {
            decoder: Some(Box::new(Delimited::new(&b"\n"[..], 1024))),
            ..tls_options(&pki)
        };
        let recorder = Recorder {
            log: Rc::clone(&log),
        };
        let client = Client::connect(&mut reactor, &addr, options, recorder).unwrap();
        reactor.run().unwrap();
        server.join().unwrap();
        assert_eq!(*log.borrow(), ["connect", "ONE", "TWO", "close"]);
        assert_eq!(client.tls_info().unwrap().version, "TLSv1.3");

        // Many records, then the server closes.
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 249) as u8).collect();
        let expected = payload.clone();
        let (addr, server) = tls_server(&pki, move |mut stream| {
            stream.write_all(&payload).unwrap();
            stream.shutdown().unwrap();
        });
        struct Collect(Rc<RefCell<(Vec<u8>, bool)>>);
        impl ClientHandler for Collect {
            fn on_receive(&mut self, _c: &Client, _r: &mut Reactor, data: Vec<u8>) {
                self.0.borrow_mut().0.extend_from_slice(&data);
            }
            fn on_close(&mut self, _c: &Client, _r: &mut Reactor) {
                self.0.borrow_mut().1 = true;
            }
        }
        let got = Rc::new(RefCell::new((Vec::new(), false)));
        let mut reactor = Reactor::new().unwrap();
        Client::connect(
            &mut reactor,
            &addr,
            tls_options(&pki),
            Collect(Rc::clone(&got)),
        )
        .unwrap();
        reactor.run().unwrap();
        server.join().unwrap();
        let got = got.borrow();
        assert!(
            got.0 == expected,
            "download differs ({} bytes)",
            got.0.len()
        );
        assert!(got.1, "on_close after EOF");
    }

    #[test]
    fn tls_rejections() {
        let pki = crate::network::tls::test_pki::generate();
        let (addr, server) = tls_server(&pki, |_| {});
        let mut reactor = Reactor::new().unwrap();
        let log = Rc::new(RefCell::new(Vec::new()));
        let options = ClientOptions {
            server_name: Some("example.test".into()),
            ..tls_options(&pki)
        };
        let recorder = Recorder {
            log: Rc::clone(&log),
        };
        Client::connect(&mut reactor, &addr, options, recorder).unwrap();
        reactor.run().unwrap();
        server.join().unwrap();
        assert_eq!(*log.borrow(), ["error Protocol", "close"]);

        let unix = SocketAddress::unix(pki.dir.join("none.sock"));
        let err = Client::connect(&mut reactor, &unix, tls_options(&pki), Recorder::default())
            .err()
            .unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    }
}
