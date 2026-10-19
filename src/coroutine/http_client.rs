//! HTTP/1.1 and WebSocket clients for coroutines, in cleartext or over TLS.
//!
//! An [`HttpClient`] keeps one connection to a host and reuses it while the server allows;
//! a request on a reused connection that the server had already closed is retried once on a
//! fresh connection. [`HttpClient::websocket`] upgrades to a [`WsClient`]. A client given a
//! [`ClientTls`] with [`HttpClient::with_tls`] speaks HTTPS (and WebSocket over TLS).

use std::net::IpAddr;
use std::time::Duration;

use super::socket::CoSocket;
use super::system;
use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, Result};
use crate::network::SocketAddress;
use crate::network::tls::ClientTls;
use crate::protocol::http::{Limits, Method, Request, Response, ResponseParser};
use crate::protocol::websocket::{
    self, Assembler, CloseReason, FrameDecoder, Message, Opcode, Role, close_code, encode_frame,
};

/// How long [`WsClient::close`] waits for the server's `Close`.
pub const CLOSE_WAIT: Duration = Duration::from_secs(5);

/// A connection-reusing client for one host.
pub struct HttpClient {
    host: String,
    port: u16,
    pub timeout: Duration,
    pub limits: Limits,
    /// Extra headers added to every request (unless the request sets them).
    pub default_headers: Vec<(String, String)>,
    tls: Option<ClientTls>,
    conn: Option<(CoSocket, ByteBuffer)>,
}

/// The parts of an `http://` or `https://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// `https`.
    pub secure: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
}

/// Splits `http[s]://host[:port]/path` into its parts.
pub fn parse_url(url: &str) -> Result<Url> {
    let bad = || {
        Error::new(
            ErrorKind::InvalidArgument,
            format!("unsupported URL {url:?}"),
        )
    };
    let (secure, rest) = match url.split_once("://") {
        Some(("http", rest)) => (false, rest),
        Some(("https", rest)) => (true, rest),
        _ => return Err(bad()),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']').ok_or_else(bad)?;
        let port = after
            .strip_prefix(':')
            .map(str::parse)
            .transpose()
            .map_err(|_| bad())?;
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port.parse().map_err(|_| bad())?)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(bad());
    }
    Ok(Url {
        secure,
        host: host.to_owned(),
        port: port.unwrap_or(if secure { 443 } else { 80 }),
        path: path.to_owned(),
    })
}

/// One-shot GET of an `http://` or `https://` URL. HTTPS verifies the server against
/// OpenSSL's default trust store.
pub fn get(url: &str) -> Result<Response> {
    let url = parse_url(url)?;
    let mut client = HttpClient::new(&url.host, url.port);
    if url.secure {
        client = client.with_tls(ClientTls::new()?);
    }
    client.request(Request::new(Method::Get, url.path))
}

impl HttpClient {
    pub fn new(host: &str, port: u16) -> HttpClient {
        HttpClient {
            host: host.to_owned(),
            port,
            timeout: Duration::from_secs(30),
            limits: Limits::default(),
            default_headers: vec![("User-Agent".into(), "weft".into())],
            tls: None,
            conn: None,
        }
    }

    /// Speaks HTTPS: connections run TLS with `tls`, verifying the server as this client's
    /// host. The client speaks HTTP/1.1 only, so `tls` must not offer other protocols
    /// through ALPN.
    pub fn with_tls(mut self, tls: ClientTls) -> HttpClient {
        self.tls = Some(tls);
        self.conn = None;
        self
    }

    fn address(&self) -> Result<SocketAddress> {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return Ok(SocketAddress::from((ip, self.port)));
        }
        let addrs = system::lookup_system(&self.host, self.port)?;
        addrs
            .into_iter()
            .next()
            .map(SocketAddress::from)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no address for {}", self.host)))
    }

    fn connect(&mut self) -> Result<()> {
        let mut socket = CoSocket::connect(&self.address()?, Some(self.timeout))?;
        if let Some(tls) = &self.tls {
            socket.start_tls_client(tls, &self.host, Some(self.timeout))?;
            let alpn = socket.tls_info().and_then(|info| info.alpn);
            if let Some(protocol) = alpn.filter(|p| p != b"http/1.1") {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!(
                        "server chose {:?} through ALPN; this client speaks HTTP/1.1",
                        String::from_utf8_lossy(&protocol)
                    ),
                ));
            }
        }
        socket.read_timeout = Some(self.timeout);
        socket.write_timeout = Some(self.timeout);
        self.conn = Some((socket, ByteBuffer::new()));
        Ok(())
    }

    fn host_header(&self) -> String {
        let default_port = if self.tls.is_some() { 443 } else { 80 };
        if self.port == default_port {
            self.host.clone()
        } else if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn prepare(&self, request: &mut Request) {
        if !request.headers.contains("host") {
            request.headers.append("Host", self.host_header());
        }
        for (name, value) in &self.default_headers {
            if !request.headers.contains(name) {
                request.headers.append(name.clone(), value.clone());
            }
        }
    }

    /// Sends `request` and reads the response.
    pub fn request(&mut self, mut request: Request) -> Result<Response> {
        self.prepare(&mut request);
        let wire = request.encode();
        let reused = self.conn.is_some();
        match self.exchange(&wire, &request.method) {
            // A kept-alive connection may have been closed by the server in the meantime.
            Err(e) if reused && e.kind() == ErrorKind::Closed => {
                self.conn = None;
                self.exchange(&wire, &request.method)
            }
            other => other,
        }
    }

    fn exchange(&mut self, wire: &[u8], method: &Method) -> Result<Response> {
        if self.conn.is_none() {
            self.connect()?;
        }
        let limits = self.limits;
        let result = (|| -> Result<Response> {
            let (socket, buffer) = self
                .conn
                .as_mut()
                .ok_or_else(|| Error::new(ErrorKind::InvalidState, "not connected"))?;
            if let Err(e) = socket.send_all(wire) {
                return Err(match e.kind() {
                    ErrorKind::Io => Error::new(ErrorKind::Closed, e.to_string()),
                    _ => e,
                });
            }
            let mut parser = ResponseParser::new(limits);
            loop {
                parser.expect_response_to(method);
                let response = loop {
                    if let Some(r) = parser.parse(buffer)? {
                        break Some(r);
                    }
                    if socket.recv_into(buffer, 64 * 1024)? == 0 {
                        break parser.finish()?;
                    }
                };
                match response {
                    // Interim responses (100 Continue etc.) precede the real one.
                    Some(r) if (100..200).contains(&r.status) && r.status != 101 => continue,
                    Some(r) => return Ok(r),
                    None => {
                        return Err(Error::new(
                            ErrorKind::Closed,
                            "server closed the connection",
                        ));
                    }
                }
            }
        })();
        match &result {
            Ok(response) if response.keep_alive() && response.status != 101 => {}
            _ => {
                if result.as_ref().is_ok_and(|r| r.status == 101) {
                    return result;
                }
                self.conn = None;
            }
        }
        result
    }

    pub fn get(&mut self, path: &str) -> Result<Response> {
        self.request(Request::new(Method::Get, path))
    }

    pub fn post(&mut self, path: &str, content_type: &str, body: Vec<u8>) -> Result<Response> {
        let mut request = Request::new(Method::Post, path);
        request.headers.append("Content-Type", content_type);
        request.body = body;
        self.request(request)
    }

    /// Upgrades a fresh connection to a WebSocket at `path`.
    pub fn websocket(mut self, path: &str) -> Result<WsClient> {
        self.conn = None;
        let key = websocket::new_key()?;
        let mut request = websocket::client_request(&self.host_header(), path, &key);
        self.prepare(&mut request);
        let response = self.exchange(&request.encode(), &Method::Get)?;
        websocket::check_server_response(&response, &key)?;
        let (socket, buffer) = self
            .conn
            .take()
            .ok_or_else(|| Error::new(ErrorKind::InvalidState, "connection lost after upgrade"))?;
        Ok(WsClient {
            socket,
            buffer,
            decoder: FrameDecoder::new(Role::Client, 64 * 1024 * 1024),
            assembler: Assembler::new(64 * 1024 * 1024),
            closed: false,
        })
    }
}

/// A WebSocket connection from the client side.
pub struct WsClient {
    socket: CoSocket,
    buffer: ByteBuffer,
    decoder: FrameDecoder,
    assembler: Assembler,
    closed: bool,
}

impl WsClient {
    /// Sends a message (masked, as clients must).
    pub fn send(&mut self, message: Message) -> Result<()> {
        if self.closed {
            return Err(Error::new(ErrorKind::Closed, "WebSocket is closed"));
        }
        let frame = encode_frame(&message.into_frame(), Some(websocket::new_mask()?));
        self.socket.send_all(&frame)
    }

    /// Receives the next data message, answering pings on the way. A `Close` from the server
    /// is answered and returned; afterwards `recv` fails with [`ErrorKind::Closed`].
    pub fn recv(&mut self, timeout: Option<Duration>) -> Result<Message> {
        self.socket.read_timeout = timeout;
        loop {
            if self.closed {
                return Err(Error::new(ErrorKind::Closed, "WebSocket is closed"));
            }
            while let Some(frame) = self.decoder.decode_frame(&mut self.buffer)? {
                match self.assembler.push(frame)? {
                    Some(Message::Ping(payload)) => self.send(Message::Pong(payload))?,
                    Some(Message::Close(reason)) => {
                        let code = reason.as_ref().map_or(close_code::NORMAL, |r| r.code);
                        let _ = self.send(Message::Close(Some(CloseReason {
                            code,
                            reason: String::new(),
                        })));
                        self.closed = true;
                        return Ok(Message::Close(reason));
                    }
                    Some(message) => return Ok(message),
                    None => {}
                }
            }
            if self.socket.recv_into(&mut self.buffer, 64 * 1024)? == 0 {
                self.closed = true;
                return Err(Error::new(ErrorKind::Closed, "connection closed"));
            }
        }
    }

    /// Runs the closing handshake: sends a `Close`, then discards incoming messages until the
    /// server's `Close` arrives, the server closes the connection, or [`CLOSE_WAIT`] passes.
    ///
    /// Waiting lets the server close TCP first (RFC 6455 §7.1.1). Dropping the socket with
    /// unread data instead makes the kernel reset the connection, which the server then sees
    /// as an error rather than a clean close.
    pub fn close(&mut self, code: u16, reason: &str) -> Result<()> {
        self.send(Message::Close(Some(CloseReason {
            code,
            reason: reason.to_owned(),
        })))?;
        self.closed = true;
        self.socket.read_timeout = Some(CLOSE_WAIT);
        loop {
            // The handshake is best effort: any decode or read failure ends it.
            match self.decoder.decode_frame(&mut self.buffer) {
                Ok(Some(frame)) if frame.opcode == Opcode::Close => return Ok(()),
                Ok(Some(_)) => continue,
                Ok(None) => {}
                Err(_) => return Ok(()),
            }
            match self.socket.recv_into(&mut self.buffer, 64 * 1024) {
                Ok(n) if n > 0 => {}
                _ => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::runtime::{run, spawn};
    use super::*;
    use crate::network::tls::{ServerTls, test_pki};
    use crate::protocol::http::RequestParser;

    #[test]
    fn urls() {
        let url = |secure, host: &str, port, path: &str| Url {
            secure,
            host: host.into(),
            port,
            path: path.into(),
        };
        assert_eq!(
            parse_url("http://example.test:8080/a?b").unwrap(),
            url(false, "example.test", 8080, "/a?b")
        );
        assert_eq!(parse_url("http://h").unwrap(), url(false, "h", 80, "/"));
        assert_eq!(
            parse_url("http://[::1]:9/x").unwrap(),
            url(false, "::1", 9, "/x")
        );
        assert_eq!(
            parse_url("https://secure.test/").unwrap(),
            url(true, "secure.test", 443, "/")
        );
        assert!(parse_url("ftp://files.test/").is_err());
        assert!(parse_url("http://:80/").is_err());
    }

    /// A tiny coroutine HTTP server: keep-alive, closes after `/bye`, upgrades `/ws`.
    fn serve(listener: CoSocket, tls: Option<ServerTls>) {
        loop {
            let Ok((mut conn, _)) = listener.accept(Some(Duration::from_secs(5))) else {
                return;
            };
            let tls = tls.clone();
            spawn(move || {
                if let Some(tls) = &tls
                    && conn
                        .start_tls_server(tls, Some(Duration::from_secs(5)))
                        .is_err()
                {
                    return;
                }
                let mut parser = RequestParser::new(Limits::default());
                let mut buf = ByteBuffer::new();
                loop {
                    let request = loop {
                        if let Some(r) = parser.parse(&mut buf).unwrap() {
                            break Some(r);
                        }
                        if conn.recv_into(&mut buf, 4096).unwrap() == 0 {
                            break None;
                        }
                    };
                    let Some(request) = request else { return };
                    if request.path() == "/ws" {
                        let reply = websocket::handshake_response(&request, None).unwrap();
                        conn.send_all(&reply.encode_head(0)).unwrap();
                        let mut decoder = FrameDecoder::new(Role::Server, 1 << 20);
                        let mut asm = Assembler::new(1 << 20);
                        loop {
                            while let Some(frame) = decoder.decode_frame(&mut buf).unwrap() {
                                match asm.push(frame).unwrap() {
                                    Some(Message::Text(t)) => {
                                        let back = Message::Text(t.to_uppercase()).into_frame();
                                        conn.send_all(&encode_frame(&back, None)).unwrap();
                                        let ping = Message::Ping(b"p".to_vec()).into_frame();
                                        conn.send_all(&encode_frame(&ping, None)).unwrap();
                                    }
                                    Some(Message::Close(_)) => {
                                        let close = Message::Close(None).into_frame();
                                        conn.send_all(&encode_frame(&close, None)).unwrap();
                                        return;
                                    }
                                    _ => {}
                                }
                            }
                            if conn.recv_into(&mut buf, 4096).unwrap() == 0 {
                                return;
                            }
                        }
                    }
                    let mut response = Response::new(200).with_body(format!(
                        "{} {} {}",
                        request.method,
                        request.path(),
                        request.headers.get("host").unwrap_or("")
                    ));
                    if request.path() == "/bye" {
                        response.headers.append("Connection", "close");
                    }
                    conn.send_all(&response.encode()).unwrap();
                    if request.path() == "/bye" {
                        return;
                    }
                }
            })
            .unwrap();
        }
    }

    #[test]
    fn requests_reuse_and_reconnect() {
        run(|| {
            let listener = CoSocket::listen(&"127.0.0.1:0".parse().unwrap(), 16).unwrap();
            let port = listener.local_address().unwrap().as_inet().unwrap().port();
            let server = spawn(move || serve(listener, None)).unwrap();

            let mut client = HttpClient::new("127.0.0.1", port);
            let first = client.get("/a").unwrap();
            assert_eq!(first.body, format!("GET /a 127.0.0.1:{port}").into_bytes());
            let posted = client.post("/b", "text/plain", b"x".to_vec()).unwrap();
            assert_eq!(
                posted.body,
                format!("POST /b 127.0.0.1:{port}").into_bytes()
            );
            assert_eq!(client.get("/bye").unwrap().status, 200);
            // The server closed the connection; the next request reconnects.
            assert_eq!(client.get("/again").unwrap().status, 200);

            let url = format!("http://127.0.0.1:{port}/oneshot");
            assert_eq!(
                get(&url).unwrap().body,
                format!("GET /oneshot 127.0.0.1:{port}").into_bytes()
            );

            let mut ws = HttpClient::new("127.0.0.1", port).websocket("/ws").unwrap();
            ws.send(Message::Text("hello".into())).unwrap();
            assert_eq!(
                ws.recv(Some(Duration::from_secs(5))).unwrap(),
                Message::Text("HELLO".into())
            );
            ws.close(close_code::NORMAL, "done").unwrap();
            assert!(ws.send(Message::Text("late".into())).is_err());
            // Stop accepting so the loop can finish.
            super::super::runtime::with_reactor(|r| super::super::runtime::cancel(r, server))
                .unwrap();
        })
        .unwrap();
    }

    #[test]
    fn https_and_wss() {
        let pki = test_pki::generate();
        let server_tls = test_pki::server_options(&pki)
            .with_alpn(["http/1.1"])
            .build()
            .unwrap();
        let client_tls = test_pki::client_options(&pki).build().unwrap();
        let h2_only = test_pki::client_options(&pki)
            .with_alpn(["h2"])
            .build()
            .unwrap();
        let h2_server = test_pki::server_options(&pki)
            .with_alpn(["h2"])
            .build()
            .unwrap();
        run(move || {
            let listener = CoSocket::listen(&"127.0.0.1:0".parse().unwrap(), 16).unwrap();
            let port = listener.local_address().unwrap().as_inet().unwrap().port();
            let server = spawn(move || serve(listener, Some(server_tls))).unwrap();

            let mut client = HttpClient::new("127.0.0.1", port).with_tls(client_tls.clone());
            let first = client.get("/a").unwrap();
            assert_eq!(first.body, format!("GET /a 127.0.0.1:{port}").into_bytes());
            assert_eq!(client.get("/bye").unwrap().status, 200);
            assert_eq!(client.get("/again").unwrap().status, 200);

            let mut ws = HttpClient::new("127.0.0.1", port)
                .with_tls(client_tls.clone())
                .websocket("/ws")
                .unwrap();
            ws.send(Message::Text("secure".into())).unwrap();
            assert_eq!(
                ws.recv(Some(Duration::from_secs(5))).unwrap(),
                Message::Text("SECURE".into())
            );
            ws.close(close_code::NORMAL, "done").unwrap();

            // Cleartext against a TLS port fails rather than hanging.
            let mut plain = HttpClient::new("127.0.0.1", port);
            plain.timeout = Duration::from_secs(5);
            assert!(plain.get("/a").is_err());
            super::super::runtime::with_reactor(|r| super::super::runtime::cancel(r, server))
                .unwrap();

            // A server that picks h2 is refused by this HTTP/1.1 client.
            let listener = CoSocket::listen(&"127.0.0.1:0".parse().unwrap(), 16).unwrap();
            let port = listener.local_address().unwrap().as_inet().unwrap().port();
            let server = spawn(move || serve(listener, Some(h2_server))).unwrap();
            let err = HttpClient::new("127.0.0.1", port)
                .with_tls(h2_only)
                .get("/")
                .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Protocol);
            super::super::runtime::with_reactor(|r| super::super::runtime::cancel(r, server))
                .unwrap();
        })
        .unwrap();
    }
}
