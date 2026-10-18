//! HTTP/1.1 and WebSocket clients for coroutines (cleartext only).
//!
//! An [`HttpClient`] keeps one connection to a host and reuses it while the server allows;
//! a request on a reused connection that the server had already closed is retried once on a
//! fresh connection. [`HttpClient::websocket`] upgrades to a [`WsClient`].

use std::net::IpAddr;
use std::time::Duration;

use super::socket::CoSocket;
use super::system;
use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, Result};
use crate::network::SocketAddress;
use crate::protocol::http::{Limits, Method, Request, Response, ResponseParser};
use crate::protocol::websocket::{
    self, Assembler, CloseReason, FrameDecoder, Message, Role, close_code, encode_frame,
};

/// A connection-reusing client for one host.
pub struct HttpClient {
    host: String,
    port: u16,
    pub timeout: Duration,
    pub limits: Limits,
    /// Extra headers added to every request (unless the request sets them).
    pub default_headers: Vec<(String, String)>,
    conn: Option<(CoSocket, ByteBuffer)>,
}

/// Splits `http://host[:port]/path` into its parts.
pub fn parse_url(url: &str) -> Result<(String, u16, String)> {
    let bad = || {
        Error::new(
            ErrorKind::InvalidArgument,
            format!("unsupported URL {url:?}"),
        )
    };
    let rest = url.strip_prefix("http://").ok_or_else(bad)?;
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
    Ok((host.to_owned(), port.unwrap_or(80), path.to_owned()))
}

/// One-shot GET of an `http://` URL.
pub fn get(url: &str) -> Result<Response> {
    let (host, port, path) = parse_url(url)?;
    let mut client = HttpClient::new(&host, port);
    client.request(Request::new(Method::Get, path))
}

impl HttpClient {
    pub fn new(host: &str, port: u16) -> HttpClient {
        HttpClient {
            host: host.to_owned(),
            port,
            timeout: Duration::from_secs(30),
            limits: Limits::default(),
            default_headers: vec![("User-Agent".into(), "weft".into())],
            conn: None,
        }
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
        socket.read_timeout = Some(self.timeout);
        socket.write_timeout = Some(self.timeout);
        self.conn = Some((socket, ByteBuffer::new()));
        Ok(())
    }

    fn host_header(&self) -> String {
        if self.port == 80 {
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

    /// Starts the closing handshake.
    pub fn close(&mut self, code: u16, reason: &str) -> Result<()> {
        self.send(Message::Close(Some(CloseReason {
            code,
            reason: reason.to_owned(),
        })))?;
        self.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::runtime::{run, spawn};
    use super::*;
    use crate::protocol::http::RequestParser;

    #[test]
    fn urls() {
        assert_eq!(
            parse_url("http://example.test:8080/a?b").unwrap(),
            ("example.test".into(), 8080, "/a?b".into())
        );
        assert_eq!(parse_url("http://h").unwrap(), ("h".into(), 80, "/".into()));
        assert_eq!(
            parse_url("http://[::1]:9/x").unwrap(),
            ("::1".into(), 9, "/x".into())
        );
        assert!(parse_url("https://secure.test/").is_err());
        assert!(parse_url("http://:80/").is_err());
    }

    /// A tiny coroutine HTTP server: keep-alive, closes after `/bye`, upgrades `/ws`.
    fn serve(listener: CoSocket) {
        loop {
            let Ok((conn, _)) = listener.accept(Some(Duration::from_secs(5))) else {
                return;
            };
            spawn(move || {
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
            let server = spawn(move || serve(listener)).unwrap();

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
}
