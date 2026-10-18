//! Incremental HTTP/1.x parsers.
//!
//! Feed bytes into a [`ByteBuffer`] and call `parse` until it yields a message. Parsers are
//! strict where leniency enables request smuggling (conflicting `Content-Length`,
//! `Transfer-Encoding` with `Content-Length`, folded headers, whitespace before the colon)
//! and lenient where RFC 9112 allows it (bare `LF` line endings, blank lines before a request).

use std::fmt;

use super::headers::{self, Headers};
use super::{Method, Request, Response, Version, bodiless_status};
use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind};

/// Size limits that bound a parser's memory use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Request/status line plus headers.
    pub max_head: usize,
    pub max_headers: usize,
    pub max_body: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_head: 64 * 1024,
            max_headers: 128,
            max_body: 8 * 1024 * 1024,
        }
    }
}

/// Why a message was rejected, with the status a server should answer with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    pub status: u16,
    pub message: String,
}

impl HttpError {
    fn new(status: u16, message: impl Into<String>) -> HttpError {
        HttpError {
            status,
            message: message.into(),
        }
    }

    fn bad(message: impl Into<String>) -> HttpError {
        HttpError::new(400, message)
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.status)
    }
}

impl std::error::Error for HttpError {}

impl From<HttpError> for Error {
    fn from(err: HttpError) -> Error {
        let kind = match err.status {
            413 | 431 => ErrorKind::TooLarge,
            _ => ErrorKind::Protocol,
        };
        Error::new(kind, err.to_string())
    }
}

type ParseResult<T> = Result<T, HttpError>;

/// How the body after a head is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    None,
    Length(usize),
    Chunked,
    /// Until the connection closes (responses only).
    UntilClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chunk {
    /// Expecting a `size[;ext]` line.
    Size,
    /// Inside chunk data, with this many bytes left.
    Data(usize),
    /// Expecting the line break after chunk data.
    DataEnd,
    /// Reading trailer lines until a blank one.
    Trailers,
}

/// Body accumulation shared by both parsers.
#[derive(Debug)]
struct Body {
    framing: Framing,
    chunk: Chunk,
    data: Vec<u8>,
    trailers: Headers,
}

impl Body {
    fn new(framing: Framing) -> Body {
        Body {
            framing,
            chunk: Chunk::Size,
            data: Vec::new(),
            trailers: Headers::new(),
        }
    }

    /// Consumes body bytes; returns `true` once the body is complete.
    fn feed(&mut self, buf: &mut ByteBuffer, limits: &Limits) -> ParseResult<bool> {
        match self.framing {
            Framing::None => Ok(true),
            Framing::Length(total) => {
                let take = (total - self.data.len()).min(buf.len());
                self.data.extend_from_slice(&buf.as_slice()[..take]);
                buf.consume(take);
                Ok(self.data.len() == total)
            }
            Framing::UntilClose => {
                if self.data.len() + buf.len() > limits.max_body {
                    return Err(HttpError::new(413, "body exceeds the limit"));
                }
                self.data.extend_from_slice(buf.as_slice());
                buf.consume(buf.len());
                Ok(false)
            }
            Framing::Chunked => self.feed_chunked(buf, limits),
        }
    }

    fn feed_chunked(&mut self, buf: &mut ByteBuffer, limits: &Limits) -> ParseResult<bool> {
        loop {
            match self.chunk {
                Chunk::Size => {
                    let Some(line) = take_line(buf, 1024)? else {
                        return Ok(false);
                    };
                    let size = line
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim_end_matches([' ', '\t']);
                    let size = parse_hex(size)
                        .ok_or_else(|| HttpError::bad(format!("bad chunk size {size:?}")))?;
                    if size == 0 {
                        self.chunk = Chunk::Trailers;
                    } else if self.data.len().saturating_add(size) > limits.max_body {
                        return Err(HttpError::new(413, "body exceeds the limit"));
                    } else {
                        self.chunk = Chunk::Data(size);
                    }
                }
                Chunk::Data(left) => {
                    if buf.is_empty() {
                        return Ok(false);
                    }
                    let take = left.min(buf.len());
                    self.data.extend_from_slice(&buf.as_slice()[..take]);
                    buf.consume(take);
                    self.chunk = if take == left {
                        Chunk::DataEnd
                    } else {
                        Chunk::Data(left - take)
                    };
                }
                Chunk::DataEnd => {
                    let Some(line) = take_line(buf, 2)? else {
                        return Ok(false);
                    };
                    if !line.is_empty() {
                        return Err(HttpError::bad("chunk data longer than its size"));
                    }
                    self.chunk = Chunk::Size;
                }
                Chunk::Trailers => {
                    let Some(line) = take_line(buf, limits.max_head)? else {
                        return Ok(false);
                    };
                    if line.is_empty() {
                        return Ok(true);
                    }
                    if self.trailers.len() >= limits.max_headers {
                        return Err(HttpError::new(431, "too many trailer fields"));
                    }
                    let (name, value) = parse_field(&line)?;
                    self.trailers.append(name, value);
                }
            }
        }
    }
}

fn parse_hex(digits: &str) -> Option<usize> {
    if digits.is_empty() || digits.len() > 15 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    usize::from_str_radix(digits, 16).ok()
}

/// Removes one line (without its `\r\n` or `\n`), failing if none arrives within `max` bytes.
fn take_line(buf: &mut ByteBuffer, max: usize) -> ParseResult<Option<String>> {
    let Some(newline) = buf.as_slice().iter().position(|&b| b == b'\n') else {
        if buf.len() > max + 1 {
            return Err(HttpError::bad("line too long"));
        }
        return Ok(None);
    };
    let raw = &buf.as_slice()[..newline];
    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
    if raw.len() > max {
        return Err(HttpError::bad("line too long"));
    }
    let line = String::from_utf8_lossy(raw).into_owned();
    buf.consume(newline + 1);
    Ok(Some(line))
}

/// Finds the end of the head: the byte after the blank line.
fn head_end(data: &[u8]) -> Option<usize> {
    let mut i = 0;
    while let Some(pos) = data[i..].iter().position(|&b| b == b'\n') {
        let after = i + pos + 1;
        match data.get(after) {
            Some(b'\n') => return Some(after + 1),
            Some(b'\r') if data.get(after + 1) == Some(&b'\n') => return Some(after + 2),
            _ => i = after,
        }
    }
    None
}

fn parse_field(line: &str) -> ParseResult<(String, String)> {
    if line.starts_with([' ', '\t']) {
        return Err(HttpError::bad("obsolete line folding is not accepted"));
    }
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| HttpError::bad("header line without a colon"))?;
    if !headers::is_token(name) {
        return Err(HttpError::bad(format!("bad header name {name:?}")));
    }
    let value = value.trim_matches([' ', '\t']);
    if !headers::is_valid_value(value) {
        return Err(HttpError::bad(format!("bad value for header {name}")));
    }
    Ok((name.to_owned(), value.to_owned()))
}

fn parse_version(text: &str) -> ParseResult<Version> {
    match text {
        "HTTP/1.1" => Ok(Version::Http11),
        "HTTP/1.0" => Ok(Version::Http10),
        v if v.starts_with("HTTP/") => Err(HttpError::new(505, format!("unsupported {v}"))),
        v => Err(HttpError::bad(format!("bad protocol version {v:?}"))),
    }
}

/// Splits a head into its first line and header fields.
fn parse_head(raw: &[u8], limits: &Limits) -> ParseResult<(String, Headers)> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .skip_while(|l| l.is_empty());
    let first = lines.next().unwrap_or("").to_owned();
    let mut headers = Headers::new();
    for line in lines.take_while(|l| !l.is_empty()) {
        if headers.len() == limits.max_headers {
            return Err(HttpError::new(431, "too many header fields"));
        }
        let (name, value) = parse_field(line)?;
        headers.append(name, value);
    }
    Ok((first, headers))
}

/// The declared `Content-Length`, after checking repeated values agree.
fn content_length(headers: &Headers) -> ParseResult<Option<usize>> {
    let mut found: Option<usize> = None;
    for value in headers.get_all("content-length").flat_map(|v| v.split(',')) {
        let value = value.trim();
        if value.is_empty() || value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HttpError::bad(format!("bad Content-Length {value:?}")));
        }
        let n: usize = value
            .parse()
            .map_err(|_| HttpError::bad("Content-Length out of range"))?;
        if found.is_some_and(|f| f != n) {
            return Err(HttpError::bad("conflicting Content-Length values"));
        }
        found = Some(n);
    }
    Ok(found)
}

/// Whether `Transfer-Encoding` ends in `chunked`; `None` without the header.
fn chunked(headers: &Headers) -> Option<bool> {
    let codings: Vec<&str> = headers
        .get_all("transfer-encoding")
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect();
    if codings.is_empty() {
        return None;
    }
    Some(
        codings
            .last()
            .is_some_and(|c| c.eq_ignore_ascii_case("chunked")),
    )
}

enum State<H> {
    Head,
    Body(H, Body),
}

struct RequestHead {
    method: Method,
    target: String,
    version: Version,
    headers: Headers,
}

/// Parses requests from a client. One parser serves a whole connection.
pub struct RequestParser {
    limits: Limits,
    state: State<RequestHead>,
}

impl RequestParser {
    pub fn new(limits: Limits) -> RequestParser {
        RequestParser {
            limits,
            state: State::Head,
        }
    }

    /// Whether the parser holds part of a message.
    pub fn in_progress(&self) -> bool {
        matches!(self.state, State::Body(..))
    }

    /// The head of the request whose body is being read, e.g. to answer `100 Continue`.
    pub fn pending(&self) -> Option<(&Method, &str, &Headers)> {
        match &self.state {
            State::Body(head, _) => Some((&head.method, &head.target, &head.headers)),
            State::Head => None,
        }
    }

    /// Returns the next complete request, or `None` if more bytes are needed.
    pub fn parse(&mut self, buf: &mut ByteBuffer) -> ParseResult<Option<Request>> {
        if let State::Head = self.state {
            let Some(end) = head_end(buf.as_slice()) else {
                if buf.len() > self.limits.max_head {
                    return Err(HttpError::new(431, "request head too large"));
                }
                return Ok(None);
            };
            if end > self.limits.max_head {
                return Err(HttpError::new(431, "request head too large"));
            }
            let (first, headers) = parse_head(&buf.as_slice()[..end], &self.limits)?;
            buf.consume(end);
            let head = self.request_line(&first, headers)?;
            let framing = self.framing(&head)?;
            self.state = State::Body(head, Body::new(framing));
        }

        let State::Body(_, body) = &mut self.state else {
            return Ok(None);
        };
        if !body.feed(buf, &self.limits)? {
            return Ok(None);
        }
        let State::Body(head, body) = std::mem::replace(&mut self.state, State::Head) else {
            return Ok(None);
        };
        Ok(Some(Request {
            method: head.method,
            target: head.target,
            version: head.version,
            headers: head.headers,
            body: body.data,
            trailers: body.trailers,
        }))
    }

    fn request_line(&self, line: &str, headers: Headers) -> ParseResult<RequestHead> {
        let mut parts = line.split(' ');
        let (Some(method), Some(target), Some(version), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(HttpError::bad("malformed request line"));
        };
        let method = method
            .parse::<Method>()
            .map_err(|()| HttpError::bad("bad method"))?;
        if target.is_empty() || !target.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(HttpError::bad("bad request target"));
        }
        let version = parse_version(version)?;
        if version == Version::Http11 && headers.get_all("host").count() != 1 {
            return Err(HttpError::bad("HTTP/1.1 requires exactly one Host header"));
        }
        Ok(RequestHead {
            method,
            target: target.to_owned(),
            version,
            headers,
        })
    }

    fn framing(&self, head: &RequestHead) -> ParseResult<Framing> {
        let length = content_length(&head.headers)?;
        match chunked(&head.headers) {
            Some(_) if head.version == Version::Http10 => {
                Err(HttpError::bad("Transfer-Encoding in an HTTP/1.0 request"))
            }
            Some(_) if length.is_some() => Err(HttpError::bad(
                "both Transfer-Encoding and Content-Length present",
            )),
            Some(true) => Ok(Framing::Chunked),
            Some(false) => Err(HttpError::new(501, "unsupported transfer coding")),
            None => match length {
                Some(n) if n > self.limits.max_body => {
                    Err(HttpError::new(413, "body exceeds the limit"))
                }
                Some(0) | None => Ok(Framing::None),
                Some(n) => Ok(Framing::Length(n)),
            },
        }
    }
}

struct ResponseHead {
    version: Version,
    status: u16,
    reason: String,
    headers: Headers,
}

/// Parses responses from a server.
pub struct ResponseParser {
    limits: Limits,
    state: State<ResponseHead>,
    /// The request being answered was HEAD (or CONNECT), so the body is absent.
    no_body: bool,
}

impl ResponseParser {
    pub fn new(limits: Limits) -> ResponseParser {
        ResponseParser {
            limits,
            state: State::Head,
            no_body: false,
        }
    }

    /// Tells the parser which request the next response answers; it matters for `HEAD`,
    /// whose responses have headers describing a body that is never sent.
    pub fn expect_response_to(&mut self, method: &Method) {
        self.no_body = matches!(method, Method::Head);
    }

    pub fn parse(&mut self, buf: &mut ByteBuffer) -> ParseResult<Option<Response>> {
        if let State::Head = self.state {
            let Some(end) = head_end(buf.as_slice()) else {
                if buf.len() > self.limits.max_head {
                    return Err(HttpError::bad("response head too large"));
                }
                return Ok(None);
            };
            let (first, headers) = parse_head(&buf.as_slice()[..end], &self.limits)?;
            buf.consume(end);
            let head = Self::status_line(&first, headers)?;
            let framing = self.framing(&head)?;
            self.state = State::Body(head, Body::new(framing));
        }
        let State::Body(_, body) = &mut self.state else {
            return Ok(None);
        };
        if !body.feed(buf, &self.limits)? {
            return Ok(None);
        }
        Ok(self.complete())
    }

    /// Signals that the connection closed. Completes a response whose body runs until close;
    /// fails if the connection ended mid-message.
    pub fn finish(&mut self) -> ParseResult<Option<Response>> {
        match &self.state {
            State::Head => Ok(None),
            State::Body(_, body) if body.framing == Framing::UntilClose => Ok(self.complete()),
            State::Body(..) => Err(HttpError::bad("connection closed mid-response")),
        }
    }

    fn complete(&mut self) -> Option<Response> {
        let State::Body(head, body) = std::mem::replace(&mut self.state, State::Head) else {
            return None;
        };
        if !(100..200).contains(&head.status) {
            self.no_body = false;
        }
        Some(Response {
            version: head.version,
            status: head.status,
            reason: head.reason,
            headers: head.headers,
            body: body.data,
            trailers: body.trailers,
        })
    }

    fn status_line(line: &str, headers: Headers) -> ParseResult<ResponseHead> {
        let mut parts = line.splitn(3, ' ');
        let version = parse_version(parts.next().unwrap_or(""))?;
        let status = parts
            .next()
            .filter(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|s| (100..600).contains(s))
            .ok_or_else(|| HttpError::bad("bad status code"))?;
        Ok(ResponseHead {
            version,
            status,
            reason: parts.next().unwrap_or("").to_owned(),
            headers,
        })
    }

    fn framing(&self, head: &ResponseHead) -> ParseResult<Framing> {
        if self.no_body || bodiless_status(head.status) {
            return Ok(Framing::None);
        }
        match chunked(&head.headers) {
            Some(true) => Ok(Framing::Chunked),
            Some(false) => Ok(Framing::UntilClose),
            None => match content_length(&head.headers)? {
                Some(n) if n > self.limits.max_body => {
                    Err(HttpError::new(413, "body exceeds the limit"))
                }
                Some(0) => Ok(Framing::None),
                Some(n) => Ok(Framing::Length(n)),
                None => Ok(Framing::UntilClose),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(input: &[u8]) -> ParseResult<Vec<Request>> {
        let mut parser = RequestParser::new(Limits::default());
        let mut buf = ByteBuffer::from(input);
        let mut out = Vec::new();
        while let Some(req) = parser.parse(&mut buf)? {
            out.push(req);
        }
        Ok(out)
    }

    #[test]
    fn pipelined_requests_byte_by_byte() {
        let wire = b"\r\nGET /a?x=1 HTTP/1.1\r\nHost: h\r\n\r\n\
POST /b HTTP/1.1\nHost: h\nContent-Length: 5\n\nhello\
PUT /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n\
3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Sum: 5\r\n\r\n";
        let mut parser = RequestParser::new(Limits::default());
        let mut buf = ByteBuffer::new();
        let mut got = Vec::new();
        for &b in wire.iter() {
            buf.extend_from_slice(&[b]);
            while let Some(req) = parser.parse(&mut buf).unwrap() {
                got.push(req);
            }
        }
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].method, Method::Get);
        assert_eq!(got[0].query(), Some("x=1"));
        assert_eq!(got[1].body, b"hello");
        assert_eq!(got[2].body, b"abcde");
        assert_eq!(got[2].trailers.get("x-sum"), Some("5"));
        assert!(!parser.in_progress());
    }

    #[test]
    fn rejects_smuggling_vectors() {
        let cases: [(&[u8], u16); 8] = [
            (
                b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
                400,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
                400,
            ),
            (b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: +3\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost : h\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost: h\r\nX: a\r\n  folded\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n", 501),
            (b"GET / HTTP/2.0\r\nHost: h\r\n\r\n", 505),
        ];
        for (wire, status) in cases {
            let err = parse_all(wire).unwrap_err();
            assert_eq!(err.status, status, "{}", String::from_utf8_lossy(wire));
        }
        // Agreeing duplicates are fine.
        let ok = parse_all(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 2, 2\r\n\r\nhi");
        assert_eq!(ok.unwrap()[0].body, b"hi");
    }

    #[test]
    fn enforces_limits() {
        let limits = Limits {
            max_head: 64,
            max_headers: 2,
            max_body: 4,
        };
        let mut parser = RequestParser::new(limits);
        let mut buf = ByteBuffer::from(&b"GET / HTTP/1.1\r\nHost: h\r\nA: 1\r\nB: 2\r\n\r\n"[..]);
        assert_eq!(parser.parse(&mut buf).unwrap_err().status, 431);

        let mut parser = RequestParser::new(limits);
        let mut buf =
            ByteBuffer::from(&b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n"[..]);
        assert_eq!(parser.parse(&mut buf).unwrap_err().status, 413);

        let mut parser = RequestParser::new(limits);
        let mut buf = ByteBuffer::from(
            &b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n"[..],
        );
        assert_eq!(parser.parse(&mut buf).unwrap_err().status, 413);

        let mut parser = RequestParser::new(limits);
        let mut buf = ByteBuffer::from(vec![b'G'; 100]);
        assert_eq!(parser.parse(&mut buf).unwrap_err().status, 431);
    }

    #[test]
    fn expect_continue_is_visible_before_the_body() {
        let mut parser = RequestParser::new(Limits::default());
        let mut buf = ByteBuffer::from(
            &b"PUT /f HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n"[..],
        );
        assert!(parser.parse(&mut buf).unwrap().is_none());
        let (_, target, headers) = parser.pending().unwrap();
        assert_eq!(
            (target, headers.get("expect")),
            ("/f", Some("100-continue"))
        );
        buf.extend_from_slice(b"ok");
        let req = parser.parse(&mut buf).unwrap().unwrap();
        assert!(req.expects_continue());
        assert_eq!(req.body, b"ok");
    }

    #[test]
    fn responses() {
        let mut parser = ResponseParser::new(Limits::default());
        let mut buf = ByteBuffer::from(
            &b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi\
HTTP/1.1 204 No Content\r\n\r\nHTTP/1.0 200 OK\r\n\r\nuntil close"[..],
        );
        let interim = parser.parse(&mut buf).unwrap().unwrap();
        assert_eq!(interim.status, 100);
        let ok = parser.parse(&mut buf).unwrap().unwrap();
        assert_eq!(
            (ok.status, ok.reason.as_str(), &ok.body[..]),
            (200, "OK", &b"hi"[..])
        );
        assert!(parser.parse(&mut buf).unwrap().unwrap().body.is_empty());
        assert!(parser.parse(&mut buf).unwrap().is_none());
        let last = parser.finish().unwrap().unwrap();
        assert_eq!(last.body, b"until close");
        assert!(!last.keep_alive());

        let mut parser = ResponseParser::new(Limits::default());
        parser.expect_response_to(&Method::Head);
        let mut buf = ByteBuffer::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"[..]);
        assert!(parser.parse(&mut buf).unwrap().unwrap().body.is_empty());

        let mut parser = ResponseParser::new(Limits::default());
        let mut buf = ByteBuffer::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\npart"[..]);
        assert!(parser.parse(&mut buf).unwrap().is_none());
        assert!(parser.finish().is_err());
        let mut buf = ByteBuffer::from(&b"HTTP/1.1 2000 Huh\r\n\r\n"[..]);
        assert!(
            ResponseParser::new(Limits::default())
                .parse(&mut buf)
                .is_err()
        );
    }
}
