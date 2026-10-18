//! HTTP/1.x messages (RFC 9110, RFC 9112).
//!
//! - [`parser`]: incremental request and response parsers with size limits.
//! - [`headers`]: an ordered, case-insensitive header map.
//! - [`url`]: percent-encoding, query strings and cookies.
//! - [`date`]: HTTP date formatting and parsing.
//! - [`multipart`]: `multipart/form-data` bodies.
//!
//! This module only converts between bytes and messages; connections and servers live
//! elsewhere.

pub mod date;
pub mod headers;
pub mod multipart;
pub mod parser;
pub mod url;

pub use headers::Headers;
pub use parser::{HttpError, Limits, RequestParser, ResponseParser};

use std::fmt;
use std::str::FromStr;

/// A request method. Methods are case-sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    /// Any other valid token, e.g. a WebDAV method.
    Other(String),
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Connect => "CONNECT",
            Method::Options => "OPTIONS",
            Method::Trace => "TRACE",
            Method::Patch => "PATCH",
            Method::Other(name) => name,
        }
    }
}

impl FromStr for Method {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        Ok(match s {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "CONNECT" => Method::Connect,
            "OPTIONS" => Method::Options,
            "TRACE" => Method::Trace,
            "PATCH" => Method::Patch,
            other if headers::is_token(other) => Method::Other(other.to_owned()),
            _ => return Err(()),
        })
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Protocol version of an HTTP/1.x message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Version {
    Http10,
    Http11,
}

impl Version {
    pub fn as_str(self) -> &'static str {
        match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
        }
    }
}

/// Whether a connection may carry another message after this one, given its version and
/// `Connection` header.
fn persistent(version: Version, headers: &Headers) -> bool {
    match version {
        Version::Http11 => !headers.has_token("connection", "close"),
        Version::Http10 => headers.has_token("connection", "keep-alive"),
    }
}

/// A parsed or outgoing request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    /// The request target as sent, e.g. `/search?q=x`.
    pub target: String,
    pub version: Version,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// Trailer fields sent after a chunked body.
    pub trailers: Headers,
}

impl Request {
    pub fn new(method: Method, target: impl Into<String>) -> Request {
        Request {
            method,
            target: target.into(),
            version: Version::Http11,
            headers: Headers::new(),
            body: Vec::new(),
            trailers: Headers::new(),
        }
    }

    /// The target's path, without the query.
    pub fn path(&self) -> &str {
        url::split_target(&self.target).0
    }

    /// The raw query string, if any.
    pub fn query(&self) -> Option<&str> {
        url::split_target(&self.target).1
    }

    /// Decoded query parameters.
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        self.query().map(url::parse_query).unwrap_or_default()
    }

    /// Decoded cookies from every `Cookie` header.
    pub fn cookies(&self) -> Vec<(String, String)> {
        self.headers
            .get_all("cookie")
            .flat_map(url::parse_cookies)
            .collect()
    }

    /// Whether the connection stays open after the response.
    pub fn keep_alive(&self) -> bool {
        persistent(self.version, &self.headers)
    }

    /// Whether the client asks to switch to `protocol` (e.g. `websocket`).
    pub fn wants_upgrade(&self, protocol: &str) -> bool {
        self.headers.has_token("connection", "upgrade")
            && self.headers.has_token("upgrade", protocol)
    }

    /// Whether the client waits for `100 Continue` before sending the body.
    pub fn expects_continue(&self) -> bool {
        self.version == Version::Http11
            && self
                .headers
                .get("expect")
                .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
    }

    /// Serializes the request, adding `Content-Length` for a non-empty body when no framing
    /// header is present.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!(
            "{} {} {}\r\n",
            self.method,
            self.target,
            self.version.as_str()
        )
        .into_bytes();
        self.headers.write_to(&mut out);
        if !self.body.is_empty()
            && !self.headers.contains("content-length")
            && !self.headers.contains("transfer-encoding")
        {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

/// A parsed or outgoing response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub version: Version,
    pub status: u16,
    pub reason: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub trailers: Headers,
}

impl Response {
    /// A response with the standard reason phrase for `status`.
    pub fn new(status: u16) -> Response {
        Response {
            version: Version::Http11,
            status,
            reason: reason_phrase(status).unwrap_or("").to_owned(),
            headers: Headers::new(),
            body: Vec::new(),
            trailers: Headers::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Response {
        self.headers.append(name, value);
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Response {
        self.body = body.into();
        self
    }

    /// Whether the connection stays open after this response.
    pub fn keep_alive(&self) -> bool {
        persistent(self.version, &self.headers)
    }

    /// Whether this status never carries a body.
    pub fn is_bodiless(&self) -> bool {
        bodiless_status(self.status)
    }

    /// The status line and headers, ending with the blank line. Adds `Content-Length` for
    /// `body_len` unless a framing header is already present or the status has no body.
    pub fn encode_head(&self, body_len: usize) -> Vec<u8> {
        let mut out = format!(
            "{} {} {}\r\n",
            self.version.as_str(),
            self.status,
            self.reason
        )
        .into_bytes();
        self.headers.write_to(&mut out);
        if !self.is_bodiless()
            && !self.headers.contains("content-length")
            && !self.headers.contains("transfer-encoding")
        {
            out.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// The complete response.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.encode_head(self.body.len());
        if !self.is_bodiless() {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

pub(crate) fn bodiless_status(status: u16) -> bool {
    (100..200).contains(&status) || status == 204 || status == 304
}

/// Encodes one chunk of a chunked body. An empty `data` would end the body, so it yields
/// nothing; append [`LAST_CHUNK`] to finish.
pub fn encode_chunk(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = format!("{:x}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

/// Terminates a chunked body that has no trailers.
pub const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// The reason phrase registered for `status` (RFC 9110 and IANA's status code registry).
pub fn reason_phrase(status: u16) -> Option<&'static str> {
    Some(match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        511 => "Network Authentication Required",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_helpers() {
        let mut req = Request::new(Method::Get, "/a/b?x=1&y=two%20words");
        req.headers.append("Cookie", "sid=1; theme=dark");
        req.headers.append("Connection", "Upgrade");
        req.headers.append("Upgrade", "websocket");
        assert_eq!(req.path(), "/a/b");
        assert_eq!(req.query_pairs()[1], ("y".into(), "two words".into()));
        assert_eq!(req.cookies().len(), 2);
        assert!(req.wants_upgrade("WebSocket"));
        assert!(req.keep_alive());

        req.version = Version::Http10;
        assert!(!req.keep_alive());
        assert_eq!(
            "PROPFIND".parse::<Method>(),
            Ok(Method::Other("PROPFIND".into()))
        );
        assert!("BAD METHOD".parse::<Method>().is_err());
    }

    #[test]
    fn encodes_messages() {
        let mut req = Request::new(Method::Post, "/submit");
        req.headers.append("Host", "example.test");
        req.body = b"k=v".to_vec();
        assert_eq!(
            req.encode(),
            b"POST /submit HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nk=v"
        );

        let res = Response::new(404)
            .with_header("Content-Type", "text/plain")
            .with_body("missing");
        assert_eq!(
            res.encode(),
            b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n\r\nmissing"
        );
        assert_eq!(
            Response::new(304).with_body("ignored").encode(),
            b"HTTP/1.1 304 Not Modified\r\n\r\n"
        );
        assert_eq!(encode_chunk(b"hello"), b"5\r\nhello\r\n");
        assert!(encode_chunk(b"").is_empty());
    }
}
