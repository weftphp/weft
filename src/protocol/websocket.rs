//! The WebSocket protocol (RFC 6455): opening handshake, frame codec and message assembly.
//!
//! Layers, from the wire up:
//!
//! 1. [`handshake_response`] / [`client_request`] / [`check_server_response`] for the HTTP
//!    upgrade.
//! 2. [`FrameDecoder`] and [`encode_frame`] for individual frames.
//! 3. [`Assembler`] for joining fragments into [`Message`]s and validating them.
//!
//! Extensions (such as compression) are not negotiated, so the RSV bits must be zero.

use std::fmt;

use super::framing::Decoder;
use super::http::{Method, Request, Response, parser::HttpError};
use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, base64, random, sha1};

/// Fixed value appended to the client key when computing the accept key (RFC 6455 §1.3).
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Largest payload of a control frame.
pub const MAX_CONTROL_PAYLOAD: usize = 125;

/// Close status codes (RFC 6455 §7.4.1).
pub mod close_code {
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const UNSUPPORTED_DATA: u16 = 1003;
    pub const INVALID_PAYLOAD: u16 = 1007;
    pub const POLICY_VIOLATION: u16 = 1008;
    pub const MESSAGE_TOO_BIG: u16 = 1009;
    pub const MANDATORY_EXTENSION: u16 = 1010;
    pub const INTERNAL_ERROR: u16 = 1011;

    /// Whether `code` may appear in a Close frame on the wire.
    pub fn is_sendable(code: u16) -> bool {
        matches!(code, 1000..=1003 | 1007..=1011 | 3000..=4999)
    }
}

/// A protocol violation, carrying the close code to answer with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsError {
    pub code: u16,
    pub message: String,
}

impl WsError {
    fn new(code: u16, message: impl Into<String>) -> WsError {
        WsError {
            code,
            message: message.into(),
        }
    }

    fn protocol(message: impl Into<String>) -> WsError {
        WsError::new(close_code::PROTOCOL_ERROR, message)
    }
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (close code {})", self.message, self.code)
    }
}

impl std::error::Error for WsError {}

impl From<WsError> for Error {
    fn from(err: WsError) -> Error {
        let kind = if err.code == close_code::MESSAGE_TOO_BIG {
            ErrorKind::TooLarge
        } else {
            ErrorKind::Protocol
        };
        Error::new(kind, err.to_string())
    }
}

// ----- handshake -----

/// The `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`.
pub fn accept_key(client_key: &str) -> String {
    let mut hasher = sha1::Sha1::new();
    hasher.update(client_key.trim().as_bytes());
    hasher.update(ACCEPT_GUID.as_bytes());
    base64::encode(&hasher.finish())
}

/// Validates an upgrade request and builds the `101 Switching Protocols` answer.
/// `protocol` is the subprotocol the server picked from `Sec-WebSocket-Protocol`, if any.
pub fn handshake_response(req: &Request, protocol: Option<&str>) -> Result<Response, HttpError> {
    let bad = |message: &str| HttpError {
        status: 400,
        message: message.to_owned(),
    };
    if req.method != Method::Get {
        return Err(bad("WebSocket upgrades must use GET"));
    }
    if !req.wants_upgrade("websocket") {
        return Err(bad("missing Upgrade: websocket"));
    }
    if req.headers.get("sec-websocket-version").map(str::trim) != Some("13") {
        // RFC 6455 §4.4: advertise the version we speak.
        return Err(HttpError {
            status: 426,
            message: "unsupported WebSocket version; this server speaks 13".into(),
        });
    }
    let key = req
        .headers
        .get("sec-websocket-key")
        .ok_or_else(|| bad("missing Sec-WebSocket-Key"))?;
    if base64::decode(key.trim()).is_none_or(|k| k.len() != 16) {
        return Err(bad("Sec-WebSocket-Key must be 16 base64-encoded bytes"));
    }
    let mut response = Response::new(101)
        .with_header("Upgrade", "websocket")
        .with_header("Connection", "Upgrade")
        .with_header("Sec-WebSocket-Accept", accept_key(key));
    if let Some(protocol) = protocol {
        response.headers.append("Sec-WebSocket-Protocol", protocol);
    }
    Ok(response)
}

/// A fresh `Sec-WebSocket-Key`.
pub fn new_key() -> Result<String, Error> {
    let mut nonce = [0u8; 16];
    random::fill(&mut nonce)?;
    Ok(base64::encode(&nonce))
}

/// Builds a client's upgrade request.
pub fn client_request(host: &str, target: &str, key: &str) -> Request {
    let mut req = Request::new(Method::Get, target);
    req.headers.append("Host", host);
    req.headers.append("Upgrade", "websocket");
    req.headers.append("Connection", "Upgrade");
    req.headers.append("Sec-WebSocket-Key", key);
    req.headers.append("Sec-WebSocket-Version", "13");
    req
}

/// Checks the server's answer to [`client_request`].
pub fn check_server_response(response: &Response, key: &str) -> Result<(), Error> {
    let fail = |m: &str| Error::new(ErrorKind::Protocol, format!("WebSocket handshake: {m}"));
    if response.status != 101 {
        return Err(fail(&format!("server answered {}", response.status)));
    }
    if !response.headers.has_token("upgrade", "websocket")
        || !response.headers.has_token("connection", "upgrade")
    {
        return Err(fail("missing upgrade headers"));
    }
    if response.headers.get("sec-websocket-accept") != Some(accept_key(key).as_str()) {
        return Err(fail("wrong Sec-WebSocket-Accept"));
    }
    Ok(())
}

// ----- frames -----

/// Frame opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    fn from_bits(bits: u8) -> Option<Opcode> {
        Some(match bits {
            0x0 => Opcode::Continuation,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            0x8 => Opcode::Close,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            _ => return None,
        })
    }

    fn bits(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
        }
    }

    pub fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
    }
}

/// One frame, payload already unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(opcode: Opcode, payload: impl Into<Vec<u8>>) -> Frame {
        Frame {
            fin: true,
            opcode,
            payload: payload.into(),
        }
    }
}

fn apply_mask(data: &mut [u8], key: [u8; 4]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % 4];
    }
}

/// Serializes `frame`. Clients must pass a fresh random `mask`; servers pass `None`.
pub fn encode_frame(frame: &Frame, mask: Option<[u8; 4]>) -> Vec<u8> {
    let len = frame.payload.len();
    let mut out = Vec::with_capacity(len + 14);
    out.push(u8::from(frame.fin) << 7 | frame.opcode.bits());
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let start = out.len() + mask.map_or(0, |_| 4);
    if let Some(key) = mask {
        out.extend_from_slice(&key);
    }
    out.extend_from_slice(&frame.payload);
    if let Some(key) = mask {
        apply_mask(&mut out[start..], key);
    }
    out
}

/// Which side is decoding: it determines whether incoming frames must be masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Frames come from clients and must be masked.
    Server,
    /// Frames come from a server and must not be masked.
    Client,
}

/// Reads frames, enforcing RFC 6455's framing rules.
#[derive(Debug, Clone)]
pub struct FrameDecoder {
    pub role: Role,
    pub max_payload: usize,
}

impl FrameDecoder {
    pub fn new(role: Role, max_payload: usize) -> FrameDecoder {
        FrameDecoder { role, max_payload }
    }

    /// Like [`Decoder::decode`], with a [`WsError`] carrying the close code.
    pub fn decode_frame(&mut self, buf: &mut ByteBuffer) -> Result<Option<Frame>, WsError> {
        let data = buf.as_slice();
        if data.len() < 2 {
            return Ok(None);
        }
        let (b0, b1) = (data[0], data[1]);
        if b0 & 0x70 != 0 {
            return Err(WsError::protocol("reserved bits set without an extension"));
        }
        let opcode = Opcode::from_bits(b0 & 0x0F)
            .ok_or_else(|| WsError::protocol(format!("reserved opcode {:#x}", b0 & 0x0F)))?;
        let fin = b0 & 0x80 != 0;
        let masked = b1 & 0x80 != 0;
        if masked != (self.role == Role::Server) {
            return Err(WsError::protocol(if masked {
                "server frames must not be masked"
            } else {
                "client frames must be masked"
            }));
        }

        let (len, mut pos) = match b1 & 0x7F {
            126 => {
                let Some(b) = data.get(2..4) else {
                    return Ok(None);
                };
                (u64::from(u16::from_be_bytes([b[0], b[1]])), 4)
            }
            127 => {
                let Some(b) = data.get(2..10) else {
                    return Ok(None);
                };
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(b);
                let len = u64::from_be_bytes(bytes);
                if len >> 63 != 0 {
                    return Err(WsError::protocol("payload length has its top bit set"));
                }
                (len, 10)
            }
            n => (u64::from(n), 2),
        };
        if opcode.is_control() && (!fin || len > MAX_CONTROL_PAYLOAD as u64) {
            return Err(WsError::protocol(
                "control frames must be unfragmented and at most 125 bytes",
            ));
        }
        if len > self.max_payload as u64 {
            return Err(WsError::new(
                close_code::MESSAGE_TOO_BIG,
                format!("frame of {len} bytes exceeds the limit"),
            ));
        }
        let len = len as usize;
        let key = if masked {
            let Some(k) = data.get(pos..pos + 4) else {
                return Ok(None);
            };
            pos += 4;
            Some([k[0], k[1], k[2], k[3]])
        } else {
            None
        };
        let Some(payload) = data.get(pos..pos + len) else {
            return Ok(None);
        };
        let mut payload = payload.to_vec();
        if let Some(key) = key {
            apply_mask(&mut payload, key);
        }
        buf.consume(pos + len);
        Ok(Some(Frame {
            fin,
            opcode,
            payload,
        }))
    }
}

impl Decoder for FrameDecoder {
    type Item = Frame;

    fn decode(&mut self, buf: &mut ByteBuffer) -> crate::core::Result<Option<Frame>> {
        Ok(self.decode_frame(buf)?)
    }
}

// ----- messages -----

/// A Close frame's body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseReason {
    pub code: u16,
    pub reason: String,
}

/// A complete application-level message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    /// `None` when the peer sent an empty Close frame.
    Close(Option<CloseReason>),
}

impl Message {
    /// The frame(s) for this message, unfragmented.
    pub fn into_frame(self) -> Frame {
        match self {
            Message::Text(text) => Frame::new(Opcode::Text, text.into_bytes()),
            Message::Binary(data) => Frame::new(Opcode::Binary, data),
            Message::Ping(data) => Frame::new(Opcode::Ping, data),
            Message::Pong(data) => Frame::new(Opcode::Pong, data),
            Message::Close(None) => Frame::new(Opcode::Close, Vec::new()),
            Message::Close(Some(CloseReason { code, reason })) => {
                Frame::new(Opcode::Close, close_payload(code, &reason))
            }
        }
    }
}

/// A Close frame payload. The reason is cut (on a character boundary) to fit 125 bytes.
pub fn close_payload(code: u16, reason: &str) -> Vec<u8> {
    let mut end = reason.len().min(MAX_CONTROL_PAYLOAD - 2);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = code.to_be_bytes().to_vec();
    out.extend_from_slice(&reason.as_bytes()[..end]);
    out
}

fn parse_close(payload: &[u8]) -> Result<Option<CloseReason>, WsError> {
    match payload {
        [] => Ok(None),
        [_] => Err(WsError::protocol("one-byte close payload")),
        [hi, lo, reason @ ..] => {
            let code = u16::from_be_bytes([*hi, *lo]);
            if !close_code::is_sendable(code) {
                return Err(WsError::protocol(format!("invalid close code {code}")));
            }
            let reason = std::str::from_utf8(reason).map_err(|_| {
                WsError::new(close_code::INVALID_PAYLOAD, "close reason is not UTF-8")
            })?;
            Ok(Some(CloseReason {
                code,
                reason: reason.to_owned(),
            }))
        }
    }
}

/// Joins fragments into messages. Control frames may arrive between fragments and are
/// returned immediately.
#[derive(Debug, Clone)]
pub struct Assembler {
    pub max_message: usize,
    partial: Option<(Opcode, Vec<u8>)>,
}

impl Assembler {
    pub fn new(max_message: usize) -> Assembler {
        Assembler {
            max_message,
            partial: None,
        }
    }

    /// Feeds one frame; returns a message once one is complete.
    pub fn push(&mut self, frame: Frame) -> Result<Option<Message>, WsError> {
        match frame.opcode {
            Opcode::Ping => return Ok(Some(Message::Ping(frame.payload))),
            Opcode::Pong => return Ok(Some(Message::Pong(frame.payload))),
            Opcode::Close => return Ok(Some(Message::Close(parse_close(&frame.payload)?))),
            Opcode::Continuation => {
                let Some((_, data)) = &mut self.partial else {
                    return Err(WsError::protocol(
                        "continuation without a message to continue",
                    ));
                };
                if data.len() + frame.payload.len() > self.max_message {
                    return Err(WsError::new(
                        close_code::MESSAGE_TOO_BIG,
                        "message exceeds the limit",
                    ));
                }
                data.extend_from_slice(&frame.payload);
            }
            Opcode::Text | Opcode::Binary => {
                if self.partial.is_some() {
                    return Err(WsError::protocol(
                        "new message before the last one finished",
                    ));
                }
                if frame.payload.len() > self.max_message {
                    return Err(WsError::new(
                        close_code::MESSAGE_TOO_BIG,
                        "message exceeds the limit",
                    ));
                }
                self.partial = Some((frame.opcode, frame.payload));
            }
        }
        if !frame.fin {
            return Ok(None);
        }
        let Some((opcode, data)) = self.partial.take() else {
            return Ok(None);
        };
        Ok(Some(if opcode == Opcode::Text {
            Message::Text(String::from_utf8(data).map_err(|_| {
                WsError::new(close_code::INVALID_PAYLOAD, "text message is not UTF-8")
            })?)
        } else {
            Message::Binary(data)
        }))
    }
}

/// A random masking key for client frames.
pub fn new_mask() -> Result<[u8; 4], Error> {
    let mut key = [0u8; 4];
    random::fill(&mut key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_rfc_example() {
        // RFC 6455 §1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn handshake_both_sides() {
        let key = new_key().unwrap();
        let req = client_request("example.test", "/chat", &key);
        let response = handshake_response(&req, Some("chat")).unwrap();
        assert_eq!(response.status, 101);
        check_server_response(&response, &key).unwrap();
        assert!(check_server_response(&response, "other").is_err());

        let mut old = req.clone();
        old.headers.set("Sec-WebSocket-Version", "8");
        assert_eq!(handshake_response(&old, None).unwrap_err().status, 426);
        let mut short = req.clone();
        short.headers.set("Sec-WebSocket-Key", "c2hvcnQ=");
        assert_eq!(handshake_response(&short, None).unwrap_err().status, 400);
    }

    #[test]
    fn rfc_frame_examples() {
        // RFC 6455 §5.7: unmasked and masked "Hello".
        let unmasked = [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
        let masked = [
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ];
        let hello = Frame::new(Opcode::Text, &b"Hello"[..]);
        assert_eq!(encode_frame(&hello, None), unmasked);
        assert_eq!(encode_frame(&hello, Some([0x37, 0xfa, 0x21, 0x3d])), masked);

        let mut client_side = FrameDecoder::new(Role::Client, 1024);
        let mut buf = ByteBuffer::from(&unmasked[..]);
        assert_eq!(
            client_side.decode_frame(&mut buf).unwrap(),
            Some(hello.clone())
        );
        let mut server_side = FrameDecoder::new(Role::Server, 1024);
        let mut buf = ByteBuffer::from(&masked[..]);
        assert_eq!(server_side.decode_frame(&mut buf).unwrap(), Some(hello));

        // 256-byte and 64 KiB binary frames use the 16- and 64-bit length forms.
        let medium = encode_frame(&Frame::new(Opcode::Binary, vec![0; 256]), None);
        assert_eq!(&medium[..4], [0x82, 0x7E, 0x01, 0x00]);
        let large = encode_frame(&Frame::new(Opcode::Binary, vec![0; 65536]), None);
        assert_eq!(&large[..10], [0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0, 0]);
    }

    #[test]
    fn decoder_waits_for_partial_frames_and_rejects_violations() {
        let wire = encode_frame(
            &Frame::new(Opcode::Binary, vec![7; 300]),
            Some([1, 2, 3, 4]),
        );
        let mut decoder = FrameDecoder::new(Role::Server, 1024);
        let mut buf = ByteBuffer::new();
        for chunk in wire.chunks(7) {
            assert!(buf.is_empty() || decoder.decode_frame(&mut buf).unwrap().is_none());
            buf.extend_from_slice(chunk);
        }
        assert_eq!(
            decoder.decode_frame(&mut buf).unwrap().unwrap().payload,
            vec![7; 300]
        );

        let reject = |bytes: &[u8], role: Role| {
            let mut buf = ByteBuffer::from(bytes);
            FrameDecoder::new(role, 100)
                .decode_frame(&mut buf)
                .unwrap_err()
        };
        assert_eq!(
            reject(&[0x81, 0x00], Role::Server).code,
            1002,
            "unmasked from client"
        );
        assert_eq!(reject(&[0x81, 0x80, 0, 0, 0, 0], Role::Client).code, 1002);
        assert_eq!(reject(&[0xC1, 0x00], Role::Client).code, 1002, "RSV1");
        assert_eq!(reject(&[0x83, 0x00], Role::Client).code, 1002, "opcode 3");
        assert_eq!(
            reject(&[0x09, 0x00], Role::Client).code,
            1002,
            "fragmented ping"
        );
        assert_eq!(reject(&[0x82, 0x7E, 0x01, 0x00], Role::Client).code, 1009);
    }

    #[test]
    fn assembles_fragments_around_control_frames() {
        let mut asm = Assembler::new(16);
        let frag = |fin, opcode, data: &str| Frame {
            fin,
            opcode,
            payload: data.as_bytes().to_vec(),
        };
        assert_eq!(asm.push(frag(false, Opcode::Text, "Hel")).unwrap(), None);
        assert_eq!(
            asm.push(frag(true, Opcode::Ping, "p")).unwrap(),
            Some(Message::Ping(b"p".to_vec()))
        );
        assert_eq!(
            asm.push(frag(true, Opcode::Continuation, "lo")).unwrap(),
            Some(Message::Text("Hello".into()))
        );

        assert!(asm.push(frag(true, Opcode::Continuation, "x")).is_err());
        asm.push(frag(false, Opcode::Binary, "a")).unwrap();
        assert!(asm.push(frag(true, Opcode::Text, "b")).is_err());

        let mut asm = Assembler::new(16);
        let bad_utf8 = Frame::new(Opcode::Text, vec![0xFF]);
        assert_eq!(asm.push(bad_utf8).unwrap_err().code, 1007);
        let big = Frame::new(Opcode::Binary, vec![0; 17]);
        assert_eq!(asm.push(big).unwrap_err().code, 1009);
    }

    #[test]
    fn close_frames() {
        let mut asm = Assembler::new(16);
        let msg = Message::Close(Some(CloseReason {
            code: 1000,
            reason: "bye".into(),
        }));
        assert_eq!(asm.push(msg.clone().into_frame()).unwrap(), Some(msg));
        assert_eq!(
            asm.push(Frame::new(Opcode::Close, vec![])).unwrap(),
            Some(Message::Close(None))
        );
        assert!(asm.push(Frame::new(Opcode::Close, vec![3])).is_err());
        assert!(
            asm.push(Frame::new(Opcode::Close, close_payload(1005, "")))
                .is_err()
        );
        assert_eq!(close_payload(1000, &"é".repeat(100)).len(), 124);
    }
}
