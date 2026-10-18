//! HTTP/2 frames (RFC 9113 §4 and §6): parsing with per-type validation, and encoding.

use std::fmt;

use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind};

/// What every HTTP/2 connection starts with, sent by the client.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const HEADER_LEN: usize = 9;

/// Smallest (and default) `SETTINGS_MAX_FRAME_SIZE`.
pub const MIN_MAX_FRAME_SIZE: u32 = 16_384;
/// Largest allowed `SETTINGS_MAX_FRAME_SIZE`.
pub const MAX_MAX_FRAME_SIZE: u32 = 16_777_215;
/// Largest flow-control window.
pub const MAX_WINDOW: u32 = (1 << 31) - 1;
/// Initial flow-control window of every stream and the connection.
pub const DEFAULT_WINDOW: u32 = 65_535;

/// Error codes (RFC 9113 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    NoError,
    ProtocolError,
    InternalError,
    FlowControlError,
    SettingsTimeout,
    StreamClosed,
    FrameSizeError,
    RefusedStream,
    Cancel,
    CompressionError,
    ConnectError,
    EnhanceYourCalm,
    InadequateSecurity,
    Http11Required,
    /// A code this implementation does not know; treated like `InternalError`.
    Unknown(u32),
}

impl Reason {
    pub fn code(self) -> u32 {
        match self {
            Reason::NoError => 0x0,
            Reason::ProtocolError => 0x1,
            Reason::InternalError => 0x2,
            Reason::FlowControlError => 0x3,
            Reason::SettingsTimeout => 0x4,
            Reason::StreamClosed => 0x5,
            Reason::FrameSizeError => 0x6,
            Reason::RefusedStream => 0x7,
            Reason::Cancel => 0x8,
            Reason::CompressionError => 0x9,
            Reason::ConnectError => 0xa,
            Reason::EnhanceYourCalm => 0xb,
            Reason::InadequateSecurity => 0xc,
            Reason::Http11Required => 0xd,
            Reason::Unknown(code) => code,
        }
    }

    pub fn from_code(code: u32) -> Reason {
        match code {
            0x0 => Reason::NoError,
            0x1 => Reason::ProtocolError,
            0x2 => Reason::InternalError,
            0x3 => Reason::FlowControlError,
            0x4 => Reason::SettingsTimeout,
            0x5 => Reason::StreamClosed,
            0x6 => Reason::FrameSizeError,
            0x7 => Reason::RefusedStream,
            0x8 => Reason::Cancel,
            0x9 => Reason::CompressionError,
            0xa => Reason::ConnectError,
            0xb => Reason::EnhanceYourCalm,
            0xc => Reason::InadequateSecurity,
            0xd => Reason::Http11Required,
            other => Reason::Unknown(other),
        }
    }
}

/// A protocol violation. With `stream` set it only affects that stream (answer with
/// RST_STREAM); otherwise the whole connection must end with GOAWAY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Error {
    pub reason: Reason,
    pub stream: Option<u32>,
    pub message: String,
}

impl H2Error {
    pub fn connection(reason: Reason, message: impl Into<String>) -> H2Error {
        H2Error {
            reason,
            stream: None,
            message: message.into(),
        }
    }

    pub fn stream(stream: u32, reason: Reason, message: impl Into<String>) -> H2Error {
        H2Error {
            reason,
            stream: Some(stream),
            message: message.into(),
        }
    }
}

impl fmt::Display for H2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.stream {
            Some(id) => write!(f, "stream {id}: {} ({:?})", self.message, self.reason),
            None => write!(f, "connection: {} ({:?})", self.message, self.reason),
        }
    }
}

impl std::error::Error for H2Error {}

impl From<H2Error> for Error {
    fn from(err: H2Error) -> Error {
        Error::new(ErrorKind::Protocol, err.to_string())
    }
}

/// Stream dependency information from HEADERS or PRIORITY. Weft parses it for validation
/// but does not schedule by it (RFC 9113 deprecates the scheme).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priority {
    pub exclusive: bool,
    pub depends_on: u32,
    pub weight: u8,
}

/// Setting identifiers (RFC 9113 §6.5.2, RFC 8441).
pub mod setting {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
    pub const ENABLE_CONNECT_PROTOCOL: u16 = 0x8;
}

/// A decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data {
        stream: u32,
        end_stream: bool,
        data: Vec<u8>,
        /// Bytes of the frame counted against flow control (data plus padding).
        flow_len: u32,
    },
    Headers {
        stream: u32,
        end_stream: bool,
        end_headers: bool,
        priority: Option<Priority>,
        block: Vec<u8>,
    },
    Priority {
        stream: u32,
        priority: Priority,
    },
    RstStream {
        stream: u32,
        reason: Reason,
    },
    Settings {
        ack: bool,
        values: Vec<(u16, u32)>,
    },
    PushPromise {
        stream: u32,
        promised: u32,
        end_headers: bool,
        block: Vec<u8>,
    },
    Ping {
        ack: bool,
        data: [u8; 8],
    },
    GoAway {
        last_stream: u32,
        reason: Reason,
        debug: Vec<u8>,
    },
    WindowUpdate {
        stream: u32,
        increment: u32,
    },
    Continuation {
        stream: u32,
        end_headers: bool,
        block: Vec<u8>,
    },
    /// Unknown frame types must be ignored.
    Unknown {
        kind: u8,
        stream: u32,
    },
}

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

fn u32_at(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn frame_size(message: &str) -> H2Error {
    H2Error::connection(Reason::FrameSizeError, message)
}

fn protocol(message: &str) -> H2Error {
    H2Error::connection(Reason::ProtocolError, message)
}

/// Removes padding from a PADDED frame's payload.
fn unpad(flags: u8, payload: &[u8]) -> Result<&[u8], H2Error> {
    if flags & PADDED == 0 {
        return Ok(payload);
    }
    let (&pad, rest) = payload
        .split_first()
        .ok_or_else(|| frame_size("padded frame without a pad length"))?;
    if pad as usize > rest.len() {
        return Err(protocol("padding longer than the payload"));
    }
    Ok(&rest[..rest.len() - pad as usize])
}

fn parse_priority(b: &[u8]) -> Priority {
    let word = u32_at(b);
    Priority {
        exclusive: word >> 31 == 1,
        depends_on: word & MAX_WINDOW,
        weight: b[4],
    }
}

/// Reads frames, rejecting any larger than `max_frame_size`.
#[derive(Debug, Clone)]
pub struct FrameDecoder {
    pub max_frame_size: u32,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        FrameDecoder {
            max_frame_size: MIN_MAX_FRAME_SIZE,
        }
    }
}

impl FrameDecoder {
    pub fn decode(&mut self, buf: &mut ByteBuffer) -> Result<Option<Frame>, H2Error> {
        let data = buf.as_slice();
        if data.len() < HEADER_LEN {
            return Ok(None);
        }
        let len = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        let (kind, flags) = (data[3], data[4]);
        let stream = u32_at(&data[5..9]) & MAX_WINDOW;
        if len > self.max_frame_size {
            return Err(frame_size("frame larger than SETTINGS_MAX_FRAME_SIZE"));
        }
        let total = HEADER_LEN + len as usize;
        if data.len() < total {
            return Ok(None);
        }
        let frame = parse(kind, flags, stream, &data[HEADER_LEN..total])?;
        buf.consume(total);
        Ok(Some(frame))
    }
}

fn parse(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Result<Frame, H2Error> {
    let needs_stream = matches!(
        kind,
        DATA | HEADERS | PRIORITY | RST_STREAM | PUSH_PROMISE | CONTINUATION
    );
    if needs_stream && stream == 0 {
        return Err(protocol("frame type requires a stream"));
    }
    if matches!(kind, SETTINGS | PING | GOAWAY) && stream != 0 {
        return Err(protocol("connection-level frame sent on a stream"));
    }
    Ok(match kind {
        DATA => Frame::Data {
            stream,
            end_stream: flags & END_STREAM != 0,
            data: unpad(flags, payload)?.to_vec(),
            flow_len: payload.len() as u32,
        },
        HEADERS => {
            let mut block = unpad(flags, payload)?;
            let priority = if flags & PRIORITY_FLAG != 0 {
                if block.len() < 5 {
                    return Err(frame_size("HEADERS priority field truncated"));
                }
                let p = parse_priority(block);
                block = &block[5..];
                Some(p)
            } else {
                None
            };
            Frame::Headers {
                stream,
                end_stream: flags & END_STREAM != 0,
                end_headers: flags & END_HEADERS != 0,
                priority,
                block: block.to_vec(),
            }
        }
        PRIORITY => {
            if payload.len() != 5 {
                return Err(H2Error::stream(
                    stream,
                    Reason::FrameSizeError,
                    "PRIORITY must be 5 bytes",
                ));
            }
            Frame::Priority {
                stream,
                priority: parse_priority(payload),
            }
        }
        RST_STREAM => {
            if payload.len() != 4 {
                return Err(frame_size("RST_STREAM must be 4 bytes"));
            }
            Frame::RstStream {
                stream,
                reason: Reason::from_code(u32_at(payload)),
            }
        }
        SETTINGS => {
            let ack = flags & ACK != 0;
            if ack && !payload.is_empty() {
                return Err(frame_size("SETTINGS ack with a payload"));
            }
            if !payload.len().is_multiple_of(6) {
                return Err(frame_size("SETTINGS length not a multiple of 6"));
            }
            let values = payload
                .as_chunks::<6>()
                .0
                .iter()
                .map(|c| (u16::from_be_bytes([c[0], c[1]]), u32_at(&c[2..])))
                .collect();
            Frame::Settings { ack, values }
        }
        PUSH_PROMISE => {
            let rest = unpad(flags, payload)?;
            if rest.len() < 4 {
                return Err(frame_size("PUSH_PROMISE truncated"));
            }
            Frame::PushPromise {
                stream,
                promised: u32_at(rest) & MAX_WINDOW,
                end_headers: flags & END_HEADERS != 0,
                block: rest[4..].to_vec(),
            }
        }
        PING => {
            let data: [u8; 8] = payload
                .try_into()
                .map_err(|_| frame_size("PING must be 8 bytes"))?;
            Frame::Ping {
                ack: flags & ACK != 0,
                data,
            }
        }
        GOAWAY => {
            if payload.len() < 8 {
                return Err(frame_size("GOAWAY truncated"));
            }
            Frame::GoAway {
                last_stream: u32_at(payload) & MAX_WINDOW,
                reason: Reason::from_code(u32_at(&payload[4..])),
                debug: payload[8..].to_vec(),
            }
        }
        WINDOW_UPDATE => {
            if payload.len() != 4 {
                return Err(frame_size("WINDOW_UPDATE must be 4 bytes"));
            }
            let increment = u32_at(payload) & MAX_WINDOW;
            if increment == 0 {
                return Err(match stream {
                    0 => protocol("zero WINDOW_UPDATE increment"),
                    id => H2Error::stream(id, Reason::ProtocolError, "zero window increment"),
                });
            }
            Frame::WindowUpdate { stream, increment }
        }
        CONTINUATION => Frame::Continuation {
            stream,
            end_headers: flags & END_HEADERS != 0,
            block: payload.to_vec(),
        },
        kind => Frame::Unknown { kind, stream },
    })
}

fn put_header(out: &mut Vec<u8>, len: usize, kind: u8, flags: u8, stream: u32) {
    out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&(stream & MAX_WINDOW).to_be_bytes());
}

fn flag(on: bool, bit: u8) -> u8 {
    if on { bit } else { 0 }
}

impl Frame {
    /// Appends the frame's wire form. Payloads must already fit the peer's maximum frame
    /// size; [`Frame::Unknown`] encodes as nothing.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Data {
                stream,
                end_stream,
                data,
                ..
            } => {
                put_header(
                    out,
                    data.len(),
                    DATA,
                    flag(*end_stream, END_STREAM),
                    *stream,
                );
                out.extend_from_slice(data);
            }
            Frame::Headers {
                stream,
                end_stream,
                end_headers,
                priority,
                block,
            } => {
                let flags = flag(*end_stream, END_STREAM)
                    | flag(*end_headers, END_HEADERS)
                    | flag(priority.is_some(), PRIORITY_FLAG);
                let extra = if priority.is_some() { 5 } else { 0 };
                put_header(out, block.len() + extra, HEADERS, flags, *stream);
                if let Some(p) = priority {
                    encode_priority(p, out);
                }
                out.extend_from_slice(block);
            }
            Frame::Priority { stream, priority } => {
                put_header(out, 5, PRIORITY, 0, *stream);
                encode_priority(priority, out);
            }
            Frame::RstStream { stream, reason } => {
                put_header(out, 4, RST_STREAM, 0, *stream);
                out.extend_from_slice(&reason.code().to_be_bytes());
            }
            Frame::Settings { ack, values } => {
                put_header(out, values.len() * 6, SETTINGS, flag(*ack, ACK), 0);
                for (id, value) in values {
                    out.extend_from_slice(&id.to_be_bytes());
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
            Frame::PushPromise {
                stream,
                promised,
                end_headers,
                block,
            } => {
                put_header(
                    out,
                    block.len() + 4,
                    PUSH_PROMISE,
                    flag(*end_headers, END_HEADERS),
                    *stream,
                );
                out.extend_from_slice(&(promised & MAX_WINDOW).to_be_bytes());
                out.extend_from_slice(block);
            }
            Frame::Ping { ack, data } => {
                put_header(out, 8, PING, flag(*ack, ACK), 0);
                out.extend_from_slice(data);
            }
            Frame::GoAway {
                last_stream,
                reason,
                debug,
            } => {
                put_header(out, 8 + debug.len(), GOAWAY, 0, 0);
                out.extend_from_slice(&(last_stream & MAX_WINDOW).to_be_bytes());
                out.extend_from_slice(&reason.code().to_be_bytes());
                out.extend_from_slice(debug);
            }
            Frame::WindowUpdate { stream, increment } => {
                put_header(out, 4, WINDOW_UPDATE, 0, *stream);
                out.extend_from_slice(&(increment & MAX_WINDOW).to_be_bytes());
            }
            Frame::Continuation {
                stream,
                end_headers,
                block,
            } => {
                put_header(
                    out,
                    block.len(),
                    CONTINUATION,
                    flag(*end_headers, END_HEADERS),
                    *stream,
                );
                out.extend_from_slice(block);
            }
            Frame::Unknown { .. } => {}
        }
    }
}

fn encode_priority(p: &Priority, out: &mut Vec<u8>) {
    let word = p.depends_on & MAX_WINDOW | u32::from(p.exclusive) << 31;
    out.extend_from_slice(&word.to_be_bytes());
    out.push(p.weight);
}

/// Connection settings, with RFC 9113 defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    /// `None` means unlimited.
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    /// `None` means unlimited.
    pub max_header_list_size: Option<u32>,
    pub enable_connect_protocol: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: DEFAULT_WINDOW,
            max_frame_size: MIN_MAX_FRAME_SIZE,
            max_header_list_size: None,
            enable_connect_protocol: false,
        }
    }
}

impl Settings {
    /// Applies received values, validating ranges (RFC 9113 §6.5.2). Unknown ids are ignored.
    pub fn apply(&mut self, values: &[(u16, u32)]) -> Result<(), H2Error> {
        for &(id, value) in values {
            match id {
                setting::HEADER_TABLE_SIZE => self.header_table_size = value,
                setting::ENABLE_PUSH => {
                    self.enable_push = match value {
                        0 => false,
                        1 => true,
                        _ => return Err(protocol("ENABLE_PUSH must be 0 or 1")),
                    }
                }
                setting::MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = Some(value),
                setting::INITIAL_WINDOW_SIZE => {
                    if value > MAX_WINDOW {
                        return Err(H2Error::connection(
                            Reason::FlowControlError,
                            "INITIAL_WINDOW_SIZE above 2^31-1",
                        ));
                    }
                    self.initial_window_size = value;
                }
                setting::MAX_FRAME_SIZE => {
                    if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) {
                        return Err(protocol("MAX_FRAME_SIZE out of range"));
                    }
                    self.max_frame_size = value;
                }
                setting::MAX_HEADER_LIST_SIZE => self.max_header_list_size = Some(value),
                setting::ENABLE_CONNECT_PROTOCOL => {
                    self.enable_connect_protocol = match value {
                        0 => false,
                        1 => true,
                        _ => return Err(protocol("ENABLE_CONNECT_PROTOCOL must be 0 or 1")),
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The values that differ from the defaults, for a SETTINGS frame.
    pub fn changes(&self) -> Vec<(u16, u32)> {
        let d = Settings::default();
        let mut out = Vec::new();
        if self.header_table_size != d.header_table_size {
            out.push((setting::HEADER_TABLE_SIZE, self.header_table_size));
        }
        if self.enable_push != d.enable_push {
            out.push((setting::ENABLE_PUSH, u32::from(self.enable_push)));
        }
        if let Some(n) = self.max_concurrent_streams {
            out.push((setting::MAX_CONCURRENT_STREAMS, n));
        }
        if self.initial_window_size != d.initial_window_size {
            out.push((setting::INITIAL_WINDOW_SIZE, self.initial_window_size));
        }
        if self.max_frame_size != d.max_frame_size {
            out.push((setting::MAX_FRAME_SIZE, self.max_frame_size));
        }
        if let Some(n) = self.max_header_list_size {
            out.push((setting::MAX_HEADER_LIST_SIZE, n));
        }
        if self.enable_connect_protocol {
            out.push((setting::ENABLE_CONNECT_PROTOCOL, 1));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame) {
        let mut wire = Vec::new();
        frame.encode(&mut wire);
        let mut buf = ByteBuffer::new();
        let mut decoder = FrameDecoder::default();
        for &b in &wire[..wire.len() - 1] {
            buf.extend_from_slice(&[b]);
            assert!(decoder.decode(&mut buf).unwrap().is_none());
        }
        buf.extend_from_slice(&wire[wire.len() - 1..]);
        assert_eq!(decoder.decode(&mut buf).unwrap(), Some(frame));
    }

    #[test]
    fn every_type_roundtrips() {
        roundtrip(Frame::Data {
            stream: 1,
            end_stream: true,
            data: b"body".to_vec(),
            flow_len: 4,
        });
        roundtrip(Frame::Headers {
            stream: 3,
            end_stream: false,
            end_headers: true,
            priority: Some(Priority {
                exclusive: true,
                depends_on: 1,
                weight: 15,
            }),
            block: vec![0x82],
        });
        roundtrip(Frame::RstStream {
            stream: 5,
            reason: Reason::Cancel,
        });
        roundtrip(Frame::Settings {
            ack: false,
            values: vec![(setting::MAX_CONCURRENT_STREAMS, 100)],
        });
        roundtrip(Frame::Ping {
            ack: true,
            data: *b"12345678",
        });
        roundtrip(Frame::GoAway {
            last_stream: 7,
            reason: Reason::EnhanceYourCalm,
            debug: b"slow down".to_vec(),
        });
        roundtrip(Frame::WindowUpdate {
            stream: 0,
            increment: 1000,
        });
        roundtrip(Frame::Continuation {
            stream: 3,
            end_headers: true,
            block: vec![1, 2, 3],
        });
        roundtrip(Frame::PushPromise {
            stream: 1,
            promised: 2,
            end_headers: true,
            block: vec![0x82],
        });
    }

    #[test]
    fn padding_is_removed() {
        // DATA, PADDED, stream 1: pad length 2, "hi", two zero bytes.
        let wire = [0, 0, 5, 0, 0x8, 0, 0, 0, 1, 2, b'h', b'i', 0, 0];
        let mut buf = ByteBuffer::from(&wire[..]);
        let Some(Frame::Data { data, flow_len, .. }) =
            FrameDecoder::default().decode(&mut buf).unwrap()
        else {
            panic!("expected DATA");
        };
        assert_eq!((data.as_slice(), flow_len), (&b"hi"[..], 5));

        let bad = [0, 0, 2, 0, 0x8, 0, 0, 0, 1, 5, b'h'];
        let mut buf = ByteBuffer::from(&bad[..]);
        assert_eq!(
            FrameDecoder::default().decode(&mut buf).unwrap_err().reason,
            Reason::ProtocolError
        );
    }

    #[test]
    fn validation() {
        let check = |wire: &[u8]| {
            let mut buf = ByteBuffer::from(wire);
            FrameDecoder::default().decode(&mut buf).unwrap_err()
        };
        assert_eq!(
            check(&[0, 0, 0, 0, 0, 0, 0, 0, 0]).reason,
            Reason::ProtocolError,
            "DATA on 0"
        );
        assert_eq!(
            check(&[0, 0, 0, 4, 0, 0, 0, 0, 1]).reason,
            Reason::ProtocolError
        );
        assert_eq!(
            check(&[0, 0, 1, 4, 1, 0, 0, 0, 0, 0]).reason,
            Reason::FrameSizeError
        );
        assert_eq!(
            check(&[0, 0, 7, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).reason,
            Reason::FrameSizeError
        );
        let zero_window = check(&[0, 0, 4, 8, 0, 0, 0, 0, 3, 0, 0, 0, 0]);
        assert_eq!(
            (zero_window.reason, zero_window.stream),
            (Reason::ProtocolError, Some(3))
        );
        assert_eq!(
            check(&[0, 0x40, 1, 0, 0, 0, 0, 0, 1]).reason,
            Reason::FrameSizeError,
            "too big"
        );

        let mut s = Settings::default();
        assert!(s.apply(&[(setting::MAX_FRAME_SIZE, 100)]).is_err());
        assert_eq!(
            s.apply(&[(setting::INITIAL_WINDOW_SIZE, 1 << 31)])
                .unwrap_err()
                .reason,
            Reason::FlowControlError
        );
        s.apply(&[(setting::ENABLE_PUSH, 0), (0x99, 7)]).unwrap();
        assert_eq!(s.changes(), [(setting::ENABLE_PUSH, 0)]);
    }

    #[test]
    fn unknown_frames_are_skipped() {
        let mut buf = ByteBuffer::from(&[0, 0, 2, 0xEE, 0xFF, 0, 0, 0, 9, 1, 2][..]);
        assert_eq!(
            FrameDecoder::default().decode(&mut buf).unwrap(),
            Some(Frame::Unknown {
                kind: 0xEE,
                stream: 9
            })
        );
        assert!(buf.is_empty());
    }
}
