//! The Redis serialization protocol, RESP2 and RESP3.
//!
//! [`Value`] covers every RESP3 type; RESP2 is the subset made of simple strings, errors,
//! integers, bulk strings and arrays (with nil bulk strings and arrays mapping to
//! [`Value::Null`]). [`RespDecoder`] parses incrementally; [`Value::encode`] and
//! [`encode_command`] produce wire bytes.

use super::framing::Decoder;
use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, Result};

/// A RESP value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `+OK`
    Simple(String),
    /// `-ERR message`
    Error(String),
    /// `:42`
    Integer(i64),
    /// `$5\r\nhello`
    Bulk(Vec<u8>),
    /// `*2\r\n...`
    Array(Vec<Value>),
    /// RESP2 nil bulk/array, or RESP3 `_`.
    Null,
    /// RESP3 `#t` / `#f`.
    Boolean(bool),
    /// RESP3 `,3.14` (also `inf`, `-inf`, `nan`).
    Double(f64),
    /// RESP3 `(` arbitrary-precision integer, kept as its decimal text.
    BigNumber(String),
    /// RESP3 `!` error with a binary-safe message.
    BlobError(Vec<u8>),
    /// RESP3 `=` text with a three-letter format tag such as `txt` or `mkd`.
    Verbatim { format: String, text: Vec<u8> },
    /// RESP3 `%` map, as ordered pairs.
    Map(Vec<(Value, Value)>),
    /// RESP3 `~` set.
    Set(Vec<Value>),
    /// RESP3 `>` out-of-band push.
    Push(Vec<Value>),
    /// RESP3 `|` attributes attached to the value that follows them.
    Attributed {
        attributes: Vec<(Value, Value)>,
        value: Box<Value>,
    },
}

impl Value {
    /// Convenience for building a bulk string.
    pub fn bulk(data: impl Into<Vec<u8>>) -> Value {
        Value::Bulk(data.into())
    }

    /// The bytes of a string-like value.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Simple(s) => Some(s.as_bytes()),
            Value::Bulk(b) => Some(b),
            Value::Verbatim { text, .. } => Some(text),
            _ => None,
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Value::Error(_) | Value::BlobError(_))
    }

    /// Appends the wire encoding of `self`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        fn line(out: &mut Vec<u8>, tag: u8, text: &str) {
            out.push(tag);
            out.extend_from_slice(text.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        fn blob(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
            line(out, tag, &data.len().to_string());
            out.extend_from_slice(data);
            out.extend_from_slice(b"\r\n");
        }
        fn seq(out: &mut Vec<u8>, tag: u8, items: &[Value]) {
            line(out, tag, &items.len().to_string());
            for item in items {
                item.encode_into(out);
            }
        }
        fn pairs(out: &mut Vec<u8>, tag: u8, items: &[(Value, Value)]) {
            line(out, tag, &items.len().to_string());
            for (k, v) in items {
                k.encode_into(out);
                v.encode_into(out);
            }
        }
        match self {
            // CR or LF would break a line-based value, so escape them as spaces.
            Value::Simple(s) => line(out, b'+', &s.replace(['\r', '\n'], " ")),
            Value::Error(s) => line(out, b'-', &s.replace(['\r', '\n'], " ")),
            Value::Integer(n) => line(out, b':', &n.to_string()),
            Value::Bulk(data) => blob(out, b'$', data),
            Value::Array(items) => seq(out, b'*', items),
            Value::Null => out.extend_from_slice(b"_\r\n"),
            Value::Boolean(b) => line(out, b'#', if *b { "t" } else { "f" }),
            Value::Double(d) => {
                let text = if d.is_nan() {
                    "nan".to_owned()
                } else if d.is_infinite() {
                    if *d > 0.0 { "inf" } else { "-inf" }.to_owned()
                } else {
                    d.to_string()
                };
                line(out, b',', &text)
            }
            Value::BigNumber(n) => line(out, b'(', n),
            Value::BlobError(data) => blob(out, b'!', data),
            Value::Verbatim { format, text } => {
                let mut data = format.as_bytes().to_vec();
                data.push(b':');
                data.extend_from_slice(text);
                blob(out, b'=', &data)
            }
            Value::Map(items) => pairs(out, b'%', items),
            Value::Set(items) => seq(out, b'~', items),
            Value::Push(items) => seq(out, b'>', items),
            Value::Attributed { attributes, value } => {
                pairs(out, b'|', attributes);
                value.encode_into(out);
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// RESP2's encoding of null: a nil bulk string.
    pub fn encode_resp2_null() -> &'static [u8] {
        b"$-1\r\n"
    }
}

/// Encodes a command as an array of bulk strings, the form servers accept.
pub fn encode_command<A: AsRef<[u8]>>(args: &[A]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        let arg = arg.as_ref();
        out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        out.extend_from_slice(arg);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Incremental RESP parser with size and nesting limits.
#[derive(Debug, Clone)]
pub struct RespDecoder {
    pub max_bulk: usize,
    pub max_elements: usize,
    pub max_depth: usize,
}

impl Default for RespDecoder {
    fn default() -> Self {
        RespDecoder {
            max_bulk: 512 * 1024 * 1024,
            max_elements: 1024 * 1024,
            max_depth: 64,
        }
    }
}

/// Parsing outcome for a prefix of the input.
enum Step<T> {
    Done(T, usize),
    Incomplete,
}

fn protocol(msg: impl Into<String>) -> Error {
    Error::new(ErrorKind::Protocol, msg)
}

impl RespDecoder {
    fn line(data: &[u8], from: usize) -> Result<Step<&[u8]>> {
        match data[from..].windows(2).position(|w| w == b"\r\n") {
            Some(pos) => Ok(Step::Done(&data[from..from + pos], from + pos + 2)),
            None if data.len() - from > 64 * 1024 => Err(protocol("RESP line too long")),
            None => Ok(Step::Incomplete),
        }
    }

    fn int(text: &[u8]) -> Result<i64> {
        std::str::from_utf8(text)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                protocol(format!(
                    "bad RESP integer {:?}",
                    String::from_utf8_lossy(text)
                ))
            })
    }

    fn count(&self, text: &[u8]) -> Result<Option<usize>> {
        match Self::int(text)? {
            -1 => Ok(None),
            n if n < 0 => Err(protocol("negative RESP length")),
            n if n as u64 > self.max_elements as u64 => Err(Error::new(
                ErrorKind::TooLarge,
                format!("RESP aggregate of {n} elements exceeds the limit"),
            )),
            n => Ok(Some(n as usize)),
        }
    }

    fn parse(&self, data: &[u8], from: usize, depth: usize) -> Result<Step<Value>> {
        if depth > self.max_depth {
            return Err(protocol("RESP nesting too deep"));
        }
        let Some(&tag) = data.get(from) else {
            return Ok(Step::Incomplete);
        };
        let (text, mut pos) = match Self::line(data, from + 1)? {
            Step::Done(text, pos) => (text, pos),
            Step::Incomplete => return Ok(Step::Incomplete),
        };
        let as_string = |t: &[u8]| String::from_utf8_lossy(t).into_owned();
        let value = match tag {
            b'+' => Value::Simple(as_string(text)),
            b'-' => Value::Error(as_string(text)),
            b':' => Value::Integer(Self::int(text)?),
            b'_' => Value::Null,
            b'#' => match text {
                b"t" => Value::Boolean(true),
                b"f" => Value::Boolean(false),
                _ => return Err(protocol("bad RESP boolean")),
            },
            b',' => {
                let text = as_string(text);
                Value::Double(match text.as_str() {
                    "inf" => f64::INFINITY,
                    "-inf" => f64::NEG_INFINITY,
                    other => other
                        .parse()
                        .map_err(|_| protocol(format!("bad RESP double {other:?}")))?,
                })
            }
            b'(' => {
                let digits = text.strip_prefix(b"-").unwrap_or(text);
                if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                    return Err(protocol("bad RESP big number"));
                }
                Value::BigNumber(as_string(text))
            }
            b'$' | b'!' | b'=' => {
                let Some(len) = self.count_bulk(text)? else {
                    return Ok(Step::Done(Value::Null, pos));
                };
                let Some(body) = data.get(pos..pos + len + 2) else {
                    return Ok(Step::Incomplete);
                };
                if &body[len..] != b"\r\n" {
                    return Err(protocol("RESP bulk string not followed by CRLF"));
                }
                let body = body[..len].to_vec();
                pos += len + 2;
                match tag {
                    b'$' => Value::Bulk(body),
                    b'!' => Value::BlobError(body),
                    _ => {
                        if body.len() < 4 || body[3] != b':' {
                            return Err(protocol("RESP verbatim string without a format"));
                        }
                        Value::Verbatim {
                            format: as_string(&body[..3]),
                            text: body[4..].to_vec(),
                        }
                    }
                }
            }
            b'*' | b'~' | b'>' => {
                let Some(n) = self.count(text)? else {
                    return Ok(Step::Done(Value::Null, pos));
                };
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    match self.parse(data, pos, depth + 1)? {
                        Step::Done(item, next) => {
                            items.push(item);
                            pos = next;
                        }
                        Step::Incomplete => return Ok(Step::Incomplete),
                    }
                }
                match tag {
                    b'*' => Value::Array(items),
                    b'~' => Value::Set(items),
                    _ => Value::Push(items),
                }
            }
            b'%' | b'|' => {
                let n = self.count(text)?.ok_or_else(|| protocol("nil RESP map"))?;
                let mut pairs = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    let Step::Done(key, next) = self.parse(data, pos, depth + 1)? else {
                        return Ok(Step::Incomplete);
                    };
                    let Step::Done(value, next) = self.parse(data, next, depth + 1)? else {
                        return Ok(Step::Incomplete);
                    };
                    pairs.push((key, value));
                    pos = next;
                }
                if tag == b'%' {
                    Value::Map(pairs)
                } else {
                    let Step::Done(value, next) = self.parse(data, pos, depth + 1)? else {
                        return Ok(Step::Incomplete);
                    };
                    pos = next;
                    Value::Attributed {
                        attributes: pairs,
                        value: Box::new(value),
                    }
                }
            }
            other => return Err(protocol(format!("unknown RESP type byte {other:#04x}"))),
        };
        Ok(Step::Done(value, pos))
    }

    fn count_bulk(&self, text: &[u8]) -> Result<Option<usize>> {
        match Self::int(text)? {
            -1 => Ok(None),
            n if n < 0 => Err(protocol("negative RESP length")),
            n if n as u64 > self.max_bulk as u64 => Err(Error::new(
                ErrorKind::TooLarge,
                format!("RESP bulk string of {n} bytes exceeds the limit"),
            )),
            n => Ok(Some(n as usize)),
        }
    }
}

impl Decoder for RespDecoder {
    type Item = Value;

    fn decode(&mut self, buf: &mut ByteBuffer) -> Result<Option<Value>> {
        match self.parse(buf.as_slice(), 0, 0)? {
            Step::Done(value, used) => {
                buf.consume(used);
                Ok(Some(value))
            }
            Step::Incomplete => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(wire: &[u8]) -> Vec<Value> {
        let mut decoder = RespDecoder::default();
        let mut buf = ByteBuffer::new();
        let mut out = Vec::new();
        for &b in wire {
            buf.extend_from_slice(&[b]);
            while let Some(v) = decoder.decode(&mut buf).unwrap() {
                out.push(v);
            }
        }
        assert!(buf.is_empty());
        out
    }

    #[test]
    fn resp2_types() {
        let wire =
            b"+OK\r\n-ERR bad\r\n:-7\r\n$5\r\nhe\r\no\r\n$-1\r\n*-1\r\n*2\r\n$3\r\nGET\r\n:1\r\n";
        assert_eq!(
            decode_all(wire),
            [
                Value::Simple("OK".into()),
                Value::Error("ERR bad".into()),
                Value::Integer(-7),
                Value::bulk(&b"he\r\no"[..]),
                Value::Null,
                Value::Null,
                Value::Array(vec![Value::bulk("GET"), Value::Integer(1)]),
            ]
        );
    }

    #[test]
    fn resp3_roundtrip() {
        let values = vec![
            Value::Null,
            Value::Boolean(true),
            Value::Double(1.5),
            Value::Double(f64::NEG_INFINITY),
            Value::BigNumber("-123456789012345678901234567890".into()),
            Value::BlobError(b"SYNTAX bad".to_vec()),
            Value::Verbatim {
                format: "txt".into(),
                text: b"Some string".to_vec(),
            },
            Value::Map(vec![(Value::Simple("a".into()), Value::Integer(1))]),
            Value::Set(vec![Value::Integer(1), Value::Integer(2)]),
            Value::Push(vec![Value::bulk("message"), Value::bulk("hi")]),
            Value::Attributed {
                attributes: vec![(Value::Simple("ttl".into()), Value::Integer(3))],
                value: Box::new(Value::Array(vec![Value::Integer(9)])),
            },
        ];
        let mut wire = Vec::new();
        for v in &values {
            v.encode_into(&mut wire);
        }
        assert_eq!(decode_all(&wire), values);
    }

    #[test]
    fn commands_and_errors() {
        assert_eq!(
            encode_command(&["SET", "k", "v v"]),
            b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$3\r\nv v\r\n"
        );
        let mut decoder = RespDecoder {
            max_bulk: 4,
            max_elements: 2,
            max_depth: 2,
        };
        let mut check = |wire: &[u8]| {
            let mut buf = ByteBuffer::from(wire);
            decoder.decode(&mut buf).unwrap_err().kind()
        };
        assert_eq!(check(b"$5\r\nhello\r\n"), ErrorKind::TooLarge);
        assert_eq!(check(b"*3\r\n"), ErrorKind::TooLarge);
        assert_eq!(check(b"*1\r\n*1\r\n*1\r\n:1\r\n"), ErrorKind::Protocol);
        assert_eq!(check(b"$2\r\nabX\r\n"), ErrorKind::Protocol);
        assert_eq!(check(b"?x\r\n"), ErrorKind::Protocol);
        assert_eq!(check(b":12a\r\n"), ErrorKind::Protocol);
    }
}
