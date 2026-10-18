//! Splitting a byte stream into messages.
//!
//! A [`Decoder`] pulls complete messages out of a connection's [`ByteBuffer`], leaving partial
//! ones in place until more bytes arrive. Two generic framings cover most custom protocols:
//!
//! - [`LengthPrefixed`]: a fixed-size header carries the body length.
//! - [`Delimited`]: messages end with a marker such as `"\r\n"`.

use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, Result};

/// Incremental message extraction.
pub trait Decoder {
    type Item;

    /// Removes and returns the next complete message, `Ok(None)` if more bytes are needed,
    /// or an error if the stream can never yield a valid message (the connection should then
    /// be closed).
    fn decode(&mut self, buf: &mut ByteBuffer) -> Result<Option<Self::Item>>;
}

/// Width of a length field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    U8,
    U16,
    U32,
    U64,
}

impl Width {
    pub fn bytes(self) -> usize {
        match self {
            Width::U8 => 1,
            Width::U16 => 2,
            Width::U32 => 4,
            Width::U64 => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

/// Messages whose header holds the body length.
///
/// Layout: `header_len` bytes of header, of which `width` bytes starting at `length_at` are
/// the length, followed by the body. If `length_counts_header` is set, the length covers the
/// header too.
#[derive(Debug, Clone)]
pub struct LengthPrefixed {
    pub header_len: usize,
    pub length_at: usize,
    pub width: Width,
    pub endian: Endian,
    pub length_counts_header: bool,
    /// Largest accepted message, header included.
    pub max_len: usize,
    /// Return only the body instead of the whole message.
    pub strip_header: bool,
}

impl LengthPrefixed {
    /// The common layout: a big-endian `width` length followed directly by the body.
    pub fn simple(width: Width, max_len: usize) -> LengthPrefixed {
        LengthPrefixed {
            header_len: width.bytes(),
            length_at: 0,
            width,
            endian: Endian::Big,
            length_counts_header: false,
            max_len,
            strip_header: true,
        }
    }

    /// Checks that the length field fits inside the header.
    pub fn validate(&self) -> Result<()> {
        if self.length_at + self.width.bytes() > self.header_len {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "length field extends past the header",
            ));
        }
        Ok(())
    }

    fn read_length(&self, header: &[u8]) -> u64 {
        let field = &header[self.length_at..self.length_at + self.width.bytes()];
        let mut bytes = [0u8; 8];
        match self.endian {
            Endian::Big => {
                bytes[8 - field.len()..].copy_from_slice(field);
                u64::from_be_bytes(bytes)
            }
            Endian::Little => {
                bytes[..field.len()].copy_from_slice(field);
                u64::from_le_bytes(bytes)
            }
        }
    }

    /// Prefixes `body` with a header for the simple layout (length at offset 0, other header
    /// bytes zero).
    pub fn encode(&self, body: &[u8]) -> Result<Vec<u8>> {
        self.validate()?;
        let total = self.header_len + body.len();
        let length = if self.length_counts_header {
            total
        } else {
            body.len()
        } as u64;
        let width = self.width.bytes();
        if total > self.max_len || (width < 8 && length >> (8 * width) != 0) {
            return Err(Error::new(
                ErrorKind::TooLarge,
                format!("message of {total} bytes does not fit the framing"),
            ));
        }
        let mut out = vec![0u8; self.header_len];
        let field = match self.endian {
            Endian::Big => length.to_be_bytes()[8 - width..].to_vec(),
            Endian::Little => length.to_le_bytes()[..width].to_vec(),
        };
        out[self.length_at..self.length_at + width].copy_from_slice(&field);
        out.extend_from_slice(body);
        Ok(out)
    }
}

impl Decoder for LengthPrefixed {
    type Item = Vec<u8>;

    fn decode(&mut self, buf: &mut ByteBuffer) -> Result<Option<Vec<u8>>> {
        self.validate()?;
        let data = buf.as_slice();
        if data.len() < self.header_len {
            return Ok(None);
        }
        let length = self.read_length(data);
        let total = if self.length_counts_header {
            length
        } else {
            length.saturating_add(self.header_len as u64)
        };
        if total < self.header_len as u64 || total > self.max_len as u64 {
            return Err(Error::new(
                ErrorKind::Protocol,
                format!("declared message length {total} is out of range"),
            ));
        }
        let total = total as usize;
        if data.len() < total {
            return Ok(None);
        }
        let from = if self.strip_header {
            self.header_len
        } else {
            0
        };
        let message = data[from..total].to_vec();
        buf.consume(total);
        Ok(Some(message))
    }
}

/// Messages terminated by a delimiter.
#[derive(Debug, Clone)]
pub struct Delimited {
    pub delimiter: Vec<u8>,
    /// Largest accepted message, delimiter included.
    pub max_len: usize,
    /// Return the message without its delimiter.
    pub strip_delimiter: bool,
}

impl Delimited {
    pub fn new(delimiter: impl Into<Vec<u8>>, max_len: usize) -> Delimited {
        Delimited {
            delimiter: delimiter.into(),
            max_len,
            strip_delimiter: true,
        }
    }
}

impl Decoder for Delimited {
    type Item = Vec<u8>;

    fn decode(&mut self, buf: &mut ByteBuffer) -> Result<Option<Vec<u8>>> {
        if self.delimiter.is_empty() {
            return Err(Error::new(ErrorKind::InvalidArgument, "empty delimiter"));
        }
        match buf.take_frame(&self.delimiter) {
            Some(frame) if frame.len() > self.max_len => Err(Error::new(
                ErrorKind::Protocol,
                format!("message of {} bytes exceeds the limit", frame.len()),
            )),
            Some(mut frame) => {
                if self.strip_delimiter {
                    frame.truncate(frame.len() - self.delimiter.len());
                }
                Ok(Some(frame))
            }
            None if buf.len() > self.max_len => Err(Error::new(
                ErrorKind::Protocol,
                "no delimiter within the size limit",
            )),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefixed_roundtrip_across_partial_reads() {
        let mut codec = LengthPrefixed::simple(Width::U32, 1024);
        let mut wire = codec.encode(b"hello").unwrap();
        wire.extend(codec.encode(b"").unwrap());
        wire.extend(codec.encode(b"world!").unwrap());

        let mut buf = ByteBuffer::new();
        let mut got = Vec::new();
        for byte in wire {
            buf.extend_from_slice(&[byte]);
            while let Some(msg) = codec.decode(&mut buf).unwrap() {
                got.push(msg);
            }
        }
        assert_eq!(got, [&b"hello"[..], b"", b"world!"]);
        assert!(buf.is_empty());
    }

    #[test]
    fn custom_header_layout() {
        // 2-byte type tag, then a little-endian u16 length that includes the 6-byte header,
        // then 2 reserved bytes.
        let mut codec = LengthPrefixed {
            header_len: 6,
            length_at: 2,
            width: Width::U16,
            endian: Endian::Little,
            length_counts_header: true,
            max_len: 64,
            strip_header: false,
        };
        let mut buf = ByteBuffer::from(&[0xAB, 0xCD, 9, 0, 0, 0, b'x', b'y', b'z', 0xFF][..]);
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg, [0xAB, 0xCD, 9, 0, 0, 0, b'x', b'y', b'z']);
        assert_eq!(buf.as_slice(), [0xFF]);

        let mut bad = ByteBuffer::from(&[0, 0, 3, 0, 0, 0][..]);
        assert_eq!(
            codec.decode(&mut bad).unwrap_err().kind(),
            ErrorKind::Protocol,
            "length smaller than the header"
        );
    }

    #[test]
    fn length_limits() {
        let mut codec = LengthPrefixed::simple(Width::U8, 8);
        assert_eq!(
            codec.encode(&[0; 8]).unwrap_err().kind(),
            ErrorKind::TooLarge
        );
        let mut buf = ByteBuffer::from(&[200u8][..]);
        assert!(codec.decode(&mut buf).is_err());
        let mut huge = LengthPrefixed::simple(Width::U8, 1000);
        assert!(huge.encode(&[0; 300]).is_err(), "300 does not fit in a u8");
        assert!(huge.decode(&mut ByteBuffer::new()).unwrap().is_none());
    }

    #[test]
    fn delimited_lines() {
        let mut codec = Delimited::new(&b"\r\n"[..], 16);
        let mut buf = ByteBuffer::from(&b"GET\r\nPU"[..]);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), b"GET");
        assert!(codec.decode(&mut buf).unwrap().is_none());
        buf.extend_from_slice(b"T\r\n");
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), b"PUT");

        buf.extend_from_slice(&[b'x'; 20]);
        assert!(codec.decode(&mut buf).is_err());
    }
}
