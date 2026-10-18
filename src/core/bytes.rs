//! Read buffer for incoming bytes, with delimiter framing.
//!
//! A connection appends whatever it reads, protocol code inspects the readable bytes, and
//! [`ByteBuffer::consume`] marks a prefix as handled. Consumed space is reclaimed lazily, just
//! before the buffer would otherwise have to grow.

use std::io;

/// Growable byte buffer with a read position.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ByteBuffer {
    data: Vec<u8>,
    /// Start of the unread bytes.
    start: usize,
    /// Where the next delimiter search resumes, so partial frames are not rescanned.
    scan: usize,
}

impl ByteBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        ByteBuffer {
            data: Vec::with_capacity(capacity),
            ..Self::default()
        }
    }

    /// Number of unread bytes.
    pub fn len(&self) -> usize {
        self.data.len() - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The unread bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..]
    }

    /// Appends bytes to the end.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.make_room(bytes.len());
        self.data.extend_from_slice(bytes);
    }

    /// Lets `fill` write up to `max` bytes directly into the buffer (e.g. a socket `read`)
    /// and keeps however many it reports writing.
    pub fn fill_with(
        &mut self,
        max: usize,
        fill: impl FnOnce(&mut [u8]) -> io::Result<usize>,
    ) -> io::Result<usize> {
        self.make_room(max);
        let old_len = self.data.len();
        self.data.resize(old_len + max, 0);
        let result = fill(&mut self.data[old_len..]);
        let written = match &result {
            Ok(n) => (*n).min(max),
            Err(_) => 0,
        };
        self.data.truncate(old_len + written);
        result.map(|_| written)
    }

    /// Marks the first `n` unread bytes as handled. `n` is clamped to [`len`](Self::len).
    pub fn consume(&mut self, n: usize) {
        self.start += n.min(self.len());
        self.scan = self.scan.max(self.start);
        if self.start == self.data.len() {
            self.clear();
        }
    }

    /// Drops every byte, read or not.
    pub fn clear(&mut self) {
        self.data.clear();
        self.start = 0;
        self.scan = 0;
    }

    /// Moves unread bytes to the front, releasing the space of consumed ones.
    pub fn compact(&mut self) {
        if self.start > 0 {
            self.data.drain(..self.start);
            self.scan -= self.start;
            self.start = 0;
        }
    }

    /// Length of the first complete frame ending in `delimiter` (delimiter included), if
    /// one has arrived. Repeated calls only scan bytes that could not be checked before.
    pub fn frame_len(&mut self, delimiter: &[u8]) -> Option<usize> {
        if delimiter.is_empty() {
            return None;
        }
        let from = self.scan.max(self.start);
        match find(&self.data[from..], delimiter) {
            Some(pos) => Some(from + pos + delimiter.len() - self.start),
            None => {
                // A delimiter may still straddle the current end; keep those bytes in range.
                let keep = delimiter.len() - 1;
                self.scan = self.data.len().saturating_sub(keep).max(self.start);
                None
            }
        }
    }

    /// Removes and returns the first complete frame ending in `delimiter`, delimiter included.
    pub fn take_frame(&mut self, delimiter: &[u8]) -> Option<Vec<u8>> {
        let len = self.frame_len(delimiter)?;
        let frame = self.as_slice()[..len].to_vec();
        self.consume(len);
        Some(frame)
    }

    /// Reclaims consumed space if appending `additional` bytes would otherwise reallocate.
    fn make_room(&mut self, additional: usize) {
        if self.start > 0 && self.data.len() + additional > self.data.capacity() {
            self.compact();
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

impl io::Write for ByteBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for ByteBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.len());
        buf[..n].copy_from_slice(&self.as_slice()[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl From<Vec<u8>> for ByteBuffer {
    fn from(data: Vec<u8>) -> Self {
        ByteBuffer {
            data,
            ..Self::default()
        }
    }
}

impl From<&[u8]> for ByteBuffer {
    fn from(bytes: &[u8]) -> Self {
        Self::from(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn consume_and_compact() {
        let mut buf = ByteBuffer::from(&b"hello world"[..]);
        buf.consume(6);
        assert_eq!(buf.as_slice(), b"world");
        buf.compact();
        assert_eq!(buf.as_slice(), b"world");
        buf.consume(100);
        assert!(buf.is_empty());
    }

    #[test]
    fn frames_arriving_in_pieces() {
        let mut buf = ByteBuffer::new();
        buf.extend_from_slice(b"one\r\ntwo\r\nth");
        assert_eq!(buf.take_frame(b"\r\n").unwrap(), b"one\r\n");
        assert_eq!(buf.take_frame(b"\r\n").unwrap(), b"two\r\n");
        assert_eq!(buf.take_frame(b"\r\n"), None);

        buf.extend_from_slice(b"ree\r");
        assert_eq!(buf.take_frame(b"\r\n"), None);
        buf.extend_from_slice(b"\nfo");
        assert_eq!(buf.take_frame(b"\r\n").unwrap(), b"three\r\n");
        assert_eq!(buf.as_slice(), b"fo");
        assert_eq!(buf.take_frame(b""), None);
    }

    #[test]
    fn fill_with_keeps_only_written_bytes() {
        let mut buf = ByteBuffer::new();
        let n = buf
            .fill_with(16, |dst| {
                dst[..3].copy_from_slice(b"abc");
                Ok(3)
            })
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf.as_slice(), b"abc");
        assert!(
            buf.fill_with(8, |_| Err(io::ErrorKind::WouldBlock.into()))
                .is_err()
        );
        assert_eq!(buf.as_slice(), b"abc");
    }

    #[test]
    fn io_traits() {
        let mut buf = ByteBuffer::new();
        buf.write_all(b"12345").unwrap();
        let mut out = [0u8; 3];
        assert_eq!(buf.read(&mut out).unwrap(), 3);
        assert_eq!(&out, b"123");
        assert_eq!(buf.as_slice(), b"45");
    }

    #[test]
    fn reclaims_consumed_space_before_growing() {
        let mut buf = ByteBuffer::with_capacity(8);
        buf.extend_from_slice(b"abcdefgh");
        buf.consume(6);
        let cap = buf.data.capacity();
        buf.extend_from_slice(b"ij");
        assert_eq!(buf.as_slice(), b"ghij");
        assert_eq!(buf.data.capacity(), cap);
    }
}
