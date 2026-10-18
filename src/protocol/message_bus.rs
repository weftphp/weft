//! Carrying messages of any size over a datagram channel (such as a Unix `SOCK_DGRAM`
//! socket pair) whose datagrams are size-limited.
//!
//! [`split`] cuts a message into datagrams that each start with a small header; a
//! [`Reassembler`] on the other side puts them back together. Datagrams of one message must
//! arrive in order (true for Unix-domain sockets), but datagrams of different messages may
//! interleave, e.g. when several threads write to the same socket.
//!
//! Header layout, big-endian: message id (8 bytes), total payload length (4), kind (1),
//! flags (1, bit 0 = first piece, bit 1 = last piece).

use std::collections::HashMap;

use crate::core::{Error, ErrorKind, Result};

pub const HEADER_LEN: usize = 14;

const FIRST: u8 = 1;
const LAST: u8 = 2;

/// A complete message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u64,
    /// Application-defined message type.
    pub kind: u8,
    pub payload: Vec<u8>,
}

/// Cuts `payload` into datagrams of at most `max_datagram` bytes.
pub fn split(id: u64, kind: u8, payload: &[u8], max_datagram: usize) -> Result<Vec<Vec<u8>>> {
    if max_datagram <= HEADER_LEN {
        return Err(Error::new(
            ErrorKind::InvalidArgument,
            "datagrams must be larger than the header",
        ));
    }
    let total = u32::try_from(payload.len())
        .map_err(|_| Error::new(ErrorKind::TooLarge, "message exceeds 4 GiB"))?;
    let room = max_datagram - HEADER_LEN;
    let pieces = payload.len().div_ceil(room).max(1);
    let mut out = Vec::with_capacity(pieces);
    for i in 0..pieces {
        let chunk = &payload[(i * room).min(payload.len())..((i + 1) * room).min(payload.len())];
        let mut flags = 0;
        if i == 0 {
            flags |= FIRST;
        }
        if i + 1 == pieces {
            flags |= LAST;
        }
        let mut datagram = Vec::with_capacity(HEADER_LEN + chunk.len());
        datagram.extend_from_slice(&id.to_be_bytes());
        datagram.extend_from_slice(&total.to_be_bytes());
        datagram.push(kind);
        datagram.push(flags);
        datagram.extend_from_slice(chunk);
        out.push(datagram);
    }
    Ok(out)
}

struct Partial {
    kind: u8,
    total: usize,
    data: Vec<u8>,
}

/// Rebuilds messages from datagrams produced by [`split`].
pub struct Reassembler {
    partial: HashMap<u64, Partial>,
    pub max_message: usize,
    /// Messages that may be in progress at once.
    pub max_partial: usize,
}

impl Reassembler {
    pub fn new(max_message: usize, max_partial: usize) -> Reassembler {
        Reassembler {
            partial: HashMap::new(),
            max_message,
            max_partial,
        }
    }

    /// Feeds one datagram; returns a message when its last piece arrives.
    pub fn push(&mut self, datagram: &[u8]) -> Result<Option<Message>> {
        let bad = |m: &str| Error::new(ErrorKind::Protocol, format!("message bus: {m}"));
        if datagram.len() < HEADER_LEN {
            return Err(bad("datagram shorter than its header"));
        }
        let id = u64::from_be_bytes(datagram[..8].try_into().map_err(|_| bad("header"))?);
        let total =
            u32::from_be_bytes(datagram[8..12].try_into().map_err(|_| bad("header"))?) as usize;
        let kind = datagram[12];
        let flags = datagram[13];
        let chunk = &datagram[HEADER_LEN..];
        if total > self.max_message {
            return Err(Error::new(
                ErrorKind::TooLarge,
                format!("message of {total} bytes exceeds the limit"),
            ));
        }

        if flags & FIRST != 0 {
            if self.partial.contains_key(&id) {
                self.partial.remove(&id);
                return Err(bad("message restarted before it finished"));
            }
            if flags & LAST != 0 {
                if chunk.len() != total {
                    return Err(bad("single-piece length mismatch"));
                }
                return Ok(Some(Message {
                    id,
                    kind,
                    payload: chunk.to_vec(),
                }));
            }
            if self.partial.len() >= self.max_partial {
                return Err(Error::new(ErrorKind::Full, "too many partial messages"));
            }
            let mut data = Vec::with_capacity(total);
            data.extend_from_slice(chunk);
            self.partial.insert(id, Partial { kind, total, data });
            return Ok(None);
        }

        let partial = self
            .partial
            .get_mut(&id)
            .ok_or_else(|| bad("continuation of an unknown message"))?;
        if partial.data.len() + chunk.len() > partial.total || partial.kind != kind {
            self.partial.remove(&id);
            return Err(bad("pieces disagree with the message header"));
        }
        partial.data.extend_from_slice(chunk);
        if flags & LAST == 0 {
            return Ok(None);
        }
        let Some(done) = self.partial.remove(&id) else {
            return Ok(None);
        };
        if done.data.len() != done.total {
            return Err(bad("message shorter than announced"));
        }
        Ok(Some(Message {
            id,
            kind: done.kind,
            payload: done.data,
        }))
    }

    /// Drops every unfinished message (for example when the peer restarted).
    pub fn reset(&mut self) {
        self.partial.clear();
    }

    pub fn in_progress(&self) -> usize {
        self.partial.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaved_messages_reassemble() {
        let a: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let b = b"short".to_vec();
        let c = Vec::new();
        let pa = split(1, 7, &a, 64).unwrap();
        let pb = split(2, 8, &b, 64).unwrap();
        let pc = split(3, 9, &c, 64).unwrap();
        assert_eq!(pa.len(), 1000usize.div_ceil(64 - HEADER_LEN));
        assert!(pa.iter().all(|d| d.len() <= 64));

        let mut r = Reassembler::new(4096, 4);
        let mut done = Vec::new();
        // Interleave: half of a, all of b and c, rest of a.
        let half = pa.len() / 2;
        for d in pa[..half].iter().chain(&pb).chain(&pc).chain(&pa[half..]) {
            if let Some(m) = r.push(d).unwrap() {
                done.push(m);
            }
        }
        assert_eq!(done.len(), 3);
        assert_eq!(
            done[0],
            Message {
                id: 2,
                kind: 8,
                payload: b
            }
        );
        assert_eq!(done[1].payload, c);
        assert_eq!(done[2].payload, a);
        assert_eq!(r.in_progress(), 0);
    }

    #[test]
    fn rejects_inconsistent_input() {
        let mut r = Reassembler::new(100, 1);
        assert!(r.push(&[0; 5]).is_err());
        let big = split(1, 0, &[0; 200], 64).unwrap();
        assert_eq!(r.push(&big[0]).unwrap_err().kind(), ErrorKind::TooLarge);
        let pieces = split(2, 0, &[1; 90], 40).unwrap();
        assert!(r.push(&pieces[1]).is_err(), "continuation first");
        r.push(&pieces[0]).unwrap();
        let other = split(3, 0, &[1; 90], 40).unwrap();
        assert_eq!(r.push(&other[0]).unwrap_err().kind(), ErrorKind::Full);
        r.reset();
        assert!(split(1, 0, b"x", HEADER_LEN).is_err());
    }
}
