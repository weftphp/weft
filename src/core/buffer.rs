//! Outgoing data queued for a connection.
//!
//! A [`WriteQueue`] holds everything a connection still has to send: in-memory bytes, file
//! regions to stream with `sendfile`, and a shutdown marker. The writer looks at the front,
//! performs one write, and reports progress with [`WriteQueue::advance`].
//!
//! Small consecutive writes are merged into one segment (up to a configurable size) so a burst
//! of tiny messages becomes few large writes.

use std::collections::VecDeque;
use std::fs::File;
use std::io::IoSlice;

/// One unit of pending output.
#[derive(Debug)]
pub enum Segment {
    /// In-memory bytes; `sent` of them have already been written.
    Bytes { data: Vec<u8>, sent: usize },
    /// `remaining` bytes of `file` starting at `offset`.
    File {
        file: File,
        offset: u64,
        remaining: u64,
    },
    /// Shut the connection down once everything before this point is written.
    Shutdown,
}

impl Segment {
    /// Bytes this segment still has to write.
    pub fn pending(&self) -> u64 {
        match self {
            Segment::Bytes { data, sent } => (data.len() - sent) as u64,
            Segment::File { remaining, .. } => *remaining,
            Segment::Shutdown => 0,
        }
    }
}

/// FIFO of pending output for one connection.
#[derive(Debug)]
pub struct WriteQueue {
    segments: VecDeque<Segment>,
    pending: u64,
    coalesce_limit: usize,
}

impl Default for WriteQueue {
    fn default() -> Self {
        Self::new(Self::DEFAULT_COALESCE_LIMIT)
    }
}

impl WriteQueue {
    /// Default upper size for merging consecutive byte writes.
    pub const DEFAULT_COALESCE_LIMIT: usize = 64 * 1024;

    /// Creates a queue that merges consecutive byte writes while the merged segment stays at
    /// or below `coalesce_limit` bytes. A limit of 0 disables merging.
    pub fn new(coalesce_limit: usize) -> Self {
        WriteQueue {
            segments: VecDeque::new(),
            pending: 0,
            coalesce_limit,
        }
    }

    /// Total bytes still to be written, across all segments.
    pub fn pending(&self) -> u64 {
        self.pending
    }

    /// Number of queued segments.
    pub fn segments(&self) -> usize {
        self.segments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn front(&self) -> Option<&Segment> {
        self.segments.front()
    }

    pub fn front_mut(&mut self) -> Option<&mut Segment> {
        self.segments.front_mut()
    }

    /// Queues bytes, merging them into the last segment when it is small enough.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.pending += bytes.len() as u64;
        if let Some(Segment::Bytes { data, sent }) = self.segments.back_mut()
            && data.len() - *sent + bytes.len() <= self.coalesce_limit
        {
            data.extend_from_slice(bytes);
            return;
        }
        self.segments.push_back(Segment::Bytes {
            data: bytes.to_vec(),
            sent: 0,
        });
    }

    /// Queues `len` bytes of `file` starting at `offset`.
    pub fn push_file(&mut self, file: File, offset: u64, len: u64) {
        if len == 0 {
            return;
        }
        self.pending += len;
        self.segments.push_back(Segment::File {
            file,
            offset,
            remaining: len,
        });
    }

    /// Queues a shutdown after everything currently queued.
    pub fn push_shutdown(&mut self) {
        self.segments.push_back(Segment::Shutdown);
    }

    /// Unwritten parts of the leading byte segments, ready for a vectored write.
    /// Stops at the first non-byte segment or after `max` slices.
    pub fn io_slices(&self, max: usize) -> Vec<IoSlice<'_>> {
        self.segments
            .iter()
            .map_while(|segment| match segment {
                Segment::Bytes { data, sent } => Some(IoSlice::new(&data[*sent..])),
                _ => None,
            })
            .take(max)
            .collect()
    }

    /// Records that `n` bytes from the front of the queue were written, dropping finished
    /// segments. Progress never crosses a [`Segment::Shutdown`]; pop it with
    /// [`pop_front`](Self::pop_front) when acting on it. Returns bytes left unaccounted
    /// for, which is non-zero only if `n` exceeded what could be advanced.
    pub fn advance(&mut self, mut n: u64) -> u64 {
        while n > 0 {
            let Some(front) = self.segments.front_mut() else {
                break;
            };
            let step = n.min(front.pending());
            match front {
                Segment::Bytes { sent, .. } => *sent += step as usize,
                Segment::File {
                    offset, remaining, ..
                } => {
                    *offset += step;
                    *remaining -= step;
                }
                Segment::Shutdown => break,
            }
            n -= step;
            self.pending -= step;
            if front.pending() == 0 {
                self.segments.pop_front();
            }
        }
        n
    }

    /// Removes the front segment regardless of progress.
    pub fn pop_front(&mut self) -> Option<Segment> {
        let segment = self.segments.pop_front()?;
        self.pending -= segment.pending();
        Some(segment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_small_writes() {
        let mut queue = WriteQueue::new(8);
        queue.push_bytes(b"abc");
        queue.push_bytes(b"def");
        queue.push_bytes(b"ghi");
        assert_eq!(queue.segments(), 2);
        assert_eq!(queue.pending(), 9);

        let mut no_merge = WriteQueue::new(0);
        no_merge.push_bytes(b"a");
        no_merge.push_bytes(b"b");
        assert_eq!(no_merge.segments(), 2);
    }

    #[test]
    fn partial_writes_and_io_slices() {
        let mut queue = WriteQueue::new(0);
        queue.push_bytes(b"hello ");
        queue.push_bytes(b"world");
        queue.push_shutdown();
        queue.push_bytes(b"late");

        let slices: Vec<Vec<u8>> = queue.io_slices(8).iter().map(|s| s.to_vec()).collect();
        assert_eq!(slices, vec![b"hello ".to_vec(), b"world".to_vec()]);

        assert_eq!(queue.advance(8), 0);
        assert_eq!(queue.io_slices(8)[0].as_ref(), b"rld");
        assert_eq!(queue.pending(), 7);

        // Writing more than is available stops at the shutdown marker.
        assert_eq!(queue.advance(10), 7);
        assert!(matches!(queue.pop_front(), Some(Segment::Shutdown)));
        assert_eq!(queue.pending(), 4);
    }

    #[test]
    fn file_segments_track_offset() {
        let file = File::open(file!()).unwrap();
        let mut queue = WriteQueue::default();
        queue.push_file(file, 10, 100);
        assert_eq!(queue.advance(30), 0);
        match queue.front() {
            Some(Segment::File {
                offset, remaining, ..
            }) => assert_eq!((*offset, *remaining), (40, 70)),
            other => panic!("unexpected {other:?}"),
        }
        assert!(queue.io_slices(4).is_empty());
        queue.advance(70);
        assert!(queue.is_empty());
    }
}
