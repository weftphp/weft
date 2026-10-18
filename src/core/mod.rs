//! Foundational building blocks shared by every other layer of weft.
//!
//! - [`error`]: the [`Error`] type and [`ErrorKind`] used across the crate.
//! - [`bytes`]: [`ByteBuffer`](bytes::ByteBuffer), a read buffer for incoming data and framing.
//! - [`buffer`]: [`WriteQueue`](buffer::WriteQueue), pending outgoing data for a connection.
//! - [`channel`]: bounded byte-message queues, single-threaded and thread-safe.
//! - [`timer`]: one-shot and repeating timers driven by an event loop.
//! - [`log`]: leveled logger with file rotation.
//! - [`base64`], [`crc32`]: encoding and checksums.

pub mod base64;
pub mod buffer;
pub mod bytes;
pub mod channel;
pub mod crc32;
pub mod error;
pub mod log;
pub mod timer;

pub use error::{Error, ErrorKind, Result};
