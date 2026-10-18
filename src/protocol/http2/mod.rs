//! HTTP/2 (RFC 9113) with HPACK header compression (RFC 7541).
//!
//! - [`frame`]: frame parsing, encoding and settings.
//! - [`hpack`], [`huffman`]: header compression.
//! - [`session`]: the server side of a connection as a sans-I/O state machine.

pub mod frame;
pub mod hpack;
pub mod huffman;
pub mod session;
