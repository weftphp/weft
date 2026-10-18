//! Wire protocols, as pure byte-to-message conversions with no I/O.
//!
//! - [`framing`]: length-prefixed and delimiter-terminated messages.
//! - [`http`]: HTTP/1.x requests and responses.
//! - [`http2`]: HTTP/2 frames, HPACK and a server session.
//! - [`message_bus`]: large messages over size-limited datagrams.
//! - [`websocket`]: WebSocket handshake, frames and messages.
//! - [`redis`]: the Redis serialization protocol (RESP2/RESP3).
//! - [`mqtt`]: MQTT 3.1.1 packets.
//! - [`socks5`]: the client side of a SOCKS5 proxy handshake.
//! - [`mime`]: media types for file extensions.

pub mod framing;
pub mod http;
pub mod http2;
pub mod message_bus;
pub mod mime;
pub mod mqtt;
pub mod redis;
pub mod socks5;
pub mod websocket;
