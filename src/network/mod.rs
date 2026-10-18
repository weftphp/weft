//! Networking primitives.
//!
//! - [`address`]: IP and Unix-domain socket addresses.
//! - [`socket`]: a non-blocking socket with full option control.
//! - [`dns`]: hosts file, resolv.conf and a DNS stub resolver.
//! - [`client`]: an event-driven, callback-style stream client.
//! - [`stream`]: a blocking request/response client for length-prefixed protocols.

pub mod address;
pub mod client;
pub mod dns;
pub mod socket;
pub mod stream;

pub use address::{Family, SocketAddress, UnixName};
pub use socket::{Socket, SocketType};
