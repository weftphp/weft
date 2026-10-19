//! Server configuration.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::core::Result;
use crate::network::SocketAddress;
use crate::network::tls::ServerTls;
use crate::protocol::framing::{Decoder, Delimited, LengthPrefixed};

/// A boxed message decoder, one per connection.
pub type BoxDecoder = Box<dyn Decoder<Item = Vec<u8>>>;

/// How a listener's byte stream is cut into the messages handed to
/// [`Handler::on_receive`](super::Handler::on_receive).
#[derive(Clone)]
pub enum Framing {
    /// Deliver bytes as they arrive, with no message boundaries.
    Raw,
    /// Messages end with a delimiter.
    Delimited(Delimited),
    /// Messages carry their length in a header.
    LengthPrefixed(LengthPrefixed),
    /// A custom decoder, created per connection.
    Custom(Arc<dyn Fn() -> BoxDecoder + Send + Sync>),
}

impl Framing {
    pub(crate) fn decoder(&self) -> Option<BoxDecoder> {
        match self {
            Framing::Raw => None,
            Framing::Delimited(d) => Some(Box::new(d.clone())),
            Framing::LengthPrefixed(l) => Some(Box::new(l.clone())),
            Framing::Custom(make) => Some(make()),
        }
    }
}

impl fmt::Debug for Framing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Framing::Raw => f.write_str("Raw"),
            Framing::Delimited(d) => f.debug_tuple("Delimited").field(d).finish(),
            Framing::LengthPrefixed(l) => f.debug_tuple("LengthPrefixed").field(l).finish(),
            Framing::Custom(_) => f.write_str("Custom"),
        }
    }
}

/// Transport of a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TCP, or a Unix stream socket.
    Stream,
    /// UDP, or a Unix datagram socket: each datagram goes to `on_packet`.
    Datagram,
}

/// One listening address and how its connections behave.
#[derive(Debug, Clone)]
pub struct Listener {
    pub address: SocketAddress,
    pub transport: Transport,
    pub framing: Framing,
    pub backlog: i32,
    /// Disable Nagle's algorithm on accepted TCP connections.
    pub nodelay: bool,
    /// Serve TLS on this (stream) listener. Handlers see decrypted data, and `on_connect`
    /// fires once the handshake has finished.
    pub tls: Option<ServerTls>,
}

impl Listener {
    /// A TCP (or Unix stream) listener delivering raw bytes.
    pub fn stream(address: SocketAddress) -> Listener {
        Listener {
            address,
            transport: Transport::Stream,
            framing: Framing::Raw,
            backlog: 512,
            nodelay: true,
            tls: None,
        }
    }

    /// A UDP (or Unix datagram) listener.
    pub fn datagram(address: SocketAddress) -> Listener {
        Listener {
            transport: Transport::Datagram,
            ..Listener::stream(address)
        }
    }

    pub fn with_framing(mut self, framing: Framing) -> Listener {
        self.framing = framing;
        self
    }

    pub fn with_tls(mut self, tls: ServerTls) -> Listener {
        self.tls = Some(tls);
        self
    }
}

/// How workers run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Each worker is a forked process, supervised and restarted by the main process.
    #[default]
    Process,
    /// Each worker is a thread of the main process.
    Thread,
}

/// Everything a server needs to start.
#[derive(Debug, Clone)]
pub struct Config {
    pub listeners: Vec<Listener>,
    pub mode: Mode,
    /// Event workers handling connections.
    pub workers: usize,
    /// Workers running [`Handler::on_task`](super::Handler::on_task).
    pub task_workers: usize,
    /// Most connections one worker accepts; extra ones are closed at once.
    pub max_connections: usize,
    /// Pending output per connection beyond which `send` fails with `Full`.
    pub max_output: usize,
    /// Bytes read from one connection per readiness event, for fairness.
    pub read_chunk: usize,
    /// Close connections idle this long (checked every `idle_timeout / 2`).
    pub idle_timeout: Option<Duration>,
    /// A worker exits (and is replaced) after handling this many messages.
    pub max_requests: Option<u64>,
    /// Time a stopping worker waits for its connections to drain.
    pub stop_grace: Duration,
    /// Each process-mode worker binds its own listening socket with `SO_REUSEPORT` (Linux),
    /// letting the kernel balance connections. Requires fixed ports.
    pub reuse_port: bool,
    /// Bytes buffered for tasks waiting for a task worker.
    pub task_queue_bytes: usize,
    /// Largest task or task result.
    pub max_task: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listeners: Vec::new(),
            mode: Mode::Process,
            workers: std::thread::available_parallelism().map_or(1, |n| n.get()),
            task_workers: 0,
            max_connections: 100_000,
            max_output: 2 * 1024 * 1024,
            read_chunk: 64 * 1024,
            idle_timeout: None,
            max_requests: None,
            stop_grace: Duration::from_secs(3),
            reuse_port: false,
            task_queue_bytes: 4 * 1024 * 1024,
            max_task: 1024 * 1024,
        }
    }
}

impl Config {
    pub(crate) fn validate(&self) -> Result<()> {
        use crate::core::{Error, ErrorKind};
        if self.listeners.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "no listeners configured",
            ));
        }
        if self.workers == 0 {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "workers must be at least 1",
            ));
        }
        if self
            .listeners
            .iter()
            .any(|l| l.tls.is_some() && l.transport == Transport::Datagram)
        {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "TLS is only available on stream listeners",
            ));
        }
        if self.read_chunk == 0 || self.max_output == 0 {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "read_chunk and max_output must be positive",
            ));
        }
        Ok(())
    }
}
