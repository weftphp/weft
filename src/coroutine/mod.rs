//! Stackful coroutines.
//!
//! - [`context`]: stacks and the machine-level context switch.
//! - [`runtime`]: the per-thread scheduler, waiting, cancellation and the event-loop bridge.
//! - [`sync`]: channels, mutexes and wait groups between coroutines.
//! - [`socket`]: sockets that suspend the coroutine instead of blocking.
//! - [`http_client`]: HTTP/1.1 and WebSocket clients.
//! - [`system`]: helper-thread offloading, files, processes, DNS and signals.

pub mod context;
pub mod http_client;
pub mod runtime;
pub mod socket;
pub mod sync;
pub mod system;

pub use runtime::{
    CoId, Waiter, Wake, cancel, current, exists, in_coroutine, resume, run, sleep, spawn, suspend,
    wait_fd, with_reactor, yield_now,
};
pub use socket::CoSocket;
pub use sync::{Channel, Mutex, WaitGroup};
