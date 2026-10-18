//! Operating-system services: descriptors, signals, processes and helper threads.
//!
//! - [`fd`]: non-blocking/close-on-exec flags, raw read/write, pipes.
//! - [`signal`]: routes signals to an event loop through a self-pipe.
//! - [`process`]: fork, wait, kill.
//! - [`process_pool`]: a supervised group of worker processes.
//! - [`sendfile`]: zero-copy file-to-socket transfer.
//! - [`file`](mod@file): bounded whole-file reads and atomic replacement.
//! - [`blocking`]: a thread pool for work that must not block an event loop.
//! - [`alarm`]: a process-wide interval timer delivered as `SIGALRM`.
//! - `msg_queue` (Linux): System V message queues.

pub mod alarm;
pub mod blocking;
pub mod fd;
pub mod file;
#[cfg(target_os = "linux")]
pub mod msg_queue;
pub mod process;
pub mod process_pool;
pub mod sendfile;
pub mod signal;
