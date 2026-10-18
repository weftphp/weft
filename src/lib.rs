//! weft — an asynchronous, coroutine-based networking engine for PHP, written in Rust.
//!
//! Layers, from the bottom up:
//!
//! - [`core`]: errors, logging, timers, buffers and small algorithms.
//! - [`os`]: descriptors, signals, processes, helper threads.
//! - [`reactor`]: the event loop; [`global`] puts one behind plain functions per thread.
//! - [`lock`], [`memory`]: primitives shared between processes.
//! - [`network`], [`protocol`]: sockets, DNS and wire protocols (no I/O in `protocol`).
//! - [`coroutine`]: stackful coroutines and coroutine-aware I/O.
//! - [`server`]: the multi-worker server and its HTTP front end.

pub mod core;
pub mod coroutine;
pub mod global;
pub mod lock;
pub mod memory;
pub mod network;
pub mod os;
pub mod protocol;
pub mod reactor;
pub mod server;
