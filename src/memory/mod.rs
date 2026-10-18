//! Memory shared between processes.
//!
//! Everything here is backed by anonymous `MAP_SHARED` mappings, so it must be created
//! *before* forking; the children then see the same memory as the parent.
//!
//! - [`shared`]: raw mappings and typed [`Shared`] values.
//! - [`table`]: a fixed-capacity hash table with typed columns.
//! - [`queue`]: a bounded queue of byte messages.
//! - [`pool`]: fixed-size blocks addressed by index.

pub mod pool;
pub mod queue;
pub mod shared;
pub mod table;

pub use shared::{Mapping, Shared, SharedSlice, ShmSafe};
