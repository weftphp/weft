//! A per-thread event loop behind plain functions, for code that does not want to own a
//! [`Reactor`](crate::reactor::Reactor): timers ([`timer`]) and descriptor watching
//! ([`event`]) register on the thread's global loop, and [`event::wait`] runs it.
//!
//! Callbacks run inside the loop and may freely call these functions again. Coroutines
//! started outside any loop also park their waits on this loop, so
//! `spawn(...)` followed by [`event::wait`] works like [`crate::coroutine::run`].

pub mod event;
pub mod timer;
