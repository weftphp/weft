# weft

An asynchronous, coroutine-based engine for PHP, written in Rust.

weft brings an event loop, coroutines, timers, and high-performance TCP/UDP/HTTP/WebSocket servers
to PHP. The goal is a **standalone PHP extension**: PHP code gets coroutine-based concurrency, while
the engine underneath is written in memory-safe Rust.

> **Status: early development.** No PHP extension exists yet. Right now weft is a Rust library
> containing the first layer of the engine. APIs will change.

## Roadmap

1. **Rust engine:** build the engine's layers in idiomatic Rust.
   - [x] `core`: errors, logging, timers, read/write buffers, channels, encoding
   - [ ] reactor (event loop on epoll / kqueue)
   - [ ] coroutines and scheduler
   - [ ] networking: sockets, clients, protocols
   - [ ] server: master / worker process model, HTTP, WebSocket
2. **PHP extension:** expose the engine to PHP userland as a loadable extension.

## What's implemented

The `weft::core` module holds the foundational building blocks:

| Module    | Provides                                                                   |
|-----------|----------------------------------------------------------------------------|
| `error`   | `Error` with a matchable `ErrorKind`, and the crate's `Result` alias       |
| `log`     | Thread-safe leveled logger: stdout, file or any writer, with rotation      |
| `timer`   | One-shot and fixed-rate repeating timers, driven by your event loop        |
| `bytes`   | `ByteBuffer`: read buffer with cheap consumption and delimiter framing     |
| `buffer`  | `WriteQueue`: pending output (bytes, file regions, shutdown) for writev     |
| `channel` | Byte-message queues bounded by total size; blocking, closable thread version |
| `base64`, `crc32` | RFC 4648 base64 and CRC-32                                         |

## Example

```rust
use std::time::Duration;
use weft::core::timer::Timer;

let mut timer = Timer::new();
timer.after(Duration::from_millis(100), |_timer, id| println!("timer {id} fired"));

// A real event loop would block on I/O for at most `timer.timeout()`.
while let Some(wait) = timer.timeout() {
    std::thread::sleep(wait);
    timer.poll();
}
```

## Building

Requires stable Rust (edition 2024). Developed on macOS; Linux is the primary target.

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

## Contributing

Read [AGENTS.md](AGENTS.md) first. It covers project conventions, the reference source,
and the design decisions that are still open. AI coding agents also read it (and
[CLAUDE.md](CLAUDE.md)).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
