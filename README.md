# weft

An asynchronous, coroutine-based engine for PHP.

weft brings an event loop, coroutines, timers, and multi-process TCP/UDP/HTTP/WebSocket servers
to PHP. The goal is a **standalone PHP extension**: PHP code gets coroutine-based concurrency, backed
by a fast, memory-safe native engine.

> **Status: early development.** The engine is in place; the PHP extension does not exist
> yet. APIs will change.

## Roadmap

1. **Engine:** build the engine's layers.
   - [x] `core`: errors, logging, timers, buffers, channels, encodings
   - [x] `reactor`: event loop on epoll / kqueue / poll
   - [x] `coroutine`: stackful coroutines, scheduler, coroutine sockets and clients
   - [x] `network`, `protocol`: sockets, DNS, HTTP/1.1, HTTP/2, WebSocket, Redis, MQTT, SOCKS5
   - [x] `server`: process and thread worker models, task workers, HTTP server
   - [ ] TLS (needs a crypto library; not yet chosen)
   - [ ] io_uring backend (Linux)
2. **PHP extension:** expose the engine to PHP userland as a loadable extension.

## What's inside

| Module      | Provides |
|-------------|----------|
| `core`      | `Error`/`ErrorKind`, logger with rotation, timers, read buffer, write queue, byte channels, base64, CRC-32, SHA-1, OS randomness |
| `os`        | fd helpers, signals routed to the event loop, fork/wait, a supervised process pool, sendfile, a helper-thread pool, interval alarms, System V message queues (Linux) |
| `reactor`   | Single-threaded event loop: I/O readiness, timers, deferred tasks, cross-thread posts, signals; epoll, kqueue and `poll(2)` backends |
| `global`    | Per-thread event loop behind plain functions (`timer::after`, `event::add`, `event::wait`) |
| `coroutine` | Stackful coroutines with a hand-written context switch (aarch64, x86_64), channels, mutex, wait group, coroutine sockets, HTTP/WebSocket client, DNS, `exec`, file I/O on helper threads |
| `network`   | Socket addresses, a non-blocking socket with full option control, DNS (hosts, resolv.conf, wire format), callback client, blocking framed client |
| `protocol`  | Framing (length-prefixed, delimited), HTTP/1.x parser with smuggling defenses, multipart, cookies, HTTP/2 frames + HPACK + server session, WebSocket, Redis RESP2/3, MQTT 3.1.1, SOCKS5, MIME types |
| `lock`      | Cross-process locks in shared memory: robust mutex, spinlock, rwlock, barrier |
| `memory`    | Shared mappings, a shared hash table with typed columns, a shared message queue, a block pool |
| `server`    | Multi-worker server: process or thread mode, listeners with framing, task workers, inter-worker messages, idle timeouts, graceful reload, HTTP/1.1 + HTTP/2 + WebSocket + static files |

The only dependency is `libc`.

## Examples

Runnable examples live in [examples/](examples/):

- `echo`: a coroutine TCP echo server on port 9501 (try it with `nc 127.0.0.1 9501`).
- `http`: an HTTP server with four supervised worker processes, answering HTTP/1.1 and HTTP/2 on
  port 9502 (try it with `curl http://127.0.0.1:9502/hello`).

## Building

Requires OpenSSL 3.0 or newer. Linux is the primary target. See [AGENTS.md](AGENTS.md) for the
build, test and lint commands.

## Contributing

Read [AGENTS.md](AGENTS.md) first. It covers project conventions, the reference source,
and the design decisions that are still open. AI coding agents also read it (and
[CLAUDE.md](CLAUDE.md)).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
