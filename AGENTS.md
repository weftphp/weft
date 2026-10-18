# AGENTS.md

Guidance for AI coding agents (Claude Code, Codex, Cursor, etc.) working in this repository.

## Project

**weft** is an event-driven, coroutine-based asynchronous networking engine written in Rust
(TCP/UDP/HTTP/WebSocket servers, coroutines, channels, process/worker management, timers).

### Goal

Building the engine in Rust is the first step. The end goal is a **standalone PHP extension
written in Rust** that exposes this engine to PHP userland as weft's own plugin. Design the Rust engine with that in mind:

- Keep the engine (reactor, timers, networking, coroutines) PHP-agnostic and put PHP bindings in a
  separate layer, like the reference implementation's split between its C++ core and its PHP binding.
- Coroutine and scheduling designs must work with the PHP VM (Zend executor state per coroutine),
  not only with Rust futures. The reference implementation's coroutine binding under `ext-src/` shows what is involved.
- Watch for things that break inside a PHP process: panics crossing the FFI boundary, global state
  under ZTS (thread-safe) PHP builds, and `fork`/process-model interactions.

### Current status

weft is a library crate (`src/lib.rs`) plus a placeholder binary (`src/main.rs`) and runnable
examples (`examples/`). The Rust engine's layers exist; the PHP extension does not yet. Each
module's `mod.rs` documents its contents:

- `src/core/` — error type, logger, timer, read buffer (`ByteBuffer`), write queue
  (`WriteQueue`), byte-message channels, base64, crc32, sha1, OS randomness.
- `src/os/` — fd helpers, signal self-pipe, fork/wait, supervised process pool, sendfile,
  helper-thread pool, interval alarm, System V message queues (Linux).
- `src/reactor/` — event loop (epoll / kqueue / poll backends) and `current` (the per-thread
  "current reactor" used by coroutines and `global`).
- `src/global/` — per-thread event loop behind plain functions (timers, fd watching).
- `src/lock/`, `src/memory/` — cross-process locks and shared-memory structures.
- `src/network/` — addresses, sockets, DNS, callback client, blocking framed client.
- `src/protocol/` — sans-I/O codecs: framing, HTTP/1.x, HTTP/2 + HPACK, WebSocket, Redis,
  MQTT, SOCKS5, message bus, MIME types.
- `src/coroutine/` — stackful coroutines (hand-written context switch for aarch64 and
  x86_64), sync primitives, coroutine sockets, HTTP/WebSocket client, system services.
- `src/server/` — multi-worker server (process or thread mode), task workers, HTTP server.

Not implemented: TLS (`ssl`/`dtls` in the reference) and an io_uring backend.

Platform coverage: everything is tested on macOS (kqueue). Linux-only paths (epoll, futex
waits, System V message queues) and the x86_64 context switch are type-checked with
`cargo clippy --target {x86_64,aarch64}-unknown-linux-gnu` but have not been run on Linux
yet; run the test suite on Linux before relying on them.

The only dependency is `libc`, used for syscalls that `std` does not expose.

Decided so far:

- Async runtime: weft has its own reactor (epoll / kqueue / poll) and stackful coroutines;
  it does not build on tokio.

Open decisions (do **not** settle these unilaterally — ask the user):

- How PHP bindings are built (e.g. `ext-php-rs` vs. hand-written Zend API FFI), which PHP versions
  are supported, and whether ZTS builds are supported.
- Whether the PHP-facing API mirrors the reference implementation's (`go()`, server classes, …) or
  is weft's own design.
- TLS: which library to depend on (e.g. OpenSSL bindings vs. rustls); this adds weft's
  first non-`libc` dependency.
- Crate/workspace layout (single crate vs. Cargo workspace split into core / net / http / etc.).

## Reference source

The reference implementation's source (Apache-2.0) lives at `../swoole-src-6.2.3/` relative to this
repo. It is **read-only reference material** for understanding behavior and ideas:

- `src/` and `include/` — the C++ core (reactor, coroutine, server, protocols, process pool).
- `ext-src/` — PHP binding layer and PHP stubs.
- `tests/`, `examples/`, `docs/` — useful for understanding expected behavior.

Rules:

- Never modify files in `../swoole-src-6.2.3/`.
- weft contains **no code derived from the reference source**, which is why it has no `NOTICE`
  file. Keep it that way: use the reference to learn *what* a feature must do, then design and
  write weft's version independently in idiomatic Rust. Never translate, paraphrase or closely
  mirror its code, data tables, constants, message strings or output formats, and never produce
  test vectors by running its code. Prefer public specifications (RFCs, papers, PHP docs).
- If deriving from the reference ever seems unavoidable, stop and ask the user first: Apache-2.0
  would then require restoring a `NOTICE` file with attribution.
- Never write the reference project's name anywhere in this repo: not in code, identifiers,
  comments, tests, docs or `Cargo.toml`. Code comments do not cite the reference at all.

## Toolchain

- Rust **edition 2024** (see `Cargo.toml`); developed with stable rustc 1.98.
- Primary dev platform: macOS (darwin). The engine targets Linux first — keep Linux-specific code
  (epoll, io_uring, signalfd, etc.) behind `cfg(target_os = ...)` and keep macOS (kqueue) building.

## Commands

```sh
cargo build                                   # build
cargo run                                     # run the binary
cargo test                                    # run all tests
cargo fmt --all                               # format
cargo clippy --all-targets -- -D warnings     # lint (treat warnings as errors)
```

Before considering a change done, run `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`,
and `cargo test`, and make sure all three pass.

## Coding conventions

- Follow standard Rust style (`rustfmt` defaults) and Rust API Guidelines naming.
- No `unwrap()` / `expect()` in library code paths; return `Result` with descriptive error types.
  `unwrap()` is fine in tests and examples.
- Every `unsafe` block needs a `// SAFETY:` comment explaining why the invariants hold. Keep
  `unsafe` minimal and encapsulated behind safe APIs (expect it around FFI, syscalls, and
  coroutine context switching).
- Prefer the standard library; justify each new dependency. Add dependencies with `cargo add`.
- Public items get `///` doc comments. Keep other comments for non-obvious *why*, not *what*.
- Write unit tests next to the code (`#[cfg(test)] mod tests`) and integration tests in `tests/`.
  Networking tests should bind to `127.0.0.1:0` (ephemeral ports) so they can run in parallel.

## Working agreements

- Keep changes scoped to what was asked. Do not implement features, add modules, or pull in
  dependencies beyond the current task.
- When expected behavior is unclear, check the reference implementation's docs and tests before
  guessing, then write weft's own design (see "Reference source").
- Do not commit or push unless asked. Commit messages: imperative mood, short summary line.
