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
examples (`examples/`). The PHP extension lives in `ext/` (see below). Each engine module's
`mod.rs` documents its contents:

- `src/core/` — error type, logger, timer, read buffer (`ByteBuffer`), write queue
  (`WriteQueue`), byte-message channels, base64, crc32, sha1, OS randomness.
- `src/os/` — fd helpers, signal self-pipe, fork/wait, supervised process pool, sendfile,
  helper-thread pool, interval alarm, System V message queues (Linux).
- `src/reactor/` — event loop (epoll / kqueue / poll backends) and `current` (the per-thread
  "current reactor" used by coroutines and `global`).
- `src/global/` — per-thread event loop behind plain functions (timers, fd watching).
- `src/lock/`, `src/memory/` — cross-process locks and shared-memory structures.
- `src/network/` — addresses, sockets, DNS, callback client (optionally TLS), blocking
  framed client, TLS contexts and sessions (`tls`).
- `src/protocol/` — sans-I/O codecs: framing, HTTP/1.x, HTTP/2 + HPACK, WebSocket, Redis,
  MQTT, SOCKS5, message bus, MIME types.
- `src/coroutine/` — stackful coroutines (hand-written context switch for aarch64 and
  x86_64), sync primitives, coroutine sockets (optionally TLS), HTTP/WebSocket client
  (`http`/`https`, `ws`/`wss`), system services.
- `src/server/` — multi-worker server (process or thread mode), task workers, HTTP server.
  Stream listeners can serve TLS; the HTTP server does HTTP/2 over TLS through ALPN.

### PHP extension (`ext/`)

A separate crate (`weft-php`, its own `[workspace]`, so root `cargo` commands ignore it) that
builds `weft.so`. `ext/README.md` documents building, loading and the PHP API.

- `ext/shim/shim.c` is the only C: Zend macros, runtime function/class tables, and the swap of
  executor state between coroutines. Everything else is Rust.
- `ext/src/php.rs` wraps the shim; `vm.rs` installs the coroutine switch hook that swaps each
  coroutine's VM stack; `coro.rs`, `sync.rs`, `timer.rs`, `socket.rs`, `http.rs` register the
  PHP-visible API (namespace `Weft\`).
- Every PHP-callable handler is declared with `handler!`, which turns errors and panics into
  `Weft\Exception` so nothing unwinds across the FFI boundary.
- The HTTP server forks workers (process mode only); each request runs in its own coroutine and
  answers through `server::http::Responder`, so handlers may suspend.

Tests: `cd ext && cargo build && tests/run.sh [debug|release]` runs `tests/php/*.php` against
the built extension and diffs against the `.expect` files. Also run `cargo fmt` and
`cargo clippy -- -D warnings` inside `ext/`.

Not implemented: DTLS, TLS in the blocking framed client (`network::stream`), kernel TLS
offload (TLS file responses are copied, not `sendfile`d), and an io_uring backend.

Platform coverage: the full suite must pass on macOS (kqueue) and on Linux (epoll, futex
waits, System V message queues), on both x86_64 and aarch64 (the two context switches), in
debug and release builds. Linux was last verified in `rust:1` containers (see Commands).

Dependencies: `libc`, for syscalls that `std` does not expose, and `openssl`, for TLS. weft
needs OpenSSL **3.0 or newer** (it relies on `SSL_OP_IGNORE_UNEXPECTED_EOF`); the
`openssl` crate finds it through `pkg-config` or `OPENSSL_DIR`.

Decided so far:

- PHP bindings: hand-written Zend API glue (a small C shim plus Rust), not `ext-php-rs`.
- PHP support: 8.4, non-thread-safe (NTS) builds only; the shim refuses ZTS at compile time.
- PHP API: weft's own `Weft\` namespace design, not a copy of another project's names.
- Layout: the extension is the separate crate in `ext/`; the engine stays a plain library.
- Async runtime: weft has its own reactor (epoll / kqueue / poll) and stackful coroutines;
  it does not build on tokio.
- TLS: OpenSSL, through the `openssl` crate (not rustls).

Open decisions (do **not** settle these unilaterally — ask the user):

- Whether to support more PHP versions (8.1–8.3) or ZTS builds.
- Whether to split the engine into a Cargo workspace (core / net / http / etc.).

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

- Rust **edition 2024** (see `Cargo.toml`), on stable.
- The engine targets Linux first — keep Linux-specific code (epoll, io_uring, signalfd, etc.)
  behind `cfg(target_os = ...)` and keep the BSD/macOS (kqueue) backend building.

## Commands

```sh
cargo build                                   # build
cargo run                                     # run the binary
cargo test                                    # run all tests
cargo fmt --all                               # format
cargo clippy --all-targets -- -D warnings     # lint (treat warnings as errors)
```

Running the suite on Linux from another OS, in a container (use `--platform linux/amd64`
for x86_64; a separate `CARGO_TARGET_DIR` keeps it from clobbering the host's `target/`):

```sh
docker run --rm -v "$PWD":/work -w /work -e CARGO_TARGET_DIR=/tmp/target rust:1 \
  sh -c 'rustup component add clippy && cargo clippy --all-targets -- -D warnings && cargo test'
```

Type-checking a Linux target from another OS needs that target installed
(`rustup target add x86_64-unknown-linux-gnu`) and OpenSSL headers for `openssl-sys`
(`OPENSSL_DIR`). Nothing is linked, so the host's headers are fine:

```sh
OPENSSL_DIR=/path/to/openssl \
  CC_x86_64_unknown_linux_gnu=clang CC_aarch64_unknown_linux_gnu=clang \
  cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
```

Before considering a change done, run `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`,
and `cargo test`, and make sure all three pass on macOS and on Linux.

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
