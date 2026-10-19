# weft PHP extension

Coroutines, channels, timers, TCP sockets, an HTTP client and a multi-process HTTP server for
PHP, powered by the weft engine. PHP 8.4, non-thread-safe builds, macOS and Linux.

## Build

Needs a Rust toolchain, `php-config`/headers for the target PHP, and OpenSSL 3 (for the engine).

```sh
cd ext   # or run `make` from the repository root
cargo build --release               # PHP_CONFIG=/path/to/php-config to pick another PHP
cp target/release/libweft_php.so target/release/weft.so     # .dylib on macOS
php -d extension=$PWD/target/release/weft.so -m | grep weft
```

Install by copying `weft.so` into `php-config --extension-dir` and adding `extension=weft` to
an ini file. Run the tests with `tests/run.sh [debug|release]`.

## Usage

Everything that suspends must run inside `Weft\run()`. It runs the callable as the first
coroutine and returns when no coroutine is left; an exception that escapes any coroutine is
rethrown from `run()`.

```php
use function Weft\{run, go, sleep};

run(function () {
    go(function () { sleep(0.1); echo "second\n"; });
    echo "first\n";
});
```

### Functions (`Weft\`)

| Function | |
|---|---|
| `run(callable)` | Run the scheduler with `callable` as the main coroutine. |
| `go(callable, ...$args): int` | Start a coroutine now; returns its id. |
| `sleep(float $seconds)` | Suspend the current coroutine. |
| `pass()` | Let other ready coroutines run. |
| `cid(): int` | Current coroutine id, or -1 outside one. |
| `exists(int $cid): bool`, `count(): int` | Liveness and number of coroutines. |
| `suspend()`, `resume(int $cid): bool` | Park the current coroutine until another resumes it. |
| `after(float, callable): int`, `tick(float, callable): int`, `clear(int): bool` | Timers; each firing runs in a new coroutine. Ticks do not keep `run()` alive once no coroutine is left. |
| `Http\request(string $method, string $url, array $headers = [], string $body = "", float $timeout = 30): array` | HTTP/HTTPS client; returns `status`, `reason`, `headers` (lowercase names), `body`. |

### Classes

- `Weft\Channel(int $capacity = 1)`: `push($v, $timeout = -1): bool`, `pop($timeout = -1)`
  (returns `null` on timeout or when closed and drained), `close()`, `isClosed()`, `length()`,
  `capacity()`.
- `Weft\Mutex`: `lock($timeout = -1): bool`, `tryLock()`, `unlock()`, `isLocked()`.
- `Weft\WaitGroup`: `add($n = 1)`, `done()`, `wait($timeout = -1): bool`, `count()`.
- `Weft\Socket`: `Socket::connect($host, $port, $timeout = -1)`, `Socket::listen($host, $port,
  $backlog = 128)`, `accept($timeout = -1)`, `send($data)`, `recv($max = 65536)` (`""` at EOF,
  `null` on timeout), `close()`, `peer()`, `local()`, `isClosed()`. Closing a socket makes
  operations blocked on it throw.
- `Weft\Http\Server($host = "127.0.0.1", $port = 8080, array $options = [])` with options
  `workers`, `tls_cert` + `tls_key` (HTTPS and HTTP/2), `static_root`; `handle(callable)` and
  `start()` (blocks; stop with SIGTERM/SIGINT). Workers are forked processes. The handler gets
  `Weft\Http\Request` (`method`, `uri`, `path`, `queryString`, `query`, `headers`, `header`,
  `cookies`, `body`) and `Weft\Http\Response` (`status`, `header`, `end`, `isSent`) and runs in
  its own coroutine, so it may sleep, wait on channels, or answer later from another coroutine.
  A handler that throws gets a 500 response and a warning.
- `Weft\Exception` is thrown for engine and usage errors.

## Limits

- Opening files, `sleep()`/`usleep()` from PHP core, and other blocking PHP functions still block
  the whole process; use the `Weft\` equivalents.
- A PHP fatal error inside a coroutine ends the process, as usual for PHP.
- ZTS builds and PHP versions before 8.4 are not supported.
