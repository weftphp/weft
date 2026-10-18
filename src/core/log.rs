//! Leveled logger writing to stdout, a file, or any writer, with optional file rotation.
//!
//! Each line looks like:
//!
//! ```text
//! 2026-10-18 21:04:05.123 WARN  [41237 worker-3] connection reset by peer
//! ```
//!
//! The bracket holds the process ID and, if set, a context label such as the role of the
//! current process. Every method takes `&self` and is safe to call from any thread.

use std::ffi::CString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::error::{Error, ErrorKind, Result};

/// Default `strftime` pattern for the timestamp.
pub const DEFAULT_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
const TIME_BUF_LEN: usize = 128;

/// Message severity, from most to least verbose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    /// Used as a threshold only: suppresses every message.
    Off,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
            Level::Off => "OFF",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// When a log file is replaced by a new one. Rotated files get a date suffix, e.g.
/// `app.log.2026-10-18` for [`Rotation::Daily`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rotation {
    #[default]
    Never,
    Hourly,
    Daily,
    Monthly,
}

impl Rotation {
    fn suffix_pattern(self) -> Option<&'static str> {
        match self {
            Rotation::Never => None,
            Rotation::Hourly => Some("%Y-%m-%d-%H"),
            Rotation::Daily => Some("%Y-%m-%d"),
            Rotation::Monthly => Some("%Y-%m"),
        }
    }
}

enum Output {
    Stdout,
    File {
        file: File,
        base: PathBuf,
        path: PathBuf,
    },
    Writer(Box<dyn Write + Send>),
}

struct State {
    output: Output,
    threshold: Level,
    time_format: String,
    millis: bool,
    rotation: Rotation,
    context: Option<String>,
    /// Original stdout/stderr, saved while they point at the log file.
    saved_std: Option<(RawFd, RawFd)>,
}

/// Thread-safe logger. Use [`logger`] for the process-wide instance.
pub struct Logger {
    state: Mutex<State>,
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}

impl Logger {
    /// Creates a logger that writes [`Level::Info`] and above to stdout.
    pub fn new() -> Self {
        Logger {
            state: Mutex::new(State {
                output: Output::Stdout,
                threshold: Level::Info,
                time_format: DEFAULT_TIME_FORMAT.to_owned(),
                millis: true,
                rotation: Rotation::Never,
                context: None,
                saved_std: None,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Appends to the file at `path`, plus a date suffix when rotation is enabled.
    pub fn log_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        self.state().open(path.as_ref().to_owned())
    }

    /// Sends output to `writer` instead of stdout or a file.
    pub fn log_to_writer(&self, writer: Box<dyn Write + Send>) {
        self.state().output = Output::Writer(writer);
    }

    /// Sends output back to stdout.
    pub fn log_to_stdout(&self) {
        self.state().output = Output::Stdout;
    }

    /// Path of the file being written, including any rotation suffix.
    pub fn current_file(&self) -> Option<PathBuf> {
        match &self.state().output {
            Output::File { path, .. } => Some(path.clone()),
            _ => None,
        }
    }

    /// Reopens the log file, e.g. after an external tool moved it away.
    pub fn reopen(&self) -> Result<()> {
        let mut state = self.state();
        match &state.output {
            Output::File { base, .. } => {
                let base = base.clone();
                state.open(base)
            }
            _ => Ok(()),
        }
    }

    pub fn threshold(&self) -> Level {
        self.state().threshold
    }

    /// Drops messages less severe than `level`.
    pub fn set_threshold(&self, level: Level) {
        self.state().threshold = level;
    }

    pub fn enabled(&self, level: Level) -> bool {
        level != Level::Off && level >= self.threshold()
    }

    /// Sets the `strftime` pattern for timestamps. Rejects patterns that produce nothing or
    /// more than 127 bytes.
    pub fn set_time_format(&self, pattern: &str) -> Result<()> {
        if format_local_time(pattern, now().0).is_none() {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                format!("unusable time format {pattern:?}"),
            ));
        }
        self.state().time_format = pattern.to_owned();
        Ok(())
    }

    /// Appends `.mmm` milliseconds to timestamps (on by default).
    pub fn set_millis(&self, enable: bool) {
        self.state().millis = enable;
    }

    /// Applies from the next [`log_to_file`](Self::log_to_file) or rotation check.
    pub fn set_rotation(&self, rotation: Rotation) {
        self.state().rotation = rotation;
    }

    /// Label shown after the process ID, e.g. `"master"` or `"worker-3"`.
    pub fn set_context(&self, context: Option<String>) {
        self.state().context = context;
    }

    /// Points the process's stdout and stderr at the log file, so output from code that
    /// prints directly also lands there. Requires an open log file.
    pub fn capture_std_streams(&self) -> Result<()> {
        let mut state = self.state();
        let Output::File { file, .. } = &state.output else {
            return Err(Error::new(ErrorKind::InvalidState, "no log file is open"));
        };
        if state.saved_std.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "std streams already captured",
            ));
        }
        let target = file.as_raw_fd();
        let out = fd::dup(libc::STDOUT_FILENO)?;
        let err = match fd::dup(libc::STDERR_FILENO) {
            Ok(err) => err,
            Err(e) => {
                fd::close(out);
                return Err(e.into());
            }
        };
        fd::point_std_streams_at(target)?;
        state.saved_std = Some((out, err));
        Ok(())
    }

    /// Undoes [`capture_std_streams`](Self::capture_std_streams).
    pub fn release_std_streams(&self) -> Result<()> {
        let Some((out, err)) = self.state().saved_std.take() else {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "std streams are not captured",
            ));
        };
        let result = fd::dup2(out, libc::STDOUT_FILENO).and(fd::dup2(err, libc::STDERR_FILENO));
        fd::close(out);
        fd::close(err);
        Ok(result?)
    }

    /// Writes `message` at `level` if it passes the threshold.
    pub fn log(&self, level: Level, message: impl fmt::Display) {
        let mut state = self.state();
        if level == Level::Off || level < state.threshold {
            return;
        }
        let (secs, millis) = now();
        state.rotate_if_due(secs);

        let mut stamp = format_local_time(&state.time_format, secs).unwrap_or_default();
        if state.millis {
            stamp.push_str(&format!(".{millis:03}"));
        }
        let pid = std::process::id();
        let line = match &state.context {
            Some(ctx) => format!("{stamp} {level:<5} [{pid} {ctx}] {message}\n"),
            None => format!("{stamp} {level:<5} [{pid}] {message}\n"),
        };
        // Nowhere sensible to report a failure to write a log line.
        let _ = state.write(line.as_bytes());
    }

    pub fn trace(&self, message: impl fmt::Display) {
        self.log(Level::Trace, message);
    }

    pub fn debug(&self, message: impl fmt::Display) {
        self.log(Level::Debug, message);
    }

    pub fn info(&self, message: impl fmt::Display) {
        self.log(Level::Info, message);
    }

    pub fn warn(&self, message: impl fmt::Display) {
        self.log(Level::Warn, message);
    }

    pub fn error(&self, message: impl fmt::Display) {
        self.log(Level::Error, message);
    }
}

impl State {
    fn open(&mut self, base: PathBuf) -> Result<()> {
        let path = rotated_name(&base, self.rotation, now().0);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        if self.saved_std.is_some() {
            fd::point_std_streams_at(file.as_raw_fd())?;
        }
        self.output = Output::File { file, base, path };
        Ok(())
    }

    fn rotate_if_due(&mut self, secs: i64) {
        let Output::File { base, path, .. } = &self.output else {
            return;
        };
        if self.rotation == Rotation::Never {
            return;
        }
        if rotated_name(base, self.rotation, secs) != *path {
            let base = base.clone();
            // If the new file cannot be opened, keep writing to the old one.
            let _ = self.open(base);
        }
    }

    fn write(&mut self, line: &[u8]) -> io::Result<()> {
        match &mut self.output {
            Output::Stdout => {
                let mut out = io::stdout().lock();
                out.write_all(line)?;
                out.flush()
            }
            Output::File { file, .. } => file.write_all(line),
            Output::Writer(writer) => {
                writer.write_all(line)?;
                writer.flush()
            }
        }
    }
}

/// The process-wide logger.
pub fn logger() -> &'static Logger {
    static LOGGER: LazyLock<Logger> = LazyLock::new(Logger::new);
    &LOGGER
}

fn rotated_name(base: &Path, rotation: Rotation, secs: i64) -> PathBuf {
    let Some(pattern) = rotation.suffix_pattern() else {
        return base.to_owned();
    };
    let mut name = base.as_os_str().to_owned();
    name.push(".");
    name.push(format_local_time(pattern, secs).unwrap_or_default());
    PathBuf::from(name)
}

/// Current Unix time as (seconds, milliseconds within the second).
fn now() -> (i64, u32) {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (since_epoch.as_secs() as i64, since_epoch.subsec_millis())
}

/// Formats Unix time `secs` in the local time zone with C `strftime`. `None` if the pattern
/// contains NUL, produces an empty string, or does not fit in [`TIME_BUF_LEN`] bytes.
fn format_local_time(pattern: &str, secs: i64) -> Option<String> {
    let pattern = CString::new(pattern).ok()?;
    let time = secs as libc::time_t;
    // SAFETY: `libc::tm` is plain old data; all-zero bytes are a valid value.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers refer to live locals for the duration of the call.
    if unsafe { libc::localtime_r(&time, &mut tm) }.is_null() {
        return None;
    }
    let mut buf = [0u8; TIME_BUF_LEN];
    // SAFETY: `buf` is writable for `buf.len()` bytes and `strftime` writes at most that
    // many; `pattern` is NUL-terminated; `tm` was filled in by `localtime_r`.
    let len = unsafe { libc::strftime(buf.as_mut_ptr().cast(), buf.len(), pattern.as_ptr(), &tm) };
    if len == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..len]).into_owned())
}

/// Checked wrappers for the file-descriptor calls used to capture stdout/stderr.
mod fd {
    use std::io;
    use std::os::fd::RawFd;

    pub fn dup(fd: RawFd) -> io::Result<RawFd> {
        // SAFETY: `dup` only touches the fd table; a bad fd is reported as EBADF.
        let new = unsafe { libc::dup(fd) };
        if new < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(new)
        }
    }

    pub fn dup2(from: RawFd, to: RawFd) -> io::Result<()> {
        // SAFETY: as for `dup`.
        if unsafe { libc::dup2(from, to) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn point_std_streams_at(target: RawFd) -> io::Result<()> {
        dup2(target, libc::STDOUT_FILENO)?;
        dup2(target, libc::STDERR_FILENO)
    }

    pub fn close(fd: RawFd) {
        // SAFETY: callers pass only fds they obtained from `dup` and have not closed.
        unsafe {
            libc::close(fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Sink {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn logger_with_sink() -> (Logger, Sink) {
        let logger = Logger::new();
        let sink = Sink::default();
        logger.log_to_writer(Box::new(sink.clone()));
        (logger, sink)
    }

    #[test]
    fn line_format_and_threshold() {
        let (logger, sink) = logger_with_sink();
        logger.debug("hidden");
        logger.set_context(Some("worker-3".into()));
        logger.warn(format_args!("reset by {}", "peer"));
        let text = sink.text();
        assert!(!text.contains("hidden"));
        let expected = format!(" WARN  [{} worker-3] reset by peer\n", std::process::id());
        assert!(text.ends_with(&expected), "{text:?}");

        logger.set_threshold(Level::Off);
        logger.error("muted");
        assert!(!sink.text().contains("muted"));
        assert!(!logger.enabled(Level::Error));
    }

    #[test]
    fn time_format() {
        let (logger, sink) = logger_with_sink();
        assert!(logger.set_time_format("").is_err());
        assert!(logger.set_time_format(&"%Y".repeat(64)).is_err());
        logger.set_time_format("%Y").unwrap();
        logger.set_millis(false);
        logger.info("x");
        let text = sink.text();
        let year = &text[..4];
        assert!(year.chars().all(|c| c.is_ascii_digit()), "{text:?}");
        assert_eq!(&text[4..10], " INFO ");
    }

    #[test]
    fn writes_to_rotated_file() {
        let base = std::env::temp_dir().join(format!("weft-log-test-{}.log", std::process::id()));
        let logger = Logger::new();
        logger.set_rotation(Rotation::Daily);
        logger.log_to_file(&base).unwrap();
        let path = logger.current_file().unwrap();
        assert!(path.to_string_lossy().starts_with(&*base.to_string_lossy()));
        assert_ne!(path, base);

        logger.info("first");
        logger.reopen().unwrap();
        logger.info("second");
        logger.log_to_stdout();
        assert_eq!(logger.current_file(), None);

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(text.contains("first") && text.contains("second"));
    }

    #[test]
    fn errors_without_a_file() {
        let logger = Logger::new();
        assert_eq!(
            logger
                .log_to_file("/nonexistent/weft/x.log")
                .unwrap_err()
                .kind(),
            ErrorKind::Io
        );
        assert_eq!(
            logger.capture_std_streams().unwrap_err().kind(),
            ErrorKind::InvalidState
        );
        assert_eq!(
            logger.release_std_streams().unwrap_err().kind(),
            ErrorKind::InvalidState
        );
    }
}
