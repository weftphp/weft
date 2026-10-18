//! The error type shared across weft.
//!
//! An [`Error`] has a coarse [`ErrorKind`] for callers to branch on, plus optional detail:
//! a human-readable message or the underlying I/O error.

use std::fmt;
use std::io;

/// Broad category of an [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An argument was out of range or otherwise unusable.
    InvalidArgument,
    /// The operation is not valid in the object's current state.
    InvalidState,
    /// A bounded container has no room for the item.
    Full,
    /// The item is larger than the container ever accepts.
    TooLarge,
    /// The resource was closed.
    Closed,
    /// Nothing matched the request (an unknown host, key or path).
    NotFound,
    /// The operation did not finish within its time limit.
    TimedOut,
    /// The peer sent data that violates the protocol being spoken.
    Protocol,
    /// An operating-system I/O error; see [`Error::io_error`].
    Io,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::InvalidArgument => "invalid argument",
            ErrorKind::InvalidState => "invalid state",
            ErrorKind::Full => "full",
            ErrorKind::TooLarge => "too large",
            ErrorKind::Closed => "closed",
            ErrorKind::NotFound => "not found",
            ErrorKind::TimedOut => "timed out",
            ErrorKind::Protocol => "protocol error",
            ErrorKind::Io => "I/O error",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
enum Detail {
    None,
    Message(Box<str>),
    Io(io::Error),
}

/// Error returned by fallible weft operations.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    detail: Detail,
}

impl Error {
    /// Creates an error of `kind` with an explanatory message.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error {
            kind,
            detail: Detail::Message(message.into().into_boxed_str()),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The underlying OS error, for errors of kind [`ErrorKind::Io`].
    pub fn io_error(&self) -> Option<&io::Error> {
        match &self.detail {
            Detail::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Detail::None => self.kind.fmt(f),
            Detail::Message(msg) => write!(f, "{}: {msg}", self.kind),
            Detail::Io(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.detail {
            Detail::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error {
            kind,
            detail: Detail::None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error {
            kind: ErrorKind::Io,
            detail: Detail::Io(err),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_kind() {
        let err = Error::new(ErrorKind::TooLarge, "message is 10 bytes, limit is 4");
        assert_eq!(err.kind(), ErrorKind::TooLarge);
        assert_eq!(
            err.to_string(),
            "too large: message is 10 bytes, limit is 4"
        );
        assert_eq!(Error::from(ErrorKind::Full).to_string(), "full");
    }

    #[test]
    fn wraps_io_errors() {
        let err = Error::from(io::Error::from(io::ErrorKind::NotFound));
        assert_eq!(err.kind(), ErrorKind::Io);
        assert_eq!(
            err.io_error().map(io::Error::kind),
            Some(io::ErrorKind::NotFound)
        );
        assert!(std::error::Error::source(&err).is_some());
    }
}
