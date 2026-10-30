//! Canonical error types shared by every OmniSec crate.
//!
//! Loader / parser / analysis crates all return [`Result<T>`]; downstream
//! code only ever needs to match against [`Error`] variants. Internal sub-
//! errors that aren't useful to expose should be flattened into
//! [`Error::Parse`] with a `context` string.

use std::path::PathBuf;

/// Convenience alias for `std::result::Result<T, omnisec_core::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// The root error type for the OmniSec platform.
///
/// Variants are intentionally chunky: we want callers to be able to display
/// nice messages without descending into a sub-error tree, and to be able to
/// programmatically distinguish "the file is wrong" from "the disk is wrong".
#[derive(Debug)]
pub enum Error {
    /// I/O failure (open, read, mmap, ...). Carries an optional path so we
    /// can point at *which* file blew up.
    Io {
        /// File this I/O was issued against, if known.
        path: Option<PathBuf>,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },

    /// The input could not be classified into any known [`Format`](crate::Format).
    UnknownFormat {
        /// Why we couldn't classify (e.g. "file too small", "bad magic").
        reason: String,
    },

    /// The input was correctly classified, but parsing failed mid-flight.
    Parse {
        /// Format we were attempting to parse.
        format: crate::Format,
        /// Free-form context — what we were doing when it failed.
        context: String,
    },

    /// A feature exists conceptually but is not yet implemented in this crate.
    Unsupported(String),

    /// Generic invariant violation — should be rare and treated as a bug.
    Internal(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => match path {
                Some(p) => write!(f, "I/O error on '{}': {source}", p.display()),
                None => write!(f, "I/O error: {source}"),
            },
            Self::UnknownFormat { reason } => {
                write!(f, "unrecognised binary format: {reason}")
            }
            Self::Parse { format, context } => write!(f, "{format} parse error: {context}"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
            Self::Internal(what) => write!(f, "internal error: {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    /// Build an [`Error::Io`] from a `std::io::Error` and an associated path.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: Some(path.into()),
            source,
        }
    }

    /// Build an [`Error::Io`] without a path (e.g. an in-memory cursor).
    #[must_use]
    pub fn io_anon(source: std::io::Error) -> Self {
        Self::Io { path: None, source }
    }

    /// Build an [`Error::Parse`] for a known format.
    pub fn parse(format: crate::Format, context: impl Into<String>) -> Self {
        Self::Parse {
            format,
            context: context.into(),
        }
    }

    /// Build an [`Error::UnknownFormat`].
    pub fn unknown_format(reason: impl Into<String>) -> Self {
        Self::UnknownFormat {
            reason: reason.into(),
        }
    }

    /// Build an [`Error::Unsupported`].
    pub fn unsupported(what: impl Into<String>) -> Self {
        Self::Unsupported(what.into())
    }

    /// Build an [`Error::Internal`] — for invariant violations.
    pub fn internal(what: impl Into<String>) -> Self {
        Self::Internal(what.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Self::io_anon(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Format;

    #[test]
    fn parse_error_carries_format() {
        let e = Error::parse(Format::Pe, "missing optional header");
        let msg = format!("{e}");
        assert!(msg.contains("PE"));
        assert!(msg.contains("missing optional header"));
    }

    #[test]
    fn io_error_with_path_renders_path() {
        let e = Error::io("C:/some/file.exe", std::io::Error::other("nope"));
        let msg = format!("{e}");
        assert!(msg.contains("file.exe"));
    }

    #[test]
    fn from_io_error_works() {
        let raw: std::io::Error = std::io::Error::other("oops");
        let e: Error = raw.into();
        assert!(matches!(e, Error::Io { path: None, .. }));
    }
}
