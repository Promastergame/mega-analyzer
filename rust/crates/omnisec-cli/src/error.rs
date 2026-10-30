//! Local replacement for `anyhow`. Keeps the CLI dependency-free.
//!
//! `anyhow` brings ~30 KB of binary weight that we don't need: the only
//! features we actually use are (a) a heap-allocated trait-object error
//! type, (b) a `?`-friendly `Result` alias, and (c) a `with_context`-style
//! attachment of free-form messages. All three are 30 lines of stdlib.

use std::error::Error as StdError;
use std::fmt;

/// CLI-wide error type. Carries a single owned message plus an optional
/// chain of contexts and an optional underlying source.
pub struct Error {
    msg: String,
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl Error {
    /// Build a free-form error from anything that can be `Display`-printed.
    #[must_use]
    pub fn msg<M: fmt::Display>(m: M) -> Self {
        Self {
            msg: m.to_string(),
            source: None,
        }
    }

    /// Wrap an underlying error with a human-readable context message.
    pub fn from_source<E>(msg: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            msg: msg.into(),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `{:#}` mirrors `anyhow`'s alternate format: full chain inline.
        if f.alternate() {
            write!(f, "{}", self.msg)?;
            // `source()` returns the bare `&dyn StdError` (no Send+Sync),
            // so this loop walks via that narrower trait object — exactly
            // how `anyhow` reports cause chains.
            let mut current: Option<&(dyn StdError + 'static)> =
                self.source.as_deref().map(|s| s as _);
            while let Some(err) = current {
                write!(f, ": {err}")?;
                current = err.source();
            }
            Ok(())
        } else {
            write!(f, "{}", self.msg)
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

/// Result alias used across the CLI.
pub type Result<T> = std::result::Result<T, Error>;

// Explicit conversions from the stdlib error types we actually hit. We
// can't use a blanket `impl<E: StdError> From<E> for Error` because Rust
// already provides a reflexive `From<T> for T` and the two collide. Listing
// the handful of real conversion sources keeps the conflict away and
// documents what the CLI actually surfaces.
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::from_source(e.to_string(), e)
    }
}

impl From<omnisec_json::JsonError> for Error {
    fn from(e: omnisec_json::JsonError) -> Self {
        Self::from_source(e.to_string(), e)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::from_source(e.to_string(), e)
    }
}

impl From<std::fmt::Error> for Error {
    fn from(e: std::fmt::Error) -> Self {
        Self::from_source(e.to_string(), e)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self::msg(s)
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self::msg(s)
    }
}

/// Add a context message to a `Result<T, _>`. Intentionally narrower than
/// `anyhow::Context` (no `with_context` / closures) — we don't need them.
pub trait ResultExt<T> {
    /// Attach a static-or-owned message that will appear before the
    /// underlying error in the formatted chain.
    fn context<M: fmt::Display>(self, msg: M) -> Result<T>;
}

impl<T, E: StdError + Send + Sync + 'static> ResultExt<T> for std::result::Result<T, E> {
    fn context<M: fmt::Display>(self, msg: M) -> Result<T> {
        self.map_err(|e| Error::from_source(msg.to_string(), e))
    }
}

/// Macro mirroring `anyhow::bail!`: short-circuit the function with an
/// error built from a format string.
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return ::std::result::Result::Err($crate::error::Error::msg(format!($($arg)*)))
    };
}
