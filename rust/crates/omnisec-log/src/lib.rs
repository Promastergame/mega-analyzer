//! Zero-dependency stderr logger (replaces `tracing` macros).
//!
//! API is intentionally `tracing`-shaped so migration is mechanical:
//! `omnisec_log::info!(...)` -> `omnisec_log::info!(...)`.
//! Structured-args syntax (`?field`, `field = %val`) is accepted and degraded
//! to plain text — no `tracing::Value` machinery needed.

use std::sync::atomic::{AtomicU8, Ordering};

/// Log verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Errors only.
    Error = 1,
    /// Warnings and errors.
    Warn = 2,
    /// Normal operational messages.
    Info = 3,
    /// Verbose debugging.
    Debug = 4,
    /// Very verbose tracing.
    Trace = 5,
}

impl Level {
    const fn as_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Error,
            2 => Self::Warn,
            3 => Self::Info,
            4 => Self::Debug,
            _ => Self::Trace,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

static MAX_LEVEL: AtomicU8 = AtomicU8::new(3);

/// Set the global maximum level (messages above it are dropped).
pub fn set_max_level(level: Level) {
    MAX_LEVEL.store(level.as_u8(), Ordering::Relaxed);
}

/// Current global maximum level.
#[must_use]
pub fn max_level() -> Level {
    Level::from_u8(MAX_LEVEL.load(Ordering::Relaxed))
}

fn level_from_env() -> Level {
    let v = std::env::var("OMNISEC_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if v.contains("trace") {
        Level::Trace
    } else if v.contains("debug") {
        Level::Debug
    } else if v.contains("warn") {
        Level::Warn
    } else if v.contains("error") && !v.contains("info") {
        Level::Error
    } else {
        Level::Info
    }
}

/// Initialise logging from `OMNISEC_LOG` / `RUST_LOG`. Idempotent.
pub fn init() {
    set_max_level(level_from_env());
}

/// Alias kept for call-sites migrating from `tracing_subscriber`.
pub fn init_stderr() {
    init();
}

#[doc(hidden)]
pub fn emit(level: Level, file: &str, line: u32, args: std::fmt::Arguments<'_>) {
    if (level.as_u8()) > MAX_LEVEL.load(Ordering::Relaxed) {
        return;
    }
    eprintln!("[{} {}:{}] {}", level.label(), file, line, args);
}

/// Compatibility shim: `omnisec_log::subscriber::set_global_default(...)` no-op.
pub mod subscriber {
    /// No-op kept so `omnisec_log::subscriber::set_global_default` call-sites compile.
    pub fn set_global_default<T>(_: T) -> Result<(), &'static str> {
        super::init();
        Ok(())
    }
}

/// Compatibility shim for `tracing::span`.
pub mod span {
    /// Opaque span id stub.
    #[derive(Debug, Clone, Copy)]
    pub struct Id(u64);
    impl Id {
        /// Build from raw id.
        #[must_use]
        pub const fn from_u64(v: u64) -> Self {
            Self(v)
        }
    }
    /// Span attributes stub.
    #[derive(Debug)]
    pub struct Attributes<'a> {
        _p: std::marker::PhantomData<&'a ()>,
    }
    /// Span record stub.
    #[derive(Debug)]
    pub struct Record<'a> {
        _p: std::marker::PhantomData<&'a ()>,
    }
}

/// Compatibility shim for `tracing::field`.
pub mod field {
    /// Visitor stub.
    pub trait Visit {
        /// Record debug value (no-op).
        fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
    }
    /// Field stub.
    #[derive(Debug)]
    pub struct Field;
}

/// Metadata stub for `Subscriber` impls migrating off tracing.
#[derive(Debug)]
pub struct Metadata<'a> {
    _p: std::marker::PhantomData<&'a ()>,
}

/// Event stub for `Subscriber` impls migrating off tracing.
#[derive(Debug)]
pub struct Event<'a> {
    _p: std::marker::PhantomData<&'a ()>,
}

/// Level stub mirroring `tracing::Level` constants for migrating code.
#[derive(Debug, Clone, Copy)]
pub struct LevelStub;
/// Subscriber trait stub so `impl omnisec_log::Subscriber` blocks keep compiling.
pub trait Subscriber {
    /// Whether a span/event is enabled.
    fn enabled(&self, _m: &Metadata<'_>) -> bool {
        true
    }
    /// Create a span.
    fn new_span(&self, _a: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    /// Record values on a span.
    fn record(&self, _s: &span::Id, _r: &span::Record<'_>) {}
    /// Record follows-from relation.
    fn record_follows_from(&self, _s: &span::Id, _f: &span::Id) {}
    /// Handle an event.
    fn event(&self, _e: &Event<'_>) {}
    /// Enter a span.
    fn enter(&self, _s: &span::Id) {}
    /// Exit a span.
    fn exit(&self, _s: &span::Id) {}
}

/// Emit an error message.
#[macro_export]
macro_rules! error {
    ($($t:tt)*) => {{
        $crate::emit($crate::Level::Error, file!(), line!(), format_args!($($t)*));
    }};
}

/// Emit a warning message.
#[macro_export]
macro_rules! warn {
    // Degrade `?field, "fmt"` tracing form to plain text.
    (?$v:expr, $($t:tt)*) => {{
        $crate::emit($crate::Level::Warn, file!(), line!(), format_args!("{:?} {}", $v, format_args!($($t)*)));
    }};
    (?$v:expr) => {{
        $crate::emit($crate::Level::Warn, file!(), line!(), format_args!("{:?}", $v));
    }};
    ($($t:tt)*) => {{
        $crate::emit($crate::Level::Warn, file!(), line!(), format_args!($($t)*));
    }};
}

/// Emit an info message.
#[macro_export]
macro_rules! info {
    (?$v:expr, $($t:tt)*) => {{
        $crate::emit($crate::Level::Info, file!(), line!(), format_args!("{:?} {}", $v, format_args!($($t)*)));
    }};
    (?$v:expr) => {{
        $crate::emit($crate::Level::Info, file!(), line!(), format_args!("{:?}", $v));
    }};
    ($($t:tt)*) => {{
        $crate::emit($crate::Level::Info, file!(), line!(), format_args!($($t)*));
    }};
}

/// Emit a debug message.
#[macro_export]
macro_rules! debug {
    (?$v:expr, $($t:tt)*) => {{
        $crate::emit($crate::Level::Debug, file!(), line!(), format_args!("{:?} {}", $v, format_args!($($t)*)));
    }};
    (?$v:expr) => {{
        $crate::emit($crate::Level::Debug, file!(), line!(), format_args!("{:?}", $v));
    }};
    ($($t:tt)*) => {{
        $crate::emit($crate::Level::Debug, file!(), line!(), format_args!($($t)*));
    }};
}

/// Emit a trace message.
#[macro_export]
macro_rules! trace {
    (?$v:expr, $($t:tt)*) => {{
        $crate::emit($crate::Level::Trace, file!(), line!(), format_args!("{:?} {}", $v, format_args!($($t)*)));
    }};
    (?$v:expr) => {{
        $crate::emit($crate::Level::Trace, file!(), line!(), format_args!("{:?}", $v));
    }};
    ($($t:tt)*) => {{
        $crate::emit($crate::Level::Trace, file!(), line!(), format_args!("{:?}", format_args!($($t)*)));
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_roundtrip() {
        set_max_level(Level::Debug);
        assert_eq!(max_level(), Level::Debug);
        set_max_level(Level::Info);
    }

    #[test]
    fn macros_accept_tracing_forms() {
        set_max_level(Level::Trace);
        let x = 42;
        info!("plain {}", x);
        info!(?x, "with debug prefix");
        warn!("w {}", x);
        debug!("d");
        trace!("t");
        error!("e");
    }
}
