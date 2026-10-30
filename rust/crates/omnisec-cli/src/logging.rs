//! Level wiring between the CLI's `-v` flags and `omnisec_log`.
//!
//! The library-side logger (`omnisec-log`) prints `LEVEL file:line message`
//! to stderr; we only need to map the CLI's verbosity count (and the
//! `RUST_LOG` / `OMNISEC_LOG` env override) onto its max level.

/// Install the level. Verbose count maps to log levels:
/// 0 → warn, 1 → info, 2 → debug, ≥3 → trace. `RUST_LOG` overrides.
pub fn init(verbose: u8) {
    use omnisec_log::Level;

    let from_flag = match verbose {
        0 => Level::Warn,
        1 => Level::Info,
        2 => Level::Debug,
        _ => Level::Trace,
    };
    let env = std::env::var("OMNISEC_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let level = if env.contains("error") {
        Level::Error
    } else if env.contains("warn") {
        Level::Warn
    } else if env.contains("debug") {
        Level::Debug
    } else if env.contains("trace") {
        Level::Trace
    } else if env.contains("info") {
        Level::Info
    } else {
        from_flag
    };
    omnisec_log::set_max_level(level);
}
