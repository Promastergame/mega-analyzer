//! Oracle interfaces — the place where Phase-4 outputs get verified.
//!
//! # Available oracles
//!
//! - [`MockOracle`] — deterministic in-memory oracle for unit tests.
//! - [`ChildProcessOracle`] — spawns a real host process, pipes the
//!   synthesized payload into stdin, and verifies the exit-code /
//!   stdout pattern. This closes Stage 4 of the ML-Patch-Ex-Apply plan
//!   ("execution in a monitored sandbox with oracles to verify
//!   success").
//!
//! The trait is intentionally minimal so callers can plug their own
//! back-end (QEMU user-mode, `prctl`-jail, hardware-glitch driver,
//! in-process JIT) without changing any code inside `omnisec-forge`.

pub mod child_process;
pub mod verification;

pub use child_process::{ChildProcessOracle, ProcessVerdict};
pub use verification::{MockOracle, Oracle, OracleVerdict};
