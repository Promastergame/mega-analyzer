//! Pre-canned [`crate::primitive::VulnerabilityPrimitive`] profiles for the
//! 2025-2026 threat landscape. These are useful both for testing the
//! Forge end-to-end and as reference shapes for callers writing their
//! own primitives.
//!
//! Every profile here is a pure constructor — it does not touch the
//! filesystem, network, or any actual target binary.

pub mod clawdbot;
pub mod ghostwrite;
pub mod mte_intra;
pub mod pac_timing;
pub mod react2shell;

pub use clawdbot::clawdbot;
pub use ghostwrite::ghostwrite;
pub use mte_intra::mte_intra_object;
pub use pac_timing::pac_timing;
pub use react2shell::react2shell;
