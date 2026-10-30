//! Gadget chain abstractions.
//!
//! - [`gadget`] — what a single gadget *is* (location + symbolic
//!   state-transition).
//! - [`finder`] — extract candidate gadgets from a code blob (linear scan
//!   for terminators, deduplicated).
//! - [`assembler`] — Bounded Generate-and-Test (BGAT) chain assembler that
//!   drives [`omnisec_smt::Solver`] with the symbolic CPU-state transitions
//!   from the candidate set.
//! - [`rop`] / [`jop`] / [`cop`] — chain-flavour shells that pre-configure
//!   the assembler's terminator filter and call convention.

pub mod assembler;
pub mod cop;
pub mod finder;
pub mod gadget;
pub mod jop;
pub mod rop;
pub mod scanner;

pub use assembler::{AssembledChain, BgatStats, SmtAssembler};
pub use cop::CopBuilder;
pub use finder::GadgetFinder;
pub use gadget::{
    CpuStateTransition, Gadget, GadgetCategory, GadgetEntry, GadgetSpec, RegisterEffect, Terminator,
};
pub use jop::JopBuilder;
pub use rop::RopBuilder;
pub use scanner::scan_into;
