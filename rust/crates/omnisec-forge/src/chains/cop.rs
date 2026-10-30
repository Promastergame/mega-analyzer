//! COP (Call-Oriented Programming) builder.
//!
//! Each gadget ends in `call reg`. Useful when the chain must remain
//! call-graph-valid (e.g. against shadow-stack-only CFI).

use crate::error::Result;
use crate::util::Prng;

use super::assembler::{AssembledChain, RegisterGoal, SmtAssembler};
use super::finder::GadgetFinder;
use super::gadget::Terminator;

/// COP chain builder.
pub struct CopBuilder<'a> {
    finder: &'a GadgetFinder,
    goals: Vec<RegisterGoal>,
}

impl<'a> CopBuilder<'a> {
    /// New empty builder.
    #[must_use]
    pub fn new(finder: &'a GadgetFinder) -> Self {
        Self {
            finder,
            goals: Vec::new(),
        }
    }

    /// Pin a register to a constant value.
    #[must_use]
    pub fn set_register(mut self, reg: impl Into<String>, value: i64) -> Self {
        self.goals.push(RegisterGoal {
            register: reg.into(),
            value,
        });
        self
    }

    /// Run the BGAT search restricted to `call reg`-style gadgets.
    pub fn build(self, prng: &mut Prng) -> Result<AssembledChain> {
        SmtAssembler::new(self.finder)
            .with_terminator(Terminator::CallReg)
            .assemble(&self.goals, prng)
    }
}
