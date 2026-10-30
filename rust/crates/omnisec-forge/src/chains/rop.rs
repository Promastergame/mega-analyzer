//! ROP (Return-Oriented Programming) builder.
//!
//! Thin shell over [`super::SmtAssembler`] that pre-configures the
//! terminator filter to `Ret` and exposes a slightly more ergonomic
//! goal-building API.

use crate::error::Result;
use crate::util::Prng;

use super::assembler::{AssembledChain, RegisterGoal, SmtAssembler};
use super::finder::GadgetFinder;
use super::gadget::Terminator;

/// ROP chain builder.
pub struct RopBuilder<'a> {
    finder: &'a GadgetFinder,
    goals: Vec<RegisterGoal>,
    budget: usize,
    max_length: usize,
}

impl<'a> RopBuilder<'a> {
    /// New empty builder.
    #[must_use]
    pub fn new(finder: &'a GadgetFinder) -> Self {
        Self {
            finder,
            goals: Vec::new(),
            budget: 4_096,
            max_length: 16,
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

    /// Override the BGAT budget.
    #[must_use]
    pub fn with_budget(mut self, budget: usize) -> Self {
        self.budget = budget;
        self
    }

    /// Override the max chain length.
    #[must_use]
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// Run the BGAT search.
    pub fn build(self, prng: &mut Prng) -> Result<AssembledChain> {
        SmtAssembler::new(self.finder)
            .with_budget(self.budget)
            .with_max_length(self.max_length)
            .with_terminator(Terminator::Ret)
            .assemble(&self.goals, prng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::finder::synthetic_pool;

    #[test]
    fn rop_builder_round_trip() {
        let finder = synthetic_pool();
        let chain = RopBuilder::new(&finder)
            .set_register("rdi", 0xCAFE_BABE)
            .set_register("rsi", 0xDEAD_BEEF)
            .build(&mut Prng::new(3))
            .unwrap();
        assert_eq!(chain.entries.len(), 2);
    }
}
