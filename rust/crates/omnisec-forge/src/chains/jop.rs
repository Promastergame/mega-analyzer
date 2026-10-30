//! JOP (Jump-Oriented Programming) builder.
//!
//! Same algorithm as [`super::RopBuilder`], but each gadget terminates in
//! an indirect jump rather than a `ret`. The difference matters because
//! some CFI mitigations only protect `call` (not `jmp`), which makes JOP
//! the natural choice when shadow-stack-style CFI is enabled.

use crate::error::Result;
use crate::util::Prng;

use super::assembler::{AssembledChain, RegisterGoal, SmtAssembler};
use super::finder::GadgetFinder;
use super::gadget::Terminator;

/// JOP chain builder.
pub struct JopBuilder<'a> {
    finder: &'a GadgetFinder,
    goals: Vec<RegisterGoal>,
}

impl<'a> JopBuilder<'a> {
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

    /// Run the BGAT search restricted to `jmp reg`-style gadgets.
    pub fn build(self, prng: &mut Prng) -> Result<AssembledChain> {
        SmtAssembler::new(self.finder)
            .with_terminator(Terminator::JumpReg)
            .assemble(&self.goals, prng)
    }
}
