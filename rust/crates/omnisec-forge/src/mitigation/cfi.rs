//! Control-Flow Integrity (CFI) bypass strategy.
//!
//! Modern CFI implementations (LLVM CFI, Clang shadow-call-stack, kCFI,
//! Intel CET shadow stack) restrict indirect calls/returns to a static
//! set of valid targets. The Forge addresses this in two ways:
//!
//! 1. **Type-confused-indirect-call reuse**: pick gadgets whose entry
//!    points are themselves legitimate CFI targets (i.e. exported or
//!    address-taken functions of the right `cfi_id`). The chain is
//!    then valid by construction.
//! 2. **Pivot to DOP**: drop the control-flow chain entirely and rely on
//!    the data-oriented programming module to mutate program state
//!    until the legitimate control-flow naturally goes where we want.
//!
//! Choosing between the two is deterministic: prefer DOP when the
//! primitive's `prefers_dop()` is true OR when `kind` is one of the
//! data-only kinds.

use omnisec_core::Arch;

use crate::chains::{GadgetCategory, GadgetSpec};
use crate::error::Result;
use crate::primitive::VulnerabilityPrimitive;
use crate::util::Prng;

use super::{Bypass, BypassPlan, MitigationKind};

/// CFI bypass.
#[derive(Debug, Default, Clone, Copy)]
pub struct CfiBypass;

impl Bypass for CfiBypass {
    fn kind(&self) -> MitigationKind {
        MitigationKind::Cfi
    }

    fn applies_to(&self, arch: Arch) -> bool {
        // CFI is a build-flag, not arch-specific. Plausible on every
        // arch we target.
        arch.is_native()
    }

    fn plan(&self, primitive: &VulnerabilityPrimitive, _prng: &mut Prng) -> Result<BypassPlan> {
        let mut plan = BypassPlan {
            kind: Some(MitigationKind::Cfi),
            ..Default::default()
        };

        if primitive.kind.prefers_dop() {
            plan.notes.push(
                "CFI bypass: switching to Data-Oriented Programming (no indirect calls)".into(),
            );
        } else {
            plan.notes
                .push("CFI bypass: chain through CFI-valid call targets only".into());
            plan.auxiliary_gadgets.push(GadgetSpec::abstract_(
                GadgetCategory::CfiCompliant,
                "type_confused_call",
            ));
        }
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitive::{ChainGoal, PrimitiveKind};

    #[test]
    fn dop_preference_wins() {
        let p = VulnerabilityPrimitive::new(
            "logic",
            Arch::X86_64,
            PrimitiveKind::LogicFlaw,
            ChainGoal::DataMutation {
                addr: 0x0060_1020,
                write: vec![1],
            },
        );
        let plan = CfiBypass.plan(&p, &mut Prng::new(0)).unwrap();
        assert!(plan.auxiliary_gadgets.is_empty());
        assert!(plan.notes.iter().any(|n| n.contains("Data-Oriented")));
    }

    #[test]
    fn falls_back_to_cfi_compliant_call() {
        let p = VulnerabilityPrimitive::new(
            "bof",
            Arch::X86_64,
            PrimitiveKind::StackBufferOverflow,
            ChainGoal::SpawnShell,
        );
        let plan = CfiBypass.plan(&p, &mut Prng::new(0)).unwrap();
        assert!(
            plan.auxiliary_gadgets
                .iter()
                .any(|g| g.category == GadgetCategory::CfiCompliant)
        );
    }
}
