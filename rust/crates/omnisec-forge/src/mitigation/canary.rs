//! Stack canary (`__stack_chk_guard`) bypass strategy.
//!
//! Most ABIs check a per-thread random canary at function epilogue. The
//! Forge bypasses this by:
//!
//! 1. Locating a leak witness whose width is exactly the canary width
//!    (8 bytes, low byte zero on glibc, low byte 0xAA on musl).
//! 2. Pinning a `stack_canary` witness override so the chain encoder
//!    splices the leaked value into the right offset of the overflow.
//! 3. If no leak is available, recording a "brute force not viable" note
//!    so the higher-level orchestrator can either reject the primitive
//!    or fall back to a non-stack chain.

use omnisec_core::Arch;

use crate::error::Result;
use crate::primitive::VulnerabilityPrimitive;
use crate::util::Prng;

use super::{Bypass, BypassPlan, MitigationKind};

/// Stack canary bypass.
#[derive(Debug, Default, Clone, Copy)]
pub struct StackCanaryBypass;

impl Bypass for StackCanaryBypass {
    fn kind(&self) -> MitigationKind {
        MitigationKind::StackCanary
    }

    fn applies_to(&self, arch: Arch) -> bool {
        arch.is_native()
    }

    fn plan(&self, primitive: &VulnerabilityPrimitive, _prng: &mut Prng) -> Result<BypassPlan> {
        let mut plan = BypassPlan {
            kind: Some(MitigationKind::StackCanary),
            ..Default::default()
        };

        // Heuristic: canary == 64-bit witness whose low byte is zero (glibc).
        let canary = primitive
            .witnesses
            .iter()
            .find(|w| w.width == 64 && (w.concrete as u64).trailing_zeros() >= 8);

        if let Some(c) = canary {
            plan.notes.push(format!(
                "Canary leak located in witness `{}` = {:#x}",
                c.name, c.concrete as u64
            ));
            plan.witness_overrides
                .push(("stack_canary".to_string(), c.concrete, 64));
        } else {
            plan.notes
                .push("No canary leak; chain must avoid stack-frame overwrite".into());
        }
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitive::{ChainGoal, PrimitiveKind};

    #[test]
    fn canary_leak_pinned_as_witness_override() {
        let p = VulnerabilityPrimitive::new(
            "canary",
            Arch::X86_64,
            PrimitiveKind::StackBufferOverflow,
            ChainGoal::SpawnShell,
        )
        .with_witness("leak", 64, 0xAABB_CCDD_EEFF_1100u64 as i128);
        let plan = StackCanaryBypass.plan(&p, &mut Prng::new(0)).unwrap();
        assert!(
            plan.witness_overrides
                .iter()
                .any(|(k, _, _)| k == "stack_canary")
        );
    }
}
