//! ASLR (Address-Space Layout Randomisation) bypass strategy.
//!
//! The Forge does not actually leak addresses at runtime — that's the
//! oracle stage's job. What this module does is emit a *plan*:
//!
//! 1. Look at the primitive's witness bag for any value that could plausibly
//!    be a leaked pointer (heuristic: 64-bit, top byte zero, low 12 bits
//!    not all zero).
//! 2. Add a note recording the inferred image base / library base.
//! 3. Pin a synthetic `aslr_slide` witness override so downstream
//!    arch-specific code can subtract it from gadget addresses to make
//!    the chain position-independent.
//!
//! All of this is deterministic given `(primitive, seed)`.

use omnisec_core::Arch;

use crate::error::Result;
use crate::primitive::VulnerabilityPrimitive;
use crate::util::Prng;

use super::{Bypass, BypassPlan, MitigationKind};

/// ASLR bypass.
#[derive(Debug, Default, Clone, Copy)]
pub struct AslrBypass;

impl Bypass for AslrBypass {
    fn kind(&self) -> MitigationKind {
        MitigationKind::Aslr
    }

    fn applies_to(&self, _arch: Arch) -> bool {
        // ASLR exists on every modern target; bypass is universal.
        true
    }

    fn plan(&self, primitive: &VulnerabilityPrimitive, _prng: &mut Prng) -> Result<BypassPlan> {
        let mut plan = BypassPlan {
            kind: Some(MitigationKind::Aslr),
            ..Default::default()
        };

        // Pick the first 64-bit witness whose top byte is zero — this is
        // the canonical "looks like a userspace pointer" heuristic.
        let leaked = primitive
            .witnesses
            .iter()
            .find(|w| w.width >= 56 && (w.concrete as u128) >> 56 == 0 && w.concrete != 0);

        if let Some(w) = leaked {
            // Base = pointer & ~0xFFF (page-align).
            let ptr = w.concrete as u128;
            let base = ptr & !0xFFFu128;
            plan.notes.push(format!(
                "Inferred image-base candidate {:#x} from witness `{}` = {:#x}",
                base, w.name, ptr
            ));
            plan.witness_overrides
                .push(("aslr_image_base".to_string(), base as i128, 64));
        } else {
            plan.notes.push(
                "No leaked pointer found; chain will use partial-overwrite ASLR strategy".into(),
            );
            // Encode a deterministic synthetic slide so downstream emitters
            // have *something* to subtract. Real-world this comes from the
            // oracle's pre-flight run; in offline synthesis we record `0`.
            plan.witness_overrides
                .push(("aslr_image_base".to_string(), 0, 64));
        }

        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitive::{ChainGoal, PrimitiveKind};

    #[test]
    fn aslr_plan_extracts_base_from_64bit_witness() {
        let p = VulnerabilityPrimitive::new(
            "test",
            Arch::X86_64,
            PrimitiveKind::StackBufferOverflow,
            ChainGoal::SpawnShell,
        )
        .with_witness("leak", 64, 0x0000_5555_5555_1234);
        let mut prng = Prng::new(1);
        let plan = AslrBypass.plan(&p, &mut prng).unwrap();
        assert_eq!(plan.kind, Some(MitigationKind::Aslr));
        let (_, val, _) = plan
            .witness_overrides
            .iter()
            .find(|(k, _, _)| k == "aslr_image_base")
            .unwrap();
        assert_eq!(*val as u128, 0x0000_5555_5555_1000);
    }

    #[test]
    fn aslr_plan_falls_back_to_zero_base() {
        let p = VulnerabilityPrimitive::new(
            "test",
            Arch::X86_64,
            PrimitiveKind::StackBufferOverflow,
            ChainGoal::SpawnShell,
        );
        let mut prng = Prng::new(1);
        let plan = AslrBypass.plan(&p, &mut prng).unwrap();
        assert!(plan.notes.iter().any(|n| n.contains("partial-overwrite")));
    }
}
