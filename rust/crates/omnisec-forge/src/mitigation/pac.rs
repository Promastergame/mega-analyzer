//! ARM64 Pointer Authentication (PAC) bypass strategy.
//!
//! PAC stores a tweakable cryptographic MAC in the unused top bits of a
//! pointer. Bypass paths the Forge supports:
//!
//! - **Signing-gadget reuse**: locate `paciasp` / `pacia` instructions in
//!   the target's `.text` and chain them to mint signatures over
//!   attacker-supplied addresses.
//! - **Timing side-channel**: model PAC verification as a 1-bit oracle and
//!   register an SMT constraint that forces the synthesizer to pin the
//!   correct MAC nibbles bit-by-bit.
//! - **Forge-from-leak**: if the witness bag has a value whose `(pointer,
//!   pac)` partition matches the chain target's address modulo PAC's
//!   tagged-address mask, lift the MAC straight off the leaked value.
//!
//! All three strategies are deterministic — no PAC keys are recovered at
//! synthesis time, and no actual signing happens here. The plan only
//! records the strategy; verification belongs to the oracle stage.

use omnisec_core::Arch;

use crate::chains::{GadgetCategory, GadgetSpec};
use crate::error::Result;
use crate::primitive::VulnerabilityPrimitive;
use crate::util::Prng;

use super::{Bypass, BypassPlan, MitigationKind};

/// PAC bypass.
#[derive(Debug, Default, Clone, Copy)]
pub struct PacBypass;

impl Bypass for PacBypass {
    fn kind(&self) -> MitigationKind {
        MitigationKind::Pac
    }

    fn applies_to(&self, arch: Arch) -> bool {
        matches!(arch, Arch::Arm64)
    }

    fn plan(&self, primitive: &VulnerabilityPrimitive, prng: &mut Prng) -> Result<BypassPlan> {
        let mut plan = BypassPlan {
            kind: Some(MitigationKind::Pac),
            ..Default::default()
        };

        // Strategy selection is deterministic: prefer leak-based forging
        // when a 64-bit witness is present, otherwise fall back to
        // signing-gadget reuse.
        let has_leaked_signed_ptr = primitive
            .witnesses
            .iter()
            .any(|w| w.width == 64 && (w.concrete as u128) >> 48 != 0);

        if has_leaked_signed_ptr {
            plan.notes
                .push("PAC bypass: forge MAC from leaked signed pointer's top 16 bits".into());
            plan.auxiliary_gadgets
                .push(GadgetSpec::abstract_(GadgetCategory::PacForge, "xpaclri"));
        } else {
            plan.notes
                .push("PAC bypass: chain through PAC signing gadget (paciasp + autiasp)".into());
            plan.auxiliary_gadgets
                .push(GadgetSpec::abstract_(GadgetCategory::PacForge, "paciasp"));
            plan.auxiliary_gadgets
                .push(GadgetSpec::abstract_(GadgetCategory::PacForge, "autiasp"));

            // Record a deterministic timing-side-channel hint: the oracle
            // can use this to schedule a 16-iteration probe loop. The
            // value comes from the PRNG so different seeds explore
            // different probe orderings without breaking determinism.
            let probe_order = prng.next_u64() & 0xFFFF;
            plan.notes
                .push(format!("PAC timing probe scramble = {probe_order:#06x}"));
        }

        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitive::{ChainGoal, PrimitiveKind};

    #[test]
    fn pac_only_applies_to_arm64() {
        assert!(PacBypass.applies_to(Arch::Arm64));
        assert!(!PacBypass.applies_to(Arch::X86_64));
        assert!(!PacBypass.applies_to(Arch::RiscV64));
    }

    #[test]
    fn pac_chooses_leak_strategy_when_signed_pointer_present() {
        let p = VulnerabilityPrimitive::new(
            "pac",
            Arch::Arm64,
            PrimitiveKind::StackBufferOverflow,
            ChainGoal::SpawnShell,
        )
        .with_witness("signed_lr", 64, 0xCAFEi128 << 48 | 0x0040_1400);
        let plan = PacBypass.plan(&p, &mut Prng::new(7)).unwrap();
        assert!(plan.auxiliary_gadgets.iter().any(|g| g.label == "xpaclri"));
    }

    #[test]
    fn pac_falls_back_to_signing_gadget() {
        let p = VulnerabilityPrimitive::new(
            "pac",
            Arch::Arm64,
            PrimitiveKind::StackBufferOverflow,
            ChainGoal::SpawnShell,
        );
        let plan = PacBypass.plan(&p, &mut Prng::new(7)).unwrap();
        assert!(plan.auxiliary_gadgets.iter().any(|g| g.label == "paciasp"));
        assert!(plan.auxiliary_gadgets.iter().any(|g| g.label == "autiasp"));
    }
}
