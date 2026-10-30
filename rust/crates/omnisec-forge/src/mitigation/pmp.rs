//! RISC-V Physical Memory Protection (PMP) bypass strategy.
//!
//! PMP is a per-core, M-mode-configured table of `(addr, attributes)` pairs
//! that gates physical memory access. Bypass paths the Forge plans for:
//!
//! - **M-mode ROP chain** that calls `csrrw mepc` then `mret` to drop into
//!   a controlled physical address with PMP relaxed.
//! - **Clock-glitch fault-injection vector**: record the strategy as a
//!   plain note (the actual glitch is hardware-side and out of Forge's
//!   scope) so the oracle stage can wire its own glitch driver in.
//! - **GhostWrite** (T-Head C910 errata): when the primitive specifies
//!   `kind = HardwareFault`, mark the chain as relying on the
//!   architecturally-illegal vector store path.

use omnisec_core::Arch;

use crate::chains::{GadgetCategory, GadgetSpec};
use crate::error::Result;
use crate::primitive::{PrimitiveKind, VulnerabilityPrimitive};
use crate::util::Prng;

use super::{Bypass, BypassPlan, MitigationKind};

/// PMP bypass.
#[derive(Debug, Default, Clone, Copy)]
pub struct PmpBypass;

impl Bypass for PmpBypass {
    fn kind(&self) -> MitigationKind {
        MitigationKind::Pmp
    }

    fn applies_to(&self, arch: Arch) -> bool {
        matches!(arch, Arch::RiscV32 | Arch::RiscV64)
    }

    fn plan(&self, primitive: &VulnerabilityPrimitive, _prng: &mut Prng) -> Result<BypassPlan> {
        let mut plan = BypassPlan {
            kind: Some(MitigationKind::Pmp),
            ..Default::default()
        };

        if primitive.kind == PrimitiveKind::HardwareFault {
            plan.notes
                .push("PMP bypass: route through GhostWrite vector-store fault path".into());
            plan.auxiliary_gadgets.push(GadgetSpec::abstract_(
                GadgetCategory::HardwareFault,
                "ghostwrite_stub",
            ));
        } else {
            plan.notes
                .push("PMP bypass: M-mode chain via csrrw mepc + mret".into());
            plan.auxiliary_gadgets.push(GadgetSpec::abstract_(
                GadgetCategory::PrivEscalation,
                "csrrw_mepc",
            ));
            plan.auxiliary_gadgets.push(GadgetSpec::abstract_(
                GadgetCategory::PrivEscalation,
                "mret",
            ));
        }

        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitive::ChainGoal;

    #[test]
    fn ghostwrite_dispatches_hardware_fault_stub() {
        let p = VulnerabilityPrimitive::new(
            "gw",
            Arch::RiscV64,
            PrimitiveKind::HardwareFault,
            ChainGoal::DataMutation {
                addr: 0x4000_0000,
                write: vec![1; 8],
            },
        );
        let plan = PmpBypass.plan(&p, &mut Prng::new(0)).unwrap();
        assert!(
            plan.auxiliary_gadgets
                .iter()
                .any(|g| g.label == "ghostwrite_stub")
        );
    }

    #[test]
    fn pmp_only_applies_to_riscv() {
        assert!(PmpBypass.applies_to(Arch::RiscV64));
        assert!(PmpBypass.applies_to(Arch::RiscV32));
        assert!(!PmpBypass.applies_to(Arch::Arm64));
        assert!(!PmpBypass.applies_to(Arch::X86_64));
    }
}
