//! GhostWrite — RISC-V T-Head C910 vector-store fault primitive.
//!
//! Exposes a hardware-fault data-mutation primitive that flips a
//! physical-memory byte without going through PMP. The Forge
//! [`crate::mitigation::pmp::PmpBypass`] picks this up and emits the
//! `ghostwrite_stub` auxiliary gadget.

use omnisec_core::Arch;

use crate::primitive::{ChainGoal, PrimitiveKind, VulnerabilityPrimitive};

/// GhostWrite primitive: a single physical-memory write.
#[must_use]
pub fn ghostwrite() -> VulnerabilityPrimitive {
    VulnerabilityPrimitive::new(
        "GhostWrite (T-Head C910)",
        Arch::RiscV64,
        PrimitiveKind::HardwareFault,
        ChainGoal::DataMutation {
            addr: 0x8000_0040,
            write: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
        },
    )
    .with_anchor(0.99, 0.95)
}
