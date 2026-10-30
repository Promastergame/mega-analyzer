//! Clawdbot (CVE-2026-25253) — OpenClaw logic flaw.
//!
//! A pure logic primitive: there is no memory corruption, so the natural
//! realisation is a Data-Oriented Programming write to the
//! `is_authenticated` global. The Forge's
//! [`crate::compiler::ForgeEngine`] picks the DOP path automatically
//! because [`crate::primitive::PrimitiveKind::LogicFlaw`] reports
//! `prefers_dop() == true`.

use omnisec_core::Arch;

use crate::primitive::{ChainGoal, PrimitiveKind, VulnerabilityPrimitive};

/// Clawdbot logic-flaw primitive.
#[must_use]
pub fn clawdbot() -> VulnerabilityPrimitive {
    VulnerabilityPrimitive::new(
        "CVE-2026-25253 / Clawdbot",
        Arch::X86_64,
        PrimitiveKind::LogicFlaw,
        ChainGoal::DataMutation {
            addr: 0x0060_2040,
            write: vec![0x01, 0x00, 0x00, 0x00],
        },
    )
    .with_anchor(0.7, 0.95)
}
