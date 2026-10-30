//! ARM64 PAC timing side-channel primitive.
//!
//! The primitive itself doesn't *do* the side-channel — that's the
//! oracle stage's job. We just pin a 64-bit witness whose top 16 bits
//! encode a candidate PAC nibble pattern, so the
//! [`crate::mitigation::pac::PacBypass`] picks the leak-based forge
//! strategy.

use omnisec_core::Arch;

use crate::config::{ForgeConfig, MitigationProfile};
use crate::primitive::{ChainGoal, PrimitiveKind, VulnerabilityPrimitive};

/// PAC timing-channel primitive.
#[must_use]
pub fn pac_timing() -> VulnerabilityPrimitive {
    VulnerabilityPrimitive::new(
        "PAC Timing Side-Channel",
        Arch::Arm64,
        PrimitiveKind::TypeConfusion,
        ChainGoal::SpawnShell,
    )
    .with_anchor(0.85, 0.7)
    // 64-bit witness with a non-zero PAC field in the top 16 bits.
    .with_witness("signed_lr", 64, ((0xCAFEi128) << 48) | 0x0040_1400)
}

/// The recommended config to pair with [`pac_timing`].
#[must_use]
pub fn pac_timing_config() -> ForgeConfig {
    ForgeConfig::for_arch(Arch::Arm64).with_mitigation(MitigationProfile::IosHardened)
}
