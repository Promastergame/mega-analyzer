//! ARM64 MTE intra-object overflow primitive.
//!
//! The sink address sits inside the same 16-byte granule as a
//! legitimately-allocated buffer, so the tag check is a no-op by
//! construction. [`crate::mitigation::mte::MteBypass`] short-circuits
//! to the "intra-object" note when this primitive is consumed.

use omnisec_core::Arch;

use crate::config::{ForgeConfig, MitigationProfile};
use crate::primitive::{ChainGoal, PrimitiveKind, VulnerabilityPrimitive};

/// MTE intra-object primitive (overflow inside one 16-byte granule).
#[must_use]
pub fn mte_intra_object() -> VulnerabilityPrimitive {
    VulnerabilityPrimitive::new(
        "MTE Intra-Object Overflow",
        Arch::Arm64,
        PrimitiveKind::HeapBufferOverflow,
        ChainGoal::DataMutation {
            addr: 0x40_0008,
            write: vec![0xFF; 8],
        },
    )
    .with_anchor(0.9, 0.8)
    .with_sink(0x40_0008)
}

/// The recommended config to pair with [`mte_intra_object`].
#[must_use]
pub fn mte_intra_object_config() -> ForgeConfig {
    ForgeConfig::for_arch(Arch::Arm64).with_mitigation(MitigationProfile::AndroidHardened)
}
