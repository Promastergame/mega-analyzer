//! React2Shell (CVE-2025-55182): pre-auth deserialisation RCE.
//!
//! Architecture-agnostic at the symbolic level — the chain goal is a
//! plain `SpawnCommand` because the deserialisation gadget chain runs
//! inside a JVM/Node-style runtime, not in native code.

use omnisec_core::Arch;

use crate::primitive::{ChainGoal, PrimitiveKind, VulnerabilityPrimitive};

/// React2Shell pre-auth deserialisation primitive.
#[must_use]
pub fn react2shell() -> VulnerabilityPrimitive {
    VulnerabilityPrimitive::new(
        "CVE-2025-55182 / React2Shell",
        Arch::X86_64,
        PrimitiveKind::Deserialisation,
        ChainGoal::SpawnCommand {
            cmd: "/usr/bin/id".into(),
        },
    )
    .with_anchor(0.95, 0.9)
    .with_witness("payload_marker", 32, 0xCAFE_BABE)
}
