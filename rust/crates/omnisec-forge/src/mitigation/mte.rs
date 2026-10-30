//! ARM64 Memory Tagging Extension (MTE) bypass strategy.
//!
//! MTE associates a 4-bit tag with every 16-byte granule and refuses
//! load/store when the pointer's tag and the granule's tag differ.
//!
//! Bypass strategies the Forge plans for:
//!
//! - **Tag foraging**: probe each granule deterministically until we
//!   land on a matching tag. With 4 bits, expected probes = 8.
//! - **Intra-object overflow**: when the OOB target lives inside the
//!   same 16-byte granule as a legitimate pointer, the tags match by
//!   construction. We model that by checking whether
//!   `(sink_address ^ object_base) < 16` and recording the offset.
//! - **Tag oracle-based**: a side-channel (e.g. asynchronous tag check
//!   reporting) used as a 1-bit oracle.
//!
//! As with PAC, the bypass plan only **records** the strategy; the
//! oracle stage drives any actual probing.

use omnisec_core::Arch;

use crate::error::Result;
use crate::primitive::VulnerabilityPrimitive;
use crate::util::Prng;

use super::{Bypass, BypassPlan, MitigationKind};

/// MTE bypass.
#[derive(Debug, Default, Clone, Copy)]
pub struct MteBypass;

impl Bypass for MteBypass {
    fn kind(&self) -> MitigationKind {
        MitigationKind::Mte
    }

    fn applies_to(&self, arch: Arch) -> bool {
        matches!(arch, Arch::Arm64)
    }

    fn plan(&self, primitive: &VulnerabilityPrimitive, prng: &mut Prng) -> Result<BypassPlan> {
        let mut plan = BypassPlan {
            kind: Some(MitigationKind::Mte),
            ..Default::default()
        };

        // 1. Intra-object check.
        if let Some(sink) = primitive.sink_address {
            // We don't actually know the object base; treat the lower 4
            // bits of the sink as the candidate offset. If the offset is
            // small the chain is intra-granule and MTE is a no-op.
            let offset = sink & 0xF;
            if offset != 0 && offset < 0x10 {
                plan.notes.push(format!(
                    "MTE intra-object: sink {sink:#x} is offset {offset} within its granule"
                ));
                return Ok(plan);
            }
        }

        // 2. Tag foraging fallback: pick a deterministic probe schedule.
        let mut order: Vec<u8> = (0..16).collect();
        prng.shuffle(&mut order);
        let order_str: String = order.iter().fold(String::new(), |mut s, t| {
            use std::fmt::Write;
            let _ = write!(s, "{t:x}");
            s
        });
        plan.notes.push(format!(
            "MTE tag-foraging order: {order_str} (deterministic from seed)"
        ));

        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitive::{ChainGoal, PrimitiveKind};

    #[test]
    fn intra_object_short_circuit() {
        let p = VulnerabilityPrimitive::new(
            "mte",
            Arch::Arm64,
            PrimitiveKind::HeapBufferOverflow,
            ChainGoal::DataMutation {
                addr: 0x40_0008,
                write: vec![1],
            },
        )
        .with_sink(0x40_0008);
        let plan = MteBypass.plan(&p, &mut Prng::new(0)).unwrap();
        assert!(plan.notes.iter().any(|n| n.contains("intra-object")));
    }

    #[test]
    fn tag_foraging_order_is_deterministic() {
        let p = VulnerabilityPrimitive::new(
            "mte",
            Arch::Arm64,
            PrimitiveKind::HeapBufferOverflow,
            ChainGoal::SpawnShell,
        );
        let a = MteBypass.plan(&p, &mut Prng::new(99)).unwrap();
        let b = MteBypass.plan(&p, &mut Prng::new(99)).unwrap();
        assert_eq!(a.notes, b.notes);
    }
}
