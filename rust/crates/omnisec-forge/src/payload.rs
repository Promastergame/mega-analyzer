//! [`SynthesizedPayload`] — the deterministic output of `omnisec-forge`.
//!
//! This is the artifact you ship to the [`crate::oracle`] for verification,
//! or attach to a forensic report. Everything here is `Serialize` so a
//! synthesis run can be re-checked off-line by replaying the same
//! `(ForgeConfig, VulnerabilityPrimitive)` pair on another machine.

use omnisec_json::{FromJson, ToJson};
use std::collections::BTreeMap;

use crate::chains::GadgetEntry;
use crate::compiler::ForgeStageReport;
use crate::complexity::ComplexityScore;
use crate::config::ForgeConfig;
use crate::mitigation::MitigationKind;

/// A concrete value Phase-4 chose for a Phase-3 [`crate::primitive::WitnessRequirement`].
///
/// We carry both the raw `i128` and a hex pre-rendering so consumers don't
/// have to re-render it (and forensic reports stay byte-identical).
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct WitnessValue {
    /// Bitvector width in bits.
    pub width: u32,
    /// Signed value Phase 3 returned.
    pub concrete: i128,
    /// Pre-rendered `0x…` form for forensic printers.
    pub hex: String,
}

impl WitnessValue {
    /// Build a value, rendering its hex form once so display is cheap.
    #[must_use]
    pub fn new(width: u32, concrete: i128) -> Self {
        let mask = if width >= 128 {
            u128::MAX
        } else {
            (1u128 << width) - 1
        };
        let unsigned = (concrete as u128) & mask;
        let nibbles = (width as usize).max(4).div_ceil(4);
        let hex = format!("0x{unsigned:0nibbles$x}");
        Self {
            width,
            concrete,
            hex,
        }
    }
}

/// Ordered set of witness values, keyed by Phase-3 variable name.
///
/// `BTreeMap` so iteration order is deterministic — critical for byte
/// identity in `SynthesizedPayload::stable_hash`.
pub type Witness = BTreeMap<String, WitnessValue>;

/// A self-contained artifact the oracle stage can ingest.
///
/// We keep this minimal on purpose: the *real* runtime stage 4 hooks into
/// QEMU/`prctl`-based sandboxing, but the data structure that crosses the
/// boundary is just bytes + metadata, fully serializable.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct Artifact {
    /// Human-readable artifact label.
    pub name: String,
    /// Raw bytes (e.g. the encoded payload, the gadget chain dump, the
    /// shellcode-style blob).
    pub bytes: Vec<u8>,
    /// MIME-style hint for renderers. Free-form, e.g. `application/x-rop-chain`.
    pub kind: String,
}

/// The deterministic output of `omnisec-forge::Forge::synthesize`.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct SynthesizedPayload {
    /// Copy of the config that produced this payload, for reproducibility.
    pub config: ForgeConfig,
    /// Primitive name (echoed back from [`crate::VulnerabilityPrimitive::name`]).
    pub primitive: String,
    /// Architecture of the produced payload.
    pub arch: omnisec_core::Arch,
    /// Mitigations the chain claims to bypass.
    pub bypassed: Vec<MitigationKind>,
    /// Witness assignments Phase-4 propagated forward.
    pub witness: Witness,
    /// Gadget chain (empty when the primitive used Data-Oriented Programming).
    pub chain: Vec<GadgetEntry>,
    /// Encoded payload bytes ready to feed the sink.
    pub payload: Vec<u8>,
    /// Per-stage report — useful for forensic visualisation.
    pub report: Vec<ForgeStageReport>,
    /// Final complexity score (lower = simpler / more reliable).
    pub complexity: ComplexityScore,
    /// Extra artifacts (decoder stubs, side-channel oracle helpers, …).
    pub artifacts: Vec<Artifact>,
}

impl SynthesizedPayload {
    /// FNV-1a hash of the deterministic content. Two payloads produced by
    /// the same `(ForgeConfig, VulnerabilityPrimitive)` pair MUST share
    /// this hash — Forge's main test suite asserts this.
    ///
    /// We deliberately hash a canonical bytewise representation rather
    /// than `format!("{self:?}")` so the hash is stable across
    /// `Debug`-impl tweaks.
    #[must_use]
    pub fn stable_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut absorb = |bytes: &[u8]| {
            for &b in bytes {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0000_0100_0000_01B3);
            }
        };

        absorb(self.primitive.as_bytes());
        absorb(self.arch.name().as_bytes());
        for m in &self.bypassed {
            absorb(m.name().as_bytes());
        }
        for (k, v) in &self.witness {
            absorb(k.as_bytes());
            absorb(&v.concrete.to_le_bytes());
            absorb(&v.width.to_le_bytes());
        }
        for entry in &self.chain {
            absorb(&entry.address.to_le_bytes());
            absorb(entry.label.as_bytes());
        }
        absorb(&self.payload);
        absorb(&self.complexity.raw().to_le_bytes());
        for art in &self.artifacts {
            absorb(art.name.as_bytes());
            absorb(art.kind.as_bytes());
            absorb(&art.bytes);
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_core::Arch;

    #[test]
    fn witness_value_formats_hex_with_correct_width() {
        let w = WitnessValue::new(32, 0xDEAD_BEEF);
        assert_eq!(w.hex, "0xdeadbeef");
        let w = WitnessValue::new(8, -1);
        assert_eq!(w.hex, "0xff");
    }

    #[test]
    fn stable_hash_is_deterministic() {
        let p = SynthesizedPayload {
            config: ForgeConfig::for_arch(Arch::X86_64),
            primitive: "fake".into(),
            arch: Arch::X86_64,
            bypassed: vec![MitigationKind::Aslr, MitigationKind::DepNx],
            witness: {
                let mut w = Witness::new();
                w.insert("v1".into(), WitnessValue::new(32, 1));
                w
            },
            chain: vec![],
            payload: vec![0x90, 0x90, 0x90],
            report: vec![],
            complexity: ComplexityScore::TRIVIAL,
            artifacts: vec![],
        };

        let a = p.stable_hash();
        let b = p.clone().stable_hash();
        assert_eq!(a, b);
    }
}
