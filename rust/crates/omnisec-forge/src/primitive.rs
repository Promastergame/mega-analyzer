//! [`VulnerabilityPrimitive`] — the fully-resolved input that the Forge
//! consumes from Phases 1–3.
//!
//! This struct is intentionally **wire-friendly**: every field is `Clone +
//! Serialize`, every reference is owned, no lifetimes leak. The whole
//! point is that you can capture a primitive in one OmniSec process,
//! ship it to a Forge instance running elsewhere, and get the same
//! payload bytes out.

use omnisec_core::Arch;
use omnisec_json::{FromJson, ToJson};
use std::collections::BTreeMap;

/// What flavour of vulnerability primitive Phase 4 is being driven by.
///
/// The Forge picks different translator strategies depending on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum PrimitiveKind {
    /// Stack buffer overflow → control over saved return address.
    StackBufferOverflow,
    /// Heap buffer overflow → corruption of adjacent metadata or vtable.
    HeapBufferOverflow,
    /// Use-after-free → control over a freshly-allocated victim object.
    UseAfterFree,
    /// Type confusion → mis-typed access primitive.
    TypeConfusion,
    /// Format-string write-what-where.
    FormatString,
    /// Integer overflow that becomes a length confusion.
    IntegerOverflow,
    /// Command / argument injection (e.g. `system(tainted)`).
    CommandInjection,
    /// Deserialisation gadget chain (e.g. React2Shell-style).
    Deserialisation,
    /// Hardware fault injection (e.g. RowHammer, GhostWrite).
    HardwareFault,
    /// Logic flaw — non-memory-corruption bypass (e.g. Clawdbot).
    LogicFlaw,
}

impl PrimitiveKind {
    /// `true` if this kind typically requires a ROP/JOP chain to be
    /// fully realised.
    #[must_use]
    pub const fn needs_chain(self) -> bool {
        matches!(
            self,
            Self::StackBufferOverflow
                | Self::HeapBufferOverflow
                | Self::UseAfterFree
                | Self::TypeConfusion
        )
    }

    /// `true` if Data-Oriented Programming is the natural realisation
    /// for this kind (no control-flow hijack needed).
    #[must_use]
    pub const fn prefers_dop(self) -> bool {
        matches!(self, Self::LogicFlaw | Self::IntegerOverflow)
    }
}

/// A *witness* requirement carried over from Phase 3 (concolic / SMT).
///
/// Each requirement says "input variable `name` must take a value
/// satisfying these constraints to drive execution to the sink". When the
/// Forge composes the final payload it consults these to lay out the
/// bytes that flow into the program's input.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct WitnessRequirement {
    /// Name of the symbolic input variable (matches the `name` used in the
    /// SMT model).
    pub name: String,
    /// Bitvector width in bits.
    pub width: u32,
    /// Concrete value Phase 3 already proved satisfies the path constraint.
    /// Stored as `i128` because that's what the SMT model returns.
    pub concrete: i128,
}

/// Mid-level "what does the gadget chain need to do" description.
///
/// We keep this a small enum because the Forge's per-arch emitters are
/// the place where ABI-specific lowering happens — this enum is purely
/// the abstract intent.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum ChainGoal {
    /// Pivot the stack to a controlled buffer and ROP from there.
    StackPivot {
        /// Address (or symbol) of the controlled buffer.
        buffer: String,
    },
    /// Call `mprotect(addr, len, RWX)` (or arch-equivalent) to make `addr`
    /// executable, then jump to it.
    MakeRwxAndJump {
        /// Address to make RWX.
        addr: u64,
        /// Region length.
        len: u64,
    },
    /// Call `system("/bin/sh")` (or arch-equivalent).
    SpawnShell,
    /// Spawn an arbitrary command.
    SpawnCommand {
        /// Command line.
        cmd: String,
    },
    /// Read or write a known global / object field — primary mode for DOP.
    DataMutation {
        /// Memory location.
        addr: u64,
        /// Bytes to write (none ⇒ read-only primitive).
        write: Vec<u8>,
    },
}

/// Fully resolved Phase-1–3 output, fed into Forge's Phase-4 synthesizer.
///
/// Note: `Eq` is intentionally **not** derived because the `anchor_*` fields
/// are `f64` (no `Eq` impl by IEEE-754 design). Callers who need
/// hash/dedup semantics should use the `name` field as the identity key.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct VulnerabilityPrimitive {
    /// Human-readable identifier (CVE id, internal report id, etc.).
    pub name: String,
    /// Architecture the primitive applies to.
    pub arch: Arch,
    /// Vulnerability kind.
    pub kind: PrimitiveKind,
    /// HDC anchor severity from Phase 1 (0.0–1.0). Used for complexity
    /// tie-breaking.
    pub anchor_severity: f64,
    /// HDC anchor jaccard similarity from Phase 1 (0.0–1.0). Used as a
    /// confidence proxy.
    pub anchor_confidence: f64,
    /// Sink address Phase 2 found at the end of the taint path.
    pub sink_address: Option<u64>,
    /// Required witnesses solved by Phase 3.
    pub witnesses: Vec<WitnessRequirement>,
    /// Abstract goal the gadget chain (or DOP graph) must achieve.
    pub goal: ChainGoal,
    /// "Notes" from earlier phases that the Forge may surface in its
    /// per-stage report. Free-form, deterministic key-ordering thanks to
    /// `BTreeMap`.
    pub notes: BTreeMap<String, String>,
}

impl VulnerabilityPrimitive {
    /// Convenience constructor for the most common primitive shape.
    #[must_use]
    pub fn new(name: impl Into<String>, arch: Arch, kind: PrimitiveKind, goal: ChainGoal) -> Self {
        Self {
            name: name.into(),
            arch,
            kind,
            anchor_severity: 0.5,
            anchor_confidence: 0.5,
            sink_address: None,
            witnesses: Vec::new(),
            goal,
            notes: BTreeMap::new(),
        }
    }

    /// Attach a Phase-3 witness.
    #[must_use]
    pub fn with_witness(mut self, name: impl Into<String>, width: u32, concrete: i128) -> Self {
        self.witnesses.push(WitnessRequirement {
            name: name.into(),
            width,
            concrete,
        });
        self
    }

    /// Set the HDC severity and confidence in one call.
    #[must_use]
    pub fn with_anchor(mut self, severity: f64, confidence: f64) -> Self {
        self.anchor_severity = severity.clamp(0.0, 1.0);
        self.anchor_confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Pin the sink address (typically copied from `MatchResult` ↔ taint sink).
    #[must_use]
    pub fn with_sink(mut self, address: u64) -> Self {
        self.sink_address = Some(address);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_routing_helpers() {
        assert!(PrimitiveKind::StackBufferOverflow.needs_chain());
        assert!(!PrimitiveKind::LogicFlaw.needs_chain());
        assert!(PrimitiveKind::LogicFlaw.prefers_dop());
        assert!(!PrimitiveKind::StackBufferOverflow.prefers_dop());
    }

    #[test]
    fn primitive_round_trips_through_serde() {
        let p = VulnerabilityPrimitive::new(
            "CVE-FAKE",
            Arch::X86_64,
            PrimitiveKind::StackBufferOverflow,
            ChainGoal::SpawnShell,
        )
        .with_witness("v1", 32, 0xDEAD_BEEF)
        .with_anchor(0.9, 0.8)
        .with_sink(0x0040_1400);

        let s = omnisec_json::to_json_string(&p);
        let q: VulnerabilityPrimitive = omnisec_json::from_json_str(&s).unwrap();
        assert_eq!(p, q);
    }
}
