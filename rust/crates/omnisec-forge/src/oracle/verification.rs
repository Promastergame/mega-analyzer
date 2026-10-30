//! Stage-4 verification interface.

use omnisec_json::{FromJson, ToJson};

use crate::payload::SynthesizedPayload;

/// What the oracle decided about a candidate payload.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct OracleVerdict {
    /// `true` if the oracle confirmed the payload's expected effect.
    pub success: bool,
    /// Free-form notes (deterministic; serialised into the report).
    pub notes: Vec<String>,
    /// Final complexity score the oracle assigned. Lower is better.
    pub adjusted_complexity: u64,
}

/// Verify-or-reject trait.
///
/// Implementors typically run the payload in a sandbox (QEMU user-mode,
/// `prctl`-based jail, etc.) and check exit codes / stdout. The Forge
/// itself only ever calls [`Oracle::verify`] *once* per synthesis call,
/// so cost here is a flat constant.
pub trait Oracle: Send + Sync {
    /// Verify `payload`. The implementation is expected to be
    /// deterministic — the engine relies on that for reproducibility.
    fn verify(&self, payload: &SynthesizedPayload) -> OracleVerdict;
}

/// In-memory deterministic oracle used by unit tests. Returns success
/// iff the payload bytes are non-empty and the complexity score is below
/// `ceiling`.
#[derive(Debug, Clone, Copy)]
pub struct MockOracle {
    /// Maximum acceptable complexity score.
    pub ceiling: u64,
}

impl MockOracle {
    /// New mock oracle with `ceiling` complexity bound.
    #[must_use]
    pub const fn new(ceiling: u64) -> Self {
        Self { ceiling }
    }
}

impl Default for MockOracle {
    fn default() -> Self {
        Self::new(u64::MAX)
    }
}

impl Oracle for MockOracle {
    fn verify(&self, payload: &SynthesizedPayload) -> OracleVerdict {
        let mut notes = Vec::new();
        let mut success = true;
        if payload.payload.is_empty() {
            success = false;
            notes.push("empty payload — nothing to verify".into());
        }
        if payload.complexity.raw() > self.ceiling {
            success = false;
            notes.push(format!(
                "complexity {} exceeds ceiling {}",
                payload.complexity.raw(),
                self.ceiling
            ));
        }
        if success {
            notes.push("mock oracle verdict = success".into());
        }
        OracleVerdict {
            success,
            notes,
            adjusted_complexity: payload.complexity.raw(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ForgeConfig;
    use crate::complexity::ComplexityScore;
    use crate::payload::Witness;
    use omnisec_core::Arch;

    fn fake_payload(bytes: Vec<u8>, complexity: u64) -> SynthesizedPayload {
        SynthesizedPayload {
            config: ForgeConfig::for_arch(Arch::X86_64),
            primitive: "fake".into(),
            arch: Arch::X86_64,
            bypassed: vec![],
            witness: Witness::new(),
            chain: vec![],
            payload: bytes,
            report: vec![],
            complexity: ComplexityScore(complexity),
            artifacts: vec![],
        }
    }

    #[test]
    fn mock_succeeds_on_simple_payload() {
        let p = fake_payload(vec![0x90, 0x90], 3);
        let v = MockOracle::default().verify(&p);
        assert!(v.success);
    }

    #[test]
    fn mock_fails_on_empty_payload() {
        let p = fake_payload(vec![], 0);
        let v = MockOracle::default().verify(&p);
        assert!(!v.success);
    }

    #[test]
    fn ceiling_rejects_complex_chains() {
        let p = fake_payload(vec![0x90], 100);
        let v = MockOracle::new(50).verify(&p);
        assert!(!v.success);
    }
}
