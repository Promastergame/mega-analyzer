//! [`ForgeConfig`] — the deterministic input that, together with a
//! [`crate::VulnerabilityPrimitive`], fully determines a synthesized payload.

use omnisec_core::Arch;
use omnisec_json::{FromJson, ToJson};

use crate::mitigation::MitigationKind;

/// Pre-canned mitigation profiles. Each profile expands to a fixed set of
/// [`MitigationKind`]s when consumed by the Forge.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum MitigationProfile {
    /// No mitigations — useful for legacy `nx=off, aslr=off` targets.
    None,
    /// "Modern desktop": ASLR + DEP/NX.
    #[default]
    Desktop,
    /// "Modern Linux server": ASLR + DEP + stack canary + CFI.
    Server,
    /// "Modern Android": ASLR + DEP + CFI + PAC + MTE (where supported).
    AndroidHardened,
    /// "Hardened iOS": everything Android has plus pointer authentication
    /// signing on every indirect call.
    IosHardened,
    /// "Embedded RISC-V (PMP)": physical memory protection bypass focus.
    EmbeddedRiscv,
}

impl MitigationProfile {
    /// Expand the profile into the explicit set of mitigations the Forge
    /// must handle.
    #[must_use]
    pub fn mitigations(self) -> &'static [MitigationKind] {
        use MitigationKind::{Aslr, Cfi, DepNx, Mte, Pac, Pmp, StackCanary};
        match self {
            Self::None => &[],
            Self::Desktop => &[Aslr, DepNx],
            Self::Server => &[Aslr, DepNx, StackCanary, Cfi],
            Self::AndroidHardened => &[Aslr, DepNx, Cfi, Pac, Mte],
            Self::IosHardened => &[Aslr, DepNx, Cfi, Pac, Mte, StackCanary],
            Self::EmbeddedRiscv => &[Pmp, DepNx],
        }
    }
}

/// Knobs that drive every Forge stage.
///
/// `ForgeConfig` is `Clone + Serialize` so it can be checkpointed alongside
/// the [`crate::SynthesizedPayload`] for reproducibility audits.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct ForgeConfig {
    /// Target architecture.
    pub arch: Arch,
    /// Pre-canned mitigation profile.
    pub mitigation: MitigationProfile,
    /// Seed for every deterministic PRNG inside the Forge. Two configs with
    /// the same seed and identical other fields produce byte-identical output.
    pub seed: u64,
    /// Maximum gadget chain length the assembler will try.
    pub max_chain_length: usize,
    /// Maximum number of BGAT (bounded generate-and-test) iterations the
    /// chain assembler will run before bailing with [`crate::ForgeError::BudgetExhausted`].
    pub bgat_budget: usize,
    /// Bytes that must NOT appear anywhere in the encoded payload (e.g.
    /// `\x00`, `\x0a`, `\x0d` for typical string-handling sinks).
    pub bad_bytes: Vec<u8>,
    /// Allow the synthesizer to emit Data-Oriented-Programming chains in
    /// addition to control-flow hijack chains. DOP is the only viable
    /// option when CFI fully covers the indirect-call graph.
    pub enable_dop: bool,
    /// Run the [`crate::oracle`] verification stage after synthesis. When
    /// `false`, the oracle stage is skipped and a "verification skipped"
    /// note is recorded on the report.
    pub run_oracle: bool,
}

impl ForgeConfig {
    /// Build a config targeting `arch` with sensible defaults: desktop
    /// mitigation profile, seed 0, 16-gadget chain budget, no bad bytes,
    /// DOP enabled, oracle stage off.
    #[must_use]
    pub fn for_arch(arch: Arch) -> Self {
        Self {
            arch,
            mitigation: MitigationProfile::Desktop,
            seed: 0,
            max_chain_length: 16,
            bgat_budget: 4_096,
            bad_bytes: Vec::new(),
            enable_dop: true,
            run_oracle: false,
        }
    }

    /// Force the seed (handy for tests).
    #[must_use]
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Force the mitigation profile.
    #[must_use]
    pub fn with_mitigation(mut self, profile: MitigationProfile) -> Self {
        self.mitigation = profile;
        self
    }

    /// Add bad bytes the encoded payload must avoid.
    #[must_use]
    pub fn with_bad_bytes(mut self, bytes: impl IntoIterator<Item = u8>) -> Self {
        self.bad_bytes.extend(bytes);
        self.bad_bytes.sort_unstable();
        self.bad_bytes.dedup();
        self
    }
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self::for_arch(Arch::X86_64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_expansion_contains_aslr() {
        for profile in [
            MitigationProfile::Desktop,
            MitigationProfile::Server,
            MitigationProfile::AndroidHardened,
            MitigationProfile::IosHardened,
        ] {
            assert!(profile.mitigations().contains(&MitigationKind::Aslr));
        }
    }

    #[test]
    fn bad_bytes_are_deduplicated_and_sorted() {
        let cfg = ForgeConfig::for_arch(Arch::X86_64).with_bad_bytes([0x0a, 0x00, 0x0a, 0x0d]);
        assert_eq!(cfg.bad_bytes, vec![0x00, 0x0a, 0x0d]);
    }
}
