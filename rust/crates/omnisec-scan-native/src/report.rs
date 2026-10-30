//! [`ScanReport`] — top-level result returned by [`crate::scan`].

use omnisec_core::{Arch, Format};
use omnisec_json::{FromJson, ToJson};

use crate::{Finding, MlFeatures, TargetProfile, Verdict};

/// Version of the [`ScanReport`] output schema. Independent from the
/// scanner package version: bump it only when the JSON *shape* changes, so
/// consumers can branch on structure without reverse-engineering the
/// semver of the crate that produced it.
pub const SCHEMA_VERSION: &str = "1.1.0";

/// Top-level result of [`crate::scan`].
///
/// Contains both raw findings and pre-computed aggregates so the CLI /
/// JSON consumer doesn't have to recompute them.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct ScanReport {
    /// Format we scanned. Currently always [`Format::Elf`].
    pub target_format: Format,
    /// ISA of the target.
    pub target_arch: Arch,
    /// Raw size of the input in bytes.
    pub target_size: usize,
    /// Android-native / ELF target profile.
    pub target_profile: TargetProfile,
    /// Compile-time mitigation posture.
    pub hardening: HardeningReport,
    /// All findings, in the order they were emitted.
    pub findings: Vec<Finding>,
    /// Aggregate risk score, 0-100.
    pub score: u32,
    /// Categorical verdict derived from `score`.
    pub verdict: Verdict,
    /// Version of the scanner (Cargo package version).
    pub scanner_version: String,
    /// Version of the output schema (independent of the scanner version).
    pub schema_version: String,
    /// Identifier of the scoring model used to derive `score` / `verdict`.
    pub scoring_model: String,
    /// Optional ML feature vector — produced when the caller opts in
    /// via [`crate::scan_with_ml_features`]. Designed for downstream
    /// classifiers; absent for backward-compatible pure scans.
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub ml_features: Option<MlFeatures>,
}

impl ScanReport {
    /// Number of findings of a given severity.
    #[must_use]
    pub fn count_at(&self, sev: crate::Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }

    /// Number of findings in a given category.
    #[must_use]
    pub fn count_in(&self, cat: crate::Category) -> usize {
        self.findings.iter().filter(|f| f.category == cat).count()
    }
}

/// Detected RELRO level. RELRO controls whether the GOT is mapped
/// read-only after the loader has finished resolving relocations,
/// which kills classic GOT-overwrite primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum RelroLevel {
    /// No `PT_GNU_RELRO` segment.
    None,
    /// `PT_GNU_RELRO` present but no `DT_BIND_NOW` / `DF_BIND_NOW` —
    /// part of the GOT remains writable until first use.
    Partial,
    /// `PT_GNU_RELRO` + `DT_BIND_NOW` (or `DF_1_NOW`) — the entire GOT
    /// is read-only after load.
    Full,
}

impl RelroLevel {
    /// Display name used in CLI / JSON.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Partial => "partial",
            Self::Full => "full",
        }
    }
}

/// Compile-time mitigation posture detected on the target.
///
/// All booleans are `Some` once the corresponding probe has been
/// executed; `None` means we could not determine the value (e.g. the
/// binary is malformed and the dynamic table couldn't be parsed).
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct HardeningReport {
    /// `PT_GNU_STACK` is present and lacks the executable flag.
    pub nx: Option<bool>,
    /// `ET_DYN` (vs `ET_EXEC`). True ⇒ position-independent code.
    pub pie: Option<bool>,
    /// RELRO level determined from `PT_GNU_RELRO` + `DT_BIND_NOW`.
    pub relro: RelroLevel,
    /// `__stack_chk_fail` (or `__stack_chk_guard`) symbol present.
    pub stack_canary: Option<bool>,
    /// At least one `*_chk` (`__memcpy_chk`, …) import — i.e. compiled
    /// with `-D_FORTIFY_SOURCE`.
    pub fortify_source: Option<bool>,
    /// Static `.symtab` is empty / absent — i.e. `strip`-ped.
    pub stripped: Option<bool>,
    /// `DT_RPATH` value, if any. Plain `RPATH` is checked *before*
    /// `LD_LIBRARY_PATH` and is a known privilege-escalation hazard.
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub rpath: Option<String>,
    /// `DT_RUNPATH` value, if any. Safer than `RPATH` (checked after
    /// `LD_LIBRARY_PATH`) but still worth surfacing.
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub runpath: Option<String>,
    /// Number of writable + executable sections (W^X violation).
    pub wx_sections: usize,
}

impl Default for HardeningReport {
    fn default() -> Self {
        Self {
            nx: None,
            pie: None,
            relro: RelroLevel::None,
            stack_canary: None,
            fortify_source: None,
            stripped: None,
            rpath: None,
            runpath: None,
            wx_sections: 0,
        }
    }
}

impl HardeningReport {
    /// Returns the count of mitigations that are confirmed enabled.
    /// Used by the CLI to print a `4/6 mitigations enabled` summary.
    #[must_use]
    pub fn enabled_count(&self) -> u32 {
        let mut c = 0;
        if self.nx == Some(true) {
            c += 1;
        }
        if self.pie == Some(true) {
            c += 1;
        }
        if matches!(self.relro, RelroLevel::Full) {
            c += 1;
        }
        if self.stack_canary == Some(true) {
            c += 1;
        }
        if self.fortify_source == Some(true) {
            c += 1;
        }
        if self.stripped == Some(true) {
            c += 1;
        }
        c
    }

    /// Total number of mitigations we probe. Keeps the `enabled / total`
    /// ratio in sync with [`Self::enabled_count`].
    #[must_use]
    pub const fn total_probes() -> u32 {
        6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_count_zero_by_default() {
        let h = HardeningReport::default();
        assert_eq!(h.enabled_count(), 0);
    }

    #[test]
    fn enabled_count_full_house() {
        let h = HardeningReport {
            nx: Some(true),
            pie: Some(true),
            relro: RelroLevel::Full,
            stack_canary: Some(true),
            fortify_source: Some(true),
            stripped: Some(true),
            rpath: None,
            runpath: None,
            wx_sections: 0,
        };
        assert_eq!(h.enabled_count(), 6);
        assert_eq!(HardeningReport::total_probes(), 6);
    }

    #[test]
    fn partial_relro_does_not_count() {
        let h = HardeningReport {
            relro: RelroLevel::Partial,
            ..HardeningReport::default()
        };
        assert_eq!(h.enabled_count(), 0);
    }
}
