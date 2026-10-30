//! ML feature extraction — turns a [`ScanReport`]-equivalent state into a
//! compact feature vector suitable for downstream classifiers.
//!
//! The features here are designed to be **scale-stable** (entropy is in
//! bits, ratios are in `[0, 1]`, counts are log-scaled) so that a model
//! trained on Android `lib*.so` corpora can still produce sensible
//! decisions on x86-64 PE samples.

use omnisec_json::{FromJson, ToJson};
use omnisec_loader::LoadedBinary;

use crate::{Confidence, Finding, Severity, entropy};

/// Feature vector produced for one scanned binary.
///
/// Stable across versions — fields are added at the end, never removed
/// or reordered. Field names match the Go ML side (snake_case) so they
/// can be passed through the FFI bridge as JSON without translation.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct MlFeatures {
    /// Number of imports (linear).
    pub import_count: u32,
    /// Number of exports (linear).
    pub export_count: u32,
    /// log2(1 + raw_size).
    pub log_size: f64,
    /// Mean Shannon entropy across executable sections (0..8).
    pub mean_section_entropy: f64,
    /// Maximum Shannon entropy observed across executable sections (0..8).
    pub max_section_entropy: f64,
    /// Number of high-entropy sections (>= 6.8 bits / byte).
    pub high_entropy_sections: u32,
    /// Ratio of dangerous-API findings to total findings (0..1).
    pub dangerous_api_ratio: f64,
    /// Ratio of anti-analysis findings to total findings (0..1).
    pub anti_analysis_ratio: f64,
    /// Ratio of dynamic-code findings to total findings (0..1).
    pub dynamic_code_ratio: f64,
    /// Ratio of network-indicator findings to total findings (0..1).
    pub network_indicator_ratio: f64,
    /// Ratio of high+critical findings to total findings (0..1).
    pub critical_ratio: f64,
    /// Stripped flag — 1.0 when the binary has no symbol table.
    pub stripped: f64,
    /// Hardening score — fraction of mitigations enabled (0..1).
    pub hardening_score: f64,
    /// Aggregate confidence — mean confidence across findings (0..1).
    pub mean_confidence: f64,
}

impl Default for MlFeatures {
    fn default() -> Self {
        Self {
            import_count: 0,
            export_count: 0,
            log_size: 0.0,
            mean_section_entropy: 0.0,
            max_section_entropy: 0.0,
            high_entropy_sections: 0,
            dangerous_api_ratio: 0.0,
            anti_analysis_ratio: 0.0,
            dynamic_code_ratio: 0.0,
            network_indicator_ratio: 0.0,
            critical_ratio: 0.0,
            stripped: 0.0,
            hardening_score: 0.0,
            mean_confidence: 0.0,
        }
    }
}

/// Build a feature vector from the loaded binary, raw bytes, and the
/// current set of findings. Hardening info is consumed by reference so
/// the caller can keep using its own `HardeningReport`.
#[must_use]
pub fn extract(
    bin: &LoadedBinary,
    bytes: &[u8],
    findings: &[Finding],
    hardening_score_pct: u32,
    stripped: bool,
) -> MlFeatures {
    let total = findings.len().max(1) as f64;

    let mut dangerous = 0u32;
    let mut anti = 0u32;
    let mut dyn_code = 0u32;
    let mut network = 0u32;
    let mut crit = 0u32;
    let mut conf_sum: f64 = 0.0;
    for f in findings {
        match f.category {
            crate::Category::Vulnerability => dangerous += 1,
            crate::Category::AntiAnalysis => anti += 1,
            crate::Category::DynamicCode => dyn_code += 1,
            crate::Category::NetworkIndicator => network += 1,
            _ => {}
        }
        if matches!(f.severity, Severity::High | Severity::Critical) {
            crit += 1;
        }
        conf_sum += confidence_to_float(f.confidence);
    }

    let (mean_e, max_e, hi_count) = section_entropy_stats(bin, bytes);

    MlFeatures {
        import_count: u32::try_from(bin.imports.len()).unwrap_or(u32::MAX),
        export_count: u32::try_from(bin.exports.len()).unwrap_or(u32::MAX),
        log_size: ((bin.raw_size as f64) + 1.0).log2(),
        mean_section_entropy: mean_e,
        max_section_entropy: max_e,
        high_entropy_sections: hi_count,
        dangerous_api_ratio: f64::from(dangerous) / total,
        anti_analysis_ratio: f64::from(anti) / total,
        dynamic_code_ratio: f64::from(dyn_code) / total,
        network_indicator_ratio: f64::from(network) / total,
        critical_ratio: f64::from(crit) / total,
        stripped: f64::from(u32::from(stripped)),
        hardening_score: f64::from(hardening_score_pct) / 100.0,
        mean_confidence: conf_sum / findings.len().max(1) as f64,
    }
}

fn confidence_to_float(c: Confidence) -> f64 {
    match c {
        Confidence::Low => 0.4,
        Confidence::Medium => 0.6,
        Confidence::High => 1.0,
    }
}

/// Compute (mean, max, count >= HIGH_THRESHOLD) entropy across
/// PROGBITS-style sections. Falls back to scanning the raw bytes when
/// section info is unavailable (PE / malformed ELF).
fn section_entropy_stats(_bin: &LoadedBinary, bytes: &[u8]) -> (f64, f64, u32) {
    let elf = omnisec_loader_elf::elfparse::parse_elf(bytes).ok();
    if let Some(ref elf) = elf {
        let mut samples: Vec<f64> = Vec::new();
        for sh in &elf.section_headers {
            let size = sh.sh_size as usize;
            if size < 1024 || sh.sh_type != 1 {
                continue;
            }
            let off = sh.sh_offset as usize;
            let end = off.saturating_add(size);
            if end > bytes.len() {
                continue;
            }
            samples.push(entropy::shannon(&bytes[off..end]));
        }
        return aggregate(&samples);
    }
    // PE / unknown: fall back to whole-file entropy as a single sample.
    if bytes.is_empty() {
        return (0.0, 0.0, 0);
    }
    let h = entropy::shannon(bytes);
    aggregate(&[h])
}

fn aggregate(samples: &[f64]) -> (f64, f64, u32) {
    if samples.is_empty() {
        return (0.0, 0.0, 0);
    }
    let mut max = 0.0_f64;
    let mut sum = 0.0_f64;
    let mut hi = 0u32;
    for &v in samples {
        if v > max {
            max = v;
        }
        sum += v;
        if v >= 6.8 {
            hi += 1;
        }
    }
    (sum / samples.len() as f64, max, hi)
}

#[cfg(test)]
mod tests {
    // Tests intentionally compare against exact, representable constants
    // (0.0, 1.0, hand-computed values); the lint would only add noise here.
    #![allow(clippy::float_cmp)]
    use super::*;
    use crate::{Category, Finding, Severity};
    use omnisec_core::{Arch, Endian, Format};
    use omnisec_loader::{Import, LoadedBinary};

    fn fake_bin(imports: &[(&str, &str)]) -> LoadedBinary {
        let mut bin = LoadedBinary::new(Format::Elf, Arch::Arm64, Endian::Little, 16384);
        for (lib, name) in imports {
            bin.imports.push(Import {
                library: (*lib).into(),
                name: (*name).into(),
                address: None,
                ordinal: None,
                is_data: false,
            });
        }
        bin
    }

    #[test]
    fn ratios_in_unit_interval() {
        let bin = fake_bin(&[("libc.so", "strcpy"), ("libc.so", "system")]);
        let findings = vec![
            Finding::new(
                "x",
                Category::Vulnerability,
                Severity::High,
                Confidence::High,
                "t",
                "d",
                "e",
            ),
            Finding::new(
                "y",
                Category::AntiAnalysis,
                Severity::Medium,
                Confidence::Medium,
                "t",
                "d",
                "e",
            ),
        ];
        let f = extract(&bin, b"", &findings, 60, false);
        assert!((0.0..=1.0).contains(&f.dangerous_api_ratio));
        assert!((0.0..=1.0).contains(&f.anti_analysis_ratio));
        assert!((0.0..=1.0).contains(&f.critical_ratio));
        assert!((0.0..=1.0).contains(&f.mean_confidence));
        assert_eq!(f.import_count, 2);
    }

    #[test]
    fn empty_findings_safe() {
        let bin = fake_bin(&[]);
        let f = extract(&bin, &[0u8; 4096], &[], 0, true);
        assert_eq!(f.dangerous_api_ratio, 0.0);
        assert_eq!(f.stripped, 1.0);
    }
}
