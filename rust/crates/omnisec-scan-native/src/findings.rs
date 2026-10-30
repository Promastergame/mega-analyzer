//! [`Finding`] — atomic unit of the scan report.

use omnisec_json::{FromJson, ToJson};

/// Severity of a [`Finding`]. Drives both pretty-print colour and
/// the aggregate risk score weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — neutral observation, no action required.
    Info,
    /// Low — best-practice nit, unlikely to be exploitable on its own.
    Low,
    /// Medium — material weakness; combine with another bug to exploit.
    Medium,
    /// High — directly dangerous primitive (`system(user_input)`, …).
    High,
    /// Critical — almost certainly malicious or remotely exploitable.
    Critical,
}

impl Severity {
    /// Score weight contributed by a finding of this severity.
    #[must_use]
    pub const fn weight(self) -> u32 {
        match self {
            Self::Info => 0,
            Self::Low => 2,
            Self::Medium => 6,
            Self::High => 14,
            Self::Critical => 28,
        }
    }

    /// Short uppercase tag used in CLI output.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MED",
            Self::High => "HIGH",
            Self::Critical => "CRIT",
        }
    }
}

/// Confidence that a finding is a real issue (vs. a false positive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "lowercase")]
pub enum Confidence {
    /// Heuristic — pattern match, easily fooled.
    Low,
    /// Pattern + corroborating signal (e.g. dangerous import + suspicious string).
    Medium,
    /// Direct evidence (symbol present, mitigation flag missing, …).
    High,
}

impl Confidence {
    /// Multiplier (in percent) applied to the severity weight when
    /// computing the score. The values are deliberately conservative for
    /// the `Medium` tier because most of our medium-confidence findings
    /// are pure pattern matches with no dataflow context — a binary that
    /// imports `strcpy` is *not* automatically vulnerable to a buffer
    /// overflow.
    #[must_use]
    pub const fn multiplier_pct(self) -> u32 {
        match self {
            Self::Low => 40,
            Self::Medium => 60,
            Self::High => 100,
        }
    }
}

/// High-level taxonomy of what kind of issue this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum Category {
    /// Missing or weak compile-time mitigation (NX/PIE/RELRO/canary/…).
    Hardening,
    /// Use of a historically dangerous CRT / libc primitive.
    Vulnerability,
    /// Anti-analysis / anti-debug / anti-emulator routine.
    AntiAnalysis,
    /// Suspicious dynamic-loading / native code execution primitive.
    DynamicCode,
    /// Cryptography + network combo or other ransomware-style indicator.
    SuspiciousBehavior,
    /// Embedded payload, high-entropy blob, hidden ELF, …
    EmbeddedPayload,
    /// Hard-coded URL / IP / `.onion` / suspicious path.
    NetworkIndicator,
    /// Generic informational note.
    Info,
}

impl Category {
    /// Stable short identifier used in JSON / log lines.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Hardening => "hardening",
            Self::Vulnerability => "vulnerability",
            Self::AntiAnalysis => "anti_analysis",
            Self::DynamicCode => "dynamic_code",
            Self::SuspiciousBehavior => "suspicious_behavior",
            Self::EmbeddedPayload => "embedded_payload",
            Self::NetworkIndicator => "network_indicator",
            Self::Info => "info",
        }
    }
}

/// One concrete observation about the binary.
///
/// Deliberately flat for trivial JSON serialisation. `evidence` carries a
/// human-readable snippet (symbol name, string, hex offset, …) while
/// `cwe` and `id` give stable identifiers for downstream tooling.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Finding {
    /// Stable kebab-case identifier ("dangerous-api-strcpy", "no-pie", …).
    pub id: String,
    /// Category bucket.
    pub category: Category,
    /// Severity tier.
    pub severity: Severity,
    /// Confidence the finding is real.
    pub confidence: Confidence,
    /// Short one-line title.
    pub title: String,
    /// Longer human-readable description / why-it-matters.
    pub description: String,
    /// Concrete evidence that triggered the rule (symbol, string, offset, …).
    pub evidence: String,
    /// CWE identifier when the finding maps to one ("CWE-120", …).
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// Optional remediation hint. Static strings; no per-instance prose.
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Optional file offset where the evidence was located.
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
    /// Optional payload generated by ML-Apli-Ex (Symbolic Execution Exploit Generation).
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub ml_apli_ex_payload: Option<String>,
    /// ML-Apli-Ex pipeline stages (1-4).
    #[json(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<String>,
}

impl Finding {
    /// Constructor for the common case (no CWE / no offset / no
    /// remediation). Use the builder-style `with_*` methods to fill in the
    /// optional fields.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        title: impl Into<String>,
        description: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            category,
            severity,
            confidence,
            title: title.into(),
            description: description.into(),
            evidence: evidence.into(),
            cwe: None,
            remediation: None,
            file_offset: None,
            ml_apli_ex_payload: None,
            stages: Vec::new(),
        }
    }

    /// Attach a CWE identifier.
    #[must_use]
    pub fn with_cwe(mut self, cwe: &'static str) -> Self {
        self.cwe = Some(cwe.to_string());
        self
    }

    /// Attach a static remediation hint.
    #[must_use]
    pub fn with_remediation(mut self, hint: &'static str) -> Self {
        self.remediation = Some(hint.to_string());
        self
    }

    /// Attach a file offset where evidence was found.
    #[must_use]
    pub fn with_offset(mut self, off: u64) -> Self {
        self.file_offset = Some(off);
        self
    }

    /// Attach a generated exploit payload.
    #[must_use]
    pub fn with_ml_apli_ex_payload(mut self, payload: String) -> Self {
        self.ml_apli_ex_payload = Some(payload);
        self
    }

    /// Add a stage description for ML-Apli-Ex pipeline reporting.
    #[must_use]
    pub fn with_stage(mut self, stage: impl Into<String>) -> Self {
        self.stages.push(stage.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_weights_are_monotonic() {
        let order = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        for w in order.windows(2) {
            assert!(w[0].weight() <= w[1].weight());
        }
    }

    #[test]
    fn finding_builder_chains() {
        let f = Finding::new(
            "x",
            Category::Vulnerability,
            Severity::High,
            Confidence::High,
            "t",
            "d",
            "e",
        )
        .with_cwe("CWE-120")
        .with_remediation("Use bounded variants")
        .with_offset(0x1234);
        assert_eq!(f.cwe.as_deref(), Some("CWE-120"));
        assert_eq!(f.file_offset, Some(0x1234));
        assert!(f.remediation.is_some());
    }
}
