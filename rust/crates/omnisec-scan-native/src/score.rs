//! Risk score + verdict aggregation.
//!
//! The score is a weighted sum of `severity × confidence` across all
//! findings, with a small bonus penalty when the hardening posture is
//! particularly poor (≤ 2 mitigations enabled out of 6). Capped at 100
//! so it slots cleanly into existing risk dashboards.
//!
//! Two anti-noise mechanisms keep high-volume rules from dominating:
//! low-severity network indicators are capped in aggregate
//! ([`NETWORK_NOISE_CAP`]), and repeated findings from the *same rule in
//! the same category* contribute with diminishing returns
//! ([`REPEAT_DECAY_PCT`]) — twenty `strcpy` hits are worse than one, but
//! not twenty times worse, while twenty *distinct* rules firing still
//! score at full weight.

use std::collections::HashMap;

use omnisec_json::{FromJson, ToJson};

use crate::{Category, Finding, Severity, report::HardeningReport};

/// Categorical verdict derived from the numeric [`crate::ScanReport::score`].
///
/// The verdict is **risk-based**, not malice-based: a JIT-heavy graphics
/// driver and a malware payload both wire up `mprotect`+`dlopen`+packed
/// data and will both land in the upper tiers. The scanner cannot tell
/// them apart from static signals alone — the verdict tells you *how
/// much manual review is required* before you should trust the binary.
///
/// Thresholds are calibrated against real-world native libraries
/// (graphics drivers, JNI bridges, anti-cheat libs); a typical `.so`
/// with one or two legacy `strcpy` calls and a `dlopen` should land in
/// `Low`, not `Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
#[json(rename_all = "lowercase")]
pub enum Verdict {
    /// 0-14 — no significant issues; safe baseline.
    Clean,
    /// 15-39 — minor weaknesses (typical for any production lib).
    Low,
    /// 40-69 — multiple medium-severity issues; targeted review wise.
    Medium,
    /// 70-89 — heavy use of dangerous primitives or strong obfuscation;
    /// a focused reverse-engineering pass is recommended.
    High,
    /// 90-100 — concentrated suspicious surface (anti-debug + dynamic
    /// code + embedded payloads + …) or critical-severity findings.
    /// Treat as untrusted until the per-finding evidence is reviewed
    /// by hand — this score does NOT prove malice on its own.
    Critical,
}

impl Verdict {
    /// Display name used in CLI output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Identifier for the current scoring model. Bump this whenever the
/// weighting, caps, or thresholds change so downstream consumers can tell
/// that a score from an older scanner is not directly comparable.
pub const MODEL_VERSION: &str = "weighted-v3-rule-dampening";

/// Maximum aggregate contribution allowed from *low-severity network*
/// indicators (embedded URLs / IPv4 literals). Without this, a perfectly
/// ordinary SDK stuffed with analytics and CDN endpoints inflates straight
/// into a scary verdict on sheer volume — the classic false-positive
/// generator this scanner used to suffer from.
const NETWORK_NOISE_CAP: u32 = 8;

/// Diminishing-returns schedule for repeated findings of the *same rule in
/// the same category*, in percent of the base contribution. The k-th
/// duplicate (sorted by contribution, largest first) is scaled by
/// `REPEAT_DECAY_PCT[min(k, 3)]`. One rule that fires on fifty call sites
/// is a single systemic weakness plus volume — dampening it stops "one
/// legacy API used everywhere" from reading like fifty independent issues,
/// while findings from distinct rules still score at full weight.
const REPEAT_DECAY_PCT: [u32; 4] = [100, 60, 40, 25];

/// Compute the (score, verdict) tuple from the raw findings + hardening
/// posture.
pub(crate) fn compute(findings: &[Finding], hardening: &HardeningReport) -> (u32, Verdict) {
    let mut score: u32 = 0;
    let mut network_noise: u32 = 0;
    // Contributions grouped by (rule id, category) for repeat dampening.
    let mut per_rule: HashMap<(&str, Category), Vec<u32>> = HashMap::new();

    for f in findings {
        let base = f.severity.weight();
        let mult = f.confidence.multiplier_pct();
        let contrib = base.saturating_mul(mult) / 100;

        // Low/Info network indicators are high-volume, low-signal on their
        // own. Accumulate them separately and cap the *combined* total so
        // dozens of hard-coded URLs cannot linearly drive the verdict.
        if matches!(f.category, Category::NetworkIndicator)
            && severity_rank(f.severity) <= severity_rank(Severity::Low)
        {
            network_noise = network_noise.saturating_add(contrib);
            continue;
        }

        per_rule
            .entry((f.id.as_str(), f.category))
            .or_default()
            .push(contrib);
    }

    // Per-rule diminishing returns: within each (rule, category) group the
    // largest contribution counts in full and duplicates decay per
    // [`REPEAT_DECAY_PCT`]. Summation order across groups is irrelevant, so
    // HashMap iteration order does not affect the result.
    for contribs in per_rule.values_mut() {
        contribs.sort_unstable_by(|a, b| b.cmp(a));
        for (k, contrib) in contribs.iter().enumerate() {
            let pct = REPEAT_DECAY_PCT[k.min(REPEAT_DECAY_PCT.len() - 1)];
            score = score.saturating_add(contrib.saturating_mul(pct) / 100);
        }
    }

    score = score.saturating_add(network_noise.min(NETWORK_NOISE_CAP));

    // Combo bonus: malware-style behaviour from *multiple distinct*
    // categories reinforces each other. We count *distinct categories*
    // among findings of *MEDIUM-or-higher severity only* — otherwise a
    // busy graphics driver with a couple of low-severity entropy blobs
    // and a debug `raise()` would auto-promote into Critical territory
    // alongside actual malware.
    let mut distinct_susp_cats: Vec<Category> = findings
        .iter()
        .filter(|f| severity_rank(f.severity) >= severity_rank(Severity::Medium))
        .filter_map(|f| match f.category {
            c @ (Category::SuspiciousBehavior
            | Category::AntiAnalysis
            | Category::DynamicCode
            | Category::EmbeddedPayload) => Some(c),
            _ => None,
        })
        .collect();
    distinct_susp_cats.sort_by_key(|c| c.slug());
    distinct_susp_cats.dedup();
    let distinct = distinct_susp_cats.len() as u32;
    if distinct >= 3 {
        // ≥ 3 distinct suspicious categories at MED+ severity ⇒
        // behaviour is too varied to be incidental.
        score = score.saturating_add(10);
    }
    if distinct >= 4 {
        // All four buckets present at MED+ severity ⇒ deliberate stack.
        score = score.saturating_add(10);
    }

    // Hardening penalty: if ≤ 2 mitigations enabled, add some risk.
    let enabled = hardening.enabled_count();
    if enabled <= 2 {
        score = score.saturating_add(5);
    }

    let score = score.min(100);
    (score, classify(score))
}

fn classify(score: u32) -> Verdict {
    match score {
        0..=14 => Verdict::Clean,
        15..=39 => Verdict::Low,
        40..=69 => Verdict::Medium,
        70..=89 => Verdict::High,
        _ => Verdict::Critical,
    }
}

/// Numeric rank for severity comparisons (Info=0 .. Critical=4).
const fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Category, Confidence, Finding, Severity, report::HardeningReport};

    fn finding(sev: Severity, conf: Confidence, cat: Category) -> Finding {
        Finding::new("x", cat, sev, conf, "t", "d", "e")
    }

    #[test]
    fn empty_findings_with_full_hardening_is_clean() {
        let h = HardeningReport {
            nx: Some(true),
            pie: Some(true),
            relro: crate::RelroLevel::Full,
            stack_canary: Some(true),
            fortify_source: Some(true),
            stripped: Some(true),
            ..HardeningReport::default()
        };
        let (s, v) = compute(&[], &h);
        assert_eq!(s, 0);
        assert_eq!(v, Verdict::Clean);
    }

    #[test]
    fn one_critical_finding_drives_low_or_medium() {
        let f = vec![finding(
            Severity::Critical,
            Confidence::High,
            Category::Vulnerability,
        )];
        let (s, v) = compute(&f, &HardeningReport::default());
        // 28 weight * 100% + hardening penalty 5 = 33 → Low.
        assert!(s >= 28);
        assert!(matches!(v, Verdict::Low | Verdict::Medium));
    }

    #[test]
    fn malware_combo_pushes_to_critical() {
        let f = vec![
            finding(Severity::High, Confidence::High, Category::AntiAnalysis),
            finding(Severity::High, Confidence::High, Category::DynamicCode),
            finding(
                Severity::High,
                Confidence::High,
                Category::SuspiciousBehavior,
            ),
            finding(Severity::High, Confidence::High, Category::EmbeddedPayload),
            finding(Severity::Critical, Confidence::High, Category::DynamicCode),
            finding(Severity::High, Confidence::High, Category::AntiAnalysis),
        ];
        let (s, v) = compute(&f, &HardeningReport::default());
        assert!(s >= 70, "expected ≥ 70, got {s}");
        assert!(matches!(v, Verdict::High | Verdict::Critical));
    }

    #[test]
    fn repeated_same_rule_findings_saturate() {
        // Ten hits from ONE rule: 14 + 14*0.6 + 14*0.4 + 7 × 14*0.25
        // = 14 + 8 + 5 + 21 = 48, plus default-hardening penalty 5 = 53.
        let same: Vec<Finding> = (0..10)
            .map(|_| finding(Severity::High, Confidence::High, Category::Vulnerability))
            .collect();
        let (s_same, _) = compute(&same, &HardeningReport::default());
        assert_eq!(s_same, 53);

        // The same ten findings from DISTINCT rules keep full weight:
        // 10 × 14 + 5 = 145 → capped at 100.
        let distinct: Vec<Finding> = (0..10)
            .map(|i| {
                Finding::new(
                    format!("rule-{i}"),
                    Category::Vulnerability,
                    Severity::High,
                    Confidence::High,
                    "t",
                    "d",
                    "e",
                )
            })
            .collect();
        let (s_distinct, _) = compute(&distinct, &HardeningReport::default());
        assert_eq!(s_distinct, 100);
        assert!(s_distinct > s_same, "{s_distinct} vs {s_same}");
    }

    #[test]
    fn single_findings_are_not_dampened() {
        // One finding per rule — v3 must reproduce v2 arithmetic exactly.
        let f = vec![
            Finding::new(
                "rule-a",
                Category::Vulnerability,
                Severity::Medium,
                Confidence::High,
                "t",
                "d",
                "e",
            ),
            Finding::new(
                "rule-b",
                Category::Vulnerability,
                Severity::High,
                Confidence::Medium,
                "t",
                "d",
                "e",
            ),
        ];
        // 6*100% + 14*60% = 6 + 8 = 14, + hardening 5 = 19.
        let (s, v) = compute(&f, &HardeningReport::default());
        assert_eq!(s, 19);
        assert_eq!(v, Verdict::Low);
    }

    #[test]
    fn score_caps_at_100() {
        let mut f = vec![];
        for _ in 0..20 {
            f.push(finding(
                Severity::Critical,
                Confidence::High,
                Category::SuspiciousBehavior,
            ));
        }
        let (s, _) = compute(&f, &HardeningReport::default());
        assert_eq!(s, 100);
    }
}
