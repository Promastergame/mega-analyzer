//! Turns each binder's raw classification into a [`DiscrepancyVector`] — a
//! compact, serialisable score that downstream consumers (compliance gate,
//! alerting, dashboards) can use without re-running the full binding logic.
//!
//! ## Interpretation
//!
//! | Field | Low (→ 0) | High (→ 1) | Source |
//! |---|---|---|---|
//! | `d_causal` | Most effects are explained | Many effects are unexplained | [`crate::effect_binder`] |
//! | `coverage_quality` | Few effects have a matched cause | Most effects have a matched cause | [`crate::effect_binder`] |
//! | `d_authority` | Observed actions matched a grant | Actions had no matching grant | [`crate::authority_binder`] |
//! | `d_capability` | Grants were all exercised | Grants went unused | [`crate::authority_binder`] |
//! | `d_information` | Flows explained by a DNS lookup | Flows with no explaining lookup | [`crate::dns_flow_binder`] |
//!
//! `d_causal`/`coverage_quality` come from [`score_causal`] or [`score_all`];
//! `d_authority`/`d_capability`/`d_information` are only populated by
//! [`score_all`], which additionally takes an [`AuthorityBindingResult`] and
//! a [`DnsFlowBindingResult`].
//!
//! `d_consequence` and `d_novelty` are always `0.0` from Rust: they depend on
//! data (finding severity, a cross-session baseline) that never crosses the
//! Go/Rust FFI boundary — see `pkg/ncer/consequence.go` and
//! `pkg/ncer/novelty.go`, which compute them on the Go side after decoding
//! this vector.

use omnisec_json::{FromJson, ToJson};

use crate::authority_binder::AuthorityBindingResult;
use crate::dns_flow_binder::DnsFlowBindingResult;
use crate::effect_binder::BindingResult;

/// A multi-dimensional discrepancy score derived from a [`BindingResult`]
/// (and, in [`score_all`], an [`AuthorityBindingResult`] and
/// [`DnsFlowBindingResult`] too).
///
/// Every field is clamped to `[0.0, 1.0]`. `d_consequence` and `d_novelty`
/// are always `0.0` here — they're computed Go-side after decoding this
/// vector, see the module doc.
///
/// Use [`score_causal`] to construct this type from just a [`BindingResult`]
/// (`d_authority`/`d_information`/`d_capability` left at `0.0`), or
/// [`score_all`] to compute all five Rust-side dimensions at once.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct DiscrepancyVector {
    /// Fraction of observed effects that have no matching cause within the
    /// binding window — the primary causal-discrepancy signal.
    ///
    /// `0.0` means every effect was explained; `1.0` means no effect was
    /// explained.
    pub d_causal: f32,

    /// Fraction of observed effects that *were* successfully bound to a cause.
    ///
    /// Complement of `d_causal`: `coverage_quality ≈ 1 − d_causal` when
    /// `effect_count > 0`.  Provided as a separate field for convenience so
    /// consumers do not have to invert `d_causal`.
    pub coverage_quality: f32,

    /// Authority-dimension discrepancy: fraction of classifiable observed
    /// actions with no matching permission grant. See [`score_authority`].
    ///
    /// `0.0` (not computed, same as a genuine zero-discrepancy result) unless
    /// produced via [`score_all`].
    pub d_authority: f32,

    /// Information-dimension discrepancy: fraction of observed network flows
    /// with no explaining DNS resolution. See [`score_dns_flow`].
    ///
    /// `0.0` (not computed, same as a genuine zero-discrepancy result) unless
    /// produced via [`score_all`].
    pub d_information: f32,

    /// Capability-dimension discrepancy: fraction of granted permissions
    /// never exercised by any observed action. See [`score_authority`].
    ///
    /// `0.0` (not computed, same as a genuine zero-discrepancy result) unless
    /// produced via [`score_all`].
    pub d_capability: f32,

    /// Consequence-dimension discrepancy — always `0.0` from Rust. Computed
    /// Go-side by `pkg/ncer.ConsequenceScore` from sandbox finding severity,
    /// which never crosses the Go/Rust FFI boundary.
    pub d_consequence: f32,

    /// Novelty-dimension discrepancy — always `0.0` from Rust. Computed
    /// Go-side by `pkg/ncer`'s baseline-fingerprint scoring
    /// (`novelty.go`), which depends on a cross-session baseline file that
    /// never crosses the Go/Rust FFI boundary.
    pub d_novelty: f32,
}

/// Scores a [`BindingResult`] and returns the corresponding
/// [`DiscrepancyVector`].
///
/// # Arguments
///
/// * `binding` — the output of [`crate::effect_binder::bind_effects`].
/// * `total_events` — the total number of raw events passed to
///   [`crate::effect_binder::bind_effects`]; reserved for future sub-dimension
///   scoring and not used in Phase 4 calculations.
///
/// # Causal discrepancy (`d_causal`)
///
/// ```text
/// effect_count = bound_pairs.len() + unbound_effects.len()
///
/// d_causal = if effect_count == 0 {
///     0.0
/// } else {
///     unbound_effects.len() as f32 / effect_count as f32
/// }
/// ```
///
/// Result is clamped to `[0.0, 1.0]`.
///
/// # Coverage quality (`coverage_quality`)
///
/// ```text
/// coverage_quality = if effect_count == 0 {
///     0.0
/// } else {
///     bound_pairs.len() as f32 / effect_count as f32
/// }
/// ```
///
/// Result is clamped to `[0.0, 1.0]`.
pub fn score_causal(binding: &BindingResult, _total_events: usize) -> DiscrepancyVector {
    let (d_causal, coverage_quality) = causal_ratio(binding);

    DiscrepancyVector {
        d_causal,
        coverage_quality,
        d_authority: 0.0,
        d_information: 0.0,
        d_capability: 0.0,
        d_consequence: 0.0,
        d_novelty: 0.0,
    }
}

/// Computes `(d_causal, coverage_quality)` from a [`BindingResult`]. Shared
/// by [`score_causal`] and [`score_all`] so both stay consistent.
fn causal_ratio(binding: &BindingResult) -> (f32, f32) {
    let effect_count = binding.bound_pairs.len() + binding.unbound_effects.len();
    if effect_count == 0 {
        return (0.0, 0.0);
    }
    let ec = effect_count as f32;
    let d = (binding.unbound_effects.len() as f32 / ec).clamp(0.0, 1.0);
    let cq = (binding.bound_pairs.len() as f32 / ec).clamp(0.0, 1.0);
    (d, cq)
}

/// Computes `(d_authority, d_capability)` from an [`AuthorityBindingResult`].
///
/// `d_authority` is the fraction of *classifiable* observed actions
/// (actions with a known required-permission mapping — see
/// `crate::authority_binder`'s module doc) that had no matching grant.
/// `0.0` when no classifiable observed actions exist, which includes the
/// common case of no authority events at all.
///
/// `d_capability` is the fraction of granted permissions never exercised by
/// any observed action. `0.0` when no grants exist.
pub fn score_authority(binding: &AuthorityBindingResult) -> (f32, f32) {
    let classified_count = binding.authorized.len() + binding.unauthorized_observed.len();
    let d_authority = if classified_count == 0 {
        0.0
    } else {
        (binding.unauthorized_observed.len() as f32 / classified_count as f32).clamp(0.0, 1.0)
    };

    // A grant can back multiple observed actions, so distinct grant ids used
    // (not the raw pair count) is what "granted_count" needs to mean here.
    let used_grants: std::collections::HashSet<&str> =
        binding.authorized.iter().map(|(g, _)| g.as_str()).collect();
    let granted_count = used_grants.len() + binding.unused_grants.len();
    let d_capability = if granted_count == 0 {
        0.0
    } else {
        (binding.unused_grants.len() as f32 / granted_count as f32).clamp(0.0, 1.0)
    };

    (d_authority, d_capability)
}

/// Computes `d_information` from a [`DnsFlowBindingResult`]: the fraction of
/// observed flows with no explaining DNS resolution within the binding
/// window. `0.0` when no flows were observed.
pub fn score_dns_flow(binding: &DnsFlowBindingResult) -> f32 {
    let flow_count = binding.bound_pairs.len() + binding.unbound_flows.len();
    if flow_count == 0 {
        return 0.0;
    }
    (binding.unbound_flows.len() as f32 / flow_count as f32).clamp(0.0, 1.0)
}

/// Combines all three Rust-side binders into one [`DiscrepancyVector`].
/// `d_consequence` and `d_novelty` are always `0.0` here — see the type doc.
pub fn score_all(
    causal: &BindingResult,
    authority: &AuthorityBindingResult,
    dns_flow: &DnsFlowBindingResult,
    _total_events: usize,
) -> DiscrepancyVector {
    let (d_causal, coverage_quality) = causal_ratio(causal);
    let (d_authority, d_capability) = score_authority(authority);
    let d_information = score_dns_flow(dns_flow);

    DiscrepancyVector {
        d_causal,
        coverage_quality,
        d_authority,
        d_information,
        d_capability,
        d_consequence: 0.0,
        d_novelty: 0.0,
    }
}

#[cfg(test)]
mod tests {
    // Tests intentionally compare against exact, representable constants
    // (0.0, 1.0, hand-computed values); the lint would only add noise here.
    #![allow(clippy::float_cmp)]
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn id(s: &str) -> String {
        s.to_string()
    }

    fn pair(req: &str, resp: &str) -> (String, String) {
        (id(req), id(resp))
    }

    fn binding(bound: Vec<(&str, &str)>, unbound: Vec<&str>, orphans: Vec<&str>) -> BindingResult {
        BindingResult {
            bound_pairs: bound.into_iter().map(|(a, b)| pair(a, b)).collect(),
            unbound_effects: unbound.into_iter().map(id).collect(),
            orphan_requests: orphans.into_iter().map(id).collect(),
        }
    }

    // ── d_causal ─────────────────────────────────────────────────────────────

    #[test]
    fn empty_binding_produces_zero_scores() {
        let result = score_causal(&BindingResult::default(), 0);
        assert_eq!(result.d_causal, 0.0);
        assert_eq!(result.coverage_quality, 0.0);
    }

    #[test]
    fn all_effects_bound_gives_d_causal_zero_and_coverage_one() {
        // 2 bound pairs, 0 unbound → effect_count = 2
        let b = binding(
            vec![("req-1", "resp-1"), ("req-2", "resp-2")],
            vec![],
            vec![],
        );
        let result = score_causal(&b, 4);
        assert_eq!(result.d_causal, 0.0);
        assert_eq!(result.coverage_quality, 1.0);
    }

    #[test]
    fn all_effects_unbound_gives_d_causal_one_and_coverage_zero() {
        // 0 bound pairs, 2 unbound → effect_count = 2
        let b = binding(vec![], vec!["resp-1", "resp-2"], vec![]);
        let result = score_causal(&b, 2);
        assert_eq!(result.d_causal, 1.0);
        assert_eq!(result.coverage_quality, 0.0);
    }

    #[test]
    fn half_unbound_gives_d_causal_half_and_coverage_half() {
        // 1 bound, 1 unbound → effect_count = 2
        let b = binding(vec![("req-1", "resp-1")], vec!["resp-2"], vec![]);
        let result = score_causal(&b, 3);
        assert!((result.d_causal - 0.5).abs() < f32::EPSILON);
        assert!((result.coverage_quality - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn orphan_requests_do_not_affect_d_causal() {
        // Orphans are causes with no effect — they don't count as effects.
        // effect_count = bound(1) + unbound(1) = 2; orphans ignored.
        let b = binding(
            vec![("req-1", "resp-1")],
            vec!["resp-2"],
            vec!["req-orphan-1", "req-orphan-2", "req-orphan-3"],
        );
        let result = score_causal(&b, 6);
        assert!((result.d_causal - 0.5).abs() < f32::EPSILON);
        assert!((result.coverage_quality - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn only_orphan_requests_no_effects_gives_zero_d_causal() {
        // No effects at all → effect_count = 0 → d_causal = 0.
        let b = binding(vec![], vec![], vec!["req-1", "req-2"]);
        let result = score_causal(&b, 2);
        assert_eq!(result.d_causal, 0.0);
        assert_eq!(result.coverage_quality, 0.0);
    }

    // ── d_causal clamping ─────────────────────────────────────────────────────

    #[test]
    fn d_causal_is_clamped_to_unit_interval() {
        // Clamping is defensive; under normal arithmetic the raw ratio is
        // already in [0, 1], but the clamp guards against any future
        // integer-overflow or NaN edge-cases.
        let b = binding(vec![], vec!["resp-1"], vec![]);
        let result = score_causal(&b, 1);
        assert!(result.d_causal >= 0.0 && result.d_causal <= 1.0);
        assert!(result.coverage_quality >= 0.0 && result.coverage_quality <= 1.0);
    }

    // ── score_causal leaves other dimensions zero ──────────────────────────────

    #[test]
    fn score_causal_alone_leaves_other_dimensions_zero() {
        // score_causal only ever sees a BindingResult, so it cannot compute
        // d_authority/d_information/d_capability (those need score_all with
        // the other two binders' results); d_consequence/d_novelty are
        // always Go-computed regardless of which scoring function is used.
        let b = binding(vec![("req-1", "resp-1")], vec![], vec![]);
        let result = score_causal(&b, 2);
        assert_eq!(result.d_authority, 0.0);
        assert_eq!(result.d_information, 0.0);
        assert_eq!(result.d_capability, 0.0);
        assert_eq!(result.d_consequence, 0.0);
        assert_eq!(result.d_novelty, 0.0);
    }

    // ── score_authority ───────────────────────────────────────────────────────

    #[test]
    fn score_authority_all_authorized_gives_zero_d_authority() {
        let b = AuthorityBindingResult {
            authorized: vec![("grant-1".to_string(), "obs-1".to_string())],
            unauthorized_observed: vec![],
            unused_grants: vec![],
        };
        let (d_authority, d_capability) = score_authority(&b);
        assert_eq!(d_authority, 0.0);
        assert_eq!(d_capability, 0.0);
    }

    #[test]
    fn score_authority_unauthorized_action_raises_d_authority() {
        let b = AuthorityBindingResult {
            authorized: vec![],
            unauthorized_observed: vec!["obs-1".to_string()],
            unused_grants: vec![],
        };
        let (d_authority, _) = score_authority(&b);
        assert_eq!(d_authority, 1.0);
    }

    #[test]
    fn score_authority_unused_grant_raises_d_capability() {
        let b = AuthorityBindingResult {
            authorized: vec![],
            unauthorized_observed: vec![],
            unused_grants: vec!["grant-1".to_string()],
        };
        let (_, d_capability) = score_authority(&b);
        assert_eq!(d_capability, 1.0);
    }

    #[test]
    fn score_authority_no_events_gives_zero() {
        let (d_authority, d_capability) = score_authority(&AuthorityBindingResult::default());
        assert_eq!(d_authority, 0.0);
        assert_eq!(d_capability, 0.0);
    }

    #[test]
    fn score_authority_dedupes_repeated_grant_usage_for_capability() {
        // One grant backing two observed actions must not count as "two
        // used grants" against zero unused ones producing something other
        // than 0.0 unused-fraction.
        let b = AuthorityBindingResult {
            authorized: vec![
                ("grant-1".to_string(), "obs-1".to_string()),
                ("grant-1".to_string(), "obs-2".to_string()),
            ],
            unauthorized_observed: vec![],
            unused_grants: vec!["grant-2".to_string()],
        };
        let (_, d_capability) = score_authority(&b);
        // 1 used (deduped) + 1 unused = 2 total; 1 unused / 2 = 0.5.
        assert!((d_capability - 0.5).abs() < f32::EPSILON);
    }

    // ── score_dns_flow ────────────────────────────────────────────────────────

    #[test]
    fn score_dns_flow_all_bound_gives_zero() {
        let b = DnsFlowBindingResult {
            bound_pairs: vec![("dns-1".to_string(), "flow-1".to_string())],
            unbound_flows: vec![],
            unresolved_queries: vec![],
        };
        assert_eq!(score_dns_flow(&b), 0.0);
    }

    #[test]
    fn score_dns_flow_unbound_flow_raises_score() {
        let b = DnsFlowBindingResult {
            bound_pairs: vec![],
            unbound_flows: vec!["flow-1".to_string()],
            unresolved_queries: vec![],
        };
        assert_eq!(score_dns_flow(&b), 1.0);
    }

    #[test]
    fn score_dns_flow_no_flows_gives_zero() {
        assert_eq!(score_dns_flow(&DnsFlowBindingResult::default()), 0.0);
    }

    // ── score_all ─────────────────────────────────────────────────────────────

    #[test]
    fn score_all_combines_all_three_binders() {
        let causal = binding(vec![("req-1", "resp-1")], vec!["resp-2"], vec![]);
        let authority = AuthorityBindingResult {
            authorized: vec![],
            unauthorized_observed: vec!["obs-1".to_string()],
            unused_grants: vec![],
        };
        let dns_flow = DnsFlowBindingResult {
            bound_pairs: vec![],
            unbound_flows: vec!["flow-1".to_string()],
            unresolved_queries: vec![],
        };
        let result = score_all(&causal, &authority, &dns_flow, 10);
        assert!((result.d_causal - 0.5).abs() < f32::EPSILON);
        assert_eq!(result.d_authority, 1.0);
        assert_eq!(result.d_information, 1.0);
        assert_eq!(result.d_consequence, 0.0);
        assert_eq!(result.d_novelty, 0.0);
    }

    // ── serde round-trip ──────────────────────────────────────────────────────

    #[test]
    fn discrepancy_vector_round_trips_through_json() {
        let b = binding(vec![("req-1", "resp-1")], vec!["resp-2"], vec![]);
        let original = score_causal(&b, 3);
        let json = omnisec_json::to_json_string(&original);
        let decoded: DiscrepancyVector =
            omnisec_json::from_json_str(&json).expect("deserialization failed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn discrepancy_vector_json_uses_expected_field_names() {
        let b = binding(vec![], vec![], vec![]);
        let value = omnisec_json::to_json_value(&score_causal(&b, 0));
        let obj = value.as_object().expect("expected a JSON object");
        let expected = [
            "d_causal",
            "coverage_quality",
            "d_authority",
            "d_information",
            "d_capability",
            "d_consequence",
            "d_novelty",
        ];
        for key in expected {
            assert!(
                obj.iter().any(|(k, _)| k == key),
                "missing expected field {key}"
            );
        }
        // Exact count: DiscrepancyVector does not cross the FFI boundary
        // directly (ReconcileResult only re-exports d_causal/coverage_quality),
        // but consumers that do serialize it whole should be able to rely on
        // this exact shape rather than "at least these fields."
        assert_eq!(
            obj.len(),
            expected.len(),
            "DiscrepancyVector gained or lost a field; update this test's \
             expected field list"
        );
    }
}
