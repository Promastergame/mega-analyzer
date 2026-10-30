//! Phase 1/2/3 → Phase 4 integration bridge.
//!
//! This module connects the earlier OmniSec pipeline stages to the Forge:
//!
//! - **Phase 1** ([`omnisec_hdc`]): anchor matching produces a
//!   [`MatchResult`](omnisec_hdc::MatchResult) with an anchor name,
//!   jaccard similarity, severity, and matched motifs.
//! - **Phase 2** ([`omnisec_ipdg`]): taint tracking produces a
//!   [`TaintPath`](omnisec_ipdg::TaintPath) describing the
//!   source → sink flow with confidence and risk scores.
//! - **Phase 3** ([`omnisec_smt`]): the concolic engine produces a
//!   [`Model`](omnisec_smt::Model) binding symbolic input variables to
//!   concrete values that drive execution to the sink.
//!
//! [`PipelineInput`] bundles these three outputs so the Forge can
//! consume them as a single contract. [`VulnerabilityPrimitive::from_pipeline`]
//! is the public entry point — it inspects each field and produces a
//! fully-populated primitive ready for `Forge::synthesize`.
//!
//! ## Heuristics applied
//!
//! - **Primitive kind inference** — the HDC anchor name is matched
//!   against a small dictionary of known motifs (`uaf`, `bof`, `oob`,
//!   `type_confusion`, …). When no match is found, falls back to
//!   [`PrimitiveKind::StackBufferOverflow`] because that's the single
//!   most common shape in the 2024-2026 landscape.
//! - **Chain goal inference** — derived from [`TaintPath::sink`]: a
//!   `CommandExecution` sink → [`ChainGoal::SpawnShell`], a `Memory`
//!   sink in a writable segment → [`ChainGoal::DataMutation`], etc.
//! - **Witness extraction** — every SMT model variable becomes a
//!   [`WitnessRequirement`] with width inferred from the model.
//! - **Anchor score** — `anchor_severity` comes directly from
//!   `MatchResult::severity`; `anchor_confidence` is the geometric mean
//!   of HDC's `jaccard` and taint path's `confidence` (both ∈ [0, 1]).

use std::collections::BTreeMap;

use omnisec_core::Arch;
use omnisec_hdc::MatchResult;
use omnisec_ipdg::{TaintPath, TaintSink};
use omnisec_smt::Model;

use crate::primitive::{ChainGoal, PrimitiveKind, VulnerabilityPrimitive, WitnessRequirement};

/// Combined Phase 1-3 output. Construct one of these from whatever you
/// have in hand, then call [`VulnerabilityPrimitive::from_pipeline`].
#[derive(Debug, Clone)]
pub struct PipelineInput<'a> {
    /// Primitive identifier (CVE, internal report id, …). Becomes
    /// [`VulnerabilityPrimitive::name`].
    pub name: String,
    /// Target architecture.
    pub arch: Arch,
    /// Phase-1 HDC anchor match result (optional — absent for primitives
    /// discovered via pattern matching alone).
    pub hdc_match: Option<&'a MatchResult>,
    /// Phase-2 taint path (optional — absent for hardware-fault and
    /// logic-flaw primitives that don't need a dataflow trace).
    pub taint_path: Option<&'a TaintPath>,
    /// Phase-3 SMT model (optional — absent for primitives that don't
    /// require symbolic path exploration).
    pub smt_model: Option<&'a Model>,
    /// Concrete sink address, when known.
    pub sink_address: Option<u64>,
    /// Explicit chain goal override. When `None`, the goal is inferred
    /// from the taint path's sink kind.
    pub goal_override: Option<ChainGoal>,
    /// Explicit primitive kind override. When `None`, the kind is
    /// inferred from the HDC anchor name.
    pub kind_override: Option<PrimitiveKind>,
}

impl<'a> PipelineInput<'a> {
    /// Build a minimal input with just the name and architecture.
    #[must_use]
    pub fn new(name: impl Into<String>, arch: Arch) -> Self {
        Self {
            name: name.into(),
            arch,
            hdc_match: None,
            taint_path: None,
            smt_model: None,
            sink_address: None,
            goal_override: None,
            kind_override: None,
        }
    }

    /// Attach Phase-1 HDC anchor match.
    #[must_use]
    pub fn with_hdc(mut self, m: &'a MatchResult) -> Self {
        self.hdc_match = Some(m);
        self
    }

    /// Attach Phase-2 taint path.
    #[must_use]
    pub fn with_taint(mut self, t: &'a TaintPath) -> Self {
        self.taint_path = Some(t);
        self
    }

    /// Attach Phase-3 SMT model.
    #[must_use]
    pub fn with_model(mut self, m: &'a Model) -> Self {
        self.smt_model = Some(m);
        self
    }

    /// Force a specific chain goal (e.g. when the caller knows better
    /// than our inference heuristic).
    #[must_use]
    pub fn with_goal(mut self, goal: ChainGoal) -> Self {
        self.goal_override = Some(goal);
        self
    }

    /// Force a specific primitive kind.
    #[must_use]
    pub fn with_kind(mut self, kind: PrimitiveKind) -> Self {
        self.kind_override = Some(kind);
        self
    }

    /// Pin the sink address.
    #[must_use]
    pub fn with_sink(mut self, address: u64) -> Self {
        self.sink_address = Some(address);
        self
    }
}

impl VulnerabilityPrimitive {
    /// Build a [`VulnerabilityPrimitive`] from an upstream pipeline bundle.
    ///
    /// This is the public bridge between the OmniSec Phase 1/2/3
    /// analysis stack and the Forge's Phase 4 synthesizer. It copies
    /// severity and confidence from HDC, extracts witnesses from the
    /// SMT model, and infers the primitive kind and chain goal from
    /// the matched anchor and taint sink.
    #[must_use]
    pub fn from_pipeline(input: &PipelineInput<'_>) -> Self {
        let kind = input
            .kind_override
            .unwrap_or_else(|| infer_kind(input.hdc_match));

        let goal = input
            .goal_override
            .clone()
            .unwrap_or_else(|| infer_goal(input.taint_path, input.sink_address));

        let (anchor_severity, anchor_confidence) = anchor_scores(input.hdc_match, input.taint_path);

        let witnesses = input.smt_model.map(extract_witnesses).unwrap_or_default();

        let mut notes: BTreeMap<String, String> = BTreeMap::new();
        if let Some(m) = input.hdc_match {
            notes.insert("hdc_anchor".into(), m.anchor_name.clone());
            notes.insert("hdc_jaccard".into(), format!("{:.4}", m.jaccard));
            if !m.matched_motifs.is_empty() {
                notes.insert("hdc_motifs".into(), m.matched_motifs.join(","));
            }
        }
        if let Some(t) = input.taint_path {
            notes.insert(
                "taint_boundary_crossings".into(),
                t.boundary_crossings.to_string(),
            );
            notes.insert("taint_risk".into(), format!("{:.4}", t.risk_score));
            notes.insert(
                "taint_crosses_privilege".into(),
                t.crosses_privilege_boundary.to_string(),
            );
        }
        if let Some(m) = input.smt_model {
            notes.insert("smt_witness_count".into(), m.len().to_string());
        }

        Self {
            name: input.name.clone(),
            arch: input.arch,
            kind,
            anchor_severity,
            anchor_confidence,
            sink_address: input.sink_address,
            witnesses,
            goal,
            notes,
        }
    }
}

/// Infer [`PrimitiveKind`] from the HDC anchor name.
///
/// Anchor names in `omnisec-hdc` follow the convention
/// `<family>_<variant>` (e.g. `uaf_classic`, `bof_stack`, `tc_vtable`).
/// We lower-case the name and match on prefixes.
fn infer_kind(hdc: Option<&MatchResult>) -> PrimitiveKind {
    let Some(m) = hdc else {
        return PrimitiveKind::StackBufferOverflow;
    };
    let name = m.anchor_name.to_ascii_lowercase();
    if name.starts_with("uaf") || name.contains("use_after_free") {
        PrimitiveKind::UseAfterFree
    } else if name.contains("heap") && (name.contains("bof") || name.contains("overflow")) {
        PrimitiveKind::HeapBufferOverflow
    } else if name.starts_with("bof")
        || name.contains("stack") && name.contains("overflow")
        || name.contains("buffer_overflow")
    {
        PrimitiveKind::StackBufferOverflow
    } else if name.starts_with("tc") || name.contains("type_confusion") {
        PrimitiveKind::TypeConfusion
    } else if name.contains("format_string") || name.contains("fmtstr") {
        PrimitiveKind::FormatString
    } else if name.contains("int_overflow") || name.contains("integer_overflow") {
        PrimitiveKind::IntegerOverflow
    } else if name.contains("cmd_injection") || name.contains("command_injection") {
        PrimitiveKind::CommandInjection
    } else if name.contains("deserial") {
        PrimitiveKind::Deserialisation
    } else if name.contains("rowhammer") || name.contains("ghostwrite") || name.contains("fault") {
        PrimitiveKind::HardwareFault
    } else if name.contains("logic") || name.contains("auth_bypass") {
        PrimitiveKind::LogicFlaw
    } else {
        // Sensible default — stack BOF is still the most common primitive.
        PrimitiveKind::StackBufferOverflow
    }
}

/// Infer [`ChainGoal`] from the taint path's sink kind and a sink address.
fn infer_goal(taint: Option<&TaintPath>, sink_address: Option<u64>) -> ChainGoal {
    let Some(t) = taint else {
        return ChainGoal::SpawnShell;
    };
    match &t.sink {
        TaintSink::CommandExecution => ChainGoal::SpawnShell,
        TaintSink::Syscall => ChainGoal::MakeRwxAndJump {
            addr: sink_address.unwrap_or(0),
            len: 0x1000,
        },
        TaintSink::Memory | TaintSink::Crypto | TaintSink::Auth => ChainGoal::DataMutation {
            addr: sink_address.unwrap_or(0),
            write: vec![1],
        },
        TaintSink::FileOperation | TaintSink::NetworkOperation => ChainGoal::SpawnCommand {
            cmd: "injected_operation".into(),
        },
        TaintSink::SqlQuery => ChainGoal::SpawnCommand {
            cmd: "injected_query".into(),
        },
        TaintSink::Custom(label) => ChainGoal::SpawnCommand { cmd: label.clone() },
    }
}

/// Extract [`WitnessRequirement`]s from every bound variable in the
/// SMT model. Deterministic iteration via a sorted key vector.
fn extract_witnesses(model: &Model) -> Vec<WitnessRequirement> {
    let mut keys: Vec<&String> = model.values.keys().collect();
    keys.sort();
    keys.iter()
        .map(|name| {
            let concrete = model.values.get(*name).copied().unwrap_or(0);
            let width = model.widths.get(*name).copied().unwrap_or(64);
            WitnessRequirement {
                name: (*name).clone(),
                width,
                concrete,
            }
        })
        .collect()
}

/// Compute `(anchor_severity, anchor_confidence)`.
///
/// - `severity` = HDC anchor's severity, or `0.5` when no HDC match is
///   available.
/// - `confidence` = geometric mean of HDC jaccard and taint confidence
///   when both are present; falls back to whichever is available; `0.5`
///   when neither is.
fn anchor_scores(hdc: Option<&MatchResult>, taint: Option<&TaintPath>) -> (f64, f64) {
    let severity = hdc.map_or(0.5, |m| m.severity.clamp(0.0, 1.0));
    let confidence = match (hdc, taint) {
        (Some(m), Some(t)) => {
            let jaccard = m.jaccard.clamp(0.0, 1.0);
            let taint_conf = f64::from(t.confidence).clamp(0.0, 1.0);
            (jaccard * taint_conf).sqrt()
        }
        (Some(m), None) => m.jaccard.clamp(0.0, 1.0),
        (None, Some(t)) => f64::from(t.confidence).clamp(0.0, 1.0),
        (None, None) => 0.5,
    };
    (severity, confidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_match(name: &str, severity: f64, jaccard: f64) -> MatchResult {
        MatchResult {
            anchor_name: name.into(),
            jaccard,
            hamming_sim: jaccard,
            is_match: true,
            severity,
            matched_motifs: vec!["motif_a".into(), "motif_b".into()],
        }
    }

    #[test]
    fn infer_kind_routes_uaf_anchor() {
        let m = fake_match("uaf_classic", 0.9, 0.85);
        assert_eq!(infer_kind(Some(&m)), PrimitiveKind::UseAfterFree);
    }

    #[test]
    fn infer_kind_routes_heap_overflow() {
        let m = fake_match("heap_bof_react2shell", 0.8, 0.7);
        assert_eq!(infer_kind(Some(&m)), PrimitiveKind::HeapBufferOverflow);
    }

    #[test]
    fn infer_kind_routes_type_confusion() {
        let m = fake_match("tc_vtable_write", 0.8, 0.7);
        assert_eq!(infer_kind(Some(&m)), PrimitiveKind::TypeConfusion);
    }

    #[test]
    fn infer_kind_routes_hardware_fault() {
        let m = fake_match("ghostwrite_vector_store", 0.99, 0.9);
        assert_eq!(infer_kind(Some(&m)), PrimitiveKind::HardwareFault);
    }

    #[test]
    fn infer_kind_falls_back_when_no_match() {
        assert_eq!(infer_kind(None), PrimitiveKind::StackBufferOverflow);
    }

    #[test]
    fn anchor_scores_geometric_mean_when_both_present() {
        let hdc = fake_match("any", 0.9, 0.64);
        let mut path = fake_taint_path();
        path.confidence = 0.25; // sqrt(0.64 * 0.25) = 0.4
        let (severity, conf) = anchor_scores(Some(&hdc), Some(&path));
        assert!((severity - 0.9).abs() < 1e-6);
        assert!((conf - 0.4).abs() < 1e-6);
    }

    #[test]
    fn from_pipeline_populates_notes_and_witnesses() {
        let hdc = fake_match("bof_stack_classic", 0.95, 0.9);
        let taint = fake_taint_path();
        let mut model = Model::default();
        model.insert("v1", 0xDEAD_BEEF, 32);
        model.insert("v2", 0xCAFE, 16);

        let input = PipelineInput::new("CVE-FAKE-1", Arch::X86_64)
            .with_hdc(&hdc)
            .with_taint(&taint)
            .with_model(&model)
            .with_sink(0x0040_1400);

        let p = VulnerabilityPrimitive::from_pipeline(&input);
        assert_eq!(p.kind, PrimitiveKind::StackBufferOverflow);
        assert_eq!(p.witnesses.len(), 2);
        assert_eq!(p.sink_address, Some(0x0040_1400));
        assert!(p.notes.contains_key("hdc_anchor"));
        assert!(p.notes.contains_key("smt_witness_count"));
    }

    #[test]
    fn from_pipeline_is_deterministic() {
        let hdc = fake_match("uaf_vtable", 0.88, 0.76);
        let mut model = Model::default();
        model.insert("v1", 1, 32);
        model.insert("v2", 2, 32);
        model.insert("v3", 3, 32);

        let input = PipelineInput::new("det", Arch::Arm64)
            .with_hdc(&hdc)
            .with_model(&model);

        let a = VulnerabilityPrimitive::from_pipeline(&input);
        let b = VulnerabilityPrimitive::from_pipeline(&input);
        // Primitive lacks Eq (f64 fields); compare serialised form.
        let sa = omnisec_json::to_json_string(&a);
        let sb = omnisec_json::to_json_string(&b);
        assert_eq!(sa, sb);
    }

    /// Minimal TaintPath we can construct without pulling the whole
    /// IPDG scaffolding into scope.
    fn fake_taint_path() -> TaintPath {
        use omnisec_ipdg::{TaintSink, TaintSource};
        TaintPath {
            source: TaintSource::UserInput,
            sink: TaintSink::CommandExecution,
            nodes: vec![],
            components: vec![],
            boundary_crossings: 2,
            crosses_privilege_boundary: true,
            confidence: 0.9,
            risk_score: 0.95,
        }
    }
}
