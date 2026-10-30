//! `ForgeEngine` — drives the six-stage pipeline.

use std::collections::BTreeMap;

use omnisec_json::{FromJson, ToJson};

use crate::arch::{ArchEmitter, emitter_for};
use crate::chains::{AssembledChain, GadgetEntry, GadgetFinder, SmtAssembler};
use crate::complexity::ComplexityScore;
use crate::config::ForgeConfig;
use crate::dop::{DataGraph, DataNode, DopCfiPlanner};
use crate::encoding::{EncodedPayload, PolymorphicEncoder};
use crate::error::{ForgeError, Result};
use crate::mitigation::{BypassPlan, MitigationKind, bypass_for};
use crate::oracle::{MockOracle, Oracle, OracleVerdict};
use crate::payload::{Artifact, SynthesizedPayload, Witness, WitnessValue};
use crate::primitive::{ChainGoal, VulnerabilityPrimitive};
use crate::util::Prng;

/// Identifier for one stage of the engine, used when tagging
/// [`ForgeStageReport`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum ForgeStage {
    /// Stage 1: input validation.
    Validate,
    /// Stage 2: mitigation planning.
    MitigationPlanning,
    /// Stage 3: goal lowering to register goals.
    GoalLowering,
    /// Stage 4: chain / DOP plan assembly.
    ChainAssembly,
    /// Stage 5: bad-byte / polymorphic encoding.
    PayloadEncoding,
    /// Stage 6: oracle verification.
    OracleVerification,
}

impl ForgeStage {
    /// Short canonical name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::MitigationPlanning => "mitigation_planning",
            Self::GoalLowering => "goal_lowering",
            Self::ChainAssembly => "chain_assembly",
            Self::PayloadEncoding => "payload_encoding",
            Self::OracleVerification => "oracle_verification",
        }
    }
}

/// One row of the per-stage report attached to every
/// [`SynthesizedPayload`].
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct ForgeStageReport {
    /// Which stage this row belongs to.
    pub stage: ForgeStage,
    /// Free-form human-readable summary.
    pub summary: String,
    /// Stage-specific structured data, deterministic key ordering.
    pub details: BTreeMap<String, String>,
}

impl ForgeStageReport {
    fn new(stage: ForgeStage, summary: impl Into<String>) -> Self {
        Self {
            stage,
            summary: summary.into(),
            details: BTreeMap::new(),
        }
    }

    fn with_detail(mut self, key: &str, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

/// The engine.
pub struct ForgeEngine {
    cfg: ForgeConfig,
    finder: GadgetFinder,
    oracle: Option<Box<dyn Oracle>>,
}

impl ForgeEngine {
    /// New engine with the synthetic gadget pool.
    ///
    /// In production you'd build the engine with `with_finder(real_finder)`
    /// once the per-arch decoder has scanned the target image; for offline
    /// synthesis (and our tests) the synthetic pool is enough.
    #[must_use]
    pub fn new(cfg: ForgeConfig) -> Self {
        Self {
            cfg,
            finder: crate::chains::finder::synthetic_pool(),
            oracle: None,
        }
    }

    /// Override the gadget finder.
    #[must_use]
    pub fn with_finder(mut self, finder: GadgetFinder) -> Self {
        self.finder = finder;
        self
    }

    /// Override the oracle. By default we use [`MockOracle::default`] when
    /// `cfg.run_oracle` is true.
    #[must_use]
    pub fn with_oracle(mut self, oracle: Box<dyn Oracle>) -> Self {
        self.oracle = Some(oracle);
        self
    }

    /// Run the full pipeline on `primitive`.
    #[allow(clippy::too_many_lines)]
    pub fn run(self, primitive: &VulnerabilityPrimitive) -> Result<SynthesizedPayload> {
        let mut report: Vec<ForgeStageReport> = Vec::new();
        let mut prng = Prng::new(self.cfg.seed);

        // ── Stage 1: Validate ──────────────────────────────────────────
        if primitive.arch != self.cfg.arch {
            return Err(ForgeError::ArchMismatch {
                expected: self.cfg.arch,
                actual: primitive.arch,
            });
        }
        report.push(
            ForgeStageReport::new(ForgeStage::Validate, "config + primitive arch agree")
                .with_detail("arch", primitive.arch.name()),
        );

        // ── Stage 2: Mitigation planning ───────────────────────────────
        let mut combined_plan = BypassPlan::empty();
        let mut bypassed: Vec<MitigationKind> = Vec::new();
        for &kind in self.cfg.mitigation.mitigations() {
            let bypass = bypass_for(kind);
            if !bypass.applies_to(self.cfg.arch) {
                report.push(
                    ForgeStageReport::new(
                        ForgeStage::MitigationPlanning,
                        format!("skipping {kind} — not applicable on {}", self.cfg.arch),
                    )
                    .with_detail("kind", kind.name()),
                );
                continue;
            }
            let plan = bypass.plan(primitive, &mut prng)?;
            for note in &plan.notes {
                report.push(
                    ForgeStageReport::new(
                        ForgeStage::MitigationPlanning,
                        format!("[{kind}] {note}"),
                    )
                    .with_detail("kind", kind.name()),
                );
            }
            combined_plan.merge(plan);
            bypassed.push(kind);
        }
        bypassed.sort();
        bypassed.dedup();

        // ── Stage 3: Goal lowering ─────────────────────────────────────
        let emitter = emitter_for(self.cfg.arch)?;
        let register_goals = emitter.lower(&primitive.goal)?;
        report.push(
            ForgeStageReport::new(
                ForgeStage::GoalLowering,
                format!("lowered goal to {} register pin(s)", register_goals.len()),
            )
            .with_detail(
                "registers",
                register_goals
                    .iter()
                    .map(|g| g.register.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        );

        // ── Stage 4: Chain / DOP assembly ──────────────────────────────
        let (chain_entries, raw_payload, complexity) =
            if primitive.kind.prefers_dop() && self.cfg.enable_dop {
                Self::run_dop_path(primitive, &mut report, emitter.as_ref())?
            } else {
                self.run_chain_path(
                    primitive,
                    &register_goals,
                    &mut report,
                    &mut prng,
                    emitter.as_ref(),
                )?
            };

        // ── Stage 5: Payload encoding ──────────────────────────────────
        let encoded = if self.cfg.bad_bytes.is_empty() {
            EncodedPayload {
                bytes: raw_payload.clone(),
                recipe: "identity".into(),
                bad_bytes_avoided: Vec::new(),
            }
        } else {
            let mut all_bad = self.cfg.bad_bytes.clone();
            all_bad.extend(combined_plan.bad_bytes.iter().copied());
            all_bad.sort_unstable();
            all_bad.dedup();
            PolymorphicEncoder.encode(&raw_payload, &all_bad, &mut prng)?
        };
        report.push(
            ForgeStageReport::new(
                ForgeStage::PayloadEncoding,
                format!(
                    "encoded {} bytes (recipe = {})",
                    encoded.bytes.len(),
                    encoded.recipe
                ),
            )
            .with_detail("bytes", encoded.bytes.len().to_string()),
        );

        // ── Build initial witness map ──────────────────────────────────
        let mut witness: Witness = Witness::new();
        for w in &primitive.witnesses {
            witness.insert(w.name.clone(), WitnessValue::new(w.width, w.concrete));
        }
        for (name, value, width) in &combined_plan.witness_overrides {
            witness.insert(name.clone(), WitnessValue::new(*width, *value));
        }

        let mut artifacts: Vec<Artifact> = Vec::new();
        if !encoded.recipe.is_empty() && encoded.recipe != "identity" {
            artifacts.push(Artifact {
                name: "decoder_recipe".into(),
                bytes: encoded.recipe.as_bytes().to_vec(),
                kind: "text/x-decoder-recipe".into(),
            });
        }

        let mut payload = SynthesizedPayload {
            config: self.cfg.clone(),
            primitive: primitive.name.clone(),
            arch: self.cfg.arch,
            bypassed: bypassed.clone(),
            witness,
            chain: chain_entries,
            payload: encoded.bytes,
            report,
            complexity,
            artifacts,
        };

        // ── Stage 6: Oracle verification ──────────────────────────────
        if self.cfg.run_oracle {
            let verdict = self.run_oracle_stage(&payload);
            let mut detail = BTreeMap::new();
            detail.insert("success".into(), verdict.success.to_string());
            detail.insert(
                "adjusted_complexity".into(),
                verdict.adjusted_complexity.to_string(),
            );
            payload.report.push(ForgeStageReport {
                stage: ForgeStage::OracleVerification,
                summary: if verdict.success {
                    "oracle confirmed payload is viable".into()
                } else {
                    "oracle rejected payload".into()
                },
                details: detail,
            });
            for n in &verdict.notes {
                payload.report.push(ForgeStageReport::new(
                    ForgeStage::OracleVerification,
                    n.clone(),
                ));
            }
            payload.complexity = ComplexityScore(verdict.adjusted_complexity);
        } else {
            payload.report.push(ForgeStageReport::new(
                ForgeStage::OracleVerification,
                "oracle stage skipped (run_oracle = false)",
            ));
        }

        Ok(payload)
    }

    fn run_chain_path(
        &self,
        _primitive: &VulnerabilityPrimitive,
        register_goals: &[crate::chains::assembler::RegisterGoal],
        report: &mut Vec<ForgeStageReport>,
        prng: &mut Prng,
        emitter: &(dyn ArchEmitter + Send + Sync),
    ) -> Result<(Vec<GadgetEntry>, Vec<u8>, ComplexityScore)> {
        let assembler = SmtAssembler::new(&self.finder)
            .with_budget(self.cfg.bgat_budget)
            .with_max_length(self.cfg.max_chain_length);

        let chain: AssembledChain = assembler.assemble(register_goals, prng)?;

        report.push(
            ForgeStageReport::new(
                ForgeStage::ChainAssembly,
                format!(
                    "BGAT assembled {}-gadget chain (smt_queries = {}, complexity = {})",
                    chain.entries.len(),
                    chain.stats.smt_queries,
                    chain.complexity.raw()
                ),
            )
            .with_detail("gadgets", chain.entries.len().to_string()),
        );

        // Lay out the raw payload: for a simple ROP, just concatenate
        // [arch-encoded address, stack_data]* across entries.
        let mut raw = Vec::new();
        for entry in &chain.entries {
            raw.extend(emitter.encode_pointer(entry.address));
            raw.extend_from_slice(&entry.stack_data);
        }

        Ok((chain.entries, raw, chain.complexity))
    }

    fn run_dop_path(
        primitive: &VulnerabilityPrimitive,
        report: &mut Vec<ForgeStageReport>,
        emitter: &(dyn ArchEmitter + Send + Sync),
    ) -> Result<(Vec<GadgetEntry>, Vec<u8>, ComplexityScore)> {
        let target = match &primitive.goal {
            ChainGoal::DataMutation { addr, .. } => DataNode::Memory { addr: *addr },
            _ => DataNode::Symbol {
                name: primitive.name.clone(),
            },
        };

        // Build a minimal data graph from primitive.notes plus an explicit
        // "AttackerSource → target" edge. Real-world callers should pass
        // a richer graph in via with_finder-style API; we keep the
        // built-in path simple so the offline tests stay tractable.
        let mut graph = DataGraph::new();
        graph.add_edge(
            DataNode::AttackerSource,
            target.clone(),
            crate::dop::DataEdgeKind::EnablesWriteTo,
        );

        let plan = DopCfiPlanner::new()
            .plan(&graph, &target)
            .ok_or(ForgeError::Invariant("DOP plan unexpectedly empty"))?;

        report.push(
            ForgeStageReport::new(
                ForgeStage::ChainAssembly,
                format!(
                    "DOP plan with {} write step(s) — no control-flow hijack",
                    plan.writes.len()
                ),
            )
            .with_detail("writes", plan.writes.len().to_string()),
        );

        // The "payload" for a DOP plan is the bytes that need to flow
        // into the attacker-controlled memory location.
        let raw = match &primitive.goal {
            ChainGoal::DataMutation { write, .. } => write.clone(),
            _ => emitter.encode_pointer(0),
        };

        let complexity = ComplexityScore::from_components(0, plan.writes.len() as u32, 0, 0);

        Ok((Vec::new(), raw, complexity))
    }

    fn run_oracle_stage(&self, payload: &SynthesizedPayload) -> OracleVerdict {
        match &self.oracle {
            Some(o) => o.verify(payload),
            None => MockOracle::default().verify(payload),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitive::PrimitiveKind;
    use omnisec_core::Arch;

    fn make_primitive() -> VulnerabilityPrimitive {
        VulnerabilityPrimitive::new(
            "CVE-FAKE",
            Arch::X86_64,
            PrimitiveKind::StackBufferOverflow,
            ChainGoal::SpawnShell,
        )
        .with_anchor(0.9, 0.85)
    }

    #[test]
    fn engine_runs_full_pipeline_on_x86_64_spawnshell() {
        let cfg = ForgeConfig::for_arch(Arch::X86_64).with_seed(7);
        let p = make_primitive();
        let payload = ForgeEngine::new(cfg).run(&p).unwrap();
        assert_eq!(payload.arch, Arch::X86_64);
        assert!(!payload.payload.is_empty());
        assert!(
            payload
                .report
                .iter()
                .any(|r| r.stage == ForgeStage::ChainAssembly)
        );
    }

    #[test]
    fn arch_mismatch_is_caught() {
        let cfg = ForgeConfig::for_arch(Arch::Arm64);
        let p = make_primitive(); // x86_64
        let r = ForgeEngine::new(cfg).run(&p);
        assert!(matches!(r, Err(ForgeError::ArchMismatch { .. })));
    }

    #[test]
    fn dop_path_runs_for_logic_flaw() {
        let cfg = ForgeConfig::for_arch(Arch::X86_64);
        let p = VulnerabilityPrimitive::new(
            "logic",
            Arch::X86_64,
            PrimitiveKind::LogicFlaw,
            ChainGoal::DataMutation {
                addr: 0x0060_1020,
                write: vec![1, 2, 3, 4],
            },
        );
        let payload = ForgeEngine::new(cfg).run(&p).unwrap();
        assert!(payload.chain.is_empty());
        assert_eq!(payload.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn engine_is_deterministic() {
        let cfg = ForgeConfig::for_arch(Arch::X86_64).with_seed(123);
        let p = make_primitive();
        let a = ForgeEngine::new(cfg.clone()).run(&p).unwrap();
        let b = ForgeEngine::new(cfg).run(&p).unwrap();
        assert_eq!(a.stable_hash(), b.stable_hash());
    }
}
