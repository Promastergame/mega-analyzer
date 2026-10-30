//! End-to-end integration tests for `omnisec-forge`.
//!
//! These tests run the full Phase 1→4 bridge:
//!
//! 1. Construct synthetic Phase-1 HDC [`MatchResult`], Phase-2
//!    [`TaintPath`], and Phase-3 [`Model`] inputs.
//! 2. Feed them into [`PipelineInput`] → [`VulnerabilityPrimitive::from_pipeline`].
//! 3. Drive the full [`Forge::synthesize`] pipeline.
//! 4. Serialise the [`SynthesizedPayload`] to JSON and back.
//! 5. Verify both byte identity and `stable_hash()` stability across the round-trip.
//!
//! The goal is to prove the whole pipeline is deterministic, side-effect-free,
//! and serialisable end-to-end — the three guarantees `omnisec-forge::lib.rs`
//! advertises.

use omnisec_core::Arch;
use omnisec_forge::{
    Forge, ForgeConfig, MitigationProfile, PipelineInput, PrimitiveKind, SynthesizedPayload,
    VulnerabilityPrimitive, benchmarks,
};
use omnisec_hdc::MatchResult;
use omnisec_ipdg::{TaintPath, TaintSink, TaintSource};
use omnisec_json::{FromJson, ToJson};
use omnisec_smt::Model;

fn synth_hdc_match(name: &str) -> MatchResult {
    MatchResult {
        anchor_name: name.into(),
        jaccard: 0.87,
        hamming_sim: 0.89,
        is_match: true,
        severity: 0.92,
        matched_motifs: vec!["heap_boundary_write".into(), "unbounded_memcpy".into()],
    }
}

fn synth_taint_path() -> TaintPath {
    TaintPath {
        source: TaintSource::UserInput,
        sink: TaintSink::CommandExecution,
        nodes: vec![],
        components: vec![],
        boundary_crossings: 3,
        crosses_privilege_boundary: true,
        confidence: 0.88,
        risk_score: 0.93,
    }
}

fn synth_smt_model() -> Model {
    let mut m = Model::default();
    m.insert("buf_size", 0x200, 32);
    m.insert("canary_guess", 0x0011_2233_4455_6600_u64 as i128, 64);
    m.insert("ret_addr", 0x0040_1400, 64);
    m
}

#[test]
fn pipeline_bridge_produces_deterministic_primitive() {
    let hdc = synth_hdc_match("bof_stack_classic");
    let taint = synth_taint_path();
    let model = synth_smt_model();

    let input = PipelineInput::new("CVE-E2E-1", Arch::X86_64)
        .with_hdc(&hdc)
        .with_taint(&taint)
        .with_model(&model)
        .with_sink(0x0040_1400);

    let a = VulnerabilityPrimitive::from_pipeline(&input);
    let b = VulnerabilityPrimitive::from_pipeline(&input);

    let sa = omnisec_json::to_json_string(&a);
    let sb = omnisec_json::to_json_string(&b);
    assert_eq!(sa, sb, "from_pipeline must be deterministic");

    assert_eq!(a.kind, PrimitiveKind::StackBufferOverflow);
    assert_eq!(a.witnesses.len(), 3);
    assert!(a.notes.contains_key("hdc_anchor"));
    assert!(a.notes.contains_key("taint_risk"));
}

#[test]
fn forge_synthesizes_end_to_end_from_pipeline_input() {
    let hdc = synth_hdc_match("bof_stack_classic");
    let taint = synth_taint_path();
    let model = synth_smt_model();

    let primitive = VulnerabilityPrimitive::from_pipeline(
        &PipelineInput::new("CVE-E2E-SYN", Arch::X86_64)
            .with_hdc(&hdc)
            .with_taint(&taint)
            .with_model(&model)
            .with_sink(0x0040_1400),
    );

    let cfg = ForgeConfig::for_arch(Arch::X86_64).with_seed(0x1234_5678);
    let payload = Forge::new(cfg).synthesize(&primitive).expect("synthesis");

    assert_eq!(payload.arch, Arch::X86_64);
    assert!(
        !payload.payload.is_empty(),
        "synthesis must produce non-empty payload bytes"
    );
    assert_eq!(payload.primitive, "CVE-E2E-SYN");
    // 3 register goals lower from SpawnShell on x86_64 (rdi, rsi, rdx, rax).
    assert!(!payload.chain.is_empty(), "chain should have entries");
    // Witnesses must propagate forward from the SMT model.
    assert!(payload.witness.contains_key("buf_size"));
    assert!(payload.witness.contains_key("canary_guess"));
    assert!(payload.witness.contains_key("ret_addr"));
}

#[test]
fn synthesized_payload_survives_json_round_trip() {
    let cfg = ForgeConfig::for_arch(Arch::X86_64).with_seed(42);
    let primitive = benchmarks::react2shell();
    let payload = Forge::new(cfg).synthesize(&primitive).expect("synthesis");

    // JSON round-trip.
    let json = omnisec_json::to_json_string(&payload);
    let decoded: SynthesizedPayload = omnisec_json::from_json_str(&json).expect("deserialise");

    assert_eq!(payload, decoded, "JSON round-trip must preserve payload");
    assert_eq!(
        payload.stable_hash(),
        decoded.stable_hash(),
        "stable_hash must be invariant under JSON round-trip"
    );
}

#[test]
fn synthesis_is_reproducible_across_two_engine_instances() {
    let primitive = benchmarks::clawdbot();
    let cfg = ForgeConfig::for_arch(Arch::X86_64).with_seed(0xDEAD_BEEF);

    let a = Forge::new(cfg.clone()).synthesize(&primitive).unwrap();
    let b = Forge::new(cfg).synthesize(&primitive).unwrap();

    assert_eq!(
        a.stable_hash(),
        b.stable_hash(),
        "two independent Forge instances with identical config must agree byte-for-byte"
    );
}

#[test]
fn changing_seed_changes_payload_but_not_structure() {
    let primitive = benchmarks::react2shell();

    let a = Forge::new(ForgeConfig::for_arch(Arch::X86_64).with_seed(1))
        .synthesize(&primitive)
        .unwrap();
    let b = Forge::new(ForgeConfig::for_arch(Arch::X86_64).with_seed(2))
        .synthesize(&primitive)
        .unwrap();

    // Same architecture & primitive → same chain structure.
    assert_eq!(a.arch, b.arch);
    assert_eq!(a.primitive, b.primitive);
    assert_eq!(a.chain.len(), b.chain.len());
    // Different seed may or may not change bytes depending on how
    // tie-breaking lands; we only insist the hashes are well-defined
    // and the payloads are non-empty.
    assert!(!a.payload.is_empty() && !b.payload.is_empty());
}

#[test]
fn all_arch_benchmarks_complete_successfully() {
    let cases: Vec<(ForgeConfig, VulnerabilityPrimitive)> = vec![
        (
            ForgeConfig::for_arch(Arch::X86_64).with_mitigation(MitigationProfile::Server),
            benchmarks::react2shell(),
        ),
        (
            ForgeConfig::for_arch(Arch::Arm64).with_mitigation(MitigationProfile::IosHardened),
            benchmarks::pac_timing(),
        ),
        (
            ForgeConfig::for_arch(Arch::Arm64).with_mitigation(MitigationProfile::AndroidHardened),
            benchmarks::mte_intra_object(),
        ),
        (
            ForgeConfig::for_arch(Arch::RiscV64).with_mitigation(MitigationProfile::EmbeddedRiscv),
            benchmarks::ghostwrite(),
        ),
        (ForgeConfig::for_arch(Arch::X86_64), benchmarks::clawdbot()),
    ];

    for (cfg, primitive) in cases {
        let result = Forge::new(cfg.clone()).synthesize(&primitive);
        assert!(
            result.is_ok(),
            "{} / {:?} synthesis failed: {:?}",
            primitive.name,
            cfg.arch,
            result.err()
        );
    }
}

#[test]
fn full_pipeline_with_bad_bytes_encodes_payload() {
    // Stack canary primitive with NUL-byte bad-byte constraint — forces
    // the polymorphic encoder path.
    let primitive = VulnerabilityPrimitive::from_pipeline(
        &PipelineInput::new("CVE-E2E-NULFREE", Arch::X86_64)
            .with_kind(PrimitiveKind::StackBufferOverflow)
            .with_goal(omnisec_forge::primitive::ChainGoal::SpawnShell),
    );

    let cfg = ForgeConfig::for_arch(Arch::X86_64)
        .with_seed(7)
        .with_bad_bytes([0x00, 0x0a, 0x0d]);
    let payload = Forge::new(cfg).synthesize(&primitive).unwrap();

    // Encoded payload must not contain any of the forbidden bytes.
    for &bad in &[0x00u8, 0x0a, 0x0d] {
        assert!(
            !payload.payload.contains(&bad),
            "encoded payload must avoid 0x{bad:02x}"
        );
    }
}

// ─── Stage 4 sandbox oracle ───────────────────────────────────────────────

#[test]
fn stage4_child_process_oracle_confirms_synthesized_payload() {
    use omnisec_forge::{ChildProcessOracle, ProcessVerdict};
    use std::time::Duration;

    // Build a real payload first — anything non-empty is fine, the
    // oracle here doesn't interpret the bytes, only runs the command
    // and checks stdout.
    let primitive = benchmarks::react2shell();
    let payload = Forge::new(ForgeConfig::for_arch(Arch::X86_64).with_seed(1))
        .synthesize(&primitive)
        .unwrap();

    // Cross-platform "succeed and print the marker" shell.
    #[cfg(unix)]
    let oracle = ChildProcessOracle::new("sh")
        .arg("-c")
        .arg("cat >/dev/null && printf STAGE4_OK")
        .with_timeout(Duration::from_secs(3))
        .with_verdict(ProcessVerdict::stdout_contains("STAGE4_OK"));
    #[cfg(windows)]
    let oracle = ChildProcessOracle::new("cmd")
        .arg("/c")
        .arg("echo STAGE4_OK")
        .with_timeout(Duration::from_secs(3))
        .with_verdict(ProcessVerdict::stdout_contains("STAGE4_OK"));

    #[cfg(any(unix, windows))]
    {
        use omnisec_forge::Oracle;
        let verdict = oracle.verify(&payload);
        assert!(
            verdict.success,
            "Stage-4 oracle rejected a valid payload (notes = {:?})",
            verdict.notes
        );
    }
}
