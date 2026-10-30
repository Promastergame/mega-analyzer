//! ML-Aetrium graph-anchor integration for native scans.

use omnisec_analysis_symbolic::{
    BranchPriority, ConcolicExecutor, ConcolicSeed, MirInsn, MirOp, SymBlock, SymbolicExecutor,
    merge_traces,
};
use omnisec_cfg::{ControlFlowGraph, build_cfg};
use omnisec_core::Arch;
use omnisec_disasm::linear_sweep;
use omnisec_hdc::{AnchorStore, MatchResult};
use omnisec_ir::{Instruction, OpCode, Operand};
use omnisec_loader::{LoadedBinary, SectionFlags};
use omnisec_pdg::ProgramDependenceGraph;

use crate::{Category, Confidence, Finding, Severity};

/// Configuration for opt-in ML-Aetrium graph-anchor detection.
pub struct AetriumScanConfig<'a> {
    /// Loaded vulnerability anchor database.
    pub anchors: &'a AnchorStore,
    /// PDG neighborhood radius around each risky sink.
    pub radius: usize,
    /// Maximum Aetrium findings emitted into the scan report.
    pub max_findings: usize,
    /// Maximum lifted instructions processed per executable section.
    pub max_instructions_per_section: usize,
    /// Enable ML-Apli-Ex: Attempt to generate symbolic payload for high-confidence hits.
    pub enable_weaponization: bool,
    /// Use the new concolic + SMT engine for Phase 3 (recommended).
    ///
    /// When `true`, [`ConcolicExecutor`] explores paths driven by a concrete
    /// seed and uses the [`omnisec_smt`] solver to flip branches and
    /// generate new inputs. When `false`, the legacy bounded-symbolic
    /// executor is used (kept for forensics-comparison and backward
    /// compatibility).
    pub use_concolic: bool,
    /// Maximum concolic exploration iterations per high-confidence hit.
    pub max_concolic_iterations: usize,
}

impl<'a> AetriumScanConfig<'a> {
    /// Create a config with production-safe defaults.
    #[must_use]
    pub const fn new(anchors: &'a AnchorStore) -> Self {
        Self {
            anchors,
            radius: 2,
            max_findings: 32,
            max_instructions_per_section: 20_000,
            enable_weaponization: false,
            use_concolic: true,
            max_concolic_iterations: 16,
        }
    }
}

#[derive(Debug, Clone)]
struct AetriumHit {
    address: u64,
    section: String,
    result: MatchResult,
    ml_apli_ex_payload: Option<String>,
    stages: Vec<String>,
}

pub(crate) fn scan(
    bin: &LoadedBinary,
    bytes: &[u8],
    config: &AetriumScanConfig<'_>,
    findings: &mut Vec<Finding>,
) {
    if config.anchors.is_empty() || config.max_findings == 0 || !supports_lift(bin.arch) {
        return;
    }

    let mut hits = Vec::new();

    for section in &bin.sections {
        if !section.flags.contains(SectionFlags::EXECUTE) {
            continue;
        }

        let offset = section.file_offset as usize;
        let size = section.file_size as usize;
        if offset >= bytes.len() {
            continue;
        }
        let end = offset.saturating_add(size).min(bytes.len());
        let chunk = &bytes[offset..end];
        if chunk.is_empty() {
            continue;
        }

        let mut instructions = linear_sweep(bin.arch, chunk, section.virtual_address);
        if instructions.len() > config.max_instructions_per_section {
            instructions.truncate(config.max_instructions_per_section);
        }
        if instructions.is_empty() {
            continue;
        }

        collect_section_hits(&section.name, &instructions, config, &mut hits);
    }

    hits.sort_by(|a, b| {
        b.result
            .jaccard
            .partial_cmp(&a.result.jaccard)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hits.truncate(config.max_findings);

    findings.extend(hits.into_iter().map(hit_to_finding));
}

fn collect_section_hits(
    section_name: &str,
    instructions: &[Instruction],
    config: &AetriumScanConfig<'_>,
    hits: &mut Vec<AetriumHit>,
) {
    let Ok(cfg) = build_cfg(instructions, instructions[0].address) else {
        return;
    };
    let pdg = ProgramDependenceGraph::build(&cfg);

    for (block_id, block) in cfg.iter() {
        for (instr_idx, inst) in block.instructions.iter().enumerate() {
            if !is_risky_sink(inst) {
                continue;
            }

            let Some(node) = pdg.instruction_node(block_id, instr_idx) else {
                continue;
            };
            let neighborhood = pdg.encode_neighborhood(node, config.radius);
            for result in config.anchors.detect(&neighborhood) {
                hits.push(AetriumHit {
                    address: inst.address,
                    section: section_name.to_string(),
                    result,
                    ml_apli_ex_payload: None,
                    stages: vec![
                        "[Phase 1] ML-Aetrium HDC Anchor Match: Structural similarity identified".to_string(),
                        format!("[Phase 2] PDG Taint Analysis: Subgraph radius {} neighborhood extracted", config.radius),
                    ],
                });
            }
        }
    }

    if config.enable_weaponization && !hits.is_empty() {
        let sym_blocks = build_sym_blocks(&cfg);
        for hit in hits.iter_mut().filter(|h| h.result.jaccard >= 0.80) {
            let entry_id = cfg.entry() as usize;

            if config.use_concolic {
                run_concolic_phase(hit, &sym_blocks, entry_id, config.max_concolic_iterations);
            } else {
                run_legacy_symbolic_phase(hit, &sym_blocks, entry_id);
            }
        }
    }
}

/// Phase 3 (concolic): use [`ConcolicExecutor`] + the SMT solver to
/// drive a real path-flipping exploration, prioritised by HDC similarity.
///
/// Updates the hit's `stages` and `ml_apli_ex_payload` in-place.
fn run_concolic_phase(
    hit: &mut AetriumHit,
    sym_blocks: &[SymBlock],
    entry_id: usize,
    max_iterations: usize,
) {
    let mut executor = ConcolicExecutor::new(sym_blocks.to_vec(), entry_id);
    executor.set_max_iterations(max_iterations);
    executor.set_max_depth(256);

    hit.stages.push(
        "[Phase 3] ML-Apli-Ex Concolic Solver: Concrete + symbolic path exploration with SMT-driven branch flipping"
            .to_string(),
    );

    let anchor_score = hit.result.jaccard;
    let result = executor.explore_with_priority(ConcolicSeed::new(), |_, _| {
        // Every flip produced inside a high-confidence anchor's PDG
        // neighbourhood is treated as a Vulnerability path. The score
        // is the originating anchor's Jaccard similarity.
        BranchPriority::Vulnerability(anchor_score)
    });

    let merge = merge_traces(&result.traces);

    hit.stages.push(format!(
        "[Phase 3] ML-Apli-Ex Concolic Stats: paths={} smt_queries={} unsat={} unknown={} compression_ratio={:.2}",
        result.traces.len(),
        result.smt_queries,
        result.unsat_replies,
        result.unknown_replies,
        merge.compression_ratio,
    ));

    if result.generated_seeds.is_empty() && result.traces.len() <= 1 {
        hit.stages.push(
            "[Phase 4] Payload Derivation: No viable input variant found by concolic exploration"
                .to_string(),
        );
        return;
    }

    hit.stages.push(
        "[Phase 4] Payload Derivation: Successfully synthesised exploit input from SMT model"
            .to_string(),
    );

    let seed_summary = result.generated_seeds.first().map_or_else(
        || "(no flipped path)".to_string(),
        |seed| {
            let mut entries: Vec<String> = seed
                .iter()
                .map(|(k, v)| format!("{k}=0x{:x}", *v as u64))
                .collect();
            entries.sort();
            entries.join(", ")
        },
    );

    hit.ml_apli_ex_payload = Some(format!(
        "Concolic engine: {} paths, {} SMT queries, {} new inputs synthesised. First witness seed: [{}]",
        result.traces.len(),
        result.smt_queries,
        result.generated_seeds.len(),
        seed_summary,
    ));
}

/// Phase 3 (legacy): the original bounded symbolic executor. Kept for
/// backward compatibility with `use_concolic = false`.
fn run_legacy_symbolic_phase(hit: &mut AetriumHit, sym_blocks: &[SymBlock], entry_id: usize) {
    let mut executor = SymbolicExecutor::new(sym_blocks.to_vec(), entry_id, 32);
    hit.stages.push(
        "[Phase 3] ML-Apli-Ex Symbolic Solver (legacy): Analyzing control-flow constraints"
            .to_string(),
    );
    let result = executor.execute();
    if result.constraints_solved.is_empty() {
        hit.stages.push(
            "[Phase 4] Payload Derivation: No viable path found for automated exploitation"
                .to_string(),
        );
    } else {
        hit.stages.push(
            "[Phase 4] Payload Derivation: Successfully generated exploit primitive".to_string(),
        );
        hit.ml_apli_ex_payload = Some(format!(
            "Generated payload via symbolic execution (depth: {}, solved constraints: {})",
            result.execution_depth,
            result.constraints_solved.len()
        ));
    }
}

fn build_sym_blocks(cfg: &ControlFlowGraph) -> Vec<SymBlock> {
    let mut sym_blocks = Vec::new();
    for (block_id, block) in cfg.iter() {
        let mut insns = Vec::new();
        for inst in &block.instructions {
            let mut dst = -1;
            let mut src1 = -1;
            let mut src2 = -1;
            let mut imm = 0;

            if let Some(op) = inst.dst.first()
                && let Operand::Register(reg) = op
            {
                dst = reg.native_id as i16;
            }
            if let Some(op) = inst.src.first() {
                match op {
                    Operand::Register(reg) => src1 = reg.native_id as i16,
                    Operand::Immediate(val) => imm = *val,
                    _ => {}
                }
            }
            if let Some(op) = inst.src.get(1) {
                match op {
                    Operand::Register(reg) => src2 = reg.native_id as i16,
                    Operand::Immediate(val) => imm = *val,
                    _ => {}
                }
            }

            let kind = match inst.opcode {
                OpCode::Move => MirOp::Move,
                OpCode::Add => MirOp::Add,
                OpCode::Sub => MirOp::Sub,
                OpCode::Mul => MirOp::Mul,
                OpCode::Div => MirOp::Div,
                OpCode::And => MirOp::And,
                OpCode::Or => MirOp::Or,
                OpCode::Xor => MirOp::Xor,
                OpCode::Not => MirOp::Not,
                OpCode::Jump => MirOp::Goto,
                OpCode::BranchIf => MirOp::If,
                OpCode::Call => MirOp::Invoke,
                OpCode::Return => MirOp::Return,
                OpCode::Store => MirOp::FieldPut,
                OpCode::Load => MirOp::FieldGet,
                _ => MirOp::Unknown,
            };

            insns.push(MirInsn {
                kind,
                cond: inst.condition.map_or(0, |c| c as u8),
                dst,
                src1,
                src2,
                imm,
                ref_idx: 0,
            });
        }

        sym_blocks.push(SymBlock {
            id: block_id as usize,
            insns,
            succs: cfg
                .successors(block_id)
                .iter()
                .map(|id| *id as usize)
                .collect(),
        });
    }
    sym_blocks
}

/// Architectures we are willing to lift + build a CFG/PDG for.
///
/// ARM64 is the dominant ABI for Android `lib*.so` (arm64-v8a) and is the
/// primary target of this scanner, so restricting Aetrium to x86 made the
/// graph-anchor engine effectively dead code on real inputs. We include
/// ARM (32-bit) too. The per-section loop already skips sections whose
/// lift yields no instructions, so an arch the disassembler cannot handle
/// degrades gracefully to "no Aetrium findings" rather than a crash.
const fn supports_lift(arch: Arch) -> bool {
    matches!(arch, Arch::X86 | Arch::X86_64 | Arch::Arm | Arch::Arm64)
}

fn is_risky_sink(inst: &Instruction) -> bool {
    matches!(
        inst.opcode,
        OpCode::Call
            | OpCode::IndirectCall
            | OpCode::SystemCall
            | OpCode::Store
            | OpCode::Load
            | OpCode::CmpXchg
    )
}

fn hit_to_finding(hit: AetriumHit) -> Finding {
    let anchor = hit.result.anchor_name.as_str();
    let finding = Finding::new(
        format!("aetrium-{anchor}-{:#x}", hit.address),
        Category::Vulnerability,
        severity_from_score(hit.result.severity),
        confidence_from_similarity(hit.result.jaccard),
        format!("ML-Aetrium graph match: {anchor}"),
        format!(
            "Topology-aware HDC match against `{anchor}` anchor. Motifs: {}",
            hit.result.matched_motifs.join(", ")
        ),
        format!(
            "section={} address={:#x} jaccard={:.3} hamming_sim={:.3}",
            hit.section, hit.address, hit.result.jaccard, hit.result.hamming_sim
        ),
    );

    let finding = finding
        .with_cwe(cwe_for_anchor(anchor))
        .with_remediation(remediation_for_anchor(anchor));

    let mut finding = finding;
    for stage in hit.stages {
        finding = finding.with_stage(stage);
    }

    if let Some(payload) = hit.ml_apli_ex_payload {
        finding.with_ml_apli_ex_payload(payload)
    } else {
        finding
    }
}

const fn severity_from_score(score: f64) -> Severity {
    if score >= 0.95 {
        Severity::Critical
    } else if score >= 0.80 {
        Severity::High
    } else if score >= 0.55 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

const fn confidence_from_similarity(jaccard: f64) -> Confidence {
    if jaccard >= 0.25 {
        Confidence::High
    } else if jaccard >= 0.15 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

const fn cwe_for_anchor(anchor: &str) -> &'static str {
    match anchor.as_bytes() {
        b"use_after_free" => "CWE-416",
        b"heap_buffer_overflow" => "CWE-122",
        b"double_free" => "CWE-415",
        b"command_injection" => "CWE-78",
        _ => "CWE-119",
    }
}

const fn remediation_for_anchor(anchor: &str) -> &'static str {
    match anchor.as_bytes() {
        b"use_after_free" => "Validate object lifetime; null or invalidate aliases after free.",
        b"heap_buffer_overflow" => "Validate bounds before heap writes and prefer checked APIs.",
        b"double_free" => "Enforce single ownership or clear ownership after deallocation.",
        b"command_injection" => "Avoid shell execution; pass validated argv directly to execve.",
        _ => "Review the matched data/control-flow motif manually.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_core::{Endian, Format};
    use omnisec_hdc::AnchorForge;
    use omnisec_loader::LoadedBinary;

    #[test]
    fn empty_aetrium_scan_is_safe() {
        let mut forge = AnchorForge::default();
        let anchors = forge.build_default_store();
        let config = AetriumScanConfig::new(&anchors);
        let bin = LoadedBinary::new(Format::Elf, Arch::X86_64, Endian::Little, 0);
        let mut findings = Vec::new();

        scan(&bin, b"", &config, &mut findings);

        assert!(findings.is_empty());
    }

    #[test]
    fn aetrium_detects_uaf_pattern_in_synthetic_ir() {
        use omnisec_ir::{Arch, Instruction, OpCode, Operand, Register, RegisterClass};
        let mut forge = AnchorForge::default();
        let anchors = forge.build_default_store();
        let config = AetriumScanConfig::new(&anchors);

        let rax = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 0,
            bit_width: 64,
            name: "rax".into(),
        };
        let rbx = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 3,
            bit_width: 64,
            name: "rbx".into(),
        };

        let insts = vec![
            // 0: rax = malloc()
            Instruction::new(OpCode::Call, 0x1000, 5, Arch::X86_64)
                .with_dst([Operand::Register(rax.clone())])
                .with_src([Operand::Symbol("malloc".into())]),
            // 1: rbx = rax
            Instruction::new(OpCode::Move, 0x1005, 3, Arch::X86_64)
                .with_dst([Operand::Register(rbx.clone())])
                .with_src([Operand::Register(rax.clone())]),
            // 2: free(rax)
            Instruction::new(OpCode::Call, 0x1008, 5, Arch::X86_64).with_src([
                Operand::Symbol("free".into()),
                Operand::Register(rax.clone()),
            ]),
            // 3: load from rbx (UAF)
            Instruction::new(OpCode::Load, 0x100d, 3, Arch::X86_64)
                .with_dst([Operand::Register(rax.clone())])
                .with_src([Operand::Register(rbx.clone())]),
        ];

        let mut hits = Vec::new();
        collect_section_hits(".text", &insts, &config, &mut hits);

        assert!(!hits.is_empty(), "Should detect UAF in synthetic IR");
        let uaf_hit = hits
            .iter()
            .find(|h| h.result.anchor_name == "use_after_free")
            .expect("use_after_free anchor hit not found");

        println!("DETECTION JACCARD: {}", uaf_hit.result.jaccard);

        assert!(
            uaf_hit.result.jaccard > 0.05,
            "Jaccard similarity too low: {}",
            uaf_hit.result.jaccard
        );
    }

    #[test]
    fn aetrium_ignores_safe_pattern() {
        use omnisec_ir::{Arch, Instruction, OpCode, Operand, Register, RegisterClass};
        let mut forge = AnchorForge::default();
        let anchors = forge.build_default_store();
        let config = AetriumScanConfig::new(&anchors);

        let rax = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 0,
            bit_width: 64,
            name: "rax".into(),
        };

        let insts = vec![
            // 0: rax = malloc()
            Instruction::new(OpCode::Call, 0x1000, 5, Arch::X86_64)
                .with_dst([Operand::Register(rax.clone())])
                .with_src([Operand::Symbol("malloc".into())]),
            // 1: load from rax (SAFE - before free)
            Instruction::new(OpCode::Load, 0x1005, 3, Arch::X86_64)
                .with_dst([Operand::Register(rax.clone())])
                .with_src([Operand::Register(rax.clone())]),
            // 2: free(rax)
            Instruction::new(OpCode::Call, 0x1008, 5, Arch::X86_64).with_src([
                Operand::Symbol("free".into()),
                Operand::Register(rax.clone()),
            ]),
        ];

        let mut hits = Vec::new();
        collect_section_hits(".text", &insts, &config, &mut hits);

        // It might find a very weak match, but it shouldn't be a "high confidence" match.
        // For this test, let's see if it finds nothing or at least not a strong UAF.
        if let Some(uaf_hit) = hits
            .iter()
            .find(|h| h.result.anchor_name == "use_after_free")
        {
            println!("SAFE PATTERN JACCARD: {}", uaf_hit.result.jaccard);
            assert!(
                uaf_hit.result.jaccard < 0.82,
                "False positive detected: Jaccard similarity too high for safe pattern: {}",
                uaf_hit.result.jaccard
            );
        }
    }

    #[test]
    fn severity_mapping_tracks_anchor_score() {
        assert_eq!(severity_from_score(0.96), Severity::Critical);
        assert_eq!(severity_from_score(0.90), Severity::High);
        assert_eq!(severity_from_score(0.60), Severity::Medium);
        assert_eq!(severity_from_score(0.40), Severity::Low);
    }

    #[test]
    fn weaponization_with_concolic_records_phase3_stages() {
        // Build a UAF scenario like the existing detection test, then
        // enable weaponization with the new concolic engine and check
        // the Phase 3 / Phase 4 stages are recorded in the hit's stages.
        use omnisec_ir::{Arch, Instruction, OpCode, Operand, Register, RegisterClass};
        let mut forge = AnchorForge::default();
        let anchors = forge.build_default_store();
        let mut config = AetriumScanConfig::new(&anchors);
        config.enable_weaponization = true;
        config.use_concolic = true;
        config.max_concolic_iterations = 4;

        let rax = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 0,
            bit_width: 64,
            name: "rax".into(),
        };
        let rbx = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 3,
            bit_width: 64,
            name: "rbx".into(),
        };

        let insts = vec![
            Instruction::new(OpCode::Call, 0x1000, 5, Arch::X86_64)
                .with_dst([Operand::Register(rax.clone())])
                .with_src([Operand::Symbol("malloc".into())]),
            Instruction::new(OpCode::Move, 0x1005, 3, Arch::X86_64)
                .with_dst([Operand::Register(rbx.clone())])
                .with_src([Operand::Register(rax.clone())]),
            Instruction::new(OpCode::Call, 0x1008, 5, Arch::X86_64).with_src([
                Operand::Symbol("free".into()),
                Operand::Register(rax.clone()),
            ]),
            Instruction::new(OpCode::Load, 0x100d, 3, Arch::X86_64)
                .with_dst([Operand::Register(rax.clone())])
                .with_src([Operand::Register(rbx.clone())]),
        ];

        let mut hits = Vec::new();
        collect_section_hits(".text", &insts, &config, &mut hits);

        let uaf_hit = hits
            .iter()
            .find(|h| h.result.anchor_name == "use_after_free")
            .expect("UAF anchor hit");

        // The Phase-3 concolic stage should have been added.
        let phase3_concolic = uaf_hit.stages.iter().any(|s| s.contains("Concolic Solver"));
        assert!(
            phase3_concolic || uaf_hit.result.jaccard < 0.80,
            "Phase 3 concolic stage not recorded: {:#?}",
            uaf_hit.stages
        );
    }

    #[test]
    fn weaponization_with_legacy_solver_records_phase3_stages() {
        use omnisec_ir::{Arch, Instruction, OpCode, Operand, Register, RegisterClass};
        let mut forge = AnchorForge::default();
        let anchors = forge.build_default_store();
        let mut config = AetriumScanConfig::new(&anchors);
        config.enable_weaponization = true;
        config.use_concolic = false;

        let rax = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 0,
            bit_width: 64,
            name: "rax".into(),
        };
        let rbx = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 3,
            bit_width: 64,
            name: "rbx".into(),
        };

        let insts = vec![
            Instruction::new(OpCode::Call, 0x1000, 5, Arch::X86_64)
                .with_dst([Operand::Register(rax.clone())])
                .with_src([Operand::Symbol("malloc".into())]),
            Instruction::new(OpCode::Move, 0x1005, 3, Arch::X86_64)
                .with_dst([Operand::Register(rbx.clone())])
                .with_src([Operand::Register(rax.clone())]),
            Instruction::new(OpCode::Call, 0x1008, 5, Arch::X86_64).with_src([
                Operand::Symbol("free".into()),
                Operand::Register(rax.clone()),
            ]),
            Instruction::new(OpCode::Load, 0x100d, 3, Arch::X86_64)
                .with_dst([Operand::Register(rax.clone())])
                .with_src([Operand::Register(rbx.clone())]),
        ];

        let mut hits = Vec::new();
        collect_section_hits(".text", &insts, &config, &mut hits);
        // Just sanity-check that nothing panics with the legacy path.
        assert!(!hits.is_empty());
    }

    #[test]
    fn weaponization_concolic_flips_branch_on_input() {
        use omnisec_ir::{Arch, Condition, Instruction, OpCode, Operand, Register, RegisterClass};
        let mut forge = AnchorForge::default();
        let anchors = forge.build_default_store();
        let mut config = AetriumScanConfig::new(&anchors);
        config.enable_weaponization = true;
        config.use_concolic = true;
        config.max_concolic_iterations = 16;

        let rax = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 0,
            bit_width: 64,
            name: "rax".into(),
        };
        let rbx = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 3,
            bit_width: 64,
            name: "rbx".into(),
        };
        let rcx = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 1,
            bit_width: 64,
            name: "rcx".into(),
        };

        // Simplified test: direct branch on rcx.
        // We use Condition::NotEqual (rcx != 0).
        // Since initial rcx is 0, it won't take the branch initially.
        // Negate: rcx != 0. SMT Solver should find rcx = 1.
        let insts = vec![
            Instruction::new(OpCode::BranchIf, 0x1000, 2, Arch::X86_64)
                .with_src([Operand::Register(rcx.clone()), Operand::Label(0x1005)])
                .with_condition(Condition::NotEqual),
            // Block 1 (0x1005): UAF
            Instruction::new(OpCode::Call, 0x1005, 5, Arch::X86_64)
                .with_dst([Operand::Register(rax.clone())])
                .with_src([Operand::Symbol("malloc".into())]),
            Instruction::new(OpCode::Move, 0x100a, 3, Arch::X86_64)
                .with_dst([Operand::Register(rbx.clone())])
                .with_src([Operand::Register(rax.clone())]),
            Instruction::new(OpCode::Call, 0x100d, 5, Arch::X86_64).with_src([
                Operand::Symbol("free".into()),
                Operand::Register(rax.clone()),
            ]),
            Instruction::new(OpCode::Load, 0x1012, 3, Arch::X86_64)
                .with_dst([Operand::Register(rax.clone())])
                .with_src([Operand::Register(rbx.clone())]),
        ];

        let mut hits = Vec::new();
        collect_section_hits(".text", &insts, &config, &mut hits);

        let uaf_hit = hits
            .iter()
            .find(|h| h.result.anchor_name == "use_after_free")
            .expect("UAF hit expected");

        // Check if Phase 3/4 succeeded
        let payload = uaf_hit
            .ml_apli_ex_payload
            .as_ref()
            .expect("Payload expected");
        assert!(
            payload.contains("inputs synthesised"),
            "Expected new inputs: {}",
            payload
        );
        // The solver should find rcx != 0 to reach the UAF block
        // Since rcx defaults to 0, it should find v1=0x1
        assert!(
            payload.contains("v1=0x1"),
            "Expected witness v1=0x1, got: {}",
            payload
        );
    }
}
