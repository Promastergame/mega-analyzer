//! ML Annotator — scores each step for the AI agent.
//!
//! Computes:
//!   - risk_score    (0.0–1.0) based on instruction type, entropy, patterns
//!   - entropy       (0.0–8.0) Shannon entropy of the memory window around RIP
//!   - entropy_delta (change in entropy vs previous step)
//!   - pattern_hits  YARA-like regex signatures
//!   - api_call      detected suspicious API
//!   - hdc_anchor    nearest HDC anchor name
//!   - hdc_similarity Hamming similarity to nearest anchor

use iced_x86::{Instruction as IcedInsn, Mnemonic, OpKind};
use omnisec_emu_x86::{CpuState, VirtualMemory};
use omnisec_json::{FromJson, ToJson};

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════════

/// Category of target memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum MemoryRegionKind {
    /// Executable code segment.
    Code,
    /// Thread stack memory.
    Stack,
    /// Allocated heap memory.
    Heap,
    /// Legitimate mapped dynamic library segment.
    MappedDll,
    /// Unmapped executable writable code segment (highly suspicious shellcode!).
    UnmappedWritableCode,
}

/// Rich context detailing the current machine step, stack frames, and symbol information.
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// Instruction pointer (PC/RIP).
    pub rip: u64,
    /// Current symbol name, if resolved.
    pub symbol: Option<String>,
    /// Associated source file and line mapping.
    pub source_location: Option<crate::backend::SourceLocation>,
    /// Current call stack frames.
    pub stack: Vec<crate::backend::StackFrame>,
    /// Available active local variables.
    pub variables: Vec<crate::backend::DebugVariable>,
    /// Mapped memory region category.
    pub memory_region: MemoryRegionKind,
}

/// ML-produced annotation for a single execution step.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MLAnnotation {
    /// Overall risk (0.0 = benign, 1.0 = critical).
    pub risk_score: f64,
    /// Shannon entropy of the memory slice at RIP (0.0–8.0).
    pub entropy: f64,
    /// Change in entropy since the previous step.
    pub entropy_delta: Option<f64>,
    /// HDC Hamming similarity to the closest anchor (0.0–1.0).
    pub hdc_similarity: f64,
    /// Name of the closest HDC anchor, if any.
    pub hdc_anchor: Option<String>,
    /// Pattern IDs that matched the current instruction / memory.
    pub pattern_hits: Vec<String>,
    /// Detected API call (e.g. "VirtualAlloc").
    pub api_call: Option<String>,
    /// Near branch/call target decoded from the instruction, when present.
    pub branch_target: Option<u64>,
    /// Human-readable reasoning for the scores.
    pub reason: Vec<String>,
    /// Suggested next actions for the AI agent.
    pub next_actions: Vec<SuggestedAction>,
    /// Confidence in this annotation (0.0–1.0).
    pub confidence: f64,
}

/// A concrete action the strategy engine (or AI) may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuggestedAction {
    /// Dump a memory region.
    DumpMemoryRegion {
        /// Start address.
        addr: u64,
        /// Size in bytes.
        size: usize,
    },
    /// Scan for printable strings.
    ScanPrintableStrings {
        /// Start address.
        addr: u64,
        /// Size in bytes.
        size: usize,
    },
    /// Create a checkpoint at the current state.
    CheckpointHere,
    /// Step one instruction.
    StepInto,
    /// Continue execution until a call instruction is reached.
    ContinueUntilCall,
    /// Explore a specific branch.
    ExploreBranch {
        /// Destination branch address.
        target: u64,
    },
    /// Set a breakpoint.
    SetBreakpoint {
        /// Target address.
        addr: u64,
    },
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML ANNOTATOR
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-based code/execution annotator that computes execution risks and patterns.
#[derive(Debug)]
pub struct MLAnnotator {
    prev_entropy: Option<f64>,
    /// Simple pattern database: (id, regex-like substrings).
    patterns: Vec<(String, Vec<String>)>,
    /// Known suspicious API names.
    suspicious_apis: Vec<String>,
}

impl Default for MLAnnotator {
    fn default() -> Self {
        Self::new()
    }
}

impl MLAnnotator {
    /// Creates a new instance of `MLAnnotator` with default patterns loaded.
    pub fn new() -> Self {
        let mut s = Self {
            prev_entropy: None,
            patterns: Vec::new(),
            suspicious_apis: Vec::new(),
        };
        s.load_builtin_patterns();
        s
    }

    /// Annotate a single step.
    pub fn annotate(
        &mut self,
        context: &AnalysisContext,
        memory: &VirtualMemory,
        insn: &IcedInsn,
    ) -> MLAnnotation {
        let rip = context.rip;
        let window = read_memory_window(memory, rip, 256).unwrap_or_default();

        let entropy = shannon_entropy(&window);
        let entropy_delta = self.prev_entropy.map(|pe| entropy - pe);
        self.prev_entropy = Some(entropy);

        let pattern_hits = self.match_patterns(insn, &window);
        let api_call = self.detect_api_call(insn, context);
        let branch_target = near_branch_target(insn);

        let mut risk = self.compute_risk(
            insn,
            entropy,
            entropy_delta,
            &pattern_hits,
            api_call.as_deref(),
        );

        let mut reason = Vec::new();
        if entropy > 7.0 {
            reason.push("high memory entropy (likely encrypted/packed)".into());
        }
        if let Some(delta) = entropy_delta {
            if delta < -1.5 {
                reason.push(format!(
                    "entropy dropped by {:.2} (decryption/unpacking)",
                    delta
                ));
            } else if delta > 1.5 {
                reason.push(format!(
                    "entropy spiked by {:.2} (packing/obfuscation)",
                    delta
                ));
            }
        }
        if !pattern_hits.is_empty() {
            reason.push(format!("matched patterns: {}", pattern_hits.join(", ")));
        }
        if let Some(ref api) = api_call {
            reason.push(format!("suspicious API: {}", api));
        }

        // Apply rule-based context diagnostics
        if context.memory_region == MemoryRegionKind::UnmappedWritableCode {
            risk = 1.0;
            reason.push("CRITICAL: Executing from unmapped writable/executable memory region (possible shellcode inject)".into());
        }

        // Call stack checks: if target caller frame is not a mapped DLL and not main code
        if context.stack.len() > 1 {
            let caller = &context.stack[1];
            if caller.symbol.is_none() && caller.pc > 0 {
                risk = (risk + 0.35).min(1.0);
                reason.push(format!(
                    "suspicious return frame to un-symbolicated address {:#x}",
                    caller.pc
                ));
            }
        }

        let next_actions = self.suggest_actions(risk, entropy, entropy_delta, &window, rip);

        MLAnnotation {
            risk_score: risk,
            entropy,
            entropy_delta,
            hdc_similarity: 0.0, // filled by HDC scanner
            hdc_anchor: None,
            pattern_hits,
            api_call,
            branch_target,
            reason,
            next_actions,
            confidence: risk.clamp(0.0, 1.0),
        }
    }

    // ── Pattern DB ───────────────────────────────────────────────────────────

    fn load_builtin_patterns(&mut self) {
        self.patterns.push((
            "crypto_loop".into(),
            vec![
                "xor".into(),
                "rol".into(),
                "ror".into(),
                "add".into(),
                "sub".into(),
            ],
        ));
        self.patterns.push((
            "string_decrypt".into(),
            vec!["xor".into(), "mov".into(), "inc".into(), "cmp".into()],
        ));
        self.patterns.push((
            "api_resolve".into(),
            vec![
                "GetProcAddress".into(),
                "LoadLibrary".into(),
                "GetModuleHandle".into(),
            ],
        ));
        self.patterns.push((
            "anti_debug".into(),
            vec![
                "IsDebuggerPresent".into(),
                "CheckRemoteDebuggerPresent".into(),
                "NtQueryInformationProcess".into(),
            ],
        ));
        self.patterns.push((
            "vm_check".into(),
            vec!["cpuid".into(), "in".into(), "sidt".into(), "sgdt".into()],
        ));

        self.suspicious_apis = vec![
            "VirtualAlloc".into(),
            "VirtualProtect".into(),
            "CreateThread".into(),
            "WriteProcessMemory".into(),
            "NtUnmapViewOfSection".into(),
            "GetProcAddress".into(),
            "LoadLibraryA".into(),
            "LoadLibraryW".into(),
            "IsDebuggerPresent".into(),
            "CheckRemoteDebuggerPresent".into(),
            "NtQueryInformationProcess".into(),
            "SetThreadContext".into(),
            "ResumeThread".into(),
            "CreateRemoteThread".into(),
        ];
    }

    fn match_patterns(&self, insn: &IcedInsn, _window: &[u8]) -> Vec<String> {
        let mut hits = Vec::new();
        let mnemonic_str = format!("{:?}", insn.mnemonic()).to_lowercase();

        for (id, keywords) in &self.patterns {
            for kw in keywords {
                if mnemonic_str.contains(kw) {
                    hits.push(id.clone());
                    break;
                }
            }
        }
        // Indirect calls/jumps (register or memory operand) are the classic
        // IAT-thunk / resolved-import shape: worth a mild pattern hit even
        // when no symbol matched.
        if matches!(insn.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
            && !matches!(
                insn.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        {
            hits.push("indirect_call".into());
        }
        hits.dedup();
        hits
    }

    fn detect_api_call(&self, insn: &IcedInsn, context: &AnalysisContext) -> Option<String> {
        // Only call instructions can be API calls.
        if insn.mnemonic() != Mnemonic::Call {
            return None;
        }
        // 1. Symbol resolved at RIP by the engine/session (import table hit).
        if let Some(name) = context
            .symbol
            .as_deref()
            .and_then(|s| self.match_suspicious_api(s))
        {
            return Some(name);
        }
        // 2. Symbols on the call stack (return addresses into imports).
        for frame in &context.stack {
            if let Some(name) = frame
                .symbol
                .as_deref()
                .and_then(|s| self.match_suspicious_api(s))
            {
                return Some(name);
            }
        }
        None
    }

    /// Case-insensitive substring match of a symbol against the suspicious
    /// API list. Returns the canonical API name on a hit.
    fn match_suspicious_api(&self, symbol: &str) -> Option<String> {
        let haystack = symbol.to_ascii_lowercase();
        // Strip common import prefixes (`IAT:`, `imp_`, `__imp_`, `.dll:`).
        let trimmed = haystack
            .trim_start_matches("iat:")
            .trim_start_matches("imp_")
            .trim_start_matches("__imp_");
        self.suspicious_apis
            .iter()
            .find(|api| {
                let needle = api.to_ascii_lowercase();
                trimmed.contains(&needle) || haystack.contains(&needle)
            })
            .cloned()
    }

    // ── Risk scoring ───────────────────────────────────────────────────────────

    fn compute_risk(
        &self,
        insn: &IcedInsn,
        entropy: f64,
        entropy_delta: Option<f64>,
        patterns: &[String],
        api_call: Option<&str>,
    ) -> f64 {
        let mut score = 0.0;

        // Entropy component (0.0–0.4)
        if entropy > 7.0 {
            score += 0.4;
        } else if entropy > 5.0 {
            score += 0.2;
        }

        // Entropy delta component (0.0–0.2)
        if let Some(delta) = entropy_delta {
            if delta.abs() > 2.0 {
                score += 0.2;
            } else if delta.abs() > 1.0 {
                score += 0.1;
            }
        }

        // Pattern component (0.0–0.2)
        for p in patterns {
            score += match p.as_str() {
                "crypto_loop" => 0.15,
                "api_resolve" => 0.1,
                "anti_debug" => 0.2,
                "vm_check" => 0.15,
                "string_decrypt" => 0.1,
                "indirect_call" => 0.05,
                _ => 0.05,
            };
        }

        // API call component (0.0–0.2)
        if api_call.is_some() {
            score += 0.2;
        }

        // Instruction-level heuristics
        let mnemonic_str = format!("{:?}", insn.mnemonic()).to_lowercase();
        if mnemonic_str.contains("int3") {
            score += 0.1; // breakpoint / anti-debug
        }

        f64::min(score, 1.0)
    }

    // ── Action suggestion ──────────────────────────────────────────────────────

    fn suggest_actions(
        &self,
        risk: f64,
        entropy: f64,
        entropy_delta: Option<f64>,
        _window: &[u8],
        rip: u64,
    ) -> Vec<SuggestedAction> {
        let mut actions = Vec::new();

        if risk > 0.7 {
            actions.push(SuggestedAction::CheckpointHere);
        }
        if entropy > 6.0 {
            actions.push(SuggestedAction::DumpMemoryRegion {
                addr: rip.saturating_sub(64),
                size: 256,
            });
        }
        if let Some(delta) = entropy_delta
            && delta < -1.0
        {
            actions.push(SuggestedAction::ScanPrintableStrings {
                addr: rip.saturating_sub(128),
                size: 512,
            });
        }
        if risk > 0.5 {
            actions.push(SuggestedAction::StepInto);
        }
        actions
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/// Strategy chosen by the engine based on MLAnnotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Default: step one instruction.
    Step,
    /// Follow interesting branch.
    ExploreBranch {
        /// The destination address of the branch to explore.
        target: u64,
    },
    /// Fast-forward through loop.
    FastForwardLoop,
    /// Dump and scan memory.
    DumpAndScan,
    /// Save checkpoint.
    Checkpoint,
    /// Stop: reached critical finding.
    Stop,
}

/// Engine that decides the exploration strategy based on risk scores.
pub struct StrategyEngine;

impl StrategyEngine {
    /// Pick the best strategy given the current ML annotation.
    pub fn decide(annotation: &MLAnnotation, _state: &CpuState) -> Strategy {
        let score = annotation.risk_score * 0.4
            + annotation.hdc_similarity * 0.3
            + annotation.entropy_delta.map_or(0.0, |d| d.abs() * 0.1)
            + annotation.pattern_hits.len() as f64 * 0.05;

        if score > 0.75 {
            Strategy::Stop
        } else if score > 0.6 {
            Strategy::Checkpoint
        } else if annotation.entropy_delta.is_some_and(|d| d < -1.0) {
            Strategy::DumpAndScan
        } else if annotation.risk_score > 0.4 {
            // Follow the decoded branch target when we have one;
            // fall back to single-stepping otherwise.
            match annotation.branch_target {
                Some(target) => Strategy::ExploreBranch { target },
                None => Strategy::Step,
            }
        } else {
            Strategy::Step
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

fn read_memory_window(mem: &VirtualMemory, addr: u64, size: usize) -> Result<Vec<u8>, ()> {
    mem.read(addr, size).map_err(|_| ())
}

/// Decoded near branch/call target, when the instruction carries one.
fn near_branch_target(insn: &IcedInsn) -> Option<u64> {
    if insn.is_call_near() || insn.is_jmp_near() || insn.is_jcc_short() || insn.is_jcc_near() {
        Some(insn.near_branch_target())
    } else {
        None
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    // Tests intentionally compare against exact, representable constants
    // (0.0, 1.0, hand-computed values); the lint would only add noise here.
    #![allow(clippy::float_cmp)]
    use super::*;
    use iced_x86::Decoder;

    fn dummy_insn(bytes: &[u8]) -> IcedInsn {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, iced_x86::DecoderOptions::NONE);
        decoder.decode()
    }

    #[test]
    fn entropy_all_same() {
        assert_eq!(shannon_entropy(&[0xAB; 256]), 0.0);
    }

    #[test]
    fn entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!(
            (e - 8.0).abs() < 0.01,
            "uniform entropy = {}, expected ~8.0",
            e
        );
    }

    #[test]
    fn ml_annotator_nop_is_benign() {
        let mut annotator = MLAnnotator::new();
        let insn = dummy_insn(&[0x90]); // nop
        let mem = VirtualMemory::new();
        let context = AnalysisContext {
            rip: 0x1000,
            symbol: None,
            source_location: None,
            stack: Vec::new(),
            variables: Vec::new(),
            memory_region: MemoryRegionKind::Code,
        };
        let ann = annotator.annotate(&context, &mem, &insn);
        assert!(
            ann.risk_score < 0.3,
            "nop should be low risk, got {}",
            ann.risk_score
        );
    }

    #[test]
    fn strategy_engine_high_risk_checkpoints() {
        let ann = MLAnnotation {
            risk_score: 0.95,
            entropy: 7.5,
            hdc_similarity: 0.9,
            ..Default::default()
        };
        let state = CpuState::default();
        let strat = StrategyEngine::decide(&ann, &state);
        assert_eq!(strat, Strategy::Checkpoint);
    }

    #[test]
    fn strategy_engine_critical_risk_stops() {
        let ann = MLAnnotation {
            risk_score: 0.99,
            entropy: 7.9,
            hdc_similarity: 0.99,
            pattern_hits: vec!["crypto".to_string(), "unpack".to_string()],
            ..Default::default()
        };
        let state = CpuState::default();
        let strat = StrategyEngine::decide(&ann, &state);
        assert_eq!(strat, Strategy::Stop);
    }

    fn context_with_symbol(symbol: Option<&str>) -> AnalysisContext {
        AnalysisContext {
            rip: 0x1000,
            symbol: symbol.map(str::to_string),
            source_location: None,
            stack: Vec::new(),
            variables: Vec::new(),
            memory_region: MemoryRegionKind::Code,
        }
    }

    #[test]
    fn detect_api_call_matches_suspicious_import() {
        let annotator = MLAnnotator::new();
        // call rel32
        let insn = dummy_insn(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(insn.mnemonic(), Mnemonic::Call);
        let context = context_with_symbol(Some("__imp_VirtualAlloc"));
        let mem = VirtualMemory::new();
        let ann = annotator_annotate(&annotator, &context, &mem, &insn);
        assert_eq!(ann.api_call.as_deref(), Some("VirtualAlloc"));
        assert!(ann.risk_score >= 0.2, "api hit must raise risk");
    }

    #[test]
    fn detect_api_call_ignores_benign_symbols() {
        let mut annotator = MLAnnotator::new();
        let insn = dummy_insn(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        let context = context_with_symbol(Some("memcpy"));
        let mem = VirtualMemory::new();
        let ann = annotator.annotate(&context, &mem, &insn);
        assert_eq!(ann.api_call, None);
    }

    #[test]
    fn branch_target_recorded_for_near_calls() {
        let mut annotator = MLAnnotator::new();
        let insn = dummy_insn(&[0xE8, 0x10, 0x00, 0x00, 0x00]);
        let context = context_with_symbol(None);
        let mem = VirtualMemory::new();
        let ann = annotator.annotate(&context, &mem, &insn);
        assert_eq!(ann.branch_target, Some(0x1000 + 5 + 0x10));
        // Strategy follows the decoded target instead of address zero.
        let strat = StrategyEngine::decide(
            &MLAnnotation {
                risk_score: 0.5,
                ..ann
            },
            &CpuState::default(),
        );
        assert_eq!(
            strat,
            Strategy::ExploreBranch {
                target: 0x1000 + 5 + 0x10
            }
        );
    }

    // Non-mutating helper so earlier tests keep working unchanged.
    fn annotator_annotate(
        annotator: &MLAnnotator,
        context: &AnalysisContext,
        mem: &VirtualMemory,
        insn: &IcedInsn,
    ) -> MLAnnotation {
        let mut clone = MLAnnotator {
            prev_entropy: None,
            patterns: annotator.patterns.clone(),
            suspicious_apis: annotator.suspicious_apis.clone(),
        };
        clone.annotate(context, mem, insn)
    }
}
