//! Virtualization detector — analyzes CFG blocks for VM-based obfuscation.

use std::fmt::Write;

use crate::patterns::{
    DetectionResult, DetectionStats, VirtualizationPattern, VirtualizationTechnique,
};

/// MIR opcode kinds (must match Go constants).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirOp {
    /// No-op.
    Nop = 0,
    /// Constant.
    Const = 1,
    /// Move.
    Move = 2,
    /// Add.
    Add = 3,
    /// Sub.
    Sub = 4,
    /// Mul.
    Mul = 5,
    /// Div.
    Div = 6,
    /// Rem.
    Rem = 7,
    /// And.
    And = 8,
    /// Or.
    Or = 9,
    /// Xor.
    Xor = 10,
    /// Not.
    Not = 11,
    /// If.
    If = 12,
    /// Goto.
    Goto = 13,
    /// Switch.
    Switch = 14,
    /// Return.
    Return = 15,
    /// Field get.
    FieldGet = 16,
    /// Field put.
    FieldPut = 17,
    /// Array get.
    ArrayGet = 18,
    /// Array put.
    ArrayPut = 19,
    /// Invoke.
    Invoke = 20,
    /// New instance.
    NewInstance = 21,
    /// New array.
    NewArray = 22,
    /// Shl.
    Shl = 23,
    /// Shr.
    Shr = 24,
    /// Unknown.
    Unknown = 255,
}

impl From<u8> for MirOp {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Nop,
            1 => Self::Const,
            2 => Self::Move,
            3 => Self::Add,
            4 => Self::Sub,
            5 => Self::Mul,
            6 => Self::Div,
            7 => Self::Rem,
            8 => Self::And,
            9 => Self::Or,
            10 => Self::Xor,
            11 => Self::Not,
            12 => Self::If,
            13 => Self::Goto,
            14 => Self::Switch,
            15 => Self::Return,
            16 => Self::FieldGet,
            17 => Self::FieldPut,
            18 => Self::ArrayGet,
            19 => Self::ArrayPut,
            20 => Self::Invoke,
            21 => Self::NewInstance,
            22 => Self::NewArray,
            23 => Self::Shl,
            24 => Self::Shr,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for MirOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Minimal MIR instruction for detection.
#[derive(Debug, Clone)]
pub struct VirtInsn {
    /// Opcode.
    pub kind: MirOp,
    /// Destination register.
    pub dst: i16,
    /// Source register 1.
    pub src1: i16,
    /// Source register 2.
    pub src2: i16,
    /// Immediate.
    pub imm: i64,
    /// Reference index.
    pub ref_idx: u32,
}

/// Basic block for virtualization detection.
#[derive(Debug, Clone)]
pub struct VirtBlock {
    /// Block ID.
    pub id: usize,
    /// Instructions.
    pub insns: Vec<VirtInsn>,
    /// Successor block IDs.
    pub succs: Vec<usize>,
}

/// The main virtualization detector.
pub struct VirtualizationDetector {
    blocks: Vec<VirtBlock>,
    patterns: Vec<VirtualizationPattern>,
    trace: Vec<String>,
    changes: usize,
    confidence_threshold: u8,
}

impl VirtualizationDetector {
    /// Create a new detector.
    pub fn new(blocks: Vec<VirtBlock>) -> Self {
        Self {
            blocks,
            patterns: Vec::new(),
            trace: Vec::new(),
            changes: 0,
            confidence_threshold: 50,
        }
    }

    /// Set the confidence threshold for including patterns.
    pub fn set_confidence_threshold(&mut self, threshold: u8) {
        self.confidence_threshold = threshold;
    }

    /// Run all detection passes and return results.
    pub fn detect(&mut self) -> DetectionResult {
        if self.blocks.is_empty() {
            self.trace.push("No blocks to analyze".into());
            return self.build_result();
        }

        self.trace.push(format!(
            "Starting virtualization detection on {} blocks",
            self.blocks.len()
        ));

        self.detect_dispatcher_patterns();
        self.detect_interpreter_patterns();
        self.detect_obfuscated_bytecode_patterns();
        self.detect_custom_vm_patterns();

        self.trace.push(format!(
            "Detected {} virtualization patterns",
            self.patterns.len()
        ));

        self.build_result()
    }

    // ─── Dispatcher detection ───────────────────────────────────────

    fn detect_dispatcher_patterns(&mut self) {
        let block_data: Vec<(usize, usize, bool, bool, bool)> = self
            .blocks
            .iter()
            .map(|b| {
                (
                    b.id,
                    b.succs.len(),
                    self.is_switch_dispatcher(b),
                    self.is_table_dispatcher(b),
                    self.is_computed_goto_dispatcher(b),
                )
            })
            .collect();

        for (id, _, is_switch, is_table, is_computed) in block_data {
            if is_switch && let Some(p) = self.analyze_switch_dispatcher(id) {
                self.patterns.push(p);
                self.changes += 1;
            }
            if is_table && let Some(p) = self.analyze_table_dispatcher(id) {
                self.patterns.push(p);
                self.changes += 1;
            }
            if is_computed && let Some(p) = self.analyze_computed_goto(id) {
                self.patterns.push(p);
                self.changes += 1;
            }
        }
    }

    fn is_switch_dispatcher(&self, block: &VirtBlock) -> bool {
        if block.insns.is_empty() {
            return false;
        }
        let last = &block.insns[block.insns.len() - 1];
        if last.kind == MirOp::Switch {
            return true;
        }
        last.kind == MirOp::If && block.succs.len() > 2
    }

    fn is_table_dispatcher(&self, block: &VirtBlock) -> bool {
        for (i, insn) in block.insns.iter().enumerate() {
            if insn.kind == MirOp::ArrayGet && i + 1 < block.insns.len() {
                let next = &block.insns[i + 1];
                if next.kind == MirOp::Goto || next.kind == MirOp::If {
                    return true;
                }
            }
        }
        false
    }

    fn is_computed_goto_dispatcher(&self, block: &VirtBlock) -> bool {
        for (i, insn) in block.insns.iter().enumerate() {
            if matches!(insn.kind, MirOp::Add | MirOp::Mul | MirOp::Shl | MirOp::Shr)
                && i + 1 < block.insns.len()
                && block.insns[i + 1].kind == MirOp::Goto
            {
                return true;
            }
        }
        false
    }

    fn analyze_switch_dispatcher(&self, block_id: usize) -> Option<VirtualizationPattern> {
        let block = self.blocks.iter().find(|b| b.id == block_id)?;

        let mut opcodes = Vec::new();
        for (i, succ_id) in block.succs.iter().enumerate() {
            if let Some(succ) = self.blocks.iter().find(|b| b.id == *succ_id)
                && !succ.insns.is_empty()
                && succ.insns[0].kind == MirOp::Const
            {
                opcodes.push(i as u32);
            }
        }

        let annotations: Vec<String> = block
            .insns
            .iter()
            .map(|insn| format!("{} [dispatcher]", insn.kind))
            .collect();

        Some(VirtualizationPattern {
            technique: VirtualizationTechnique::Dispatcher,
            block_id,
            insn_index: 0,
            dispatcher_block_id: Some(block_id),
            dispatcher_type: "switch".into(),
            virtual_opcodes: opcodes,
            confidence: 75,
            rationale: format!(
                "Switch-based dispatcher with {} branches detected",
                block.succs.len()
            ),
            annotated_instructions: annotations,
        })
    }

    fn analyze_table_dispatcher(&self, block_id: usize) -> Option<VirtualizationPattern> {
        let block = self.blocks.iter().find(|b| b.id == block_id)?;

        let opcodes: Vec<u32> = block
            .insns
            .iter()
            .enumerate()
            .filter(|(_, insn)| insn.kind == MirOp::ArrayGet)
            .map(|(i, _)| i as u32)
            .collect();

        let annotations: Vec<String> = block
            .insns
            .iter()
            .map(|insn| format!("{} [table_dispatch]", insn.kind))
            .collect();

        Some(VirtualizationPattern {
            technique: VirtualizationTechnique::Dispatcher,
            block_id,
            insn_index: 0,
            dispatcher_block_id: Some(block_id),
            dispatcher_type: "table".into(),
            virtual_opcodes: opcodes.clone(),
            confidence: 70,
            rationale: format!(
                "Table-based dispatcher with {} entries detected",
                opcodes.len()
            ),
            annotated_instructions: annotations,
        })
    }

    fn analyze_computed_goto(&self, block_id: usize) -> Option<VirtualizationPattern> {
        let block = self.blocks.iter().find(|b| b.id == block_id)?;

        let opcodes: Vec<u32> = block
            .insns
            .iter()
            .enumerate()
            .filter(|(_, insn)| matches!(insn.kind, MirOp::Add | MirOp::Mul))
            .map(|(i, _)| i as u32)
            .collect();

        let annotations: Vec<String> = block
            .insns
            .iter()
            .map(|insn| format!("{} [computed_goto]", insn.kind))
            .collect();

        Some(VirtualizationPattern {
            technique: VirtualizationTechnique::Dispatcher,
            block_id,
            insn_index: 0,
            dispatcher_block_id: Some(block_id),
            dispatcher_type: "computed_goto".into(),
            virtual_opcodes: opcodes.clone(),
            confidence: 65,
            rationale: format!(
                "Computed goto dispatcher with {} computations detected",
                opcodes.len()
            ),
            annotated_instructions: annotations,
        })
    }

    // ─── Interpreter detection ──────────────────────────────────────

    fn detect_interpreter_patterns(&mut self) {
        let candidates: Vec<usize> = self
            .blocks
            .iter()
            .filter(|b| !b.insns.is_empty() && self.is_interpreter_loop(b))
            .map(|b| b.id)
            .collect();

        for block_id in candidates {
            if let Some(p) = self.analyze_interpreter_loop(block_id) {
                self.patterns.push(p);
                self.changes += 1;
            }
        }
    }

    fn is_interpreter_loop(&self, block: &VirtBlock) -> bool {
        // Check for back-edge (successor with ID <= current)
        let has_back_edge = block.succs.iter().any(|s| *s <= block.id);
        has_back_edge && self.has_state_machine_pattern(block)
    }

    fn has_state_machine_pattern(&self, block: &VirtBlock) -> bool {
        let state_loads = block
            .insns
            .iter()
            .filter(|i| matches!(i.kind, MirOp::FieldGet | MirOp::ArrayGet))
            .count();
        let state_updates = block
            .insns
            .iter()
            .filter(|i| matches!(i.kind, MirOp::FieldPut | MirOp::ArrayPut))
            .count();
        state_loads >= 2 && state_updates >= 1
    }

    fn analyze_interpreter_loop(&self, block_id: usize) -> Option<VirtualizationPattern> {
        let block = self.blocks.iter().find(|b| b.id == block_id)?;

        let opcodes: Vec<u32> = block
            .insns
            .iter()
            .enumerate()
            .filter(|(_, insn)| matches!(insn.kind, MirOp::FieldGet | MirOp::FieldPut))
            .map(|(i, _)| i as u32)
            .collect();

        let annotations: Vec<String> = block
            .insns
            .iter()
            .map(|insn| format!("{} [interpreter]", insn.kind))
            .collect();

        Some(VirtualizationPattern {
            technique: VirtualizationTechnique::Interpreter,
            block_id,
            insn_index: 0,
            dispatcher_block_id: None,
            dispatcher_type: String::new(),
            virtual_opcodes: opcodes.clone(),
            confidence: 60,
            rationale: format!(
                "Interpreter loop with {} state operations detected",
                opcodes.len()
            ),
            annotated_instructions: annotations,
        })
    }

    // ─── Obfuscated bytecode detection ──────────────────────────────

    fn detect_obfuscated_bytecode_patterns(&mut self) {
        let candidates: Vec<usize> = self
            .blocks
            .iter()
            .filter(|b| b.insns.len() >= 3 && self.has_unusual_sequence(b))
            .map(|b| b.id)
            .collect();

        for block_id in candidates {
            if let Some(p) = self.analyze_obfuscated(block_id) {
                self.patterns.push(p);
                self.changes += 1;
            }
        }
    }

    fn has_unusual_sequence(&self, block: &VirtBlock) -> bool {
        let arith = block
            .insns
            .iter()
            .filter(|i| {
                matches!(
                    i.kind,
                    MirOp::Add
                        | MirOp::Sub
                        | MirOp::Mul
                        | MirOp::Div
                        | MirOp::Xor
                        | MirOp::And
                        | MirOp::Or
                )
            })
            .count();
        arith >= 3
    }

    fn analyze_obfuscated(&self, block_id: usize) -> Option<VirtualizationPattern> {
        let block = self.blocks.iter().find(|b| b.id == block_id)?;

        let opcodes: Vec<u32> = block
            .insns
            .iter()
            .enumerate()
            .filter(|(_, insn)| matches!(insn.kind, MirOp::Add | MirOp::Xor))
            .map(|(i, _)| i as u32)
            .collect();

        let annotations: Vec<String> = block
            .insns
            .iter()
            .map(|insn| format!("{} [obfuscated]", insn.kind))
            .collect();

        Some(VirtualizationPattern {
            technique: VirtualizationTechnique::ObfuscatedBytecode,
            block_id,
            insn_index: 0,
            dispatcher_block_id: None,
            dispatcher_type: String::new(),
            virtual_opcodes: opcodes.clone(),
            confidence: 55,
            rationale: format!(
                "Obfuscated bytecode with {} suspicious operations detected",
                opcodes.len()
            ),
            annotated_instructions: annotations,
        })
    }

    // ─── Custom VM detection ────────────────────────────────────────

    fn detect_custom_vm_patterns(&mut self) {
        let candidates: Vec<usize> = self
            .blocks
            .iter()
            .filter(|b| !b.insns.is_empty() && self.is_custom_vm_entry(b))
            .map(|b| b.id)
            .collect();

        for block_id in candidates {
            if let Some(p) = self.analyze_custom_vm(block_id) {
                self.patterns.push(p);
                self.changes += 1;
            }
        }
    }

    fn is_custom_vm_entry(&self, block: &VirtBlock) -> bool {
        let init_count = block
            .insns
            .iter()
            .filter(|i| matches!(i.kind, MirOp::Const | MirOp::NewArray))
            .count();
        init_count >= 2
    }

    fn analyze_custom_vm(&self, block_id: usize) -> Option<VirtualizationPattern> {
        let block = self.blocks.iter().find(|b| b.id == block_id)?;

        let opcodes: Vec<u32> = block
            .insns
            .iter()
            .enumerate()
            .filter(|(_, insn)| matches!(insn.kind, MirOp::Const | MirOp::NewArray))
            .map(|(i, _)| i as u32)
            .collect();

        let annotations: Vec<String> = block
            .insns
            .iter()
            .map(|insn| format!("{} [custom_vm]", insn.kind))
            .collect();

        Some(VirtualizationPattern {
            technique: VirtualizationTechnique::CustomVm,
            block_id,
            insn_index: 0,
            dispatcher_block_id: None,
            dispatcher_type: String::new(),
            virtual_opcodes: opcodes.clone(),
            confidence: 50,
            rationale: format!(
                "Custom VM with {} initialization operations detected",
                opcodes.len()
            ),
            annotated_instructions: annotations,
        })
    }

    // ─── Results ────────────────────────────────────────────────────

    fn build_result(&self) -> DetectionResult {
        let stats = self.compute_stats();
        let report = self.generate_report(&stats);

        DetectionResult {
            patterns: self.patterns.clone(),
            stats,
            trace: self.trace.clone(),
            changes: self.changes,
            report,
        }
    }

    fn compute_stats(&self) -> DetectionStats {
        let mut stats = DetectionStats {
            total: self.patterns.len(),
            ..Default::default()
        };

        let mut total_conf: u64 = 0;
        for p in &self.patterns {
            match p.technique {
                VirtualizationTechnique::Dispatcher => stats.dispatcher += 1,
                VirtualizationTechnique::Interpreter => stats.interpreter += 1,
                VirtualizationTechnique::Jit => stats.jit += 1,
                VirtualizationTechnique::ObfuscatedBytecode => stats.obfuscated += 1,
                VirtualizationTechnique::CustomVm => stats.custom_vm += 1,
                VirtualizationTechnique::Unknown => {}
            }
            total_conf += u64::from(p.confidence);
        }

        if !self.patterns.is_empty() {
            stats.average_confidence = (total_conf / self.patterns.len() as u64) as u8;
        }

        stats
    }

    fn generate_report(&self, stats: &DetectionStats) -> String {
        let mut report = String::with_capacity(2048);
        let _ = writeln!(
            report,
            "═══════════════════════════════════════════════════════════════"
        );
        let _ = writeln!(report, "VIRTUALIZATION DETECTION REPORT");
        let _ = writeln!(
            report,
            "═══════════════════════════════════════════════════════════════"
        );
        let _ = writeln!(report);
        let _ = writeln!(report, "Total Patterns Detected: {}", stats.total);
        let _ = writeln!(report, "  - Dispatcher: {}", stats.dispatcher);
        let _ = writeln!(report, "  - Interpreter: {}", stats.interpreter);
        let _ = writeln!(report, "  - JIT: {}", stats.jit);
        let _ = writeln!(report, "  - Obfuscated Bytecode: {}", stats.obfuscated);
        let _ = writeln!(report, "  - Custom VM: {}", stats.custom_vm);
        let _ = writeln!(
            report,
            "\nAverage Confidence: {}%",
            stats.average_confidence
        );
        let _ = writeln!(report, "Total Changes: {}", self.changes);
        let _ = writeln!(report);

        if !self.patterns.is_empty() {
            let _ = writeln!(report, "Detected Patterns:");
            let _ = writeln!(
                report,
                "─────────────────────────────────────────────────────────────"
            );
            for (i, p) in self.patterns.iter().enumerate() {
                let _ = writeln!(
                    report,
                    "{}. {} (Confidence: {}%)",
                    i + 1,
                    p.technique,
                    p.confidence
                );
                let _ = writeln!(report, "   Location: Block {}", p.block_id);
                let _ = writeln!(report, "   Rationale: {}", p.rationale);
                if let Some(disp_id) = p.dispatcher_block_id {
                    let _ = writeln!(
                        report,
                        "   Dispatcher: Block {} ({})",
                        disp_id, p.dispatcher_type
                    );
                }
                let _ = writeln!(report, "   Virtual Opcodes: {}", p.virtual_opcodes.len());
                let _ = writeln!(report);
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_blocks() {
        let mut detector = VirtualizationDetector::new(vec![]);
        let result = detector.detect();
        assert_eq!(result.patterns.len(), 0);
        assert_eq!(result.stats.total, 0);
    }

    #[test]
    fn test_switch_dispatcher_detection() {
        let blocks = vec![
            VirtBlock {
                id: 0,
                insns: vec![
                    VirtInsn {
                        kind: MirOp::FieldGet,
                        dst: 0,
                        src1: 0,
                        src2: 0,
                        imm: 0,
                        ref_idx: 0,
                    },
                    VirtInsn {
                        kind: MirOp::Switch,
                        dst: 0,
                        src1: 0,
                        src2: 0,
                        imm: 0,
                        ref_idx: 0,
                    },
                ],
                succs: vec![1, 2, 3, 4, 5, 6],
            },
            VirtBlock {
                id: 1,
                insns: vec![VirtInsn {
                    kind: MirOp::Const,
                    dst: 0,
                    src1: 0,
                    src2: 0,
                    imm: 0,
                    ref_idx: 0,
                }],
                succs: vec![],
            },
            VirtBlock {
                id: 2,
                insns: vec![],
                succs: vec![],
            },
            VirtBlock {
                id: 3,
                insns: vec![],
                succs: vec![],
            },
            VirtBlock {
                id: 4,
                insns: vec![],
                succs: vec![],
            },
            VirtBlock {
                id: 5,
                insns: vec![],
                succs: vec![],
            },
            VirtBlock {
                id: 6,
                insns: vec![],
                succs: vec![],
            },
        ];

        let mut detector = VirtualizationDetector::new(blocks);
        let result = detector.detect();

        assert!(
            result.stats.dispatcher > 0,
            "should detect dispatcher pattern"
        );
    }

    #[test]
    fn test_obfuscated_bytecode_detection() {
        let blocks = vec![VirtBlock {
            id: 0,
            insns: vec![
                VirtInsn {
                    kind: MirOp::Add,
                    dst: 0,
                    src1: 1,
                    src2: 2,
                    imm: 0,
                    ref_idx: 0,
                },
                VirtInsn {
                    kind: MirOp::Xor,
                    dst: 1,
                    src1: 0,
                    src2: 3,
                    imm: 0,
                    ref_idx: 0,
                },
                VirtInsn {
                    kind: MirOp::Sub,
                    dst: 2,
                    src1: 1,
                    src2: 0,
                    imm: 0,
                    ref_idx: 0,
                },
                VirtInsn {
                    kind: MirOp::And,
                    dst: 3,
                    src1: 2,
                    src2: 1,
                    imm: 0,
                    ref_idx: 0,
                },
            ],
            succs: vec![],
        }];

        let mut detector = VirtualizationDetector::new(blocks);
        let result = detector.detect();

        assert!(
            result.stats.obfuscated > 0,
            "should detect obfuscated bytecode"
        );
    }
}
