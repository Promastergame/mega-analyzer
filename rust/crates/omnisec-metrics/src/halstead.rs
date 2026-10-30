//! Halstead metrics.

use std::collections::HashSet as FxHashSet;

use omnisec_cfg::ControlFlowGraph;
use omnisec_ir::{OpCode, Operand};

/// Halstead software science metrics.
#[derive(Debug, Clone)]
#[allow(non_snake_case)] // Halstead metrics traditionally use N1/N2 notation
pub struct HalsteadMetrics {
    /// Number of distinct operators.
    pub n1: usize,
    /// Number of distinct operands.
    pub n2: usize,
    /// Total number of operators.
    pub N1: usize,
    /// Total number of operands.
    pub N2: usize,
    /// Program length.
    pub length: f64,
    /// Vocabulary.
    pub vocabulary: f64,
    /// Difficulty.
    pub difficulty: f64,
    /// Effort.
    pub effort: f64,
}

impl HalsteadMetrics {
    /// Compute Halstead metrics from a CFG.
    #[must_use]
    #[allow(non_snake_case)] // Halstead metrics traditionally use N1/N2 notation
    pub fn from_cfg(cfg: &ControlFlowGraph) -> Self {
        let mut distinct_operators: FxHashSet<OpCode> = FxHashSet::default();
        let mut distinct_operands: FxHashSet<String> = FxHashSet::default();
        let mut total_operators = 0usize;
        let mut total_operands = 0usize;

        for block in cfg.iter_blocks() {
            for inst in &block.instructions {
                // Count operator (opcode)
                distinct_operators.insert(inst.opcode);
                total_operators += 1;

                // Count operands
                for op in &inst.dst {
                    distinct_operands.insert(operand_to_string(op));
                    total_operands += 1;
                }
                for op in &inst.src {
                    distinct_operands.insert(operand_to_string(op));
                    total_operands += 1;
                }
            }
        }

        let n1 = distinct_operators.len();
        let n2 = distinct_operands.len();
        let N1 = total_operators;
        let N2 = total_operands;

        // Compute Halstead metrics
        let vocabulary = (n1 + n2) as f64;
        let length = if vocabulary > 0.0 {
            (N1 + N2) as f64
        } else {
            0.0
        };

        let difficulty = if n2 > 0 {
            (n1 as f64 / 2.0) * (N2 as f64 / n2 as f64)
        } else {
            0.0
        };

        let effort = length * difficulty;

        Self {
            n1,
            n2,
            N1,
            N2,
            length,
            vocabulary,
            difficulty,
            effort,
        }
    }
}

/// Convert an operand to a string for uniqueness checking.
fn operand_to_string(op: &Operand) -> String {
    match op {
        Operand::Register(reg) => format!("reg_{}", reg.name),
        Operand::Immediate(imm) => format!("imm_{imm}"),
        Operand::Memory(addr) => format!("mem_{:?}", addr),
        Operand::Label(addr) => format!("label_{addr}"),
        Operand::Symbol(sym) => format!("sym_{sym}"),
        Operand::Type(ty) => format!("type_{ty:?}"),
    }
}

/// Compute Halstead metrics for a CFG.
#[must_use]
pub fn compute_halstead(cfg: &ControlFlowGraph) -> HalsteadMetrics {
    HalsteadMetrics::from_cfg(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_cfg::{BasicBlock, BlockKind};
    use omnisec_core::Arch;
    use omnisec_ir::{Instruction, OpCode};

    #[test]
    fn empty_cfg() {
        let cfg = ControlFlowGraph::empty(0);
        let metrics = compute_halstead(&cfg);

        assert_eq!(metrics.n1, 0);
        assert_eq!(metrics.n2, 0);
        assert_eq!(metrics.N1, 0);
        assert_eq!(metrics.N2, 0);
    }

    #[test]
    fn simple_cfg() {
        let mut cfg = ControlFlowGraph::empty(0);
        let mut inst = Instruction::new(OpCode::Move, 0x1000, 1, Arch::X86_64);
        let reg = omnisec_ir::operand::Register {
            arch: Arch::X86_64,
            class: omnisec_ir::operand::RegisterClass::GeneralPurpose,
            native_id: 0,
            bit_width: 64,
            name: "rax".to_string(),
        };
        inst.dst = vec![Operand::Register(reg)];
        inst.src = vec![Operand::Immediate(42)];

        cfg.insert_block(BasicBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1001,
            instructions: vec![inst],
            kind: BlockKind::Entry,
        });

        let metrics = compute_halstead(&cfg);

        assert_eq!(metrics.n1, 1); // Move
        assert_eq!(metrics.n2, 2); // reg_rax, imm_42
        assert_eq!(metrics.N1, 1);
        assert_eq!(metrics.N2, 2);
    }
}
