//! **Constant Propagation** — the backbone of deobfuscation.
//!
//! Walks the CFG in reverse postorder and tracks the abstract value
//! ([`AbstractValue`]) of every register. When both operands of an arithmetic
//! instruction are constants, the result is computed at analysis time and the
//! instruction is replaced with a simple `Move` of the folded value.
//!
//! This pass is the single most effective weapon against:
//! - Constant unfolding (splitting `0xDEADBEEF` into `a = 0xDE00; a |= 0xAD; ...`)
//! - Arithmetic obfuscation chains
//! - Key derivation sequences for string decryption

use std::time::Instant;

use omnisec_cfg::ControlFlowGraph;
use omnisec_ir::{Instruction, OpCode, Operand};
use std::collections::HashMap as FxHashMap;

use super::DeobfuscationPass;
use crate::lattice::{AbstractValue, opcode_to_binop, opcode_to_unop};
use crate::stats::PassStats;

/// Constant propagation pass.
pub struct ConstantPropagationPass;

impl DeobfuscationPass for ConstantPropagationPass {
    fn name(&self) -> &'static str {
        "ConstantPropagation"
    }

    fn run(&self, cfg: &mut ControlFlowGraph) -> PassStats {
        let start = Instant::now();
        let mut stats = PassStats::new(self.name());

        // Phase 1: Analyze — compute the constant value of every register at
        // every program point using a fixed-point worklist algorithm.
        let rpo = cfg.reverse_postorder();
        let mut block_in_states: FxHashMap<u32, FxHashMap<u32, AbstractValue>> =
            FxHashMap::default();

        // Fixed-point iteration
        let mut changed = true;
        let mut iterations = 0;
        while changed && iterations < 100 {
            changed = false;
            iterations += 1;

            for &block_id in &rpo {
                let block = match cfg.block(block_id) {
                    Some(b) => b,
                    None => continue,
                };

                // Merge incoming states from predecessors
                let preds = cfg.predecessors(block_id);
                let mut current_state = if preds.is_empty() {
                    FxHashMap::default()
                } else {
                    let mut merged = FxHashMap::default();
                    for &pred_id in preds {
                        if let Some(pred_state) = block_in_states.get(&pred_id) {
                            for (&reg, &val) in pred_state {
                                let entry = merged.entry(reg).or_insert(AbstractValue::Top);
                                *entry = entry.meet(val);
                            }
                        }
                    }
                    merged
                };

                // Process each instruction in the block
                for insn in &block.instructions {
                    process_instruction(insn, &mut current_state);
                }

                // Check if this block's state changed
                let old_state = block_in_states.get(&block_id);
                if old_state != Some(&current_state) {
                    block_in_states.insert(block_id, current_state);
                    changed = true;
                }
            }
        }

        stats.trace.push(format!(
            "Constant propagation converged in {iterations} iterations"
        ));

        // Phase 2: Transform — replace instructions whose operands are now
        // known constants with simpler equivalents.
        for &block_id in &rpo {
            let preds = cfg.predecessors(block_id).to_vec();
            let mut current_state: FxHashMap<u32, AbstractValue> = if preds.is_empty() {
                FxHashMap::default()
            } else {
                let mut merged = FxHashMap::default();
                for pred_id in &preds {
                    if let Some(pred_state) = block_in_states.get(pred_id) {
                        for (&reg, &val) in pred_state {
                            let entry = merged.entry(reg).or_insert(AbstractValue::Top);
                            *entry = entry.meet(val);
                        }
                    }
                }
                merged
            };

            let block = match cfg.block(block_id) {
                Some(b) => b,
                None => continue,
            };

            let mut new_instructions = Vec::with_capacity(block.instructions.len());
            let mut block_changed = false;

            for insn in &block.instructions {
                // Try to fold this instruction
                if let Some(folded) = try_fold(insn, &current_state) {
                    new_instructions.push(folded);
                    stats.constants_resolved += 1;
                    stats.instructions_changed += 1;
                    block_changed = true;
                } else {
                    new_instructions.push(insn.clone());
                }

                // Update state for subsequent instructions
                process_instruction(new_instructions.last().unwrap(), &mut current_state);
            }

            if block_changed && let Some(block_mut) = cfg.block_mut(block_id) {
                block_mut.instructions = new_instructions;
            }
        }

        stats.duration = start.elapsed();
        stats
    }
}

/// Update register state based on one instruction.
fn process_instruction(insn: &Instruction, state: &mut FxHashMap<u32, AbstractValue>) {
    // Extract destination register
    let dst_reg = match insn.dst.first() {
        Some(Operand::Register(r)) => r.native_id,
        _ => return,
    };

    match insn.opcode {
        OpCode::Move => {
            let val = resolve_operand(insn.src.first(), state);
            state.insert(dst_reg, val);
        }
        op if opcode_to_binop(op).is_some() => {
            let binop = opcode_to_binop(op).unwrap();
            let a = resolve_operand(insn.src.first(), state);
            let b = resolve_operand(insn.src.get(1), state);
            state.insert(dst_reg, a.eval_binop(binop, b));
        }
        op if opcode_to_unop(op).is_some() => {
            let unop = opcode_to_unop(op).unwrap();
            let a = resolve_operand(insn.src.first(), state);
            state.insert(dst_reg, a.eval_unop(unop));
        }
        // Any other instruction kills the destination register
        _ => {
            state.insert(dst_reg, AbstractValue::Bottom);
        }
    }
}

/// Resolve an operand to an abstract value.
fn resolve_operand(
    operand: Option<&Operand>,
    state: &FxHashMap<u32, AbstractValue>,
) -> AbstractValue {
    match operand {
        Some(Operand::Immediate(v)) => AbstractValue::Const(*v),
        Some(Operand::Register(r)) => state
            .get(&r.native_id)
            .copied()
            .unwrap_or(AbstractValue::Top),
        _ => AbstractValue::Bottom,
    }
}

/// Try to fold an instruction into a simpler form using known constants.
fn try_fold(insn: &Instruction, state: &FxHashMap<u32, AbstractValue>) -> Option<Instruction> {
    let dst = insn.dst.first()?;

    match insn.opcode {
        op if opcode_to_binop(op).is_some() => {
            let binop = opcode_to_binop(op)?;
            let a = resolve_operand(insn.src.first(), state);
            let b = resolve_operand(insn.src.get(1), state);
            let result = a.eval_binop(binop, b);

            result.as_const().map(|val| {
                Instruction::new(OpCode::Move, insn.address, insn.size, insn.arch)
                    .with_dst([dst.clone()])
                    .with_src([Operand::Immediate(val)])
            })
        }
        op if opcode_to_unop(op).is_some() => {
            let unop = opcode_to_unop(op)?;
            let a = resolve_operand(insn.src.first(), state);
            let result = a.eval_unop(unop);

            result.as_const().map(|val| {
                Instruction::new(OpCode::Move, insn.address, insn.size, insn.arch)
                    .with_dst([dst.clone()])
                    .with_src([Operand::Immediate(val)])
            })
        }
        _ => None,
    }
}
