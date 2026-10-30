//! Build a [`ControlFlowGraph`] from a flat slice of OmniIR instructions.
//!
//! The builder makes one pass to collect *leader* addresses (block-start
//! candidates) and a second pass to slice the instruction stream into
//! basic blocks at those leaders. Edges are wired up from terminator
//! semantics (jump targets, branch fall-through, return → no successors).

use omnisec_ir::{Instruction, OpCode, Operand};
use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

use crate::block::{BasicBlock, BlockId, BlockKind};
use crate::graph::ControlFlowGraph;

/// Reasons the builder can refuse to produce a CFG.
#[derive(Debug)]
pub enum BuildError {
    /// `instructions` was empty.
    Empty,

    /// `entry_addr` was not the start address of any instruction in
    /// `instructions`.
    EntryNotFound(u64),

    /// Instructions overlap or run out-of-order — addresses must be strictly
    /// increasing across the slice.
    NotSorted {
        /// Index where the order breaks down.
        at: usize,
        /// Previous instruction's address.
        prev: u64,
        /// Current instruction's address.
        cur: u64,
    },
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "cannot build CFG from an empty instruction stream"),
            Self::EntryNotFound(addr) => {
                write!(
                    f,
                    "entry address {addr:#x} is not present in the instruction stream"
                )
            }
            Self::NotSorted { at, prev, cur } => write!(
                f,
                "instruction stream is not address-sorted (at index {at}: {prev:#x} >= {cur:#x})"
            ),
        }
    }
}

impl std::error::Error for BuildError {}

/// Build a [`ControlFlowGraph`] from `instructions` rooted at `entry_addr`.
///
/// `instructions` must be sorted by [`Instruction::address`] and represent
/// a contiguous-ish region of code (gaps are tolerated as long as branches
/// don't target inside them). `entry_addr` must be the address of one of
/// the instructions.
pub fn build_cfg(
    instructions: &[Instruction],
    entry_addr: u64,
) -> Result<ControlFlowGraph, BuildError> {
    if instructions.is_empty() {
        return Err(BuildError::Empty);
    }

    // Validate ordering and build address → index map.
    let mut addr_to_idx: FxHashMap<u64, usize> = FxHashMap::default();
    let mut prev_addr = u64::MIN;
    for (i, ins) in instructions.iter().enumerate() {
        if i > 0 && ins.address <= prev_addr {
            return Err(BuildError::NotSorted {
                at: i,
                prev: prev_addr,
                cur: ins.address,
            });
        }
        addr_to_idx.insert(ins.address, i);
        prev_addr = ins.address;
    }
    if !addr_to_idx.contains_key(&entry_addr) {
        return Err(BuildError::EntryNotFound(entry_addr));
    }

    // Step 1: collect leader addresses.
    //
    // A leader is the first instruction of a basic block. Leaders are:
    //   (a) the entry instruction,
    //   (b) the target of any direct jump / branch we can resolve,
    //   (c) the instruction *after* any terminator.
    let leaders = collect_leaders(instructions, entry_addr, &addr_to_idx);

    // Step 2: slice the stream into blocks at leader boundaries.
    let mut blocks: Vec<BasicBlock> = Vec::with_capacity(leaders.len());
    let mut leader_to_id: FxHashMap<u64, BlockId> = FxHashMap::default();

    let leader_indices: Vec<usize> = {
        let mut v: Vec<usize> = leaders.iter().map(|a| addr_to_idx[a]).collect();
        v.sort_unstable();
        v.dedup();
        v
    };

    for (next_id, &start_idx) in leader_indices.iter().enumerate() {
        let next_leader_idx = leader_indices
            .get(next_id + 1)
            .copied()
            .unwrap_or(instructions.len());
        let last_idx = next_leader_idx.saturating_sub(1);
        let block_insts: Vec<Instruction> = instructions[start_idx..next_leader_idx].to_vec();
        let start_address = instructions[start_idx].address;
        let end_address = instructions[last_idx].fallthrough_address();

        let kind = classify_block(&block_insts, entry_addr, start_address);

        let id = next_id as BlockId;
        leader_to_id.insert(start_address, id);

        blocks.push(BasicBlock {
            id,
            start_address,
            end_address,
            instructions: block_insts,
            kind,
        });
    }

    // Build the empty CFG and register every block.
    let entry_id = leader_to_id[&entry_addr];
    let mut cfg = ControlFlowGraph::empty(entry_id);
    for b in blocks {
        cfg.insert_block(b);
    }

    // Step 3: wire up edges.
    //
    // We can't borrow cfg immutably while iterating + adding edges, so we
    // collect (from, to) pairs first and apply them in a second pass.
    let mut edges: Vec<(BlockId, BlockId)> = Vec::new();
    for id in cfg.block_ids().collect::<Vec<_>>() {
        // Clone is cheap-ish; this lets us read instructions without
        // holding an immutable borrow on cfg through the next loop body.
        let block = cfg.block(id).expect("block by id we just listed").clone();
        let block_term = block.terminator().cloned();

        match block_term {
            // ── Pure data block (no terminator) → fall through ──────────
            None => {
                if let Some(next_id) = next_block_after(&cfg, &block) {
                    edges.push((id, next_id));
                }
            }
            Some(t) => match t.opcode {
                OpCode::Jump => {
                    if let Some(target) = label_target(&t)
                        && let Some(target_id) = cfg.block_at_address(target)
                    {
                        edges.push((id, target_id));
                    }
                    // else: target outside this region — no edge.
                    // else: indirect jump — block keeps `UnresolvedExit` kind.
                }
                OpCode::BranchIf => {
                    // Taken edge.
                    if let Some(target) = label_target(&t)
                        && let Some(target_id) = cfg.block_at_address(target)
                    {
                        edges.push((id, target_id));
                    }
                    // Fall-through edge.
                    if let Some(next_id) = next_block_after(&cfg, &block) {
                        edges.push((id, next_id));
                    }
                }
                _ => {
                    // Other terminator-flagged opcodes (e.g. unresolved
                    // synthetic exits): just treat as no-successor.
                }
            },
        }
    }

    for (from, to) in edges {
        cfg.add_edge(from, to);
    }

    Ok(cfg)
}

/// Find every instruction-address that *could* be the start of a basic block.
fn collect_leaders(
    instructions: &[Instruction],
    entry_addr: u64,
    addr_to_idx: &FxHashMap<u64, usize>,
) -> FxHashSet<u64> {
    let mut leaders: FxHashSet<u64> = FxHashSet::default();

    // (a) entry.
    leaders.insert(entry_addr);

    // (b) and (c).
    for ins in instructions {
        if !ins.is_terminator() {
            continue;
        }
        // (c) post-terminator instruction is a leader, if it exists.
        let after = ins.fallthrough_address();
        if addr_to_idx.contains_key(&after) {
            leaders.insert(after);
        }
        // (b) jump / branch target if it resolves to a known address.
        if matches!(ins.opcode, OpCode::Jump | OpCode::BranchIf)
            && let Some(target) = label_target(ins)
            && addr_to_idx.contains_key(&target)
        {
            leaders.insert(target);
        }
    }

    leaders
}

/// Read the (`Operand::Label(addr)`) target out of a jump / branch
/// instruction. Returns `None` for indirect jumps, unresolved targets,
/// or any non-jump opcode.
fn label_target(ins: &Instruction) -> Option<u64> {
    if !matches!(ins.opcode, OpCode::Jump | OpCode::BranchIf | OpCode::Call) {
        return None;
    }
    ins.src.iter().find_map(|o| match o {
        Operand::Label(addr) => Some(*addr),
        _ => None,
    })
}

/// Compute the [`BlockKind`] for a freshly built block.
fn classify_block(insts: &[Instruction], entry_addr: u64, start_address: u64) -> BlockKind {
    let Some(t) = insts.last() else {
        // Empty block - if it's the entry, mark as Entry, otherwise Normal
        return if start_address == entry_addr {
            BlockKind::Entry
        } else {
            BlockKind::Normal
        };
    };
    if !t.is_terminator() {
        return if start_address == entry_addr {
            BlockKind::Entry
        } else {
            BlockKind::Normal
        };
    }
    match t.opcode {
        OpCode::Return | OpCode::Halt | OpCode::Trap => {
            if start_address == entry_addr {
                BlockKind::Entry
            } else {
                BlockKind::Exit
            }
        }
        OpCode::Jump if label_target(t).is_none() => {
            // Indirect jump (no resolvable label target) → unresolved exit.
            if start_address == entry_addr {
                BlockKind::Entry
            } else {
                BlockKind::UnresolvedExit
            }
        }
        _ => {
            if start_address == entry_addr {
                BlockKind::Entry
            } else {
                BlockKind::Normal
            }
        }
    }
}

/// Find the block whose start address equals the given block's
/// `end_address` (= the natural fall-through target).
fn next_block_after(cfg: &ControlFlowGraph, block: &BasicBlock) -> Option<BlockId> {
    cfg.block_at_address(block.end_address)
}

#[cfg(test)]
mod tests {
    use omnisec_core::Arch;
    use omnisec_ir::{Instruction, OpCode, Operand};

    use super::*;
    use crate::BlockKind;

    /// Helper: synthetic instruction at `addr` of opcode `op` with size 1.
    fn ins(addr: u64, op: OpCode) -> Instruction {
        Instruction::new(op, addr, 1, Arch::X86_64)
    }

    /// Helper: synthetic terminator with one Label src.
    fn jump_to(addr: u64, target: u64) -> Instruction {
        let mut i = Instruction::new(OpCode::Jump, addr, 1, Arch::X86_64);
        i.src = vec![Operand::Label(target)];
        i
    }

    fn branch_to(addr: u64, target: u64) -> Instruction {
        let mut i = Instruction::new(OpCode::BranchIf, addr, 1, Arch::X86_64);
        i.src = vec![Operand::Label(target)];
        i
    }

    #[test]
    fn empty_input_is_an_error() {
        let r = build_cfg(&[], 0x1000);
        assert!(matches!(r, Err(BuildError::Empty)));
    }

    #[test]
    fn unsorted_input_is_an_error() {
        let v = vec![ins(0x1010, OpCode::Nop), ins(0x1000, OpCode::Nop)];
        let r = build_cfg(&v, 0x1010);
        assert!(matches!(r, Err(BuildError::NotSorted { .. })));
    }

    #[test]
    fn missing_entry_is_an_error() {
        let v = vec![ins(0x1000, OpCode::Nop)];
        let r = build_cfg(&v, 0x9999);
        assert!(matches!(r, Err(BuildError::EntryNotFound(0x9999))));
    }

    #[test]
    fn straight_line_is_one_block() {
        // nop; nop; ret
        let v = vec![
            ins(0x1000, OpCode::Nop),
            ins(0x1001, OpCode::Nop),
            ins(0x1002, OpCode::Return),
        ];
        let cfg = build_cfg(&v, 0x1000).unwrap();
        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.edge_count(), 0);
        let entry = cfg.block(cfg.entry()).unwrap();
        assert_eq!(entry.kind, BlockKind::Entry);
        assert_eq!(entry.terminator().unwrap().opcode, OpCode::Return);
    }

    #[test]
    fn forward_jump_creates_two_blocks_and_one_edge() {
        // 0x1000: jmp 0x1010
        // 0x1010: ret
        let v = vec![jump_to(0x1000, 0x1010), ins(0x1010, OpCode::Return)];
        let cfg = build_cfg(&v, 0x1000).unwrap();
        assert_eq!(cfg.block_count(), 2);
        assert_eq!(cfg.edge_count(), 1);
        let entry_id = cfg.entry();
        let target_id = cfg.block_at_address(0x1010).unwrap();
        assert_eq!(cfg.successors(entry_id), &[target_id]);
        assert_eq!(cfg.predecessors(target_id), &[entry_id]);
    }

    #[test]
    fn diamond_via_conditional_branch() {
        // 0x1000: jne 0x1020   (BranchIf)
        // 0x1001: nop          (true side, falls through)
        // 0x1002: jmp 0x1030
        // 0x1020: nop          (false side, falls through)
        // 0x1021: jmp 0x1030
        // 0x1030: ret
        let v = vec![
            branch_to(0x1000, 0x1020),
            ins(0x1001, OpCode::Nop),
            jump_to(0x1002, 0x1030),
            ins(0x1020, OpCode::Nop),
            jump_to(0x1021, 0x1030),
            ins(0x1030, OpCode::Return),
        ];
        let cfg = build_cfg(&v, 0x1000).unwrap();
        assert_eq!(cfg.block_count(), 4); // {0x1000, 0x1001, 0x1020, 0x1030}
        // Both arms should converge on 0x1030.
        let join = cfg.block_at_address(0x1030).unwrap();
        assert_eq!(cfg.predecessors(join).len(), 2);
        let entry = cfg.entry();
        assert_eq!(cfg.successors(entry).len(), 2);
    }

    #[test]
    fn indirect_jump_yields_no_successors() {
        // Indirect jmp = OpCode::Jump but no Label src.
        let mut indirect = Instruction::new(OpCode::Jump, 0x1000, 1, Arch::X86_64);
        indirect.src = vec![]; // no operands at all
        let v = vec![indirect];
        let cfg = build_cfg(&v, 0x1000).unwrap();
        let b = cfg.block(cfg.entry()).unwrap();
        // Entry block with unresolved jump has no successors
        assert_eq!(cfg.successors(b.id).len(), 0);
    }

    #[test]
    fn jump_outside_region_drops_edge() {
        // jmp 0x9999 (target not in our slice).
        let v = vec![jump_to(0x1000, 0x9999)];
        let cfg = build_cfg(&v, 0x1000).unwrap();
        // Only the entry block exists; no outgoing edge to the unknown target.
        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.edge_count(), 0);
    }

    #[test]
    fn reverse_postorder_respects_order_in_loop() {
        // Simple while loop:
        //   header:  nop          (0x1000)
        //            br back if   (0x1001) -> header (0x1000)
        //            ret          (0x1002)
        //
        // Note: we conditionally branch BACK to 0x1000.
        let v = vec![
            ins(0x1000, OpCode::Nop),
            branch_to(0x1001, 0x1000),
            ins(0x1002, OpCode::Return),
        ];
        let cfg = build_cfg(&v, 0x1000).unwrap();
        // Three blocks: {0x1000, 0x1001, 0x1002}? No — 0x1000..=0x1001 is one
        // straight-line chunk (Nop falls through to BranchIf). The branch
        // creates a back-edge target = 0x1000, which is already a leader.
        // Post-branch fall-through 0x1002 is also a leader. So we get two
        // blocks: [0x1000..0x1002] and [0x1002].
        assert_eq!(cfg.block_count(), 2);

        let rpo = cfg.reverse_postorder();
        assert_eq!(rpo.len(), 2);
        assert_eq!(rpo[0], cfg.entry());
    }
}
