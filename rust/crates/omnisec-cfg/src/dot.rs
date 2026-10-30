//! Graphviz DOT export for control-flow graphs.

use std::fmt::Write;

use crate::block::BlockKind;
use crate::graph::ControlFlowGraph;

/// Export a CFG to Graphviz DOT format.
///
/// The output can be rendered with `dot -Tpng input.dot -o output.png`.
#[must_use]
pub fn to_dot(cfg: &ControlFlowGraph) -> String {
    let mut out = String::new();
    writeln!(out, "digraph cfg {{").unwrap();
    writeln!(out, "  rankdir=TD;").unwrap();
    writeln!(out, "  node [shape=box,fontname=\"Courier New\"];").unwrap();

    // Emit nodes.
    for block in cfg.iter_blocks() {
        let label = block_label(block);
        let color = block_color(block);
        writeln!(out, "  \"{}\" [label=\"{}\",{}];", block.id, label, color).unwrap();
    }

    // Emit edges.
    for (src_id, _block) in cfg.iter() {
        for &dst_id in cfg.successors(src_id) {
            let edge_label = edge_label(cfg, src_id, dst_id);
            writeln!(
                out,
                "  \"{}\" -> \"{}\" [label=\"{}\"];",
                src_id, dst_id, edge_label
            )
            .unwrap();
        }
    }

    writeln!(out, "}}").unwrap();
    out
}

/// Generate a label for a basic block.
fn block_label(block: &crate::block::BasicBlock) -> String {
    let kind_label = match block.kind {
        BlockKind::Entry => " [ENTRY]",
        BlockKind::Exit => " [EXIT]",
        BlockKind::UnresolvedExit => " [UNRESOLVED]",
        BlockKind::Normal => "",
    };

    let addr_label = if block.start_address == block.end_address {
        format!("{:#x}", block.start_address)
    } else {
        format!("{:#x}-{:#x}", block.start_address, block.end_address)
    };

    let inst_count = block.len();
    format!(
        "BB{}\\n{}\\n{} instrs{}",
        block.id, addr_label, inst_count, kind_label
    )
}

/// Get a color attribute for a block based on its kind.
fn block_color(block: &crate::block::BasicBlock) -> &'static str {
    match block.kind {
        BlockKind::Entry => "color=green",
        BlockKind::Exit => "color=red",
        BlockKind::UnresolvedExit => "color=orange",
        BlockKind::Normal => "",
    }
}

/// Generate a label for an edge.
fn edge_label(cfg: &ControlFlowGraph, src: u32, dst: u32) -> String {
    let src_block = cfg.block(src).unwrap();
    let Some(term) = src_block.terminator() else {
        return "fallthrough".to_string();
    };

    match term.opcode {
        omnisec_ir::OpCode::Jump => {
            // Check if this is the taken edge or fallthrough
            if let Some(target) = label_target(term) {
                if target == cfg.block(dst).unwrap().start_address {
                    "jump".to_string()
                } else {
                    "fallthrough".to_string()
                }
            } else {
                "jump".to_string()
            }
        }
        omnisec_ir::OpCode::BranchIf => {
            if let Some(target) = label_target(term) {
                if target == cfg.block(dst).unwrap().start_address {
                    "taken".to_string()
                } else {
                    "not taken".to_string()
                }
            } else {
                "branch".to_string()
            }
        }
        _ => String::new(),
    }
}

/// Read the (`Operand::Label(addr)`) target out of a jump / branch instruction.
fn label_target(ins: &omnisec_ir::Instruction) -> Option<u64> {
    if !matches!(
        ins.opcode,
        omnisec_ir::OpCode::Jump | omnisec_ir::OpCode::BranchIf | omnisec_ir::OpCode::Call
    ) {
        return None;
    }
    ins.src.iter().find_map(|o| match o {
        omnisec_ir::Operand::Label(addr) => Some(*addr),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use crate::block::{BasicBlock, BlockKind};

    use super::*;

    #[test]
    fn dot_output_is_valid() {
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(BasicBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1010,
            instructions: vec![],
            kind: BlockKind::Entry,
        });
        cfg.insert_block(BasicBlock {
            id: 1,
            start_address: 0x1010,
            end_address: 0x1020,
            instructions: vec![],
            kind: BlockKind::Normal,
        });
        cfg.add_edge(0, 1);

        let dot = to_dot(&cfg);
        assert!(dot.contains("digraph cfg"));
        assert!(dot.contains("BB0"));
        assert!(dot.contains("BB1"));
        assert!(dot.contains("->"));
    }
}
