//! Basic blocks — the nodes of the control-flow graph.

use omnisec_ir::Instruction;
use omnisec_json::{FromJson, ToJson};

/// Stable per-CFG identifier of a basic block.
///
/// Block IDs are dense `u32`s assigned during construction in the order in
/// which leaders are discovered. Use them as keys; never assume their
/// numeric value carries semantic meaning.
pub type BlockId = u32;

/// What role a block plays in its CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum BlockKind {
    /// The CFG entry block — exactly one of these per CFG.
    Entry,
    /// A block whose terminator is `Return` / `Halt` / `Trap`. Has no
    /// in-CFG successors but may transfer control out of the function.
    Exit,
    /// A block whose terminator is an unresolved indirect branch / call.
    /// We didn't add edges, but the block is otherwise normal.
    UnresolvedExit,
    /// Normal block reachable from `Entry` along recorded edges.
    Normal,
}

/// A basic block: a maximal straight-line sequence of OmniIR instructions
/// with a single entry and a single terminator.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct BasicBlock {
    /// Stable id within the owning [`super::ControlFlowGraph`].
    pub id: BlockId,

    /// Address of the first instruction.
    pub start_address: u64,

    /// Address *after* the last instruction (exclusive).
    pub end_address: u64,

    /// Instructions in program order. The last one (if any) is the
    /// terminator iff [`BlockKind::Exit`] / [`BlockKind::UnresolvedExit`]
    /// or there is exactly one outgoing edge per `Jump` / two per
    /// `BranchIf`.
    pub instructions: Vec<Instruction>,

    /// What kind of block this is.
    pub kind: BlockKind,
}

impl BasicBlock {
    /// Number of instructions in this block.
    #[must_use]
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// `true` iff the block has no instructions (synthetic placeholder).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// The terminator instruction, if any. The terminator is the last
    /// instruction iff that instruction's `is_terminator()` returns `true`.
    #[must_use]
    pub fn terminator(&self) -> Option<&Instruction> {
        self.instructions.last().filter(|ins| ins.is_terminator())
    }

    /// `true` if this block falls through to the next block in the address
    /// stream (i.e. it has no terminator).
    #[must_use]
    pub fn falls_through(&self) -> bool {
        self.instructions
            .last()
            .is_none_or(|ins| !ins.is_terminator())
    }
}

#[cfg(test)]
mod tests {
    use omnisec_core::Arch;
    use omnisec_ir::{Instruction, OpCode};

    use super::*;

    #[test]
    fn empty_block_helpers() {
        let bb = BasicBlock {
            id: 0,
            start_address: 0,
            end_address: 0,
            instructions: vec![],
            kind: BlockKind::Entry,
        };
        assert!(bb.is_empty());
        assert_eq!(bb.len(), 0);
        assert!(bb.terminator().is_none());
        assert!(bb.falls_through());
    }

    #[test]
    fn terminator_detection() {
        let bb = BasicBlock {
            id: 1,
            start_address: 0x1000,
            end_address: 0x1004,
            instructions: vec![
                Instruction::new(OpCode::Move, 0x1000, 2, Arch::X86_64),
                Instruction::new(OpCode::Return, 0x1002, 1, Arch::X86_64),
            ],
            kind: BlockKind::Exit,
        };
        assert_eq!(bb.terminator().unwrap().opcode, OpCode::Return);
        assert!(!bb.falls_through());
    }
}
