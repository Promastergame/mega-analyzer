//! Specific dataflow analyses.

use omnisec_cfg::{BlockId, ControlFlowGraph};
use omnisec_ir::{Instruction, OpCode, Operand, Register};
use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

use super::framework::{DataflowAnalysis, Direction, MeetOperator};

/// Union meet operator for set-based analyses.
#[derive(Debug, Clone, Copy)]
pub struct UnionMeet;

impl<T> MeetOperator<FxHashSet<T>> for UnionMeet
where
    T: Clone + Eq + std::hash::Hash + Send + Sync,
{
    fn meet(&self, a: &FxHashSet<T>, b: &FxHashSet<T>) -> FxHashSet<T> {
        a.union(b).cloned().collect()
    }
}

/// Intersection meet operator for set-based analyses.
#[derive(Debug, Clone, Copy)]
pub struct IntersectMeet;

impl<T> MeetOperator<FxHashSet<T>> for IntersectMeet
where
    T: Clone + Eq + std::hash::Hash + Send + Sync,
{
    fn meet(&self, a: &FxHashSet<T>, b: &FxHashSet<T>) -> FxHashSet<T> {
        a.intersection(b).cloned().collect()
    }
}

/// Flat lattice value for constant propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstValue {
    /// Nothing known yet (identity of the meet).
    Top,
    /// Register holds this constant.
    Const(i64),
    /// Conflicting / non-constant (absorbing).
    Bottom,
}

impl ConstValue {
    /// Greatest-lower-bound of two lattice values.
    #[must_use]
    pub const fn meet(a: Self, b: Self) -> Self {
        match (a, b) {
            (Self::Top, x) | (x, Self::Top) => x,
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Const(x), Self::Const(y)) => {
                if x == y {
                    Self::Const(x)
                } else {
                    Self::Bottom
                }
            }
        }
    }
}

/// Meet operator for constant-propagation facts (key-wise lattice meet;
/// a register absent from a fact is `Top`).
#[derive(Debug, Clone, Copy)]
pub struct ConstMeet;

impl MeetOperator<FxHashMap<Register, ConstValue>> for ConstMeet {
    fn meet(
        &self,
        a: &FxHashMap<Register, ConstValue>,
        b: &FxHashMap<Register, ConstValue>,
    ) -> FxHashMap<Register, ConstValue> {
        let mut out = FxHashMap::default();
        for (reg, va) in a {
            let vb = b.get(reg).copied().unwrap_or(ConstValue::Top);
            let m = ConstValue::meet(*va, vb);
            if m != ConstValue::Top {
                out.insert(reg.clone(), m);
            }
        }
        for (reg, vb) in b {
            if !a.contains_key(reg) && *vb != ConstValue::Top {
                out.insert(reg.clone(), *vb);
            }
        }
        out
    }
}

/// Forward constant propagation over the flat lattice.
///
/// The transfer function folds `Move` of immediates, register-to-register
/// copies, and constant arithmetic (`Add`/`Sub`/`Mul`/`And`/`Or`/`Xor`/
/// shifts/`Neg`/`Not` with wrapping semantics). Memory loads and unknown
/// definitions yield `Bottom`; calls conservatively clobber all tracked
/// registers to `Bottom`.
#[derive(Debug, Clone)]
pub struct ConstantPropagation {
    blocks: FxHashMap<BlockId, Vec<Instruction>>,
}

impl ConstantPropagation {
    /// Snapshot the CFG blocks this analysis runs over.
    #[must_use]
    pub fn new(cfg: &ControlFlowGraph) -> Self {
        let mut blocks = FxHashMap::default();
        for (block_id, block) in cfg.iter() {
            blocks.insert(block_id, block.instructions.clone());
        }
        Self { blocks }
    }

    /// Query the outbound fact for one register, if the block was analyzed.
    #[must_use]
    pub fn lookup(
        result: &super::framework::AnalysisResult<FxHashMap<Register, ConstValue>>,
        block_id: u32,
        register: &Register,
    ) -> ConstValue {
        result
            .out_fact(block_id)
            .and_then(|fact| fact.get(register).copied())
            .unwrap_or(ConstValue::Top)
    }
}

impl DataflowAnalysis<FxHashMap<Register, ConstValue>> for ConstantPropagation {
    fn direction(&self) -> Direction {
        Direction::Forward
    }

    fn initial_fact(&self) -> FxHashMap<Register, ConstValue> {
        FxHashMap::default()
    }

    fn transfer(
        &self,
        block_id: u32,
        mut fact: FxHashMap<Register, ConstValue>,
    ) -> FxHashMap<Register, ConstValue> {
        let Some(instructions) = self.blocks.get(&block_id) else {
            return fact;
        };
        for instruction in instructions {
            transfer_instruction(instruction, &mut fact);
        }
        fact
    }

    fn meet(&self) -> Box<dyn MeetOperator<FxHashMap<Register, ConstValue>>> {
        Box::new(ConstMeet)
    }
}

/// Evaluate an operand in the current lattice state.
fn eval_operand(operand: &Operand, fact: &FxHashMap<Register, ConstValue>) -> ConstValue {
    match operand {
        Operand::Immediate(value) => ConstValue::Const(*value),
        Operand::Register(register) => fact.get(register).copied().unwrap_or(ConstValue::Top),
        // Memory contents are not tracked: any load is non-constant.
        Operand::Memory(_) | Operand::Label(_) | Operand::Symbol(_) | Operand::Type(_) => {
            ConstValue::Bottom
        }
    }
}

/// Apply one instruction to the constant fact.
fn transfer_instruction(instruction: &Instruction, fact: &mut FxHashMap<Register, ConstValue>) {
    // Calls clobber everything tracked (conservative without ABI knowledge).
    if matches!(instruction.opcode, OpCode::Call | OpCode::IndirectCall) {
        for value in fact.values_mut() {
            *value = ConstValue::Bottom;
        }
        return;
    }

    // Destination register, if this instruction defines one.
    let Some(dst) = instruction.dst.first().and_then(|op| match op {
        Operand::Register(register) => Some(register.clone()),
        _ => None,
    }) else {
        return;
    };
    if !instruction_defines_destination(instruction.opcode) {
        return;
    }

    let value = match instruction.opcode {
        OpCode::Move | OpCode::Load => instruction
            .src
            .first()
            .map_or(ConstValue::Bottom, |src| eval_operand(src, fact)),
        OpCode::Add => fold_binary(instruction, fact, i64::wrapping_add),
        OpCode::Sub => fold_binary(instruction, fact, i64::wrapping_sub),
        OpCode::Mul | OpCode::UMul => fold_binary(instruction, fact, i64::wrapping_mul),
        OpCode::And => fold_binary(instruction, fact, |a, b| a & b),
        OpCode::Or => fold_binary(instruction, fact, |a, b| a | b),
        OpCode::Xor => fold_binary(instruction, fact, |a, b| a ^ b),
        OpCode::Shl => fold_shift(instruction, fact, |a, b| a.wrapping_shl(b)),
        OpCode::Shr => fold_shift(instruction, fact, |a, b| (a as u64).wrapping_shr(b) as i64),
        OpCode::Sar => fold_shift(instruction, fact, |a, b| a.wrapping_shr(b)),
        OpCode::Neg => fold_unary(instruction, fact, i64::wrapping_neg),
        OpCode::Not => fold_unary(instruction, fact, |a| !a),
        _ => ConstValue::Bottom,
    };
    fact.insert(dst, value);
}

/// Fold a two-operand instruction when both sides are constant.
///
/// `Top` propagates (wait for more facts); `Bottom` poisons the result.
fn fold_binary(
    instruction: &Instruction,
    fact: &FxHashMap<Register, ConstValue>,
    op: impl Fn(i64, i64) -> i64,
) -> ConstValue {
    if instruction.src.len() < 2 {
        return ConstValue::Bottom;
    }
    match (
        eval_operand(&instruction.src[0], fact),
        eval_operand(&instruction.src[1], fact),
    ) {
        (ConstValue::Const(a), ConstValue::Const(b)) => ConstValue::Const(op(a, b)),
        (ConstValue::Bottom, _) | (_, ConstValue::Bottom) => ConstValue::Bottom,
        _ => ConstValue::Top,
    }
}

/// Fold a shift with a constant distance (masked to the operand width).
fn fold_shift(
    instruction: &Instruction,
    fact: &FxHashMap<Register, ConstValue>,
    op: impl Fn(i64, u32) -> i64,
) -> ConstValue {
    if instruction.src.len() < 2 {
        return ConstValue::Bottom;
    }
    match (
        eval_operand(&instruction.src[0], fact),
        eval_operand(&instruction.src[1], fact),
    ) {
        (ConstValue::Const(a), ConstValue::Const(b)) => {
            ConstValue::Const(op(a, (b as u64 & 63) as u32))
        }
        (ConstValue::Bottom, _) | (_, ConstValue::Bottom) => ConstValue::Bottom,
        _ => ConstValue::Top,
    }
}

/// Fold a single-operand instruction when its input is constant.
fn fold_unary(
    instruction: &Instruction,
    fact: &FxHashMap<Register, ConstValue>,
    op: impl Fn(i64) -> i64,
) -> ConstValue {
    match instruction.src.first().map(|src| eval_operand(src, fact)) {
        Some(ConstValue::Const(a)) => ConstValue::Const(op(a)),
        Some(ConstValue::Bottom) => ConstValue::Bottom,
        _ => ConstValue::Top,
    }
}

/// Backward live-register analysis.
#[derive(Debug, Clone)]
pub struct LiveVariables {
    block_uses: FxHashMap<BlockId, FxHashSet<Register>>,
    block_defs: FxHashMap<BlockId, FxHashSet<Register>>,
}

impl LiveVariables {
    /// Create a live-register analysis for a CFG.
    #[must_use]
    pub fn new(cfg: &ControlFlowGraph) -> Self {
        let mut block_uses = FxHashMap::default();
        let mut block_defs = FxHashMap::default();

        for (block_id, block) in cfg.iter() {
            let (uses, defs) = compute_block_use_def(&block.instructions);
            block_uses.insert(block_id, uses);
            block_defs.insert(block_id, defs);
        }

        Self {
            block_uses,
            block_defs,
        }
    }
}

impl DataflowAnalysis<FxHashSet<Register>> for LiveVariables {
    fn direction(&self) -> Direction {
        Direction::Backward
    }

    fn initial_fact(&self) -> FxHashSet<Register> {
        FxHashSet::default()
    }

    fn transfer(&self, block_id: u32, mut fact: FxHashSet<Register>) -> FxHashSet<Register> {
        if let Some(defs) = self.block_defs.get(&block_id) {
            fact.retain(|reg| !defs.contains(reg));
        }
        if let Some(uses) = self.block_uses.get(&block_id) {
            fact.extend(uses.iter().cloned());
        }
        fact
    }

    fn meet(&self) -> Box<dyn MeetOperator<FxHashSet<Register>>> {
        Box::new(UnionMeet)
    }
}

/// A single reaching definition of a register.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Definition {
    /// Register defined by the instruction.
    pub variable: Register,
    /// Basic block containing the definition.
    pub block_id: BlockId,
    /// Instruction index inside the basic block.
    pub instruction_index: usize,
    /// Source instruction address.
    pub address: u64,
}

/// Forward reaching-definitions analysis.
#[derive(Debug, Clone)]
pub struct ReachingDefinitions {
    block_defs: FxHashMap<BlockId, Vec<Definition>>,
}

impl ReachingDefinitions {
    /// Create a reaching-definitions analysis for a CFG.
    #[must_use]
    pub fn new(cfg: &ControlFlowGraph) -> Self {
        let mut block_defs = FxHashMap::default();

        for (block_id, block) in cfg.iter() {
            let defs = block
                .instructions
                .iter()
                .enumerate()
                .flat_map(|(instruction_index, instruction)| {
                    registers_defined_by(instruction)
                        .into_iter()
                        .map(move |variable| Definition {
                            variable,
                            block_id,
                            instruction_index,
                            address: instruction.address,
                        })
                })
                .collect();
            block_defs.insert(block_id, defs);
        }

        Self { block_defs }
    }
}

impl DataflowAnalysis<FxHashSet<Definition>> for ReachingDefinitions {
    fn direction(&self) -> Direction {
        Direction::Forward
    }

    fn initial_fact(&self) -> FxHashSet<Definition> {
        FxHashSet::default()
    }

    fn transfer(&self, block_id: u32, mut fact: FxHashSet<Definition>) -> FxHashSet<Definition> {
        if let Some(defs) = self.block_defs.get(&block_id) {
            for def in defs {
                fact.retain(|existing| existing.variable != def.variable);
                fact.insert(def.clone());
            }
        }
        fact
    }

    fn meet(&self) -> Box<dyn MeetOperator<FxHashSet<Definition>>> {
        Box::new(UnionMeet)
    }
}

fn compute_block_use_def(
    instructions: &[Instruction],
) -> (FxHashSet<Register>, FxHashSet<Register>) {
    let mut uses = FxHashSet::default();
    let mut defs = FxHashSet::default();

    for instruction in instructions {
        for register in registers_read_by(instruction) {
            if !defs.contains(&register) {
                uses.insert(register);
            }
        }
        defs.extend(registers_defined_by(instruction));
    }

    (uses, defs)
}

/// Get all registers read by an instruction.
pub fn registers_read_by(instruction: &Instruction) -> FxHashSet<Register> {
    let mut reads = FxHashSet::default();

    for operand in &instruction.src {
        collect_read_registers(operand, &mut reads);
    }
    for operand in &instruction.dst {
        collect_address_registers(operand, &mut reads);
    }
    if instruction_reads_destination(instruction.opcode) {
        for operand in &instruction.dst {
            if let Operand::Register(register) = operand {
                reads.insert(register.clone());
            }
        }
    }

    reads
}

/// Get all registers defined by an instruction.
pub fn registers_defined_by(instruction: &Instruction) -> FxHashSet<Register> {
    if !instruction_defines_destination(instruction.opcode) {
        return FxHashSet::default();
    }

    instruction
        .dst
        .iter()
        .filter_map(|operand| match operand {
            Operand::Register(register) => Some(register.clone()),
            Operand::Immediate(_)
            | Operand::Memory(_)
            | Operand::Label(_)
            | Operand::Symbol(_)
            | Operand::Type(_) => None,
        })
        .collect()
}

fn collect_read_registers(operand: &Operand, out: &mut FxHashSet<Register>) {
    match operand {
        Operand::Register(register) => {
            out.insert(register.clone());
        }
        Operand::Memory(_) => collect_address_registers(operand, out),
        Operand::Immediate(_) | Operand::Label(_) | Operand::Symbol(_) | Operand::Type(_) => {}
    }
}

fn collect_address_registers(operand: &Operand, out: &mut FxHashSet<Register>) {
    let Operand::Memory(address) = operand else {
        return;
    };

    if let Some(register) = &address.base {
        out.insert(register.clone());
    }
    if let Some(register) = &address.index {
        out.insert(register.clone());
    }
    if let Some(register) = &address.segment {
        out.insert(register.clone());
    }
}

const fn instruction_reads_destination(opcode: OpCode) -> bool {
    matches!(
        opcode,
        OpCode::Add
            | OpCode::Sub
            | OpCode::Mul
            | OpCode::UMul
            | OpCode::Div
            | OpCode::UDiv
            | OpCode::Rem
            | OpCode::URem
            | OpCode::Neg
            | OpCode::And
            | OpCode::Or
            | OpCode::Xor
            | OpCode::Not
            | OpCode::Shl
            | OpCode::Shr
            | OpCode::Sar
            | OpCode::Rol
            | OpCode::Ror
            | OpCode::Compare
            | OpCode::Test
            | OpCode::CmpXchg
    )
}

const fn instruction_defines_destination(opcode: OpCode) -> bool {
    !matches!(
        opcode,
        OpCode::Nop
            | OpCode::Store
            | OpCode::Compare
            | OpCode::Test
            | OpCode::Fence
            | OpCode::Jump
            | OpCode::BranchIf
            | OpCode::Call
            | OpCode::IndirectCall
            | OpCode::Return
            | OpCode::Trap
            | OpCode::SystemCall
            | OpCode::Halt
            | OpCode::Invalid
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_cfg::{BasicBlock, BlockKind, ControlFlowGraph};
    use omnisec_ir::{Arch, MemoryAddress, RegisterClass};

    fn reg(name: &str, native_id: u32) -> Register {
        Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id,
            bit_width: 64,
            name: name.into(),
        }
    }

    fn mov(address: u64, dst: Register, src: Register) -> Instruction {
        Instruction::new(OpCode::Move, address, 1, Arch::X86_64)
            .with_dst([Operand::Register(dst)])
            .with_src([Operand::Register(src)])
    }

    #[test]
    fn constant_propagation_tracks_immediates() {
        let rax = reg("rax", 0);
        let rbx = reg("rbx", 1);

        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(BasicBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1002,
            instructions: vec![
                Instruction::new(OpCode::Move, 0x1000, 1, Arch::X86_64)
                    .with_dst([Operand::Register(rax.clone())])
                    .with_src([Operand::Immediate(40)]),
                Instruction::new(OpCode::Add, 0x1001, 1, Arch::X86_64)
                    .with_dst([Operand::Register(rbx.clone())])
                    .with_src([Operand::Register(rax.clone()), Operand::Immediate(2)]),
            ],
            kind: BlockKind::Entry,
        });

        let result = ConstantPropagation::new(&cfg).analyze(&cfg);
        assert_eq!(
            ConstantPropagation::lookup(&result, 0, &rax),
            ConstValue::Const(40)
        );
        assert_eq!(
            ConstantPropagation::lookup(&result, 0, &rbx),
            ConstValue::Const(42)
        );
    }

    #[test]
    fn constant_propagation_meets_conflicts_to_bottom() {
        let rax = reg("rax", 0);
        let input = reg("rbx", 1);

        let mut cfg = ControlFlowGraph::empty(0);
        for (id, value, kind) in [
            (0u32, None, BlockKind::Entry),
            (1u32, Some(1i64), BlockKind::Normal),
            (2u32, Some(2i64), BlockKind::Normal),
            (3u32, None, BlockKind::Exit),
        ] {
            let instructions = value.map_or(vec![], |v| {
                vec![
                    Instruction::new(OpCode::Move, 0x1000 + u64::from(id), 1, Arch::X86_64)
                        .with_dst([Operand::Register(rax.clone())])
                        .with_src([Operand::Immediate(v)]),
                ]
            });
            cfg.insert_block(BasicBlock {
                id,
                start_address: 0x1000 + u64::from(id) * 0x10,
                end_address: 0x1001 + u64::from(id) * 0x10,
                instructions,
                kind,
            });
        }
        // Silence the unused-variable warning while keeping the shape clear.
        let _ = input;
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);

        let result = ConstantPropagation::new(&cfg).analyze(&cfg);
        assert_eq!(
            result.in_fact(3).map(|fact| fact.get(&rax).copied()),
            Some(Some(ConstValue::Bottom))
        );
    }

    #[test]
    fn framework_smoke_test() {
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

        let analysis = ConstantPropagation::new(&cfg);
        let result = analysis.analyze(&cfg);

        assert!(result.in_fact(0).is_some());
        assert!(result.in_fact(1).is_some());
        assert!(result.out_fact(0).is_some());
        assert!(result.out_fact(1).is_some());
    }

    #[test]
    fn live_variables_tracks_backward_register_liveness() {
        let source = reg("rax", 0);
        let live_across_edge = reg("rbx", 1);
        let sink = reg("rcx", 2);

        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(BasicBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1001,
            instructions: vec![mov(0x1000, live_across_edge.clone(), source.clone())],
            kind: BlockKind::Entry,
        });
        cfg.insert_block(BasicBlock {
            id: 1,
            start_address: 0x1001,
            end_address: 0x1002,
            instructions: vec![mov(0x1001, sink, live_across_edge.clone())],
            kind: BlockKind::Exit,
        });
        cfg.add_edge(0, 1);

        let result = LiveVariables::new(&cfg).analyze(&cfg);

        assert!(result.out_fact(0).unwrap().contains(&live_across_edge));
        assert!(result.in_fact(0).unwrap().contains(&source));
        assert!(!result.in_fact(0).unwrap().contains(&live_across_edge));
        assert!(result.in_fact(1).unwrap().contains(&live_across_edge));
    }

    #[test]
    fn reaching_definitions_merges_path_specific_defs() {
        let variable = reg("rax", 0);
        let input = reg("rbx", 1);

        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(BasicBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1001,
            instructions: vec![mov(0x1000, variable.clone(), input.clone())],
            kind: BlockKind::Entry,
        });
        cfg.insert_block(BasicBlock {
            id: 1,
            start_address: 0x1010,
            end_address: 0x1011,
            instructions: vec![mov(0x1010, variable.clone(), input.clone())],
            kind: BlockKind::Normal,
        });
        cfg.insert_block(BasicBlock {
            id: 2,
            start_address: 0x1020,
            end_address: 0x1020,
            instructions: vec![],
            kind: BlockKind::Normal,
        });
        cfg.insert_block(BasicBlock {
            id: 3,
            start_address: 0x1030,
            end_address: 0x1031,
            instructions: vec![mov(0x1030, reg("rcx", 2), variable.clone())],
            kind: BlockKind::Exit,
        });
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);

        let result = ReachingDefinitions::new(&cfg).analyze(&cfg);
        let join_defs = result.in_fact(3).unwrap();

        assert!(join_defs.iter().any(|def| def.address == 0x1000));
        assert!(join_defs.iter().any(|def| def.address == 0x1010));
        assert_eq!(
            result
                .out_fact(1)
                .unwrap()
                .iter()
                .filter(|def| def.variable == variable)
                .count(),
            1
        );
    }

    #[test]
    fn reaching_definitions_kills_earlier_local_definitions() {
        let variable = reg("rax", 0);
        let input = reg("rbx", 1);

        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(BasicBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1002,
            instructions: vec![
                mov(0x1000, variable.clone(), input.clone()),
                mov(0x1001, variable.clone(), input),
            ],
            kind: BlockKind::Entry,
        });

        let result = ReachingDefinitions::new(&cfg).analyze(&cfg);
        let out = result.out_fact(0).unwrap();

        assert!(!out.iter().any(|def| def.address == 0x1000));
        assert!(out.iter().any(|def| def.address == 0x1001));
    }

    #[test]
    fn live_variables_reads_memory_address_registers() {
        let base = reg("rbp", 5);
        let dst = reg("rax", 0);
        let inst = Instruction::new(OpCode::Load, 0x1000, 3, Arch::X86_64)
            .with_dst([Operand::Register(dst.clone())])
            .with_src([Operand::Memory(MemoryAddress::reg_offset(
                base.clone(),
                -8,
                8,
            ))]);

        let (uses, defs) = compute_block_use_def(&[inst]);

        assert!(uses.contains(&base));
        assert!(defs.contains(&dst));
    }

    #[test]
    fn live_variables_reads_compare_destination_operand() {
        let lhs = reg("rax", 0);
        let rhs = reg("rbx", 1);
        let inst = Instruction::new(OpCode::Compare, 0x1000, 3, Arch::X86_64)
            .with_dst([Operand::Register(lhs.clone())])
            .with_src([Operand::Register(rhs.clone())]);

        let (uses, defs) = compute_block_use_def(&[inst]);

        assert!(uses.contains(&lhs));
        assert!(uses.contains(&rhs));
        assert!(!defs.contains(&lhs));
        assert!(!defs.contains(&rhs));
    }
}
