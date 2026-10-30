//! SSA construction using the Cytron algorithm.

use std::collections::VecDeque;

use omnisec_cfg::{BlockId, ControlFlowGraph, DominanceFrontiers, DominatorTree};
use omnisec_ir::{Instruction, OpCode, Operand, Register, RegisterClass};
use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

/// Errors that can occur during SSA construction.
#[derive(Debug)]
pub enum SsaError {
    /// The CFG entry id does not point at a block.
    MissingEntry(BlockId),
    /// A block id referenced by the CFG could not be found.
    MissingBlock(BlockId),
}

impl std::fmt::Display for SsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingEntry(id) => write!(f, "CFG entry block {id} is missing"),
            Self::MissingBlock(id) => write!(f, "CFG block {id} is missing"),
        }
    }
}

impl std::error::Error for SsaError {}

/// A register version in SSA form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SsaVariable {
    /// Original architectural or virtual register.
    pub register: Register,
    /// SSA version. Version `0` is the implicit entry value.
    pub version: u32,
}

impl SsaVariable {
    /// Build the implicit entry value for a register.
    #[must_use]
    pub const fn entry(register: Register) -> Self {
        Self {
            register,
            version: 0,
        }
    }
}

/// A phi-function at a CFG merge point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhiFunction {
    /// Original variable this phi merges.
    pub variable: Register,
    /// SSA destination produced by this phi.
    pub destination: SsaVariable,
    /// Incoming value per predecessor block.
    pub operands: FxHashMap<BlockId, SsaVariable>,
    /// Block that owns this phi-function.
    pub block_id: BlockId,
}

/// One OmniIR instruction annotated with SSA uses and definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsaInstruction {
    /// Owning basic block id.
    pub block_id: BlockId,
    /// Instruction index inside the basic block.
    pub instruction_index: usize,
    /// Original OmniIR instruction.
    pub original: Instruction,
    /// SSA values read by this instruction.
    pub uses: Vec<SsaVariable>,
    /// SSA values defined by this instruction.
    pub definitions: Vec<SsaVariable>,
}

/// SSA representation of one CFG basic block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsaBlock {
    /// Original CFG block id.
    pub block_id: BlockId,
    /// Phi-functions placed at block entry.
    pub phis: Vec<PhiFunction>,
    /// SSA-annotated instructions in original order.
    pub instructions: Vec<SsaInstruction>,
}

/// SSA representation of one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsaFunction {
    /// Entry block id.
    pub entry: BlockId,
    /// Blocks in CFG insertion order.
    pub block_order: Vec<BlockId>,
    /// SSA blocks keyed by original CFG block id.
    pub blocks: FxHashMap<BlockId, SsaBlock>,
    /// Highest allocated SSA version per original register.
    pub version_counts: FxHashMap<Register, u32>,
}

impl SsaFunction {
    /// Look up an SSA block by id.
    #[must_use]
    pub fn block(&self, id: BlockId) -> Option<&SsaBlock> {
        self.blocks.get(&id)
    }

    /// Iterate blocks in CFG insertion order.
    pub fn iter_blocks(&self) -> impl Iterator<Item = &SsaBlock> + '_ {
        self.block_order
            .iter()
            .filter_map(|block_id| self.blocks.get(block_id))
    }

    /// Count all phi-functions in the function.
    #[must_use]
    pub fn phi_count(&self) -> usize {
        self.blocks.values().map(|block| block.phis.len()).sum()
    }
}

/// SSA builder using Cytron phi placement and dominator-tree renaming.
pub struct SsaBuilder {
    cfg: ControlFlowGraph,
}

/// Backward-compatible alias for the original all-caps builder name.
pub type SSABuilder = SsaBuilder;

impl SsaBuilder {
    /// Create a new SSA builder.
    #[must_use]
    pub const fn new(cfg: ControlFlowGraph) -> Self {
        Self { cfg }
    }

    /// Construct SSA form.
    pub fn build(&self) -> Result<SsaFunction, SsaError> {
        let entry = self.cfg.entry();
        if self.cfg.block(entry).is_none() {
            return Err(SsaError::MissingEntry(entry));
        }

        let domtree = DominatorTree::compute(&self.cfg);
        let frontiers = DominanceFrontiers::compute(&self.cfg, &domtree);
        let definitions = collect_definition_blocks(&self.cfg);
        let phi_placements = place_phi_functions(&definitions, &frontiers);
        let block_order: Vec<BlockId> = self.cfg.block_ids().collect();
        let mut blocks = initialize_blocks(&self.cfg, &block_order, phi_placements);
        let children = dominator_children(&self.cfg, &domtree);
        let mut state = RenameState::default();
        let mut visited = FxHashSet::default();

        rename_block(
            entry,
            &self.cfg,
            &children,
            &mut blocks,
            &mut state,
            &mut visited,
        )?;

        for &block_id in &block_order {
            if !visited.contains(&block_id) {
                rename_block(
                    block_id,
                    &self.cfg,
                    &children,
                    &mut blocks,
                    &mut state,
                    &mut visited,
                )?;
            }
        }

        Ok(SsaFunction {
            entry,
            block_order,
            blocks,
            version_counts: state.counters,
        })
    }
}

fn collect_definition_blocks(cfg: &ControlFlowGraph) -> FxHashMap<Register, FxHashSet<BlockId>> {
    let mut definitions: FxHashMap<Register, FxHashSet<BlockId>> = FxHashMap::default();
    let mut observed = FxHashSet::new();

    for (block_id, block) in cfg.iter() {
        let mut block_defs = FxHashSet::new();
        for instruction in &block.instructions {
            observed.extend(registers_read_by(instruction));
            let instruction_defs = registers_defined_by(instruction);
            observed.extend(instruction_defs.iter().cloned());
            block_defs.extend(instruction_defs);
        }
        for register in block_defs {
            definitions.entry(register).or_default().insert(block_id);
        }
    }

    for register in observed {
        definitions.entry(register).or_default().insert(cfg.entry());
    }

    definitions
}

fn place_phi_functions(
    definitions: &FxHashMap<Register, FxHashSet<BlockId>>,
    frontiers: &DominanceFrontiers,
) -> FxHashMap<BlockId, Vec<PhiFunction>> {
    let mut phis: FxHashMap<BlockId, Vec<PhiFunction>> = FxHashMap::default();
    let mut placed: FxHashMap<BlockId, FxHashSet<Register>> = FxHashMap::default();

    for (register, def_blocks) in definitions {
        let mut worklist: VecDeque<BlockId> = def_blocks.iter().copied().collect();

        while let Some(block_id) = worklist.pop_front() {
            for frontier_block in frontiers.frontier(block_id) {
                if !placed
                    .entry(frontier_block)
                    .or_default()
                    .insert(register.clone())
                {
                    continue;
                }

                phis.entry(frontier_block).or_default().push(PhiFunction {
                    variable: register.clone(),
                    destination: SsaVariable::entry(register.clone()),
                    operands: FxHashMap::default(),
                    block_id: frontier_block,
                });

                if !def_blocks.contains(&frontier_block) {
                    worklist.push_back(frontier_block);
                }
            }
        }
    }

    for block_phis in phis.values_mut() {
        block_phis.sort_by(|left, right| compare_registers(&left.variable, &right.variable));
    }

    phis
}

fn initialize_blocks(
    cfg: &ControlFlowGraph,
    block_order: &[BlockId],
    mut phi_placements: FxHashMap<BlockId, Vec<PhiFunction>>,
) -> FxHashMap<BlockId, SsaBlock> {
    let mut blocks = FxHashMap::default();

    for &block_id in block_order {
        let instruction_capacity = cfg
            .block(block_id)
            .map_or(0, |block| block.instructions.len());
        blocks.insert(
            block_id,
            SsaBlock {
                block_id,
                phis: phi_placements.remove(&block_id).unwrap_or_default(),
                instructions: Vec::with_capacity(instruction_capacity),
            },
        );
    }

    blocks
}

fn dominator_children(
    cfg: &ControlFlowGraph,
    domtree: &DominatorTree,
) -> FxHashMap<BlockId, Vec<BlockId>> {
    let mut children = FxHashMap::default();
    for block_id in cfg.block_ids() {
        let mut block_children: Vec<BlockId> = domtree.children(block_id).into_iter().collect();
        block_children.sort_unstable();
        children.insert(block_id, block_children);
    }
    children
}

fn rename_block(
    block_id: BlockId,
    cfg: &ControlFlowGraph,
    children: &FxHashMap<BlockId, Vec<BlockId>>,
    blocks: &mut FxHashMap<BlockId, SsaBlock>,
    state: &mut RenameState,
    visited: &mut FxHashSet<BlockId>,
) -> Result<(), SsaError> {
    if !visited.insert(block_id) {
        return Ok(());
    }

    let snapshot = state.snapshot();

    {
        let block = blocks
            .get_mut(&block_id)
            .ok_or(SsaError::MissingBlock(block_id))?;
        for phi in &mut block.phis {
            phi.destination = state.push(&phi.variable);
        }
    }

    let source_block = cfg
        .block(block_id)
        .ok_or(SsaError::MissingBlock(block_id))?;
    let mut instructions = Vec::with_capacity(source_block.instructions.len());
    for (instruction_index, instruction) in source_block.instructions.iter().enumerate() {
        let uses = registers_read_by(instruction)
            .into_iter()
            .map(|register| state.current(&register))
            .collect();
        let definitions = registers_defined_by(instruction)
            .into_iter()
            .map(|register| state.push(&register))
            .collect();
        instructions.push(SsaInstruction {
            block_id,
            instruction_index,
            original: instruction.clone(),
            uses,
            definitions,
        });
    }
    blocks
        .get_mut(&block_id)
        .ok_or(SsaError::MissingBlock(block_id))?
        .instructions = instructions;

    for &successor in cfg.successors(block_id) {
        if let Some(successor_block) = blocks.get_mut(&successor) {
            for phi in &mut successor_block.phis {
                phi.operands.insert(block_id, state.current(&phi.variable));
            }
        }
    }

    if let Some(block_children) = children.get(&block_id) {
        for &child in block_children {
            rename_block(child, cfg, children, blocks, state, visited)?;
        }
    }

    state.restore(snapshot);
    Ok(())
}

#[derive(Debug, Default)]
struct RenameState {
    stacks: FxHashMap<Register, Vec<u32>>,
    counters: FxHashMap<Register, u32>,
}

impl RenameState {
    fn push(&mut self, register: &Register) -> SsaVariable {
        let version = self.counters.entry(register.clone()).or_insert(0);
        *version += 1;
        self.stacks
            .entry(register.clone())
            .or_default()
            .push(*version);
        SsaVariable {
            register: register.clone(),
            version: *version,
        }
    }

    fn current(&self, register: &Register) -> SsaVariable {
        let version = self
            .stacks
            .get(register)
            .and_then(|stack| stack.last())
            .copied()
            .unwrap_or(0);
        SsaVariable {
            register: register.clone(),
            version,
        }
    }

    fn snapshot(&self) -> FxHashMap<Register, usize> {
        self.stacks
            .iter()
            .map(|(register, stack)| (register.clone(), stack.len()))
            .collect()
    }

    fn restore(&mut self, snapshot: FxHashMap<Register, usize>) {
        let registers: Vec<Register> = self.stacks.keys().cloned().collect();
        for register in registers {
            let height = snapshot.get(&register).copied().unwrap_or(0);
            if let Some(stack) = self.stacks.get_mut(&register) {
                stack.truncate(height);
            }
        }
    }
}

fn registers_read_by(instruction: &Instruction) -> Vec<Register> {
    let mut reads = Vec::new();

    for operand in &instruction.src {
        collect_read_registers(operand, &mut reads);
    }
    for operand in &instruction.dst {
        collect_address_registers(operand, &mut reads);
    }
    if instruction_reads_destination(instruction.opcode) {
        for operand in &instruction.dst {
            if let Operand::Register(register) = operand {
                push_unique(&mut reads, register.clone());
            }
        }
    }

    reads
}

fn registers_defined_by(instruction: &Instruction) -> Vec<Register> {
    if !instruction_defines_destination(instruction.opcode) {
        return Vec::new();
    }

    let mut definitions = Vec::new();
    for operand in &instruction.dst {
        if let Operand::Register(register) = operand {
            push_unique(&mut definitions, register.clone());
        }
    }
    definitions
}

fn collect_read_registers(operand: &Operand, out: &mut Vec<Register>) {
    match operand {
        Operand::Register(register) => push_unique(out, register.clone()),
        Operand::Memory(_) => collect_address_registers(operand, out),
        Operand::Immediate(_) | Operand::Label(_) | Operand::Symbol(_) | Operand::Type(_) => {}
    }
}

fn collect_address_registers(operand: &Operand, out: &mut Vec<Register>) {
    let Operand::Memory(address) = operand else {
        return;
    };

    if let Some(register) = &address.base {
        push_unique(out, register.clone());
    }
    if let Some(register) = &address.index {
        push_unique(out, register.clone());
    }
    if let Some(register) = &address.segment {
        push_unique(out, register.clone());
    }
}

fn push_unique(out: &mut Vec<Register>, register: Register) {
    if !out.contains(&register) {
        out.push(register);
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

fn compare_registers(left: &Register, right: &Register) -> std::cmp::Ordering {
    left.arch
        .name()
        .cmp(right.arch.name())
        .then_with(|| register_class_rank(left.class).cmp(&register_class_rank(right.class)))
        .then_with(|| left.native_id.cmp(&right.native_id))
        .then_with(|| left.bit_width.cmp(&right.bit_width))
        .then_with(|| left.name.cmp(&right.name))
}

const fn register_class_rank(class: RegisterClass) -> u8 {
    match class {
        RegisterClass::GeneralPurpose => 0,
        RegisterClass::StackPointer => 1,
        RegisterClass::FramePointer => 2,
        RegisterClass::ProgramCounter => 3,
        RegisterClass::Flags => 4,
        RegisterClass::Float => 5,
        RegisterClass::Vector => 6,
        RegisterClass::Segment => 7,
        RegisterClass::Control => 8,
        RegisterClass::Virtual => 9,
    }
}

#[cfg(test)]
mod tests {
    use omnisec_cfg::{BasicBlock, BlockKind};
    use omnisec_ir::{Arch, RegisterClass};

    use super::*;

    fn reg(name: &str, native_id: u32) -> Register {
        Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id,
            bit_width: 64,
            name: name.into(),
        }
    }

    fn block(id: BlockId, instructions: Vec<Instruction>) -> BasicBlock {
        BasicBlock {
            id,
            start_address: u64::from(id) * 0x10,
            end_address: u64::from(id) * 0x10 + instructions.len() as u64,
            instructions,
            kind: if id == 0 {
                BlockKind::Entry
            } else {
                BlockKind::Normal
            },
        }
    }

    fn mov(address: u64, dst: Register, src: Register) -> Instruction {
        Instruction::new(OpCode::Move, address, 1, Arch::X86_64)
            .with_dst([Operand::Register(dst)])
            .with_src([Operand::Register(src)])
    }

    fn add(address: u64, dst: Register, src: Register) -> Instruction {
        Instruction::new(OpCode::Add, address, 1, Arch::X86_64)
            .with_dst([Operand::Register(dst)])
            .with_src([Operand::Register(src)])
    }

    fn has_version(values: &[SsaVariable], register: &Register, version: u32) -> bool {
        values
            .iter()
            .any(|value| value.register == *register && value.version == version)
    }

    #[test]
    fn straight_line_renames_uses_before_definitions() {
        let input = reg("rax", 0);
        let accumulator = reg("rbx", 1);
        let increment = reg("rcx", 2);

        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(block(
            0,
            vec![
                mov(0x1000, accumulator.clone(), input.clone()),
                add(0x1001, accumulator.clone(), increment.clone()),
            ],
        ));

        let ssa = SsaBuilder::new(cfg).build().unwrap();
        let entry = ssa.block(0).unwrap();

        assert_eq!(ssa.phi_count(), 0);
        assert_eq!(entry.instructions.len(), 2);
        assert!(has_version(&entry.instructions[0].uses, &input, 0));
        assert!(has_version(
            &entry.instructions[0].definitions,
            &accumulator,
            1
        ));
        assert!(has_version(&entry.instructions[1].uses, &accumulator, 1));
        assert!(has_version(&entry.instructions[1].uses, &increment, 0));
        assert!(has_version(
            &entry.instructions[1].definitions,
            &accumulator,
            2
        ));
    }

    #[test]
    fn diamond_places_phi_and_fills_predecessor_operands() {
        let variable = reg("rax", 0);
        let entry_input = reg("rbx", 1);
        let branch_input = reg("rcx", 2);
        let output = reg("rdx", 3);

        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(block(
            0,
            vec![mov(0x1000, variable.clone(), entry_input.clone())],
        ));
        cfg.insert_block(block(1, vec![mov(0x1010, variable.clone(), branch_input)]));
        cfg.insert_block(block(2, vec![]));
        cfg.insert_block(block(3, vec![mov(0x1030, output, variable.clone())]));
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);

        let ssa = SsaBuilder::new(cfg).build().unwrap();
        let join = ssa.block(3).unwrap();

        assert_eq!(ssa.phi_count(), 1);
        assert_eq!(join.phis.len(), 1);
        let phi = &join.phis[0];
        assert_eq!(phi.variable, variable);
        assert_eq!(phi.destination.version, 3);
        assert_eq!(phi.operands.get(&1).unwrap().version, 2);
        assert_eq!(phi.operands.get(&2).unwrap().version, 1);
        assert!(has_version(&join.instructions[0].uses, &variable, 3));
    }

    #[test]
    fn loop_header_gets_phi_for_back_edge_value() {
        let variable = reg("rax", 0);
        let input = reg("rbx", 1);
        let output = reg("rcx", 2);

        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(block(0, vec![mov(0x1000, variable.clone(), input.clone())]));
        cfg.insert_block(block(1, vec![mov(0x1010, output, variable.clone())]));
        cfg.insert_block(block(2, vec![mov(0x1020, variable.clone(), input)]));
        cfg.insert_block(block(3, vec![]));
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 1);

        let ssa = SsaBuilder::new(cfg).build().unwrap();
        let header = ssa.block(1).unwrap();
        let phi = header
            .phis
            .iter()
            .find(|phi| phi.variable == variable)
            .unwrap();

        assert_eq!(phi.operands.get(&0).unwrap().version, 1);
        assert_eq!(phi.operands.get(&2).unwrap().version, 3);
        assert!(has_version(&header.instructions[0].uses, &variable, 2));
    }

    #[test]
    fn missing_entry_is_reported() {
        let cfg = ControlFlowGraph::empty(42);
        let error = SsaBuilder::new(cfg).build().unwrap_err();

        assert!(matches!(error, SsaError::MissingEntry(42)));
    }
}
