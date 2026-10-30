//! Symbolic executor — the main engine.
//!
//! Explores execution paths through a method's CFG, tracking symbolic and
//! concrete values through registers. Forks at branch points when conditions
//! are symbolic, and prunes paths when depth/count limits are reached.

use omnisec_json::ToJson;

use crate::constraint::Constraint;
use crate::state::{BranchDecision, ExecutionPath, ExecutionState, SymbolicValue};

/// MIR opcode kinds — must match Go's MIROpKind constants.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirOp {
    /// No-op.
    Nop = 0,
    /// Constant load.
    Const = 1,
    /// Register move.
    Move = 2,
    /// Addition.
    Add = 3,
    /// Subtraction.
    Sub = 4,
    /// Multiplication.
    Mul = 5,
    /// Division.
    Div = 6,
    /// Remainder.
    Rem = 7,
    /// Bitwise AND.
    And = 8,
    /// Bitwise OR.
    Or = 9,
    /// Bitwise XOR.
    Xor = 10,
    /// Bitwise NOT.
    Not = 11,
    /// Conditional branch.
    If = 12,
    /// Unconditional goto.
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
    /// Method invoke.
    Invoke = 20,
    /// New instance.
    NewInstance = 21,
    /// New array.
    NewArray = 22,
    /// Left shift.
    Shl = 23,
    /// Right shift (arithmetic).
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

/// A minimal MIR instruction for symbolic execution.
#[derive(Debug, Clone)]
pub struct MirInsn {
    /// Opcode kind.
    pub kind: MirOp,
    /// Condition code (for branches).
    pub cond: u8,
    /// Destination register.
    pub dst: i16,
    /// Source register 1.
    pub src1: i16,
    /// Source register 2.
    pub src2: i16,
    /// Immediate value.
    pub imm: i64,
    /// Reference index (for fields/methods).
    pub ref_idx: u32,
}

/// A basic block for symbolic execution.
#[derive(Debug, Clone)]
pub struct SymBlock {
    /// Block ID.
    pub id: usize,
    /// Instructions in this block.
    pub insns: Vec<MirInsn>,
    /// Successor block IDs.
    pub succs: Vec<usize>,
}

/// Result of symbolic execution.
#[derive(Debug, Clone, ToJson)]
pub struct SymbolicExecutionResult {
    /// All explored paths.
    pub paths: Vec<ExecutionPath>,
    /// Final symbolic register values (from the first/longest path).
    pub symbolic_values: Vec<(i16, String, u8)>, // (reg, expr, confidence)
    /// Solved constraints.
    pub constraints_solved: Vec<Constraint>,
    /// Unsolved constraints.
    pub constraints_unsolved: Vec<Constraint>,
    /// Maximum execution depth reached.
    pub execution_depth: usize,
    /// Total paths explored.
    pub path_count: usize,
    /// Paths pruned due to limits.
    pub pruned_paths: usize,
    /// Whether fallback to concrete execution was used.
    pub fallback_used: bool,
    /// Execution trace messages.
    pub trace: Vec<String>,
}

/// Symbolic executor — explores paths through a method's CFG.
pub struct SymbolicExecutor {
    blocks: Vec<SymBlock>,
    entry_id: usize,
    max_depth: usize,
    max_paths: usize,
    current_path_id: usize,
    paths: Vec<(ExecutionPath, ExecutionState)>,
    trace: Vec<String>,
    pruned_paths: usize,
    original_reg_count: usize,
}

impl SymbolicExecutor {
    /// Create a new symbolic executor.
    pub fn new(blocks: Vec<SymBlock>, entry_id: usize, reg_count: usize) -> Self {
        Self {
            blocks,
            entry_id,
            max_depth: 30,  // Higher than Go's 10
            max_paths: 200, // Higher than Go's 100
            current_path_id: 0,
            paths: Vec::new(),
            trace: Vec::new(),
            pruned_paths: 0,
            original_reg_count: reg_count,
        }
    }

    /// Set maximum exploration depth.
    pub fn set_max_depth(&mut self, depth: usize) {
        self.max_depth = depth;
    }

    /// Set maximum number of paths.
    pub fn set_max_paths(&mut self, paths: usize) {
        self.max_paths = paths;
    }

    /// Run symbolic execution and collect results.
    pub fn execute(&mut self) -> SymbolicExecutionResult {
        self.trace.push("Starting symbolic execution".into());

        let mut initial = ExecutionState::new(self.entry_id, self.current_path_id);
        self.current_path_id += 1;

        // Initialize registers as symbolic
        for i in 0..self.original_reg_count as i16 {
            initial.set_reg(
                i,
                SymbolicValue::symbolic(&format!("v{i}"), 50, "parameter"),
            );
        }
        self.trace.push(format!(
            "Initialized {} symbolic registers",
            self.original_reg_count
        ));

        self.explore_path(initial);

        self.trace.push(format!(
            "Symbolic execution complete: {} paths explored, {} pruned",
            self.paths.len(),
            self.pruned_paths
        ));

        self.collect_results()
    }

    fn explore_path(&mut self, mut state: ExecutionState) {
        if state.depth >= self.max_depth {
            self.trace.push(format!(
                "Path {}: depth limit reached ({})",
                state.path_id, state.depth
            ));
            self.pruned_paths += 1;
            return;
        }

        if self.paths.len() >= self.max_paths {
            self.trace
                .push(format!("Path {}: path count limit reached", state.path_id));
            self.pruned_paths += 1;
            return;
        }

        let block = if let Some(b) = self.find_block(state.block_id) {
            b.clone()
        } else {
            state.is_terminated = true;
            state.termination_reason = "block not found".into();
            let path = ExecutionPath {
                path_id: state.path_id,
                depth: state.depth,
                terminated: true,
                termination_reason: "block not found".into(),
                branches: Vec::new(),
                instructions_executed: 0,
                constraint_count: state.constraints.len(),
            };
            self.paths.push((path, state));
            return;
        };

        let mut branches = Vec::new();
        let mut insn_count = 0;

        for (i, insn) in block.insns.iter().enumerate() {
            self.execute_instruction(&mut state, insn);
            state.depth += 1;
            insn_count += 1;

            if insn.kind == MirOp::If {
                let (taken, reason) = self.evaluate_branch(&state, insn);
                branches.push(BranchDecision {
                    insn_index: i,
                    condition: self.get_branch_condition(insn.cond),
                    taken,
                    reason: reason.clone(),
                });

                let is_symbolic = state.get_reg(insn.src1).is_some_and(|v| v.is_symbolic);

                if is_symbolic {
                    let true_id = self.current_path_id;
                    self.current_path_id += 1;
                    let false_id = self.current_path_id;
                    self.current_path_id += 1;

                    let mut true_branch = state.fork(true_id);
                    let mut false_branch = state.fork(false_id);

                    if let Some(&succ) = block.succs.first() {
                        true_branch.block_id = succ;
                    }
                    if let Some(&succ) = block.succs.get(1) {
                        false_branch.block_id = succ;
                    } else if let Some(&succ) = block.succs.first() {
                        false_branch.block_id = succ;
                    }

                    self.trace.push(format!(
                        "Path {}: branching at instruction {i}",
                        state.path_id
                    ));

                    self.explore_path(true_branch);
                    self.explore_path(false_branch);
                    return;
                }

                if let Some(&succ) = block.succs.first() {
                    state.block_id = succ;
                    self.explore_path(state);
                    return;
                }
            }
        }

        if let Some(&succ) = block.succs.first() {
            state.block_id = succ;
            self.explore_path(state);
        } else {
            state.is_terminated = true;
            state.termination_reason = "no successors".into();
            let path = ExecutionPath {
                path_id: state.path_id,
                depth: state.depth,
                terminated: true,
                termination_reason: "no successors".into(),
                branches,
                instructions_executed: insn_count,
                constraint_count: state.constraints.len(),
            };
            self.paths.push((path, state));
        }
    }

    fn execute_instruction(&mut self, state: &mut ExecutionState, insn: &MirInsn) {
        match insn.kind {
            MirOp::Const => {
                state.set_reg(insn.dst, SymbolicValue::concrete(insn.imm, "literal"));
                self.trace.push(format!(
                    "Path {}: v{} = {} (const)",
                    state.path_id, insn.dst, insn.imm
                ));
            }
            MirOp::Move => {
                if let Some(src) = state.get_reg(insn.src1).cloned() {
                    let mut val = src;
                    val.source = "move".into();
                    state.set_reg(insn.dst, val);
                }
            }
            MirOp::Add | MirOp::Sub | MirOp::Mul | MirOp::Div | MirOp::Rem => {
                self.execute_arithmetic(state, insn);
            }
            MirOp::And | MirOp::Or | MirOp::Xor => {
                self.execute_logical(state, insn);
            }
            MirOp::Not => {
                if let Some(src) = state.get_reg(insn.src1).cloned() {
                    if src.is_symbolic {
                        state.set_reg(
                            insn.dst,
                            SymbolicValue::symbolic(
                                &format!("~({})", src.symbolic),
                                src.confidence,
                                "not",
                            ),
                        );
                    } else {
                        state.set_reg(insn.dst, SymbolicValue::concrete(!src.concrete, "not"));
                    }
                }
            }
            MirOp::FieldGet => {
                let key = format!("field_{}", insn.ref_idx);
                if let Some(val) = state.memory.get(&key).cloned() {
                    state.set_reg(insn.dst, val);
                } else {
                    state.set_reg(insn.dst, SymbolicValue::symbolic(&key, 30, "field_read"));
                }
            }
            MirOp::FieldPut => {
                let key = format!("field_{}", insn.ref_idx);
                if let Some(val) = state.get_reg(insn.src1).cloned() {
                    state.memory.insert(key, val);
                }
            }
            MirOp::If => { /* handled in explore_path */ }
            _ => {
                if insn.dst >= 0 {
                    state.set_reg(
                        insn.dst,
                        SymbolicValue::symbolic(
                            &format!("unknown_{}", insn.kind as u8),
                            20,
                            "unknown",
                        ),
                    );
                }
            }
        }
    }

    fn execute_arithmetic(&mut self, state: &mut ExecutionState, insn: &MirInsn) {
        let (src1, src2) = match (
            state.get_reg(insn.src1).cloned(),
            state.get_reg(insn.src2).cloned(),
        ) {
            (Some(a), Some(b)) => (a, b),
            _ => return,
        };

        if !src1.is_symbolic && !src2.is_symbolic {
            let v1 = src1.concrete;
            let v2 = src2.concrete;
            let result = match insn.kind {
                MirOp::Add => v1.wrapping_add(v2),
                MirOp::Sub => v1.wrapping_sub(v2),
                MirOp::Mul => v1.wrapping_mul(v2),
                MirOp::Div => {
                    if v2 != 0 {
                        v1 / v2
                    } else {
                        return;
                    }
                }
                MirOp::Rem if v2 != 0 => v1 % v2,
                _ => return,
            };
            state.set_reg(insn.dst, SymbolicValue::concrete(result, "arithmetic"));
            self.trace.push(format!(
                "Path {}: v{} = {result} (arithmetic)",
                state.path_id, insn.dst
            ));
            return;
        }

        let op = op_name(insn.kind);
        let expr = format!("({} {op} {})", src1.display(), src2.display());
        let conf = (src1.confidence / 2) + (src2.confidence / 2);
        state.set_reg(insn.dst, SymbolicValue::symbolic(&expr, conf, "arithmetic"));
    }

    fn execute_logical(&mut self, state: &mut ExecutionState, insn: &MirInsn) {
        let (src1, src2) = match (
            state.get_reg(insn.src1).cloned(),
            state.get_reg(insn.src2).cloned(),
        ) {
            (Some(a), Some(b)) => (a, b),
            _ => return,
        };

        if !src1.is_symbolic && !src2.is_symbolic {
            let result = match insn.kind {
                MirOp::And => src1.concrete & src2.concrete,
                MirOp::Or => src1.concrete | src2.concrete,
                MirOp::Xor => src1.concrete ^ src2.concrete,
                _ => return,
            };
            state.set_reg(insn.dst, SymbolicValue::concrete(result, "logical"));
            return;
        }

        let op = op_name(insn.kind);
        let expr = format!("({} {op} {})", src1.display(), src2.display());
        let conf = (src1.confidence / 2) + (src2.confidence / 2);
        state.set_reg(insn.dst, SymbolicValue::symbolic(&expr, conf, "logical"));
    }

    fn evaluate_branch(&self, state: &ExecutionState, insn: &MirInsn) -> (bool, String) {
        if let Some(src) = state.get_reg(insn.src1)
            && !src.is_symbolic
        {
            let taken = src.concrete != 0;
            return (taken, format!("concrete: {} != 0 = {taken}", src.concrete));
        }
        (true, "symbolic condition".into())
    }

    fn get_branch_condition(&self, cond: u8) -> String {
        match cond {
            0 => "== 0",
            1 => "!= 0",
            2 => "< 0",
            3 => "<= 0",
            4 => "> 0",
            5 => ">= 0",
            6 => "== 0",
            7 => "!= 0",
            8 => "< 0",
            9 => "<= 0",
            10 => "> 0",
            11 => ">= 0",
            _ => "unknown",
        }
        .into()
    }

    fn find_block(&self, id: usize) -> Option<&SymBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    fn collect_results(&self) -> SymbolicExecutionResult {
        let mut symbolic_values = Vec::new();

        if let Some((_, state)) = self.paths.first() {
            for (&reg, val) in &state.registers {
                symbolic_values.push((reg, val.display(), val.confidence));
            }
            symbolic_values.sort_by_key(|(reg, _, _)| *reg);
        }

        let mut solved = Vec::new();
        let mut unsolved = Vec::new();
        for (_, state) in &self.paths {
            for c in &state.constraints {
                if c.is_solvable() {
                    solved.push(c.clone());
                } else {
                    unsolved.push(c.clone());
                }
            }
        }

        let max_depth = self.paths.iter().map(|(p, _)| p.depth).max().unwrap_or(0);

        SymbolicExecutionResult {
            paths: self.paths.iter().map(|(p, _)| p.clone()).collect(),
            symbolic_values,
            constraints_solved: solved,
            constraints_unsolved: unsolved,
            execution_depth: max_depth,
            path_count: self.paths.len(),
            pruned_paths: self.pruned_paths,
            fallback_used: false,
            trace: self.trace.clone(),
        }
    }
}

fn op_name(kind: MirOp) -> &'static str {
    match kind {
        MirOp::Add => "+",
        MirOp::Sub => "-",
        MirOp::Mul => "*",
        MirOp::Div => "/",
        MirOp::Rem => "%",
        MirOp::And => "&",
        MirOp::Or => "|",
        MirOp::Xor => "^",
        MirOp::Not => "~",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_const_insn(dst: i16, imm: i64) -> MirInsn {
        MirInsn {
            kind: MirOp::Const,
            cond: 0,
            dst,
            src1: 0,
            src2: 0,
            imm,
            ref_idx: 0,
        }
    }

    fn make_add_insn(dst: i16, src1: i16, src2: i16) -> MirInsn {
        MirInsn {
            kind: MirOp::Add,
            cond: 0,
            dst,
            src1,
            src2,
            imm: 0,
            ref_idx: 0,
        }
    }

    #[test]
    fn test_simple_const_propagation() {
        let blocks = vec![SymBlock {
            id: 0,
            insns: vec![
                make_const_insn(0, 42),
                make_const_insn(1, 10),
                make_add_insn(2, 0, 1),
            ],
            succs: vec![],
        }];

        let mut executor = SymbolicExecutor::new(blocks, 0, 3);
        let result = executor.execute();

        assert_eq!(result.path_count, 1);
        assert!(!result.paths.is_empty());

        // v2 should be concrete 52
        let v2 = result.symbolic_values.iter().find(|(r, _, _)| *r == 2);
        assert!(v2.is_some());
        assert_eq!(v2.unwrap().1, "52");
    }

    #[test]
    fn test_empty_blocks() {
        let blocks: Vec<SymBlock> = vec![];
        let mut executor = SymbolicExecutor::new(blocks, 0, 0);
        let result = executor.execute();
        assert_eq!(result.path_count, 1); // terminated immediately
    }
}
