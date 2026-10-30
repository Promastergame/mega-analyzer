//! Execution state — registers, memory, constraints, and path tracking.

use omnisec_json::ToJson;
use std::collections::HashMap as FxHashMap;

/// A value that may be symbolic (unknown) or concrete (known).
#[derive(Debug, Clone, ToJson)]
pub struct SymbolicValue {
    /// Whether this value is symbolic (true) or concrete (false).
    pub is_symbolic: bool,
    /// Concrete value (only valid when `is_symbolic == false`).
    pub concrete: i64,
    /// Symbolic expression string (e.g. "v1 + 5", "v2 & 0xFF").
    pub symbolic: String,
    /// Confidence in this value (0-100).
    pub confidence: u8,
    /// Source of this value (e.g. "literal", "parameter", "arithmetic").
    pub source: String,
}

impl SymbolicValue {
    /// Create a concrete value.
    pub fn concrete(value: i64, source: &str) -> Self {
        Self {
            is_symbolic: false,
            concrete: value,
            symbolic: String::new(),
            confidence: 100,
            source: source.to_string(),
        }
    }

    /// Create a symbolic value.
    pub fn symbolic(expr: &str, confidence: u8, source: &str) -> Self {
        Self {
            is_symbolic: true,
            concrete: 0,
            symbolic: expr.to_string(),
            confidence,
            source: source.to_string(),
        }
    }

    /// Get a display representation.
    pub fn display(&self) -> String {
        if self.is_symbolic {
            self.symbolic.clone()
        } else {
            format!("{}", self.concrete)
        }
    }
}

/// Snapshot of the execution state at a point in symbolic execution.
#[derive(Debug, Clone)]
pub struct ExecutionState {
    /// Current basic block ID.
    pub block_id: usize,
    /// Current instruction index within the block.
    pub insn_index: usize,
    /// Register values (register number → symbolic value).
    pub registers: FxHashMap<i16, SymbolicValue>,
    /// Memory/field values (field key → symbolic value).
    pub memory: FxHashMap<String, SymbolicValue>,
    /// Accumulated path constraints.
    pub constraints: Vec<crate::constraint::Constraint>,
    /// Execution depth (number of steps taken).
    pub depth: usize,
    /// Unique path identifier.
    pub path_id: usize,
    /// Whether this path has terminated.
    pub is_terminated: bool,
    /// Reason for termination.
    pub termination_reason: String,
}

impl ExecutionState {
    /// Create a new initial state at the entry block.
    pub fn new(entry_block_id: usize, path_id: usize) -> Self {
        Self {
            block_id: entry_block_id,
            insn_index: 0,
            registers: FxHashMap::default(),
            memory: FxHashMap::default(),
            constraints: Vec::new(),
            depth: 0,
            path_id,
            is_terminated: false,
            termination_reason: String::new(),
        }
    }

    /// Deep clone the state for forking at a branch point.
    pub fn fork(&self, new_path_id: usize) -> Self {
        Self {
            block_id: self.block_id,
            insn_index: self.insn_index,
            registers: self.registers.clone(),
            memory: self.memory.clone(),
            constraints: self.constraints.clone(),
            depth: self.depth,
            path_id: new_path_id,
            is_terminated: false,
            termination_reason: String::new(),
        }
    }

    /// Get a register's symbolic value.
    pub fn get_reg(&self, reg: i16) -> Option<&SymbolicValue> {
        self.registers.get(&reg)
    }

    /// Set a register's value.
    pub fn set_reg(&mut self, reg: i16, value: SymbolicValue) {
        self.registers.insert(reg, value);
    }
}

/// A single execution path through the method.
#[derive(Debug, Clone, ToJson)]
pub struct ExecutionPath {
    /// Path identifier.
    pub path_id: usize,
    /// Execution depth reached.
    pub depth: usize,
    /// Whether the path terminated normally.
    pub terminated: bool,
    /// Termination reason.
    pub termination_reason: String,
    /// Branch decisions made along this path.
    pub branches: Vec<BranchDecision>,
    /// Number of instructions executed.
    pub instructions_executed: usize,
    /// Number of constraints accumulated.
    pub constraint_count: usize,
}

/// A decision made at a branch point.
#[derive(Debug, Clone, ToJson)]
pub struct BranchDecision {
    /// Index of the branch instruction.
    pub insn_index: usize,
    /// Condition expression string.
    pub condition: String,
    /// Which branch was taken.
    pub taken: bool,
    /// Reason for the decision.
    pub reason: String,
}
