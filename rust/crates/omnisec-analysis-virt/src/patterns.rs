//! Pattern types for virtualization detection.

use omnisec_json::ToJson;

/// Classification of virtualization technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson)]
pub enum VirtualizationTechnique {
    /// Unknown technique.
    Unknown,
    /// Dispatcher-based virtualization (switch, table, computed goto).
    Dispatcher,
    /// Interpreter loop (fetch-decode-execute).
    Interpreter,
    /// JIT compilation.
    Jit,
    /// Obfuscated bytecode (dense arithmetic).
    ObfuscatedBytecode,
    /// Custom virtual machine.
    CustomVm,
}

impl std::fmt::Display for VirtualizationTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Dispatcher => write!(f, "Dispatcher"),
            Self::Interpreter => write!(f, "Interpreter"),
            Self::Jit => write!(f, "JIT"),
            Self::ObfuscatedBytecode => write!(f, "ObfuscatedBytecode"),
            Self::CustomVm => write!(f, "CustomVM"),
        }
    }
}

/// A detected virtualization pattern.
#[derive(Debug, Clone, ToJson)]
pub struct VirtualizationPattern {
    /// Type of virtualization detected.
    pub technique: VirtualizationTechnique,
    /// Block ID where the pattern was found.
    pub block_id: usize,
    /// Instruction index within the block.
    pub insn_index: usize,
    /// Dispatcher block ID (if applicable).
    pub dispatcher_block_id: Option<usize>,
    /// Dispatcher type (e.g. "switch", "table", "computed_goto").
    pub dispatcher_type: String,
    /// Virtual opcode indices found.
    pub virtual_opcodes: Vec<u32>,
    /// Confidence level (0-100).
    pub confidence: u8,
    /// Human-readable rationale.
    pub rationale: String,
    /// Annotated instructions.
    pub annotated_instructions: Vec<String>,
}

/// Statistics about detected patterns.
#[derive(Debug, Clone, Default, ToJson)]
pub struct DetectionStats {
    /// Total patterns detected.
    pub total: usize,
    /// Dispatcher patterns.
    pub dispatcher: usize,
    /// Interpreter patterns.
    pub interpreter: usize,
    /// JIT patterns.
    pub jit: usize,
    /// Obfuscated bytecode patterns.
    pub obfuscated: usize,
    /// Custom VM patterns.
    pub custom_vm: usize,
    /// Average confidence across all patterns.
    pub average_confidence: u8,
}

/// Full detection result.
#[derive(Debug, Clone, ToJson)]
pub struct DetectionResult {
    /// All detected patterns.
    pub patterns: Vec<VirtualizationPattern>,
    /// Detection statistics.
    pub stats: DetectionStats,
    /// Execution trace.
    pub trace: Vec<String>,
    /// Total changes (patterns found).
    pub changes: usize,
    /// Human-readable report.
    pub report: String,
}
