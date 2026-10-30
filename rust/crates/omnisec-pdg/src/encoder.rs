//! Symbolic encoder: maps OmniIR instructions → sparse HyperVectors via
//! the HDC [`CodeBook`].
//!
//! Each instruction is encoded as:
//!
//! ```text
//! HV_inst = OpcodeHV ⊕ ρ₁(DstType₀) ⊕ ρ₂(DstType₁) ⊕ ...
//!                    ⊕ ρ₅(SrcType₀) ⊕ ρ₆(SrcType₁) ⊕ ...
//!                    ⊕ ρ₉(RegClassBundle) ⊕ ρ₁₀(MemTag) ⊕ ρ₁₁(CfTag)
//! ```
//!
//! Where `ρₙ` is the n-th Feistel permutation from the codebook.

use omnisec_hdc::HyperVector;
use omnisec_hdc::codebook::{
    CodeBook, ControlFlowTag, LifecycleStage, MemoryAccessTag, SyscallProximity,
};
use omnisec_ir::{Instruction, OpCode, Operand, RegisterClass};

/// Encodes OmniIR instructions into sparse HyperVectors.
///
/// Wraps a [`CodeBook`] and provides the mapping from concrete IR types
/// to the numeric IDs the codebook expects.
pub struct SymbolicEncoder {
    codebook: CodeBook,
}

impl SymbolicEncoder {
    /// Create a new encoder with the given master seed.
    ///
    /// Deterministic: same seed → same encoder → same HVs.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            codebook: CodeBook::new(seed),
        }
    }

    /// Encode a single instruction into a sparse HyperVector with explicit context.
    pub fn encode(
        &mut self,
        inst: &Instruction,
        lifecycle: LifecycleStage,
        syscall_prox: SyscallProximity,
    ) -> HyperVector {
        let opcode_id = opcode_to_id(inst.opcode);

        let dst_types: Vec<u8> = inst.dst.iter().map(operand_type_id).collect();
        let src_types: Vec<u8> = inst.src.iter().map(operand_type_id).collect();

        // Collect register classes from all operands.
        let mut reg_classes: Vec<u8> = Vec::new();
        for op in inst.dst.iter().chain(inst.src.iter()) {
            if let Operand::Register(r) = op {
                reg_classes.push(register_class_id(r.class));
            }
        }

        let mem_tag = classify_memory_access(inst);
        let cf_tag = classify_control_flow(inst.opcode);

        self.codebook.encode_instruction(
            opcode_id,
            &dst_types,
            &src_types,
            &reg_classes,
            mem_tag,
            cf_tag,
            lifecycle,
            syscall_prox,
        )
    }

    /// Encode a basic block as the bundle (thresholded majority) of its
    /// instruction HVs.
    pub fn encode_block(&mut self, instructions: &[Instruction]) -> HyperVector {
        if instructions.is_empty() {
            return HyperVector::zero();
        }
        let hvs: Vec<HyperVector> = instructions
            .iter()
            .map(|i| self.encode(i, LifecycleStage::Unknown, SyscallProximity::FarFromSyscall))
            .collect();
        HyperVector::bundle(&hvs)
    }

    /// Get a reference to the underlying codebook.
    #[must_use]
    pub fn codebook(&self) -> &CodeBook {
        &self.codebook
    }
}

// ── Mapping helpers ──────────────────────────────────────────────────────

/// Map OpCode → u32 discriminant for the codebook.
fn opcode_to_id(op: OpCode) -> u32 {
    match op {
        OpCode::Nop => 0,
        OpCode::Move => 1,
        OpCode::Add => 2,
        OpCode::Sub => 3,
        OpCode::Mul => 4,
        OpCode::UMul => 5,
        OpCode::Div => 6,
        OpCode::UDiv => 7,
        OpCode::Rem => 8,
        OpCode::URem => 9,
        OpCode::Neg => 10,
        OpCode::And => 11,
        OpCode::Or => 12,
        OpCode::Xor => 13,
        OpCode::Not => 14,
        OpCode::Shl => 15,
        OpCode::Shr => 16,
        OpCode::Sar => 17,
        OpCode::Rol => 18,
        OpCode::Ror => 19,
        OpCode::Compare => 20,
        OpCode::Test => 21,
        OpCode::Load => 22,
        OpCode::Store => 23,
        OpCode::CmpXchg => 24,
        OpCode::Fence => 25,
        OpCode::Push => 26,
        OpCode::Pop => 27,
        OpCode::Jump => 28,
        OpCode::BranchIf => 29,
        OpCode::Call => 30,
        OpCode::IndirectCall => 31,
        OpCode::Return => 32,
        OpCode::SignExtend => 33,
        OpCode::ZeroExtend => 34,
        OpCode::Truncate => 35,
        OpCode::Trap => 36,
        OpCode::SystemCall => 37,
        OpCode::Halt => 38,
        OpCode::Invalid => 39,
        OpCode::Custom(id) => 1000 + id,
    }
}

/// Map Operand variant → type ID for the codebook.
fn operand_type_id(op: &Operand) -> u8 {
    match op {
        Operand::Register(_) => 0,
        Operand::Immediate(_) => 1,
        Operand::Memory(_) => 2,
        Operand::Label(_) => 3,
        Operand::Symbol(_) => 4,
        Operand::Type(_) => 5,
    }
}

/// Map RegisterClass → u8 for the codebook.
fn register_class_id(class: RegisterClass) -> u8 {
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

/// Classify the memory access pattern of an instruction.
fn classify_memory_access(inst: &Instruction) -> MemoryAccessTag {
    match inst.opcode {
        OpCode::Load => {
            // Check if source is stack-relative.
            if is_stack_access(&inst.src) {
                MemoryAccessTag::StackRead
            } else {
                MemoryAccessTag::HeapRead
            }
        }
        OpCode::Store => {
            if is_stack_access(&inst.dst) {
                MemoryAccessTag::StackWrite
            } else {
                MemoryAccessTag::HeapWrite
            }
        }
        OpCode::Push => MemoryAccessTag::StackWrite,
        OpCode::Pop => MemoryAccessTag::StackRead,
        OpCode::CmpXchg | OpCode::Fence => MemoryAccessTag::Atomic,
        _ => MemoryAccessTag::None,
    }
}

/// Check if any operand is a stack-relative memory access.
fn is_stack_access(operands: &[Operand]) -> bool {
    operands.iter().any(|op| {
        if let Operand::Memory(addr) = op {
            addr.base
                .as_ref()
                .is_some_and(omnisec_ir::Register::is_stack_pointer)
                || addr
                    .base
                    .as_ref()
                    .is_some_and(|r| matches!(r.class, RegisterClass::FramePointer))
        } else {
            false
        }
    })
}

/// Classify the control-flow role of an opcode.
fn classify_control_flow(opcode: OpCode) -> ControlFlowTag {
    match opcode {
        OpCode::Jump => ControlFlowTag::UnconditionalJump,
        OpCode::BranchIf => ControlFlowTag::ConditionalBranch,
        OpCode::Call => ControlFlowTag::CallSite,
        OpCode::IndirectCall => ControlFlowTag::IndirectCallSite,
        OpCode::Return => ControlFlowTag::ReturnSite,
        OpCode::SystemCall => ControlFlowTag::SystemCall,
        _ => ControlFlowTag::Sequential,
    }
}
