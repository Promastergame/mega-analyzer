//! ARM64 → OmniIR lifter.

use omnisec_arm64_decode::{decode, Decoded, Operand as DOp};
use omnisec_core::Arch;
use omnisec_ir::{Instruction, InstructionFlags, OpCode, Operand, Register, RegisterClass};

/// Errors that can occur during ARM64 lifting.
#[derive(Debug)]
pub enum LiftError {
    /// Unsupported ARM64 instruction.
    UnsupportedInstruction(String),
    /// Decode failed.
    DecodeFailed(String),
}

impl std::fmt::Display for LiftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedInstruction(text) => {
                write!(f, "unsupported ARM64 instruction: {text}")
            }
            Self::DecodeFailed(text) => write!(f, "decode failed: {text}"),
        }
    }
}

impl std::error::Error for LiftError {}

/// Lift ARM64 machine code to OmniIR instructions.
pub struct Arm64Lifter {
    arch: Arch,
}

impl Arm64Lifter {
    /// Create a new ARM64 lifter.
    #[must_use]
    pub const fn new() -> Self {
        Self { arch: Arch::Arm64 }
    }

    /// Architecture this lifter targets.
    #[must_use]
    pub const fn arch(&self) -> Arch {
        self.arch
    }

    /// Lift a slice of ARM64 bytes to OmniIR instructions.
    pub fn lift(&self, base_addr: u64, bytes: &[u8]) -> Result<Vec<Instruction>, LiftError> {
        let mut out = Vec::with_capacity(bytes.len() / 4);
        let mut addr = base_addr;
        let mut off = 0;

        while off + 4 <= bytes.len() {
            let word =
                u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
            let raw = bytes[off..off + 4].to_vec();
            out.push(lift_inst(&decode(word, addr), self.arch, addr, raw));
            addr += 4;
            off += 4;
        }

        Ok(out)
    }
}

impl Default for Arm64Lifter {
    fn default() -> Self {
        Self::new()
    }
}

fn lift_inst(dec: &Decoded, arch: Arch, address: u64, raw: Vec<u8>) -> Instruction {
    let opcode = map_opcode(dec.mnemonic);

    let mut inst = Instruction::new(opcode, address, 4, arch);
    inst.raw = raw.into();
    inst.mnemonic = Some(dec.mnemonic.into());

    if opcode.is_terminator()
        || matches!(
            opcode,
            OpCode::Jump
                | OpCode::BranchIf
                | OpCode::Call
                | OpCode::IndirectCall
                | OpCode::Return
                | OpCode::Trap
        )
    {
        inst.flags |= InstructionFlags::TERMINATOR;
    }

    let mut has_dst = !matches!(
        opcode,
        OpCode::Jump
            | OpCode::BranchIf
            | OpCode::Call
            | OpCode::IndirectCall
            | OpCode::Return
            | OpCode::Trap
            | OpCode::Compare
            | OpCode::Store
    );
    if opcode == OpCode::Nop {
        has_dst = false;
    }

    // `Store` convention (matches the dataflow layer): the memory location
    // is the destination, the stored value is a source.
    if opcode == OpCode::Store {
        for op in dec.ops {
            if matches!(op, DOp::None) {
                continue;
            }
            let omni_op = lift_operand(&op, arch);
            if matches!(omni_op, Operand::Memory(_)) {
                inst.dst.push(omni_op);
            } else {
                inst.src.push(omni_op);
            }
        }
        return inst;
    }

    let mut first = true;
    for op in dec.ops {
        if matches!(op, DOp::None) {
            continue;
        }
        let omni_op = lift_operand(&op, arch);
        if first && has_dst {
            inst.dst.push(omni_op);
        } else {
            inst.src.push(omni_op);
        }
        first = false;
    }

    inst
}

fn map_opcode(op: &str) -> OpCode {
    match op {
        "ADD" | "ADDS" => OpCode::Add,
        "SUB" | "SUBS" => OpCode::Sub,
        "MUL" | "MADD" | "MSUB" | "SMULH" | "UMULH" | "SMULL" | "UMULL" => OpCode::Mul,
        "SDIV" => OpCode::Div,
        "UDIV" => OpCode::UDiv,
        "AND" | "ANDS" => OpCode::And,
        "ORR" | "ORN" => OpCode::Or,
        "EOR" => OpCode::Xor,
        "MOV" | "MOVK" | "MOVN" | "MOVZ" | "ADR" | "ADRP" | "CSEL" | "CSINC" | "CSINV"
        | "CSNEG" => OpCode::Move,
        "MVN" => OpCode::Not,
        "NEG" | "NEGS" => OpCode::Neg,
        "LSL" => OpCode::Shl,
        "LSR" => OpCode::Shr,
        "ASR" => OpCode::Sar,
        "ROR" | "EXTR" => OpCode::Ror,
        "CMP" | "CMN" | "TST" | "CCMP" | "CCMN" => OpCode::Compare,
        "B" => OpCode::Jump,
        "B_cond" | "BC_cond" | "CBZ" | "CBNZ" | "TBZ" | "TBNZ" => OpCode::BranchIf,
        "BL" | "BLR" => OpCode::Call,
        "BR" | "BRAA" | "BRAB" | "BLRAA" | "BLRAB" => OpCode::IndirectCall,
        "RET" | "RETAA" | "RETAB" => OpCode::Return,
        "SVC" | "HVC" | "SMC" | "BRK" | "HLT" | "DCPS1" | "DCPS2" | "DCPS3" => OpCode::Trap,
        "DSB" | "DMB" | "ISB" => OpCode::Fence,
        "LDR" | "LDRSW" | "LDP" | "LDPSW" | "LDUR" | "LDAXR" | "LDAR" => OpCode::Load,
        "LDRB" | "LDRH" | "LDRSB" | "LDRSH" | "LDURB" | "LDURH" | "LDURSW" => OpCode::Load,
        "STR" | "STP" | "STUR" | "STLXR" | "STLR" | "STRB" | "STRH" => OpCode::Store,
        "STURB" | "STURH" => OpCode::Store,
        "SXTW" | "SXTH" | "SXTB" => OpCode::SignExtend,
        "UXTW" | "UXTH" | "UXTB" => OpCode::ZeroExtend,
        "NOP" | "HINT" => OpCode::Nop,
        "PUSH" => OpCode::Push,
        "POP" => OpCode::Pop,
        _ => OpCode::Custom(0),
    }
}

fn lift_operand(op: &DOp, arch: Arch) -> Operand {
    match *op {
        DOp::None => Operand::Immediate(0),
        DOp::Imm(v) => Operand::Immediate(v),
        DOp::Reg { id, width, is_sp } => Operand::Register(reg_name(id, width, is_sp, arch)),
        DOp::Mem {
            base,
            base_is_sp,
            disp,
        } => {
            use omnisec_ir::MemoryAddress;
            Operand::Memory(MemoryAddress::reg_offset(
                reg_name(base, 64, base_is_sp, arch),
                disp,
                8,
            ))
        }
    }
}

/// Build an OmniIR register. Id 31 renders as SP/WSP or XZR/WZR.
fn reg_name(id: u8, width: u8, is_sp: bool, arch: Arch) -> Register {
    if id == 31 {
        let name = match (is_sp, width) {
            (true, 32) => "wsp",
            (true, _) => "sp",
            (false, 32) => "wzr",
            _ => "xzr",
        };
        return Register {
            arch,
            class: RegisterClass::GeneralPurpose,
            native_id: 31,
            bit_width: u16::from(width),
            name: name.into(),
        };
    }
    let (prefix, class, bit_width) = if width == 32 {
        ('w', RegisterClass::GeneralPurpose, 32)
    } else {
        ('x', RegisterClass::GeneralPurpose, 64)
    };
    Register {
        arch,
        class,
        native_id: u32::from(id),
        bit_width,
        name: format!("{prefix}{id}"),
    }
}
