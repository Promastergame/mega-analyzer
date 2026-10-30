//! x86 / x86_64 disassembler — wraps `iced-x86` and lifts into OmniIR.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction as IcedInstruction, Mnemonic, OpKind,
    Register as IcedReg,
};
use omnisec_core::Arch;
use omnisec_ir::{
    Condition, Instruction, InstructionFlags, MemoryAddress, OpCode, Operand, Register,
    RegisterClass,
};

use crate::Disassembler;

/// x86 / x86_64 linear-sweep disassembler.
#[derive(Debug, Clone, Copy)]
pub struct X86Disassembler {
    /// Decoder bitness: 16, 32 or 64.
    bitness: u32,
}

impl X86Disassembler {
    /// 32-bit x86 disassembler.
    #[must_use]
    pub const fn new_32() -> Self {
        Self { bitness: 32 }
    }

    /// 64-bit x86_64 disassembler.
    #[must_use]
    pub const fn new_64() -> Self {
        Self { bitness: 64 }
    }

    /// Source [`Arch`] this decoder maps to.
    #[must_use]
    pub const fn arch(self) -> Arch {
        match self.bitness {
            32 => Arch::X86,
            64 => Arch::X86_64,
            _ => Arch::Unknown,
        }
    }
}

impl Disassembler for X86Disassembler {
    fn disassemble(&self, bytes: &[u8], base_addr: u64) -> Vec<Instruction> {
        let mut decoder = Decoder::with_ip(self.bitness, bytes, base_addr, DecoderOptions::NONE);
        let mut out = Vec::with_capacity(bytes.len() / 4);
        let mut iced = IcedInstruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut iced);
            out.push(lift(&iced, self.arch(), bytes));
        }
        out
    }
}

/// Convert one `iced_x86::Instruction` into our [`Instruction`].
fn lift(iced: &IcedInstruction, arch: Arch, image_bytes: &[u8]) -> Instruction {
    let opcode = map_opcode(iced);
    let condition = map_condition(iced.mnemonic());

    let address = iced.ip();
    let size = u8::try_from(iced.len()).unwrap_or(u8::MAX);

    let raw_start = (address.wrapping_sub(iced.ip().wrapping_sub(0))) as usize;
    let raw = if raw_start + size as usize <= image_bytes.len() {
        image_bytes[raw_start..raw_start + size as usize].to_vec()
    } else {
        Vec::new()
    };

    let mut dst = vec![];
    let mut src = vec![];
    let op_count = iced.op_count();
    if op_count > 0 {
        // First operand: usually the destination (for two-operand ops). For
        // pure-source ops (push, ret, jmp) we'll move it back below.
        dst.push(lift_operand(iced, 0, arch));
        for i in 1..op_count {
            src.push(lift_operand(iced, i, arch));
        }
    }

    // Some opcodes have a "first operand is actually a source" pattern
    // (push reg, jcc target, call target, ret, jmp target).
    if matches!(
        opcode,
        OpCode::Push
            | OpCode::Jump
            | OpCode::BranchIf
            | OpCode::Call
            | OpCode::IndirectCall
            | OpCode::Return
            | OpCode::Trap
    ) && !dst.is_empty()
    {
        let only = dst.remove(0);
        src.insert(0, only);
    }

    let mut flags = InstructionFlags::empty();
    if matches!(
        iced.flow_control(),
        FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
            | FlowControl::Return
            | FlowControl::IndirectBranch
            | FlowControl::Interrupt
            | FlowControl::Exception
    ) {
        flags |= InstructionFlags::TERMINATOR;
    }
    if iced.is_privileged() {
        flags |= InstructionFlags::PRIVILEGED;
    }
    if !iced.rflags_modified() == 0 {
        // rflags_modified() returns a bitfield; non-zero means flags are touched.
    }
    if iced.rflags_modified() != 0 {
        flags |= InstructionFlags::SETS_FLAGS;
    }

    let mut inst = Instruction {
        opcode,
        dst,
        src,
        condition,
        address,
        size,
        arch,
        flags,
        raw: raw.into(),
        mnemonic: Some(format!("{iced}")),
    };
    // Preserve "data-flow" hint via flags for downstream passes.
    if opcode == OpCode::Invalid {
        inst.flags |= InstructionFlags::HAS_SIDE_EFFECTS;
    }
    inst
}

/// Map an iced mnemonic to our [`OpCode`].
fn map_opcode(iced: &IcedInstruction) -> OpCode {
    use Mnemonic as M;
    match iced.mnemonic() {
        M::INVALID => OpCode::Invalid,
        M::Nop | M::Pause | M::Wait => OpCode::Nop,

        M::Mov
        | M::Movzx
        | M::Movsx
        | M::Lea
        | M::Cmove
        | M::Cmovne
        | M::Cmova
        | M::Cmovae
        | M::Cmovb
        | M::Cmovbe
        | M::Cmovg
        | M::Cmovge
        | M::Cmovl
        | M::Cmovle
        | M::Cmovs
        | M::Cmovns
        | M::Cmovo
        | M::Cmovno
        | M::Cmovp
        | M::Cmovnp => OpCode::Move,
        M::Movsxd => OpCode::SignExtend,

        M::Add | M::Adc | M::Inc => OpCode::Add,
        M::Sub | M::Sbb | M::Dec => OpCode::Sub,
        M::Imul => OpCode::Mul,
        M::Mul => OpCode::UMul,
        M::Idiv => OpCode::Div,
        M::Div => OpCode::UDiv,
        M::Neg => OpCode::Neg,

        M::And => OpCode::And,
        M::Or => OpCode::Or,
        M::Xor => OpCode::Xor,
        M::Not => OpCode::Not,
        M::Shl | M::Sal => OpCode::Shl,
        M::Shr => OpCode::Shr,
        M::Sar => OpCode::Sar,
        M::Rol => OpCode::Rol,
        M::Ror => OpCode::Ror,

        M::Cmp => OpCode::Compare,
        M::Test => OpCode::Test,

        M::Push => OpCode::Push,
        M::Pop => OpCode::Pop,

        M::Jmp => OpCode::Jump,
        M::Je
        | M::Jne
        | M::Ja
        | M::Jae
        | M::Jb
        | M::Jbe
        | M::Jg
        | M::Jge
        | M::Jl
        | M::Jle
        | M::Js
        | M::Jns
        | M::Jo
        | M::Jno
        | M::Jp
        | M::Jnp
        | M::Jcxz
        | M::Jecxz
        | M::Jrcxz
        | M::Loop
        | M::Loope
        | M::Loopne => OpCode::BranchIf,

        M::Call => OpCode::Call,
        M::Ret => OpCode::Return,

        M::Int | M::Int1 | M::Int3 | M::Into => OpCode::Trap,
        M::Syscall | M::Sysenter | M::Sysexit | M::Sysret => OpCode::SystemCall,
        M::Hlt => OpCode::Halt,

        // Memory fences.
        M::Mfence | M::Lfence | M::Sfence => OpCode::Fence,

        // Cmpxchg / atomic.
        M::Cmpxchg | M::Cmpxchg8b | M::Cmpxchg16b => OpCode::CmpXchg,

        _ => OpCode::Custom(iced.code() as u32),
    }
}

/// Map a Jcc mnemonic to its OmniIR [`Condition`].
fn map_condition(m: Mnemonic) -> Option<Condition> {
    use Condition as C;
    use Mnemonic as M;
    match m {
        M::Je | M::Cmove => Some(C::Equal),
        M::Jne | M::Cmovne => Some(C::NotEqual),
        M::Ja | M::Cmova => Some(C::UnsignedGreater),
        M::Jae | M::Cmovae => Some(C::UnsignedGreaterEq),
        M::Jb | M::Cmovb => Some(C::UnsignedLess),
        M::Jbe | M::Cmovbe => Some(C::UnsignedLessEq),
        M::Jg | M::Cmovg => Some(C::SignedGreater),
        M::Jge | M::Cmovge => Some(C::SignedGreaterEq),
        M::Jl | M::Cmovl => Some(C::SignedLess),
        M::Jle | M::Cmovle => Some(C::SignedLessEq),
        M::Js | M::Cmovs => Some(C::Negative),
        M::Jns | M::Cmovns => Some(C::NonNegative),
        M::Jo | M::Cmovo => Some(C::Overflow),
        M::Jno | M::Cmovno => Some(C::NoOverflow),
        M::Jmp => Some(C::Always),
        // Parity-flag jumps (Jp / Jnp / Cmovp / Cmovnp) and everything else
        // — no [`Condition`] variant yet.
        _ => None,
    }
}

/// Lift one operand of an iced instruction at index `op` into our [`Operand`].
fn lift_operand(iced: &IcedInstruction, op: u32, arch: Arch) -> Operand {
    match iced.op_kind(op) {
        OpKind::Register => Operand::Register(reg_to_omni(iced.op_register(op), arch)),
        OpKind::Immediate8 => Operand::Immediate(i64::from(iced.immediate8() as i8)),
        OpKind::Immediate8_2nd => Operand::Immediate(i64::from(iced.immediate8_2nd() as i8)),
        OpKind::Immediate16 => Operand::Immediate(i64::from(iced.immediate16() as i16)),
        OpKind::Immediate32 => Operand::Immediate(i64::from(iced.immediate32() as i32)),
        OpKind::Immediate64 => Operand::Immediate(iced.immediate64() as i64),
        OpKind::Immediate8to16 => Operand::Immediate(i64::from(iced.immediate8to16())),
        OpKind::Immediate8to32 => Operand::Immediate(i64::from(iced.immediate8to32())),
        OpKind::Immediate8to64 => Operand::Immediate(iced.immediate8to64()),
        OpKind::Immediate32to64 => Operand::Immediate(iced.immediate32to64()),
        OpKind::NearBranch16 => Operand::Label(u64::from(iced.near_branch16())),
        OpKind::NearBranch32 => Operand::Label(u64::from(iced.near_branch32())),
        OpKind::NearBranch64 => Operand::Label(iced.near_branch64()),
        OpKind::FarBranch16 => Operand::Label(u64::from(iced.far_branch16())),
        OpKind::FarBranch32 => Operand::Label(u64::from(iced.far_branch32())),
        OpKind::Memory => Operand::Memory(memory_to_omni(iced, arch)),
        // String-instruction operands (`movs`, `cmps`, etc.) are implicit
        // `[ds:si]` / `[es:di]` style accesses. We surface them as an
        // unresolved absolute memory operand for now and refine in Phase 2.
        OpKind::MemorySegSI
        | OpKind::MemorySegESI
        | OpKind::MemorySegRSI
        | OpKind::MemorySegDI
        | OpKind::MemorySegEDI
        | OpKind::MemorySegRDI
        | OpKind::MemoryESDI
        | OpKind::MemoryESEDI
        | OpKind::MemoryESRDI => Operand::Memory(MemoryAddress::absolute(0, 0)),
    }
}

/// Build an OmniIR memory operand from an iced "memory" operand.
fn memory_to_omni(iced: &IcedInstruction, arch: Arch) -> MemoryAddress {
    let base = if iced.memory_base() == IcedReg::None {
        None
    } else {
        Some(reg_to_omni(iced.memory_base(), arch))
    };
    let index = if iced.memory_index() == IcedReg::None {
        None
    } else {
        Some(reg_to_omni(iced.memory_index(), arch))
    };
    let segment = if iced.segment_prefix() == IcedReg::None {
        None
    } else {
        Some(reg_to_omni(iced.segment_prefix(), arch))
    };
    MemoryAddress {
        base,
        index,
        scale: u8::try_from(iced.memory_index_scale()).unwrap_or(1),
        displacement: iced.memory_displacement64() as i64,
        segment,
        access_size: u16::try_from(iced.memory_size().size()).unwrap_or(0),
    }
}

/// Convert an iced register to our [`Register`] type.
fn reg_to_omni(r: IcedReg, arch: Arch) -> Register {
    let class = classify_reg(r);
    let name = format!("{r:?}").to_ascii_lowercase();
    Register {
        arch,
        class,
        native_id: r as u32,
        bit_width: u16::try_from(r.size() * 8).unwrap_or(0),
        name,
    }
}

/// Bucket an iced register into one of our [`RegisterClass`] variants.
fn classify_reg(r: IcedReg) -> RegisterClass {
    if r == IcedReg::None {
        return RegisterClass::GeneralPurpose;
    }
    if r.is_segment_register() {
        return RegisterClass::Segment;
    }
    if r.is_xmm() || r.is_ymm() || r.is_zmm() || r.is_vector_register() {
        return RegisterClass::Vector;
    }
    if r.is_st() {
        return RegisterClass::Float;
    }
    if r == IcedReg::RIP || r == IcedReg::EIP {
        return RegisterClass::ProgramCounter;
    }
    if matches!(r, IcedReg::RSP | IcedReg::ESP | IcedReg::SP) {
        return RegisterClass::StackPointer;
    }
    if matches!(r, IcedReg::RBP | IcedReg::EBP | IcedReg::BP) {
        return RegisterClass::FramePointer;
    }
    RegisterClass::GeneralPurpose
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode `mov rax, 1; ret` (x86_64).
    #[test]
    fn lifts_mov_imm_then_ret() {
        // mov rax, 1     => 48 C7 C0 01 00 00 00
        // ret            => C3
        let bytes = [0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3];
        let dis = X86Disassembler::new_64();
        let insts = dis.disassemble(&bytes, 0x1000);
        assert_eq!(insts.len(), 2);

        assert_eq!(insts[0].opcode, OpCode::Move);
        assert_eq!(insts[0].address, 0x1000);
        assert_eq!(insts[0].size, 7);
        assert_eq!(insts[0].dst.len(), 1);
        assert_eq!(insts[0].src.len(), 1);
        assert!(matches!(insts[0].src[0], Operand::Immediate(1)));

        assert_eq!(insts[1].opcode, OpCode::Return);
        assert!(insts[1].is_terminator());
    }

    #[test]
    fn lifts_jcc_with_condition() {
        // jne 0x1010 (rel8)  => 75 0E
        let bytes = [0x75, 0x0E];
        let dis = X86Disassembler::new_64();
        let insts = dis.disassemble(&bytes, 0x1000);
        assert_eq!(insts.len(), 1);
        assert_eq!(insts[0].opcode, OpCode::BranchIf);
        assert_eq!(insts[0].condition, Some(Condition::NotEqual));
        assert!(insts[0].is_terminator());
        // The branch target should be a Label.
        assert!(matches!(insts[0].src.first(), Some(Operand::Label(_))));
    }

    #[test]
    fn lifts_arithmetic() {
        // add rax, rbx  => 48 01 D8
        let bytes = [0x48, 0x01, 0xD8];
        let insts = X86Disassembler::new_64().disassemble(&bytes, 0x2000);
        assert_eq!(insts.len(), 1);
        assert_eq!(insts[0].opcode, OpCode::Add);
        assert_eq!(insts[0].dst.len(), 1);
        assert_eq!(insts[0].src.len(), 1);
    }

    #[test]
    fn lifts_call() {
        // call rel32 => E8 00 00 00 00  (call to next instruction)
        let bytes = [0xE8, 0x00, 0x00, 0x00, 0x00];
        let insts = X86Disassembler::new_64().disassemble(&bytes, 0x3000);
        assert_eq!(insts.len(), 1);
        assert_eq!(insts[0].opcode, OpCode::Call);
        assert!(matches!(insts[0].src.first(), Some(Operand::Label(_))));
    }

    #[test]
    fn unsupported_arch_returns_empty() {
        // The default_for() helper returns None for arches we don't ship,
        // so linear_sweep returns no instructions.
        let v = crate::linear_sweep(Arch::Mips, &[0u8; 4], 0);
        assert!(v.is_empty());
    }

    #[test]
    fn arch_helpers_match_bitness() {
        assert_eq!(X86Disassembler::new_32().arch(), Arch::X86);
        assert_eq!(X86Disassembler::new_64().arch(), Arch::X86_64);
    }

    #[test]
    fn invalid_bytes_become_invalid_opcode() {
        // 0x06 is an invalid opcode in 64-bit mode (former PUSH ES).
        let bytes = [0x06];
        let insts = X86Disassembler::new_64().disassemble(&bytes, 0x4000);
        assert_eq!(insts.len(), 1);
        assert_eq!(insts[0].opcode, OpCode::Invalid);
    }
}
