//! [`Instruction`] — the central node of OmniIR.

use omnisec_core::Arch;
use omnisec_json::{FromJson, ToJson};

use crate::{Condition, OpCode, Operand};

/// Flags that decorate an [`Instruction`] beyond its opcode/operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, ToJson, FromJson)]
pub struct InstructionFlags(u32);

impl InstructionFlags {
    /// The instruction is the last in its basic block.
    pub const TERMINATOR: Self = Self(0b0000_0001);
    /// The instruction has architecturally observable side-effects
    /// beyond its operands (e.g. flag updates, MMIO).
    pub const HAS_SIDE_EFFECTS: Self = Self(0b0000_0010);
    /// The instruction sets condition flags (used by x86 / ARM).
    pub const SETS_FLAGS: Self = Self(0b0000_0100);
    /// The instruction is privileged (ring 0 / EL1+).
    pub const PRIVILEGED: Self = Self(0b0000_1000);
    /// The instruction was reconstructed by deobfuscation.
    pub const RECONSTRUCTED: Self = Self(0b0001_0000);

    /// No flags set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Raw bit value.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Build from raw bits (unknown bits are preserved).
    #[must_use]
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits)
    }

    /// `true` if no bits are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// `true` if all bits of `other` are set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// `true` if any bit of `other` is set.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Set the given bits.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Clear the given bits.
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}

impl std::ops::BitOr for InstructionFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for InstructionFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// One OmniIR instruction.
///
/// We keep operand storage compact via `SmallVec`: most instructions have
/// 0-3 operands (mov, add, jmp), and we never want to heap-allocate for them.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct Instruction {
    /// What the instruction does.
    pub opcode: OpCode,

    /// Destination operand(s) (typically 0 or 1).
    pub dst: Vec<Operand>,

    /// Source operand(s) (typically 0-2).
    pub src: Vec<Operand>,

    /// Branch / compare predicate (only meaningful for `BranchIf` / `Compare`).
    pub condition: Option<Condition>,

    /// Original instruction address in the source binary.
    pub address: u64,

    /// Size of the original instruction in bytes (post-decode).
    pub size: u8,

    /// Source ISA / VM the instruction was lifted from.
    pub arch: Arch,

    /// Decorations.
    pub flags: InstructionFlags,

    /// Verbatim raw bytes of the original instruction (for round-trip /
    /// patching). Empty if the instruction is synthetic.
    #[json(default, skip_serializing_if = "Vec::is_empty")]
    pub raw: Vec<u8>,

    /// Optional human-readable mnemonic carried over from the source ISA.
    /// Useful for debugging and for [`OpCode::Custom`].
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

impl Instruction {
    /// Build a brand-new instruction with no operands and default flags.
    #[must_use]
    pub fn new(opcode: OpCode, address: u64, size: u8, arch: Arch) -> Self {
        Self {
            opcode,
            dst: Vec::new(),
            src: Vec::new(),
            condition: None,
            address,
            size,
            arch,
            flags: if opcode.is_terminator() {
                InstructionFlags::TERMINATOR
            } else {
                InstructionFlags::empty()
            },
            raw: Vec::new(),
            mnemonic: None,
        }
    }

    /// Replace the destinations.
    #[must_use]
    pub fn with_dst(mut self, dst: impl IntoIterator<Item = Operand>) -> Self {
        self.dst = dst.into_iter().collect();
        self
    }

    /// Replace the sources.
    #[must_use]
    pub fn with_src(mut self, src: impl IntoIterator<Item = Operand>) -> Self {
        self.src = src.into_iter().collect();
        self
    }

    /// Set the predicate condition.
    #[must_use]
    pub fn with_condition(mut self, cond: Condition) -> Self {
        self.condition = Some(cond);
        self
    }

    /// Set the raw bytes the instruction was decoded from.
    #[must_use]
    pub fn with_raw(mut self, raw: impl IntoIterator<Item = u8>) -> Self {
        self.raw = raw.into_iter().collect();
        self
    }

    /// Set the human-readable mnemonic.
    #[must_use]
    pub fn with_mnemonic(mut self, mnemonic: impl Into<String>) -> Self {
        self.mnemonic = Some(mnemonic.into());
        self
    }

    /// `true` if this is the last instruction of a basic block.
    #[must_use]
    pub fn is_terminator(&self) -> bool {
        self.flags.contains(InstructionFlags::TERMINATOR) || self.opcode.is_terminator()
    }

    /// `true` if this instruction reads or writes memory.
    #[must_use]
    pub fn touches_memory(&self) -> bool {
        if self.opcode.touches_memory() {
            return true;
        }
        self.dst.iter().any(Operand::is_memory) || self.src.iter().any(Operand::is_memory)
    }

    /// Address of the instruction *immediately after* this one in memory.
    #[must_use]
    pub const fn fallthrough_address(&self) -> u64 {
        self.address.wrapping_add(self.size as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Operand, Register, RegisterClass};

    #[test]
    fn new_instruction_terminator_flag_follows_opcode() {
        let nop = Instruction::new(OpCode::Nop, 0, 1, Arch::X86_64);
        assert!(!nop.is_terminator());
        let ret = Instruction::new(OpCode::Return, 0x100, 1, Arch::X86_64);
        assert!(ret.is_terminator());
        assert!(ret.flags.contains(InstructionFlags::TERMINATOR));
    }

    #[test]
    fn fluent_builders_compose() {
        let rax = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 0,
            bit_width: 64,
            name: "rax".into(),
        };
        let inst = Instruction::new(OpCode::Move, 0x1000, 3, Arch::X86_64)
            .with_dst([Operand::Register(rax.clone())])
            .with_src([Operand::Immediate(42)])
            .with_mnemonic("mov rax, 42")
            .with_raw([0x48, 0xC7, 0xC0]);
        assert_eq!(inst.opcode, OpCode::Move);
        assert_eq!(inst.dst.len(), 1);
        assert_eq!(inst.src.len(), 1);
        assert_eq!(inst.mnemonic.as_deref(), Some("mov rax, 42"));
        assert_eq!(inst.raw.as_slice(), &[0x48, 0xC7, 0xC0]);
    }

    #[test]
    fn fallthrough_address_is_addition() {
        let i = Instruction::new(OpCode::Nop, 0x100, 5, Arch::X86_64);
        assert_eq!(i.fallthrough_address(), 0x105);
    }

    #[test]
    fn touches_memory_detects_via_operands() {
        let abs_mem = Operand::Memory(crate::MemoryAddress::absolute(0x1000, 8));
        let inst = Instruction::new(OpCode::Move, 0, 4, Arch::X86_64)
            .with_dst([abs_mem.clone()])
            .with_src([Operand::Immediate(0)]);
        assert!(inst.touches_memory());
    }
}
