//! [`Operand`] — what an OmniIR instruction reads / writes.

use omnisec_core::Arch;
use omnisec_json::{FromJson, ToJson};

/// A value type carried by an [`Operand`].
///
/// We model integer widths explicitly because branch / compare semantics
/// depend on them. Floating-point and SIMD types are placeholders for now —
/// real lifters will populate them in Phase 2+.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum ValueType {
    /// Boolean (1 bit, but stored at least 1 byte at the target level).
    Bool,
    /// 8-bit integer.
    I8,
    /// 16-bit integer.
    I16,
    /// 32-bit integer.
    I32,
    /// 64-bit integer.
    I64,
    /// 128-bit integer (used by SSE / AVX / NEON spills).
    I128,
    /// 32-bit float (`single`).
    F32,
    /// 64-bit float (`double`).
    F64,
    /// 80-bit x87 extended precision.
    F80,
    /// Native pointer width — resolved by the lifter from [`Arch`].
    Pointer,
    /// Untyped (use sparingly — only when the source ISA is itself untyped).
    Untyped,
}

impl ValueType {
    /// Size in bytes, when known. Returns `None` for [`ValueType::Untyped`]
    /// and [`ValueType::Pointer`] (resolved by the lifter from [`Arch`]).
    #[must_use]
    pub const fn size_bytes(self) -> Option<usize> {
        match self {
            Self::Bool | Self::I8 => Some(1),
            Self::I16 => Some(2),
            Self::I32 | Self::F32 => Some(4),
            Self::I64 | Self::F64 => Some(8),
            Self::F80 => Some(10),
            Self::I128 => Some(16),
            Self::Pointer | Self::Untyped => None,
        }
    }
}

/// Coarse classification of physical / virtual registers.
///
/// Real ISAs have many register banks (gp, fp, simd, flags, segment, ...).
/// We bucket them so that downstream analyses can ask "is this a flags
/// register?" without per-ISA knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum RegisterClass {
    /// General-purpose integer (eax, rdi, x0, ...).
    GeneralPurpose,
    /// Stack pointer (esp/rsp/sp).
    StackPointer,
    /// Frame pointer (ebp/rbp/x29 when used as FP).
    FramePointer,
    /// Program counter / instruction pointer (rip, pc).
    ProgramCounter,
    /// Status / flags register (eflags, cpsr, xpsr).
    Flags,
    /// Floating-point register (xmm, st, d, s, ...).
    Float,
    /// SIMD / vector register (ymm, zmm, v0, ...).
    Vector,
    /// Segment register (cs, ds, ss, fs, gs).
    Segment,
    /// Control / system register (cr0, msr, sctlr_el1, ...).
    Control,
    /// SSA-temporary virtual register introduced by the lifter.
    Virtual,
}

/// A register reference inside OmniIR.
///
/// We carry both the architecture-native id (`native_id`) — useful when
/// printing or round-tripping back to ISA bytes — and a stable per-arch
/// `name` for human consumption.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToJson, FromJson)]
pub struct Register {
    /// Source ISA the register belongs to.
    pub arch: Arch,
    /// Class of this register.
    pub class: RegisterClass,
    /// Native register identifier (whatever encoding the ISA uses).
    pub native_id: u32,
    /// Width of the register in bits (e.g. 32 for `eax`, 64 for `rax`).
    pub bit_width: u16,
    /// Human-readable name (e.g. `"rax"`, `"x0"`, `"v0"`).
    pub name: String,
}

impl Register {
    /// Build a virtual SSA temporary.
    #[must_use]
    pub fn virtual_temp(id: u32, bit_width: u16) -> Self {
        Self {
            arch: Arch::Unknown,
            class: RegisterClass::Virtual,
            native_id: id,
            bit_width,
            name: format!("%t{id}"),
        }
    }

    /// `true` if this is the stack pointer for its ISA.
    #[must_use]
    pub const fn is_stack_pointer(&self) -> bool {
        matches!(self.class, RegisterClass::StackPointer)
    }
}

/// A memory address expression: `[base + index*scale + displacement]`.
///
/// Any of `base` / `index` / `displacement` may be absent. `segment` is
/// kept for x86 fs:/gs:/cs: prefixes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToJson, FromJson)]
pub struct MemoryAddress {
    /// Base register.
    pub base: Option<Register>,
    /// Index register.
    pub index: Option<Register>,
    /// Index scale: 1, 2, 4 or 8 on x86; ignored on architectures without it.
    pub scale: u8,
    /// Constant displacement.
    pub displacement: i64,
    /// Optional segment register (x86 fs:/gs:/cs:).
    pub segment: Option<Register>,
    /// Width of the access in bytes (1, 2, 4, 8, 16, ...).
    pub access_size: u16,
}

impl MemoryAddress {
    /// Build a simple `[reg + disp]` address.
    #[must_use]
    pub fn reg_offset(base: Register, displacement: i64, access_size: u16) -> Self {
        Self {
            base: Some(base),
            index: None,
            scale: 1,
            displacement,
            segment: None,
            access_size,
        }
    }

    /// Build a `[disp]` absolute address.
    #[must_use]
    pub fn absolute(displacement: i64, access_size: u16) -> Self {
        Self {
            base: None,
            index: None,
            scale: 1,
            displacement,
            segment: None,
            access_size,
        }
    }
}

/// One operand of an OmniIR instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum Operand {
    /// Register (physical or virtual).
    Register(Register),
    /// Sign-extended integer immediate. Width comes from the surrounding
    /// instruction; the bare `i64` is enough for all integer immediates we
    /// expect on 32/64-bit targets.
    Immediate(i64),
    /// Memory access.
    Memory(MemoryAddress),
    /// Branch / call target (instruction address inside the same image).
    Label(u64),
    /// External symbol (import / relocation name).
    Symbol(String),
    /// Type carrier for ops that need it (e.g. `SignExtend` from `I32`→`I64`).
    Type(ValueType),
}

impl Operand {
    /// `true` if this operand reads memory (memory loads / stores).
    #[must_use]
    pub const fn is_memory(&self) -> bool {
        matches!(self, Self::Memory(_))
    }

    /// `true` if this operand is a register.
    #[must_use]
    pub const fn is_register(&self) -> bool {
        matches!(self, Self::Register(_))
    }

    /// `true` if this operand is a branch target / label.
    #[must_use]
    pub const fn is_label(&self) -> bool {
        matches!(self, Self::Label(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_type_sizes() {
        assert_eq!(ValueType::Bool.size_bytes(), Some(1));
        assert_eq!(ValueType::I8.size_bytes(), Some(1));
        assert_eq!(ValueType::I16.size_bytes(), Some(2));
        assert_eq!(ValueType::I32.size_bytes(), Some(4));
        assert_eq!(ValueType::I64.size_bytes(), Some(8));
        assert_eq!(ValueType::I128.size_bytes(), Some(16));
        assert_eq!(ValueType::F32.size_bytes(), Some(4));
        assert_eq!(ValueType::F64.size_bytes(), Some(8));
        assert_eq!(ValueType::F80.size_bytes(), Some(10));
        assert_eq!(ValueType::Pointer.size_bytes(), None);
        assert_eq!(ValueType::Untyped.size_bytes(), None);
    }

    #[test]
    fn virtual_temp_register() {
        let r = Register::virtual_temp(7, 64);
        assert_eq!(r.bit_width, 64);
        assert_eq!(r.name, "%t7");
        assert_eq!(r.class, RegisterClass::Virtual);
        assert!(!r.is_stack_pointer());
    }

    #[test]
    fn memory_address_helpers() {
        let r = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 0,
            bit_width: 64,
            name: "rax".into(),
        };
        let m = MemoryAddress::reg_offset(r.clone(), -8, 8);
        assert_eq!(m.base.as_ref().unwrap().name, "rax");
        assert_eq!(m.displacement, -8);
        assert_eq!(m.access_size, 8);

        let abs = MemoryAddress::absolute(0x1000, 4);
        assert!(abs.base.is_none());
        assert_eq!(abs.displacement, 0x1000);
    }

    #[test]
    fn operand_classifiers() {
        let r = Operand::Register(Register::virtual_temp(0, 64));
        assert!(r.is_register());
        assert!(!r.is_memory());
        let m = Operand::Memory(MemoryAddress::absolute(0x1000, 8));
        assert!(m.is_memory());
        assert!(!m.is_register());
        assert!(Operand::Label(0x1000).is_label());
    }
}
