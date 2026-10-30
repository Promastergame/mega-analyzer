//! [`OpCode`] — the operation half of an OmniIR [`super::Instruction`].

use omnisec_json::{FromJson, ToJson};

/// What an OmniIR instruction *does*.
///
/// Operations are grouped by domain. Variants in the same group share
/// operand semantics: e.g. all `*Arith` ops take 1-2 source operands and
/// produce one destination, all `Branch*` ops are control-flow, etc.
///
/// The set is deliberately small. ISA-specific instructions that don't fit
/// these slots map to [`OpCode::Custom`] with an arch-defined opaque ID and
/// optional human-readable mnemonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum OpCode {
    /// No operation / placeholder.
    Nop,
    /// Move a value (register-to-register, immediate-to-register, ...).
    Move,

    // ── Arithmetic ───────────────────────────────────────────────────────
    /// Integer addition.
    Add,
    /// Integer subtraction.
    Sub,
    /// Signed integer multiplication.
    Mul,
    /// Unsigned integer multiplication.
    UMul,
    /// Signed integer division.
    Div,
    /// Unsigned integer division.
    UDiv,
    /// Signed integer remainder.
    Rem,
    /// Unsigned integer remainder.
    URem,
    /// Two's-complement negation.
    Neg,

    // ── Bitwise ──────────────────────────────────────────────────────────
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Bitwise NOT.
    Not,
    /// Logical left shift.
    Shl,
    /// Logical right shift.
    Shr,
    /// Arithmetic right shift (sign-extending).
    Sar,
    /// Rotate left.
    Rol,
    /// Rotate right.
    Ror,

    // ── Comparison & test ────────────────────────────────────────────────
    /// `dst = (a == b) ? 1 : 0` etc. — a signed/unsigned comparison flagged
    /// by [`Condition`] in the instruction's `cond` field.
    Compare,
    /// Set flags from `a & b`, no destination.
    Test,

    // ── Memory ───────────────────────────────────────────────────────────
    /// Load value from memory into a register.
    Load,
    /// Store value from a register into memory.
    Store,
    /// Atomic compare-and-swap.
    CmpXchg,
    /// Memory fence / barrier.
    Fence,

    // ── Stack ────────────────────────────────────────────────────────────
    /// Push value onto the architectural stack.
    Push,
    /// Pop value from the architectural stack.
    Pop,

    // ── Control flow ─────────────────────────────────────────────────────
    /// Unconditional jump.
    Jump,
    /// Conditional jump (taken iff `Condition` holds).
    BranchIf,
    /// Function call.
    Call,
    /// Indirect call (target is in a register / memory operand).
    IndirectCall,
    /// Return from function.
    Return,

    // ── Type / width conversions ─────────────────────────────────────────
    /// Sign-extend a narrower value to a wider type.
    SignExtend,
    /// Zero-extend a narrower value to a wider type.
    ZeroExtend,
    /// Truncate a wider value to a narrower type.
    Truncate,

    // ── Misc / abstract ──────────────────────────────────────────────────
    /// Trap / breakpoint / debugger hint.
    Trap,
    /// Privileged or environment call (syscall, svc, hvc, ecall).
    SystemCall,
    /// Halt the processor (`hlt`, `wfi`).
    Halt,
    /// Could not be decoded — preserved as bytes via `Instruction.raw`.
    Invalid,

    /// Architecture-specific or as-yet-uncategorised instruction. Carries
    /// an opaque ID assigned by the lifter.
    Custom(u32),
}

impl OpCode {
    /// `true` if this opcode transfers control (call, jump, branch, return, syscall).
    #[must_use]
    pub const fn is_control_flow(self) -> bool {
        matches!(
            self,
            Self::Jump
                | Self::BranchIf
                | Self::Call
                | Self::IndirectCall
                | Self::Return
                | Self::SystemCall
                | Self::Trap
                | Self::Halt
        )
    }

    /// `true` if this opcode terminates a basic block.
    #[must_use]
    pub const fn is_terminator(self) -> bool {
        matches!(
            self,
            Self::Jump | Self::BranchIf | Self::Return | Self::Halt | Self::Trap
        )
    }

    /// `true` if this opcode reads or writes memory.
    #[must_use]
    pub const fn touches_memory(self) -> bool {
        matches!(
            self,
            Self::Load | Self::Store | Self::Push | Self::Pop | Self::CmpXchg
        )
    }

    /// `true` if this opcode is a "simple" data-flow op (arith / bitwise / move / cmp).
    #[must_use]
    pub const fn is_data_op(self) -> bool {
        matches!(
            self,
            Self::Move
                | Self::Add
                | Self::Sub
                | Self::Mul
                | Self::UMul
                | Self::Div
                | Self::UDiv
                | Self::Rem
                | Self::URem
                | Self::Neg
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::Not
                | Self::Shl
                | Self::Shr
                | Self::Sar
                | Self::Rol
                | Self::Ror
                | Self::Compare
                | Self::Test
                | Self::SignExtend
                | Self::ZeroExtend
                | Self::Truncate
        )
    }
}

/// A signed/unsigned comparison predicate, used by [`OpCode::BranchIf`] and
/// [`OpCode::Compare`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum Condition {
    /// Always taken (unconditional in a `BranchIf` is rare but legal).
    Always,
    /// Never taken (rare, used by some peephole rewrites).
    Never,

    /// Equal (`==`).
    Equal,
    /// Not equal (`!=`).
    NotEqual,

    /// Signed `<`.
    SignedLess,
    /// Signed `<=`.
    SignedLessEq,
    /// Signed `>`.
    SignedGreater,
    /// Signed `>=`.
    SignedGreaterEq,

    /// Unsigned `<` (a.k.a. "below").
    UnsignedLess,
    /// Unsigned `<=` (a.k.a. "below or equal").
    UnsignedLessEq,
    /// Unsigned `>` (a.k.a. "above").
    UnsignedGreater,
    /// Unsigned `>=` (a.k.a. "above or equal").
    UnsignedGreaterEq,

    /// Result is zero (commonly used by jcc against a flag register).
    Zero,
    /// Result is non-zero.
    NotZero,

    /// Negative (sign flag set).
    Negative,
    /// Non-negative.
    NonNegative,

    /// Carry flag set (unsigned overflow on sub).
    Carry,
    /// Carry flag clear.
    NoCarry,

    /// Overflow flag set (signed overflow).
    Overflow,
    /// Overflow flag clear.
    NoOverflow,
}

impl Condition {
    /// Logical inverse of this condition.
    #[must_use]
    pub const fn inverse(self) -> Self {
        match self {
            Self::Always => Self::Never,
            Self::Never => Self::Always,
            Self::Equal => Self::NotEqual,
            Self::NotEqual => Self::Equal,
            Self::SignedLess => Self::SignedGreaterEq,
            Self::SignedLessEq => Self::SignedGreater,
            Self::SignedGreater => Self::SignedLessEq,
            Self::SignedGreaterEq => Self::SignedLess,
            Self::UnsignedLess => Self::UnsignedGreaterEq,
            Self::UnsignedLessEq => Self::UnsignedGreater,
            Self::UnsignedGreater => Self::UnsignedLessEq,
            Self::UnsignedGreaterEq => Self::UnsignedLess,
            Self::Zero => Self::NotZero,
            Self::NotZero => Self::Zero,
            Self::Negative => Self::NonNegative,
            Self::NonNegative => Self::Negative,
            Self::Carry => Self::NoCarry,
            Self::NoCarry => Self::Carry,
            Self::Overflow => Self::NoOverflow,
            Self::NoOverflow => Self::Overflow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_double_inverse_is_identity() {
        for cond in [
            Condition::Equal,
            Condition::NotEqual,
            Condition::SignedLess,
            Condition::UnsignedGreaterEq,
            Condition::Zero,
            Condition::Carry,
            Condition::Overflow,
        ] {
            assert_eq!(cond.inverse().inverse(), cond);
        }
    }

    #[test]
    fn opcode_classifications_are_self_consistent() {
        assert!(OpCode::Jump.is_control_flow());
        assert!(OpCode::Jump.is_terminator());
        assert!(OpCode::BranchIf.is_terminator());
        assert!(OpCode::Return.is_terminator());
        assert!(!OpCode::Add.is_control_flow());
        assert!(!OpCode::Add.is_terminator());
        assert!(OpCode::Add.is_data_op());
        assert!(OpCode::Load.touches_memory());
        assert!(OpCode::Push.touches_memory());
        assert!(!OpCode::Add.touches_memory());
    }
}
