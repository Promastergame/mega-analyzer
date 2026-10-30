//! Abstract value lattice for constant propagation and symbolic evaluation.
//!
//! The lattice models the "knowledge" we have about each register/variable:
//!
//! ```text
//!         ⊤ (Top / Unknown)
//!        / | \
//!   Const(0) Const(1) Const(2) ...
//!        \ | /
//!         ⊥ (Bottom / Overdefined)
//! ```
//!
//! - **Top** means we haven't seen a definition yet (uninitialized).
//! - **Const(v)** means we know the exact value.
//! - **Bottom** means multiple conflicting values were merged — we gave up.
//!
//! The meet operation is:
//! - `Top ⊓ x = x`
//! - `Const(a) ⊓ Const(a) = Const(a)`
//! - `Const(a) ⊓ Const(b) = Bottom` when `a ≠ b`
//! - `Bottom ⊓ x = Bottom`

use omnisec_json::{FromJson, ToJson};
use std::fmt;

/// Abstract value in the constant propagation lattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum AbstractValue {
    /// Not yet defined — no information.
    Top,
    /// Known constant value (signed 64-bit covers all integer types).
    Const(i64),
    /// Multiple conflicting values — cannot be resolved.
    Bottom,
}

impl AbstractValue {
    /// Meet (greatest lower bound) of two abstract values.
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Top, x) | (x, Self::Top) => x,
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Const(a), Self::Const(b)) => {
                if a == b {
                    Self::Const(a)
                } else {
                    Self::Bottom
                }
            }
        }
    }

    /// Returns `true` if this is a known constant.
    #[must_use]
    pub const fn is_const(self) -> bool {
        matches!(self, Self::Const(_))
    }

    /// Returns the constant value if known.
    #[must_use]
    pub const fn as_const(self) -> Option<i64> {
        match self {
            Self::Const(v) => Some(v),
            _ => None,
        }
    }

    /// Returns `true` if this value is `Bottom` (overdefined).
    #[must_use]
    pub const fn is_bottom(self) -> bool {
        matches!(self, Self::Bottom)
    }

    /// Returns `true` if this value is `Top` (undefined).
    #[must_use]
    pub const fn is_top(self) -> bool {
        matches!(self, Self::Top)
    }

    /// Try to evaluate a binary operation on two abstract values.
    /// Returns `Bottom` if either operand is not a constant.
    #[must_use]
    pub fn eval_binop(self, op: BinOp, rhs: Self) -> Self {
        match (self.as_const(), rhs.as_const()) {
            (Some(a), Some(b)) => {
                let result = match op {
                    BinOp::Add => a.wrapping_add(b),
                    BinOp::Sub => a.wrapping_sub(b),
                    BinOp::Mul => a.wrapping_mul(b),
                    BinOp::Div => {
                        if b == 0 {
                            return Self::Bottom;
                        }
                        a.wrapping_div(b)
                    }
                    BinOp::Rem => {
                        if b == 0 {
                            return Self::Bottom;
                        }
                        a.wrapping_rem(b)
                    }
                    BinOp::And => a & b,
                    BinOp::Or => a | b,
                    BinOp::Xor => a ^ b,
                    BinOp::Shl => a.wrapping_shl(b as u32),
                    BinOp::Shr => ((a as u64).wrapping_shr(b as u32)) as i64,
                    BinOp::Sar => a.wrapping_shr(b as u32),
                    BinOp::Rol => (a as u64).rotate_left(b as u32) as i64,
                    BinOp::Ror => (a as u64).rotate_right(b as u32) as i64,
                };
                Self::Const(result)
            }
            _ => {
                // Even with unknown operands, some operations have known results
                match op {
                    // x & 0 = 0, 0 & x = 0
                    BinOp::And if self == Self::Const(0) || rhs == Self::Const(0) => Self::Const(0),
                    // x | -1 = -1, -1 | x = -1
                    BinOp::Or if self == Self::Const(-1) || rhs == Self::Const(-1) => {
                        Self::Const(-1)
                    }
                    // x * 0 = 0, 0 * x = 0
                    BinOp::Mul if self == Self::Const(0) || rhs == Self::Const(0) => Self::Const(0),
                    _ => Self::Bottom,
                }
            }
        }
    }

    /// Evaluate a unary operation on an abstract value.
    #[must_use]
    pub fn eval_unop(self, op: UnOp) -> Self {
        match self.as_const() {
            Some(v) => {
                let result = match op {
                    UnOp::Neg => v.wrapping_neg(),
                    UnOp::Not => !v,
                };
                Self::Const(result)
            }
            None => Self::Bottom,
        }
    }
}

impl fmt::Display for AbstractValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top => write!(f, "⊤"),
            Self::Const(v) => write!(f, "{v:#x}"),
            Self::Bottom => write!(f, "⊥"),
        }
    }
}

/// Binary operations supported by the lattice evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOp {
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Signed division.
    Div,
    /// Signed remainder.
    Rem,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Logical left shift.
    Shl,
    /// Logical right shift.
    Shr,
    /// Arithmetic right shift.
    Sar,
    /// Rotate left.
    Rol,
    /// Rotate right.
    Ror,
}

/// Unary operations supported by the lattice evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnOp {
    /// Two's-complement negation.
    Neg,
    /// Bitwise NOT.
    Not,
}

/// Map an OmniIR opcode to a lattice binary operation.
#[must_use]
pub fn opcode_to_binop(op: omnisec_ir::OpCode) -> Option<BinOp> {
    match op {
        omnisec_ir::OpCode::Add => Some(BinOp::Add),
        omnisec_ir::OpCode::Sub => Some(BinOp::Sub),
        omnisec_ir::OpCode::Mul | omnisec_ir::OpCode::UMul => Some(BinOp::Mul),
        omnisec_ir::OpCode::Div | omnisec_ir::OpCode::UDiv => Some(BinOp::Div),
        omnisec_ir::OpCode::Rem | omnisec_ir::OpCode::URem => Some(BinOp::Rem),
        omnisec_ir::OpCode::And => Some(BinOp::And),
        omnisec_ir::OpCode::Or => Some(BinOp::Or),
        omnisec_ir::OpCode::Xor => Some(BinOp::Xor),
        omnisec_ir::OpCode::Shl => Some(BinOp::Shl),
        omnisec_ir::OpCode::Shr => Some(BinOp::Shr),
        omnisec_ir::OpCode::Sar => Some(BinOp::Sar),
        omnisec_ir::OpCode::Rol => Some(BinOp::Rol),
        omnisec_ir::OpCode::Ror => Some(BinOp::Ror),
        _ => None,
    }
}

/// Map an OmniIR opcode to a lattice unary operation.
#[must_use]
pub fn opcode_to_unop(op: omnisec_ir::OpCode) -> Option<UnOp> {
    match op {
        omnisec_ir::OpCode::Neg => Some(UnOp::Neg),
        omnisec_ir::OpCode::Not => Some(UnOp::Not),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meet_lattice_laws() {
        // Top is the identity
        assert_eq!(
            AbstractValue::Top.meet(AbstractValue::Const(42)),
            AbstractValue::Const(42)
        );
        assert_eq!(
            AbstractValue::Const(42).meet(AbstractValue::Top),
            AbstractValue::Const(42)
        );

        // Same constant stays constant
        assert_eq!(
            AbstractValue::Const(7).meet(AbstractValue::Const(7)),
            AbstractValue::Const(7)
        );

        // Different constants -> bottom
        assert_eq!(
            AbstractValue::Const(1).meet(AbstractValue::Const(2)),
            AbstractValue::Bottom
        );

        // Bottom absorbs everything
        assert_eq!(
            AbstractValue::Bottom.meet(AbstractValue::Const(5)),
            AbstractValue::Bottom
        );
        assert_eq!(
            AbstractValue::Const(5).meet(AbstractValue::Bottom),
            AbstractValue::Bottom
        );
    }

    #[test]
    fn eval_arithmetic() {
        let a = AbstractValue::Const(10);
        let b = AbstractValue::Const(3);
        assert_eq!(a.eval_binop(BinOp::Add, b), AbstractValue::Const(13));
        assert_eq!(a.eval_binop(BinOp::Sub, b), AbstractValue::Const(7));
        assert_eq!(a.eval_binop(BinOp::Mul, b), AbstractValue::Const(30));
        assert_eq!(a.eval_binop(BinOp::Div, b), AbstractValue::Const(3));
        assert_eq!(a.eval_binop(BinOp::Rem, b), AbstractValue::Const(1));
    }

    #[test]
    fn eval_bitwise() {
        let a = AbstractValue::Const(0xFF00);
        let b = AbstractValue::Const(0x0F0F);
        assert_eq!(a.eval_binop(BinOp::And, b), AbstractValue::Const(0x0F00));
        assert_eq!(a.eval_binop(BinOp::Or, b), AbstractValue::Const(0xFF0F));
        assert_eq!(a.eval_binop(BinOp::Xor, b), AbstractValue::Const(0xF00F));
    }

    #[test]
    fn eval_div_by_zero_is_bottom() {
        let a = AbstractValue::Const(42);
        let zero = AbstractValue::Const(0);
        assert_eq!(a.eval_binop(BinOp::Div, zero), AbstractValue::Bottom);
        assert_eq!(a.eval_binop(BinOp::Rem, zero), AbstractValue::Bottom);
    }

    #[test]
    fn eval_absorbing_elements() {
        let unknown = AbstractValue::Bottom;
        let zero = AbstractValue::Const(0);

        // x & 0 = 0 even if x is unknown
        assert_eq!(
            unknown.eval_binop(BinOp::And, zero),
            AbstractValue::Const(0)
        );
        // 0 * x = 0 even if x is unknown
        assert_eq!(
            zero.eval_binop(BinOp::Mul, unknown),
            AbstractValue::Const(0)
        );
    }

    #[test]
    fn eval_unary() {
        assert_eq!(
            AbstractValue::Const(5).eval_unop(UnOp::Neg),
            AbstractValue::Const(-5)
        );
        assert_eq!(
            AbstractValue::Const(0).eval_unop(UnOp::Not),
            AbstractValue::Const(-1)
        );
    }
}
