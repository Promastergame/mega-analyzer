//! Expression AST — bitvector and boolean terms.
//!
//! Both `BvExpr` and `BoolExpr` are reference-counted (via [`std::rc::Rc`])
//! so cloning is cheap and the solver can share sub-expressions across
//! many assertions without blowing up memory.

use std::rc::Rc;

use omnisec_json::{FromJson, ToJson};

/// Bitvector width in bits. We support 1, 8, 16, 32, 64, and 128.
pub type Width = u32;

/// Bitvector binary / unary operator kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum BvOp {
    /// Addition (modular).
    Add,
    /// Subtraction (modular).
    Sub,
    /// Multiplication (modular).
    Mul,
    /// Unsigned division. `x / 0 = ~0` (saturating, SMT-LIB convention).
    Udiv,
    /// Signed division.
    Sdiv,
    /// Unsigned remainder.
    Urem,
    /// Signed remainder.
    Srem,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Bitwise NOT (unary).
    Not,
    /// Two's-complement negation (unary).
    Neg,
    /// Logical left shift.
    Shl,
    /// Logical right shift.
    Lshr,
    /// Arithmetic right shift.
    Ashr,
}

/// Boolean operator kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum BoolOp {
    /// Bitvector equality.
    Eq,
    /// Bitvector disequality.
    Ne,
    /// Unsigned less-than.
    Ult,
    /// Unsigned less-or-equal.
    Ule,
    /// Unsigned greater-than.
    Ugt,
    /// Unsigned greater-or-equal.
    Uge,
    /// Signed less-than.
    Slt,
    /// Signed less-or-equal.
    Sle,
    /// Signed greater-than.
    Sgt,
    /// Signed greater-or-equal.
    Sge,
    /// Logical negation (unary, on `BoolExpr`).
    Not,
    /// Conjunction (n-ary).
    And,
    /// Disjunction (n-ary).
    Or,
    /// Biconditional.
    Iff,
    /// Implication.
    Implies,
}

/// Bitvector expression.
///
/// All operations are modular at the given [`Width`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BvExpr {
    /// Constant value (truncated to `width` bits).
    Const {
        /// Value as an unsigned 128-bit integer (interpretation follows context).
        value: u128,
        /// Bit width.
        width: Width,
    },
    /// Named symbolic variable.
    Var {
        /// Variable name.
        name: Rc<str>,
        /// Bit width.
        width: Width,
    },
    /// Unary or binary operation.
    Op {
        /// Operator.
        op: BvOp,
        /// Operands (1 for unary, 2 for binary).
        args: Vec<Rc<BvExpr>>,
        /// Result width.
        width: Width,
    },
    /// If-then-else: `cond ? a : b`.
    Ite {
        /// Condition.
        cond: Rc<BoolExpr>,
        /// Then-branch.
        then_branch: Rc<BvExpr>,
        /// Else-branch.
        else_branch: Rc<BvExpr>,
        /// Result width.
        width: Width,
    },
}

// Builder methods deliberately shadow `std::ops::*` names because the
// `Rc<BvExpr>` API doesn't fit the `Self` signature those traits require.
#[allow(clippy::should_implement_trait)]
impl BvExpr {
    /// Width of this expression.
    #[must_use]
    pub fn width(&self) -> Width {
        match self {
            Self::Const { width, .. }
            | Self::Var { width, .. }
            | Self::Op { width, .. }
            | Self::Ite { width, .. } => *width,
        }
    }

    /// Build a constant.
    #[must_use]
    pub fn con(value: u128, width: Width) -> Rc<Self> {
        Rc::new(Self::Const {
            value: mask(value, width),
            width,
        })
    }

    /// Build a signed constant from `i64`.
    #[must_use]
    pub fn icon(value: i64, width: Width) -> Rc<Self> {
        Self::con(value as u128, width)
    }

    /// Build a variable.
    #[must_use]
    pub fn var(name: &str, width: Width) -> Rc<Self> {
        Rc::new(Self::Var {
            name: Rc::from(name),
            width,
        })
    }

    /// Build a binary op (both args must have matching width).
    #[must_use]
    pub fn binop(op: BvOp, a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        let width = a.width();
        debug_assert_eq!(
            width,
            b.width(),
            "BvOp::{op:?} operand width mismatch ({} vs {})",
            a.width(),
            b.width()
        );
        Rc::new(Self::Op {
            op,
            args: vec![a, b],
            width,
        })
    }

    /// Build a unary op.
    #[must_use]
    pub fn unop(op: BvOp, a: Rc<BvExpr>) -> Rc<Self> {
        let width = a.width();
        Rc::new(Self::Op {
            op,
            args: vec![a],
            width,
        })
    }

    /// Build `a + b`.
    #[must_use]
    pub fn add(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Self::binop(BvOp::Add, a, b)
    }

    /// Build `a - b`.
    #[must_use]
    pub fn sub(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Self::binop(BvOp::Sub, a, b)
    }

    /// Build `a * b`.
    #[must_use]
    pub fn mul(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Self::binop(BvOp::Mul, a, b)
    }

    /// Build `-a`.
    #[must_use]
    pub fn neg(a: Rc<BvExpr>) -> Rc<Self> {
        Self::unop(BvOp::Neg, a)
    }

    /// Build `a & b`.
    #[must_use]
    pub fn and(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Self::binop(BvOp::And, a, b)
    }

    /// Build `a | b`.
    #[must_use]
    pub fn or(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Self::binop(BvOp::Or, a, b)
    }

    /// Build `a ^ b`.
    #[must_use]
    pub fn xor(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Self::binop(BvOp::Xor, a, b)
    }

    /// Build `~a`.
    #[must_use]
    pub fn bvnot(a: Rc<BvExpr>) -> Rc<Self> {
        Self::unop(BvOp::Not, a)
    }
}

/// Boolean expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BoolExpr {
    /// Constant `true`.
    True,
    /// Constant `false`.
    False,
    /// Atomic comparison between two bitvector terms.
    Atom {
        /// Comparison operator (must be a relational `BoolOp`).
        op: BoolOp,
        /// Left-hand side.
        lhs: Rc<BvExpr>,
        /// Right-hand side.
        rhs: Rc<BvExpr>,
    },
    /// Connective: `Not`, `And`, `Or`, `Iff`, `Implies`.
    Connective {
        /// Logical operator.
        op: BoolOp,
        /// Operands (1 for `Not`, ≥1 for `And`/`Or`, exactly 2 for `Iff`/`Implies`).
        args: Vec<Rc<BoolExpr>>,
    },
}

impl BoolExpr {
    /// `true` literal.
    #[must_use]
    pub fn tt() -> Rc<Self> {
        Rc::new(Self::True)
    }

    /// `false` literal.
    #[must_use]
    pub fn ff() -> Rc<Self> {
        Rc::new(Self::False)
    }

    /// Equality atom.
    #[must_use]
    pub fn eq(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        debug_assert_eq!(a.width(), b.width());
        Rc::new(Self::Atom {
            op: BoolOp::Eq,
            lhs: a,
            rhs: b,
        })
    }

    /// Disequality atom.
    #[must_use]
    pub fn ne(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Rc::new(Self::Atom {
            op: BoolOp::Ne,
            lhs: a,
            rhs: b,
        })
    }

    /// Signed less-than atom.
    #[must_use]
    pub fn slt(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Rc::new(Self::Atom {
            op: BoolOp::Slt,
            lhs: a,
            rhs: b,
        })
    }

    /// Signed less-or-equal atom.
    #[must_use]
    pub fn sle(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Rc::new(Self::Atom {
            op: BoolOp::Sle,
            lhs: a,
            rhs: b,
        })
    }

    /// Signed greater-than atom.
    #[must_use]
    pub fn sgt(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Rc::new(Self::Atom {
            op: BoolOp::Sgt,
            lhs: a,
            rhs: b,
        })
    }

    /// Signed greater-or-equal atom.
    #[must_use]
    pub fn sge(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Rc::new(Self::Atom {
            op: BoolOp::Sge,
            lhs: a,
            rhs: b,
        })
    }

    /// Unsigned less-than atom.
    #[must_use]
    pub fn ult(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Rc::new(Self::Atom {
            op: BoolOp::Ult,
            lhs: a,
            rhs: b,
        })
    }

    /// Unsigned less-or-equal atom.
    #[must_use]
    pub fn ule(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Rc::new(Self::Atom {
            op: BoolOp::Ule,
            lhs: a,
            rhs: b,
        })
    }

    /// Unsigned greater-than atom.
    #[must_use]
    pub fn ugt(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Rc::new(Self::Atom {
            op: BoolOp::Ugt,
            lhs: a,
            rhs: b,
        })
    }

    /// Unsigned greater-or-equal atom.
    #[must_use]
    pub fn uge(a: Rc<BvExpr>, b: Rc<BvExpr>) -> Rc<Self> {
        Rc::new(Self::Atom {
            op: BoolOp::Uge,
            lhs: a,
            rhs: b,
        })
    }

    /// Negation.
    #[must_use]
    pub fn not(a: Rc<BoolExpr>) -> Rc<Self> {
        Rc::new(Self::Connective {
            op: BoolOp::Not,
            args: vec![a],
        })
    }

    /// N-ary conjunction.
    #[must_use]
    pub fn and(args: Vec<Rc<BoolExpr>>) -> Rc<Self> {
        Rc::new(Self::Connective {
            op: BoolOp::And,
            args,
        })
    }

    /// N-ary disjunction.
    #[must_use]
    pub fn or(args: Vec<Rc<BoolExpr>>) -> Rc<Self> {
        Rc::new(Self::Connective {
            op: BoolOp::Or,
            args,
        })
    }

    /// Implication.
    #[must_use]
    pub fn implies(a: Rc<BoolExpr>, b: Rc<BoolExpr>) -> Rc<Self> {
        Rc::new(Self::Connective {
            op: BoolOp::Implies,
            args: vec![a, b],
        })
    }
}

/// Mask `value` to `width` bits.
#[must_use]
pub(crate) fn mask(value: u128, width: Width) -> u128 {
    if width >= 128 {
        value
    } else {
        value & ((1u128 << width) - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_is_propagated_through_ops() {
        let x = BvExpr::var("x", 32);
        let y = BvExpr::var("y", 32);
        let sum = BvExpr::add(x, y);
        assert_eq!(sum.width(), 32);
    }

    #[test]
    fn mask_truncates() {
        assert_eq!(mask(0x1FF, 8), 0xFF);
        assert_eq!(mask(0xDEAD_BEEF, 16), 0xBEEF);
        assert_eq!(mask(0xFFFF_FFFF, 32), 0xFFFF_FFFF);
    }

    #[test]
    fn bool_atom_builders_round_trip() {
        let x = BvExpr::var("x", 32);
        let z = BvExpr::con(0, 32);
        let pos = BoolExpr::sgt(x.clone(), z.clone());
        let nonneg = BoolExpr::sge(x, z);
        assert!(matches!(
            *pos,
            BoolExpr::Atom {
                op: BoolOp::Sgt,
                ..
            }
        ));
        assert!(matches!(
            *nonneg,
            BoolExpr::Atom {
                op: BoolOp::Sge,
                ..
            }
        ));
    }
}
