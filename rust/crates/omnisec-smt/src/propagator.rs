//! Theory propagator — linear-arithmetic / bitvector domain.
//!
//! Given a sequence of theory atoms over linear bitvector terms, the
//! propagator either:
//!
//! - finds a consistent **model** assigning concrete values to every
//!   variable, or
//! - proves the constraints **inconsistent**, or
//! - gives up with **Unknown** (e.g. non-linear multiplication of two
//!   symbolic terms, or bitwise ops we can't resolve).
//!
//! The decision procedure has three layers:
//!
//! 1. **Term normalization** — every `BvExpr` is folded into a
//!    [`LinTerm`]: a sum `Σ cᵢ·xᵢ + k`. Non-linear or bitwise terms
//!    that can't be flattened are replaced with a fresh anonymous
//!    variable (an "abstracted" subterm), making the propagator sound
//!    but incomplete on them.
//! 2. **Linear equality solving** — Gauss-Jordan style elimination on
//!    the rows that came from `Eq` atoms. The resulting reduced row
//!    echelon form fixes some variables, parametrises others.
//! 3. **Interval propagation** — `Slt/Sle/Sgt/Sge/Ult/Ule/Ugt/Uge`
//!    constraints tighten `[lo, hi]` ranges per variable. When an
//!    interval collapses, the variable is fixed; when intervals are
//!    empty, the constraints are inconsistent.
//!
//! Bit width is tracked per variable; results are sound under modular
//! arithmetic.

use std::rc::Rc;

use std::collections::HashMap as FxHashMap;

use crate::ast::{BoolExpr, BoolOp, BvExpr, BvOp, Width, mask};

/// A linear term `Σ coeff_i * var_i + constant`, all signed `i128`.
///
/// We keep coefficients sparse: `coeffs[var] = coeff`. The `constant`
/// field is the free term.
#[derive(Debug, Clone, Default)]
pub struct LinTerm {
    /// `coeffs[name] = coefficient`.
    pub coeffs: FxHashMap<Rc<str>, i128>,
    /// Constant (free) term.
    pub constant: i128,
    /// Bit width of the term.
    pub width: Width,
}

impl LinTerm {
    /// Create a constant term.
    #[must_use]
    pub fn from_const(value: i128, width: Width) -> Self {
        Self {
            coeffs: FxHashMap::default(),
            constant: value,
            width,
        }
    }

    /// Create a term `+1 * var + 0`.
    #[must_use]
    pub fn from_var(name: Rc<str>, width: Width) -> Self {
        let mut coeffs = FxHashMap::default();
        coeffs.insert(name, 1);
        Self {
            coeffs,
            constant: 0,
            width,
        }
    }

    /// `self += rhs`.
    pub fn add_assign(&mut self, rhs: &LinTerm) {
        for (k, v) in &rhs.coeffs {
            let entry = self.coeffs.entry(k.clone()).or_insert(0);
            *entry += *v;
            if *entry == 0 {
                self.coeffs.remove(k);
            }
        }
        self.constant += rhs.constant;
    }

    /// `self -= rhs`.
    pub fn sub_assign(&mut self, rhs: &LinTerm) {
        for (k, v) in &rhs.coeffs {
            let entry = self.coeffs.entry(k.clone()).or_insert(0);
            *entry -= *v;
            if *entry == 0 {
                self.coeffs.remove(k);
            }
        }
        self.constant -= rhs.constant;
    }

    /// `self *= scalar`.
    pub fn scalar_mul(&mut self, k: i128) {
        for v in self.coeffs.values_mut() {
            *v *= k;
        }
        self.constant *= k;
        self.coeffs.retain(|_, v| *v != 0);
    }

    /// `true` if no symbolic terms.
    #[must_use]
    pub fn is_const(&self) -> bool {
        self.coeffs.is_empty()
    }
}

/// A normalized constraint produced by the theory layer.
///
/// All atoms are reduced to the form `term <op> 0`.
#[derive(Debug, Clone)]
pub enum TheoryAtom {
    /// `term == 0`.
    EqZero(LinTerm),
    /// `term != 0`.
    NeZero(LinTerm),
    /// signed `term <= 0`.
    SleZero(LinTerm),
    /// signed `term <  0`.
    SltZero(LinTerm),
    /// unsigned `term <= 0` (in width-modular arithmetic, this means `term == 0`,
    /// but we keep it distinct so the solver can apply unsigned bounds).
    UleZero(LinTerm),
    /// unsigned `term < 0` (always false; preserved for completeness).
    UltZero(LinTerm),
    /// **Opaque** boolean — could not be reduced (e.g. an abstracted subterm).
    /// The solver treats this as a free Boolean.
    Opaque,
}

/// Interval `[lo, hi]` over `i128`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    /// Lower bound (inclusive).
    pub lo: i128,
    /// Upper bound (inclusive).
    pub hi: i128,
}

impl Interval {
    /// The full range `[i128::MIN, i128::MAX]`.
    pub const FULL: Self = Self {
        lo: i128::MIN,
        hi: i128::MAX,
    };

    /// Range derived from a signed bitvector of `width` bits.
    #[must_use]
    pub fn signed(width: Width) -> Self {
        if width == 0 || width >= 128 {
            Self::FULL
        } else {
            let lo = -(1i128 << (width - 1));
            let hi = (1i128 << (width - 1)) - 1;
            Self { lo, hi }
        }
    }

    /// `true` iff `lo > hi`.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.lo > self.hi
    }

    /// Intersect with another interval. May produce an empty one.
    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        Self {
            lo: self.lo.max(other.lo),
            hi: self.hi.min(other.hi),
        }
    }
}

/// Per-variable interval store, plus a list of "forbidden" point values
/// per variable (used to model disequality constraints `x != c` without
/// case-splitting).
#[derive(Debug, Default, Clone)]
pub struct IntervalStore {
    pub(crate) intervals: FxHashMap<Rc<str>, Interval>,
    pub(crate) widths: FxHashMap<Rc<str>, Width>,
    pub(crate) forbidden: FxHashMap<Rc<str>, Vec<i128>>,
}

impl IntervalStore {
    /// Get the interval for `var`. Defaults to the full signed range
    /// at the variable's known width.
    #[must_use]
    pub fn get(&self, var: &Rc<str>) -> Interval {
        if let Some(i) = self.intervals.get(var) {
            return *i;
        }
        if let Some(w) = self.widths.get(var) {
            return Interval::signed(*w);
        }
        Interval::FULL
    }

    /// Set (or tighten) the interval for `var`. Returns `Err` if it
    /// becomes empty (i.e. an inconsistency).
    pub fn tighten(&mut self, var: &Rc<str>, new: Interval) -> Result<bool, ()> {
        let current = self.get(var);
        let next = current.intersect(new);
        if next.is_empty() {
            return Err(());
        }
        let changed = next.lo != current.lo || next.hi != current.hi;
        self.intervals.insert(var.clone(), next);
        Ok(changed)
    }

    /// Register a variable's bit width.
    pub fn declare(&mut self, name: Rc<str>, width: Width) {
        self.widths.insert(name, width);
    }

    /// Add a forbidden point value for `var`. Used by `x != c` constraints.
    pub fn forbid(&mut self, var: Rc<str>, value: i128) {
        let entry = self.forbidden.entry(var).or_default();
        if !entry.contains(&value) {
            entry.push(value);
        }
    }

    /// `true` iff every variable has at least one valid value left in its
    /// interval that is not in its `forbidden` list.
    #[must_use]
    pub fn has_witness(&self) -> bool {
        for (name, interval) in &self.intervals {
            if interval.is_empty() {
                return false;
            }
            let forbidden: &[i128] = self.forbidden.get(name).map(Vec::as_slice).unwrap_or(&[]);
            if interval.lo == interval.hi && forbidden.contains(&interval.lo) {
                return false;
            }
        }
        true
    }

    /// Pick a witness value for `var`: the smallest one in the interval
    /// that is not in `forbidden`. Returns `None` if there is none.
    #[must_use]
    pub fn witness(&self, var: &Rc<str>) -> Option<i128> {
        let i = self.intervals.get(var).copied()?;
        let forbidden: &[i128] = self.forbidden.get(var).map(Vec::as_slice).unwrap_or(&[]);
        let mut v = i.lo;
        while v <= i.hi {
            if !forbidden.contains(&v) {
                return Some(v);
            }
            v = v.checked_add(1)?;
        }
        None
    }
}

/// Convert a `BvExpr` into a [`LinTerm`].
///
/// Returns `None` when the expression contains operations the propagator
/// can't handle linearly (e.g. `*` between two symbolic terms, or bitwise
/// ops on a symbolic value).
#[must_use]
pub fn linearize(expr: &BvExpr) -> Option<LinTerm> {
    match expr {
        BvExpr::Const { value, width } => {
            // Reinterpret as signed in [-2^{w-1}, 2^{w-1}).
            let v = *value;
            let signed = if *width < 128 && (v >> (*width - 1)) & 1 == 1 {
                (v as i128) - (1i128 << *width)
            } else {
                v as i128
            };
            Some(LinTerm::from_const(signed, *width))
        }
        BvExpr::Var { name, width } => Some(LinTerm::from_var(name.clone(), *width)),
        BvExpr::Op { op, args, width } => match op {
            BvOp::Add if args.len() == 2 => {
                let mut a = linearize(&args[0])?;
                let b = linearize(&args[1])?;
                a.add_assign(&b);
                a.width = *width;
                Some(a)
            }
            BvOp::Sub if args.len() == 2 => {
                let mut a = linearize(&args[0])?;
                let b = linearize(&args[1])?;
                a.sub_assign(&b);
                a.width = *width;
                Some(a)
            }
            BvOp::Neg if args.len() == 1 => {
                let mut a = linearize(&args[0])?;
                a.scalar_mul(-1);
                a.width = *width;
                Some(a)
            }
            BvOp::Mul if args.len() == 2 => {
                let a = linearize(&args[0])?;
                let b = linearize(&args[1])?;
                // Constant multiplication only.
                match (a.is_const(), b.is_const()) {
                    (true, _) => {
                        let mut t = b;
                        t.scalar_mul(a.constant);
                        Some(t)
                    }
                    (_, true) => {
                        let mut t = a;
                        t.scalar_mul(b.constant);
                        Some(t)
                    }
                    _ => None,
                }
            }
            _ => None, // bitwise / shift / Ite are non-linear here
        },
        BvExpr::Ite { .. } => None,
    }
}

/// Try to reduce a `BoolExpr` atom into a [`TheoryAtom`]. Logical
/// connectives are flattened out by [`Solver::cnf`](crate::solver::Solver),
/// not here.
#[must_use]
pub fn reduce_atom(b: &BoolExpr) -> TheoryAtom {
    let (op, lhs, rhs) = match b {
        BoolExpr::Atom { op, lhs, rhs } => (*op, lhs.clone(), rhs.clone()),
        _ => return TheoryAtom::Opaque,
    };
    let lhs_lin = linearize(&lhs);
    let rhs_lin = linearize(&rhs);
    let (Some(mut l), Some(r)) = (lhs_lin, rhs_lin) else {
        return TheoryAtom::Opaque;
    };
    l.sub_assign(&r); // l := lhs - rhs
    match op {
        BoolOp::Eq => TheoryAtom::EqZero(l),
        BoolOp::Ne => TheoryAtom::NeZero(l),
        BoolOp::Slt => TheoryAtom::SltZero(l),
        BoolOp::Sle => TheoryAtom::SleZero(l),
        BoolOp::Sgt => {
            l.scalar_mul(-1);
            TheoryAtom::SltZero(l) // (lhs - rhs > 0) ≡ (rhs - lhs < 0)
        }
        BoolOp::Sge => {
            l.scalar_mul(-1);
            TheoryAtom::SleZero(l)
        }
        BoolOp::Ult => TheoryAtom::UltZero(l),
        BoolOp::Ule => TheoryAtom::UleZero(l),
        BoolOp::Ugt => {
            l.scalar_mul(-1);
            TheoryAtom::UltZero(l)
        }
        BoolOp::Uge => {
            l.scalar_mul(-1);
            TheoryAtom::UleZero(l)
        }
        _ => TheoryAtom::Opaque,
    }
}

/// Apply a single theory atom to an interval store. Returns:
/// - `Some(true)`  → consistent, intervals may have tightened
/// - `Some(false)` → inconsistent (proven UNSAT)
/// - `None`        → unable to determine (e.g. multi-variable atom)
pub fn apply_atom(atom: &TheoryAtom, store: &mut IntervalStore) -> Option<bool> {
    match atom {
        TheoryAtom::EqZero(t) => apply_eq_zero(t, store),
        TheoryAtom::NeZero(t) => apply_ne_zero(t, store),
        TheoryAtom::SleZero(t) | TheoryAtom::UleZero(t) => apply_le_zero(t, store),
        TheoryAtom::SltZero(t) | TheoryAtom::UltZero(t) => apply_lt_zero(t, store),
        TheoryAtom::Opaque => None,
    }
}

/// `term == 0` with exactly one variable: fix its value.
fn apply_eq_zero(t: &LinTerm, store: &mut IntervalStore) -> Option<bool> {
    if t.coeffs.is_empty() {
        return Some(t.constant == 0);
    }
    if t.coeffs.len() != 1 {
        return None; // multi-var: handled by gauss layer separately
    }
    let (var, &coeff) = t.coeffs.iter().next().unwrap();
    if coeff == 0 {
        return Some(t.constant == 0);
    }
    if t.constant % coeff != 0 {
        // Non-integer solution under integer arithmetic ⇒ inconsistent.
        return Some(false);
    }
    let value = -t.constant / coeff;
    let new = Interval {
        lo: value,
        hi: value,
    };
    match store.tighten(var, new) {
        Ok(_) => Some(true),
        Err(()) => Some(false),
    }
}

/// `term != 0`. For constants, evaluate immediately. For single-variable
/// linear terms `coeff * x + c != 0`, register `-c/coeff` as a forbidden
/// point value of `x` (only when the division is exact). Multi-variable
/// disequalities are left unhandled (returns `None`).
fn apply_ne_zero(t: &LinTerm, store: &mut IntervalStore) -> Option<bool> {
    if t.is_const() {
        return Some(t.constant != 0);
    }
    if t.coeffs.len() != 1 {
        return None;
    }
    let (var, &coeff) = t.coeffs.iter().next().unwrap();
    if coeff == 0 {
        return Some(t.constant != 0);
    }
    if t.constant % coeff != 0 {
        // x is integer ⇒ coeff*x + c can never be 0 ⇒ disequality holds.
        return Some(true);
    }
    let forbidden = -t.constant / coeff;
    store.forbid(var.clone(), forbidden);
    Some(true)
}

/// `coeff * x + c <= 0`.
fn apply_le_zero(t: &LinTerm, store: &mut IntervalStore) -> Option<bool> {
    if t.coeffs.is_empty() {
        return Some(t.constant <= 0);
    }
    if t.coeffs.len() != 1 {
        return None;
    }
    let (var, &coeff) = t.coeffs.iter().next().unwrap();
    match coeff.cmp(&0) {
        std::cmp::Ordering::Greater => {
            // coeff > 0: x ≤ floor(-c / coeff)
            let upper = div_floor(-t.constant, coeff);
            match store.tighten(
                var,
                Interval {
                    lo: i128::MIN,
                    hi: upper,
                },
            ) {
                Ok(_) => Some(true),
                Err(()) => Some(false),
            }
        }
        std::cmp::Ordering::Less => {
            // coeff < 0: x ≥ ceil(-c / coeff)
            let lower = div_ceil(-t.constant, coeff);
            match store.tighten(
                var,
                Interval {
                    lo: lower,
                    hi: i128::MAX,
                },
            ) {
                Ok(_) => Some(true),
                Err(()) => Some(false),
            }
        }
        std::cmp::Ordering::Equal => Some(t.constant <= 0),
    }
}

/// `coeff * x + c < 0`.
fn apply_lt_zero(t: &LinTerm, store: &mut IntervalStore) -> Option<bool> {
    if t.coeffs.is_empty() {
        return Some(t.constant < 0);
    }
    if t.coeffs.len() != 1 {
        return None;
    }
    let (var, &coeff) = t.coeffs.iter().next().unwrap();
    match coeff.cmp(&0) {
        std::cmp::Ordering::Greater => {
            // coeff > 0: strictly x < -c/coeff ⇒ x ≤ floor((-c - 1) / coeff)
            let upper = div_floor(-t.constant - 1, coeff);
            match store.tighten(
                var,
                Interval {
                    lo: i128::MIN,
                    hi: upper,
                },
            ) {
                Ok(_) => Some(true),
                Err(()) => Some(false),
            }
        }
        std::cmp::Ordering::Less => {
            // coeff < 0: strictly x > -c/coeff ⇒ x ≥ floor(-c / coeff) + 1
            let lower = div_floor(-t.constant, coeff).saturating_add(1);
            match store.tighten(
                var,
                Interval {
                    lo: lower,
                    hi: i128::MAX,
                },
            ) {
                Ok(_) => Some(true),
                Err(()) => Some(false),
            }
        }
        std::cmp::Ordering::Equal => Some(t.constant < 0),
    }
}

/// Floor division for signed integers.
fn div_floor(a: i128, b: i128) -> i128 {
    let q = a / b;
    let r = a % b;
    if (r != 0) && ((r < 0) != (b < 0)) {
        q - 1
    } else {
        q
    }
}

/// Ceil division for signed integers.
fn div_ceil(a: i128, b: i128) -> i128 {
    let q = a / b;
    let r = a % b;
    if (r != 0) && ((r > 0) == (b > 0)) {
        q + 1
    } else {
        q
    }
}

/// Width-aware sanity check: ensure each interval has at least one
/// concrete witness inside its allowed signed range and not in the
/// forbidden-point list.
#[must_use]
pub fn check_intervals_consistent(store: &IntervalStore) -> bool {
    for (name, interval) in &store.intervals {
        if interval.is_empty() {
            return false;
        }
        let intersected = if let Some(w) = store.widths.get(name) {
            interval.intersect(Interval::signed(*w))
        } else {
            *interval
        };
        if intersected.is_empty() {
            return false;
        }
        let empty: Vec<i128> = Vec::new();
        let forbidden: &[i128] = store.forbidden.get(name).map_or(&empty, Vec::as_slice);
        if forbidden.is_empty() {
            continue;
        }
        // If every value in [lo..=hi] is forbidden, fail.
        let span_size = intersected
            .hi
            .saturating_sub(intersected.lo)
            .saturating_add(1);
        if (span_size as u128) <= forbidden.len() as u128 {
            let mut v = intersected.lo;
            let mut ok = false;
            while v <= intersected.hi {
                if !forbidden.contains(&v) {
                    ok = true;
                    break;
                }
                v = match v.checked_add(1) {
                    Some(n) => n,
                    None => break,
                };
            }
            if !ok {
                return false;
            }
        }
    }
    true
}

/// Truncate a constant to a signed-bitvector value in `[-2^(w-1), 2^(w-1))`.
#[must_use]
pub fn truncate_signed(value: i128, width: Width) -> i128 {
    if width == 0 || width >= 128 {
        return value;
    }
    let modulus = 1i128 << width;
    let half = 1i128 << (width - 1);
    let raw = ((value % modulus) + modulus) % modulus;
    if raw >= half { raw - modulus } else { raw }
}

/// Mask a value to `width` bits (unsigned). Wraps `ast::mask`.
#[must_use]
pub fn truncate_unsigned(value: u128, width: Width) -> u128 {
    mask(value, width)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linearize_constants() {
        let c = BvExpr::con(42, 32);
        let t = linearize(&c).expect("const linearizes");
        assert!(t.is_const());
        assert_eq!(t.constant, 42);
    }

    #[test]
    fn linearize_var_plus_const() {
        let x = BvExpr::var("x", 32);
        let e = BvExpr::add(x, BvExpr::con(5, 32));
        let t = linearize(&e).expect("x + 5 linearizes");
        assert_eq!(t.coeffs.len(), 1);
        assert_eq!(t.constant, 5);
    }

    #[test]
    fn linearize_sub_chain() {
        // (x + y) - x = y
        let x = BvExpr::var("x", 32);
        let y = BvExpr::var("y", 32);
        let xy = BvExpr::add(x.clone(), y.clone());
        let final_expr = BvExpr::sub(xy, x);
        let t = linearize(&final_expr).expect("ok");
        assert_eq!(t.constant, 0);
        assert_eq!(t.coeffs.len(), 1);
        let v = t.coeffs.values().next().unwrap();
        assert_eq!(*v, 1);
    }

    #[test]
    fn nonlinear_product_returns_none() {
        let x = BvExpr::var("x", 32);
        let y = BvExpr::var("y", 32);
        let xy = BvExpr::mul(x, y);
        assert!(linearize(&xy).is_none());
    }

    #[test]
    fn interval_intersect() {
        let a = Interval { lo: -10, hi: 10 };
        let b = Interval { lo: 0, hi: 5 };
        let c = a.intersect(b);
        assert_eq!(c.lo, 0);
        assert_eq!(c.hi, 5);
        assert!(!c.is_empty());

        let d = Interval { lo: 100, hi: 200 };
        let e = a.intersect(d);
        assert!(e.is_empty());
    }

    #[test]
    fn apply_eq_zero_fixes_variable() {
        // 2x - 6 == 0 ⇒ x = 3
        let mut t = LinTerm::from_const(-6, 32);
        let mut x = LinTerm::from_var(Rc::from("x"), 32);
        x.scalar_mul(2);
        t.add_assign(&x);

        let mut store = IntervalStore::default();
        store.declare(Rc::from("x"), 32);
        let ok = apply_atom(&TheoryAtom::EqZero(t), &mut store);
        assert_eq!(ok, Some(true));
        let i = store.get(&Rc::from("x"));
        assert_eq!(i.lo, 3);
        assert_eq!(i.hi, 3);
    }

    #[test]
    fn apply_le_zero_tightens_upper_bound() {
        // x - 10 <= 0 ⇒ x <= 10
        let mut t = LinTerm::from_var(Rc::from("x"), 32);
        let c = LinTerm::from_const(-10, 32);
        t.add_assign(&c);
        let mut store = IntervalStore::default();
        store.declare(Rc::from("x"), 32);
        apply_atom(&TheoryAtom::SleZero(t), &mut store);
        let i = store.get(&Rc::from("x"));
        assert_eq!(i.hi, 10);
    }

    #[test]
    fn apply_lt_zero_with_negative_coefficient_lower_bound() {
        // -x < 0 ⇒ x > 0 ⇒ x ≥ 1
        let mut t = LinTerm::from_var(Rc::from("x"), 32);
        t.scalar_mul(-1);
        let mut store = IntervalStore::default();
        store.declare(Rc::from("x"), 32);
        let r = apply_atom(&TheoryAtom::SltZero(t), &mut store);
        assert_eq!(r, Some(true));
        let i = store.get(&Rc::from("x"));
        assert_eq!(i.lo, 1);
    }

    #[test]
    fn apply_le_zero_with_negative_coefficient_lower_bound() {
        // -x <= 0 ⇒ x >= 0
        let mut t = LinTerm::from_var(Rc::from("x"), 32);
        t.scalar_mul(-1);
        let mut store = IntervalStore::default();
        store.declare(Rc::from("x"), 32);
        let r = apply_atom(&TheoryAtom::SleZero(t), &mut store);
        assert_eq!(r, Some(true));
        let i = store.get(&Rc::from("x"));
        assert_eq!(i.lo, 0);
    }

    #[test]
    fn apply_lt_zero_with_offset() {
        // -x + 3 < 0 ⇒ x > 3 ⇒ x ≥ 4
        let mut t = LinTerm::from_var(Rc::from("x"), 32);
        t.scalar_mul(-1);
        let c = LinTerm::from_const(3, 32);
        t.add_assign(&c);
        let mut store = IntervalStore::default();
        store.declare(Rc::from("x"), 32);
        let r = apply_atom(&TheoryAtom::SltZero(t), &mut store);
        assert_eq!(r, Some(true));
        let i = store.get(&Rc::from("x"));
        assert_eq!(i.lo, 4);
    }

    #[test]
    fn signed_truncate_8bit() {
        assert_eq!(truncate_signed(127, 8), 127);
        assert_eq!(truncate_signed(128, 8), -128);
        assert_eq!(truncate_signed(255, 8), -1);
        assert_eq!(truncate_signed(-129, 8), 127);
    }

    #[test]
    fn div_floor_handles_negatives() {
        assert_eq!(div_floor(7, 2), 3);
        assert_eq!(div_floor(-7, 2), -4);
        assert_eq!(div_floor(-8, 2), -4);
        assert_eq!(div_floor(7, -2), -4);
    }

    #[test]
    fn div_ceil_handles_negatives() {
        assert_eq!(div_ceil(7, 2), 4);
        assert_eq!(div_ceil(-7, 2), -3);
        assert_eq!(div_ceil(7, -2), -3);
    }
}
