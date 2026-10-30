//! Top-level SMT solver.
//!
//! The solver glues together:
//!
//! - the AST (`BvExpr` / `BoolExpr`),
//! - the linear-arithmetic propagator (`crate::propagator`), and
//! - a DPLL SAT engine (`crate::sat`)
//!
//! into a usable `assert + check` API. It is deliberately small (~500 LOC):
//! the goal is to handle the constraint shapes produced by symbolic
//! execution of disassembled native code, not to be a general SMT
//! competitor.

use std::rc::Rc;

use omnisec_json::ToJson;
use std::collections::HashMap as FxHashMap;

use crate::ast::{BoolExpr, BoolOp, BvExpr, Width};
use crate::model::Model;
use crate::propagator::{
    IntervalStore, TheoryAtom, apply_atom, check_intervals_consistent, reduce_atom,
};
use crate::sat::{Lit, SatSolver, Value, Var};

/// Why the solver returned `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq, ToJson)]
#[json(rename_all = "snake_case")]
pub enum UnknownReason {
    /// Constraints contain non-linear operations the propagator can't handle.
    NonLinear,
    /// Constraints contain opaque (bit-blasted-only) terms.
    OpaqueTerm,
    /// The SAT engine hit `max_decisions` without resolving.
    DecisionBudget,
}

/// Result of [`Solver::check`].
#[derive(Debug, Clone)]
pub enum SolveResult {
    /// Satisfiable, with a concrete model.
    Sat(Model),
    /// Unsatisfiable.
    Unsat,
    /// Unable to determine.
    Unknown(UnknownReason),
}

impl SolveResult {
    /// `true` iff `Sat`.
    #[must_use]
    pub const fn is_sat(&self) -> bool {
        matches!(self, Self::Sat(_))
    }

    /// `true` iff `Unsat`.
    #[must_use]
    pub const fn is_unsat(&self) -> bool {
        matches!(self, Self::Unsat)
    }

    /// `true` iff `Unknown`.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }
}

/// Solver configuration knobs.
#[derive(Debug, Clone)]
pub struct SolverConfig {
    /// Maximum SAT decisions before giving up.
    pub max_decisions: u64,
    /// Maximum theory-propagation iterations before giving up.
    pub max_propagations: u64,
    /// Maximum recursion depth during CNF translation.
    pub max_cnf_depth: u32,
}

impl Default for SolverConfig {
    fn default() -> Self {
        Self {
            max_decisions: 10_000,
            max_propagations: 50_000,
            max_cnf_depth: 32,
        }
    }
}

/// The SMT solver.
pub struct Solver {
    config: SolverConfig,
    sat: SatSolver,
    /// Atom interning: each unique [`TheoryAtom`] gets a SAT variable.
    atom_to_var: Vec<(TheoryAtom, Var)>,
    /// Tracks all asserted top-level boolean formulas.
    assertions: Vec<Rc<BoolExpr>>,
    /// Declared bitvector vars (name → width).
    declared: FxHashMap<Rc<str>, Width>,
    /// A SAT variable that is always True.
    true_var: Var,
}

impl Default for Solver {
    fn default() -> Self {
        Self::new()
    }
}

impl Solver {
    /// New solver with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(SolverConfig::default())
    }

    /// New solver with explicit config.
    #[must_use]
    pub fn with_config(config: SolverConfig) -> Self {
        let mut sat = SatSolver::new();
        let true_var = sat.new_var();
        sat.add_clause([Lit::pos(true_var)]);
        Self {
            config,
            sat,
            atom_to_var: Vec::new(),
            assertions: Vec::new(),
            declared: FxHashMap::default(),
            true_var,
        }
    }

    /// Declare a fresh bitvector variable and return it as an expression.
    ///
    /// Re-declaring the same name with the same width is idempotent.
    pub fn fresh_bv(&mut self, name: &str, width: Width) -> Rc<BvExpr> {
        let key: Rc<str> = Rc::from(name);
        self.declared.insert(key.clone(), width);
        BvExpr::var(name, width)
    }

    /// Assert a boolean formula.
    pub fn assert(&mut self, expr: Rc<BoolExpr>) {
        self.collect_declared(&expr);
        self.assertions.push(expr);
    }

    /// Walk an expression, recording every variable's width.
    fn collect_declared(&mut self, expr: &BoolExpr) {
        match expr {
            BoolExpr::True | BoolExpr::False => {}
            BoolExpr::Atom { lhs, rhs, .. } => {
                self.collect_bv(lhs);
                self.collect_bv(rhs);
            }
            BoolExpr::Connective { args, .. } => {
                for a in args {
                    self.collect_declared(a);
                }
            }
        }
    }

    fn collect_bv(&mut self, expr: &BvExpr) {
        match expr {
            BvExpr::Const { .. } => {}
            BvExpr::Var { name, width } => {
                self.declared.insert(name.clone(), *width);
            }
            BvExpr::Op { args, .. } => {
                for a in args {
                    self.collect_bv(a);
                }
            }
            BvExpr::Ite {
                cond,
                then_branch,
                else_branch,
                ..
            } => {
                self.collect_declared(cond);
                self.collect_bv(then_branch);
                self.collect_bv(else_branch);
            }
        }
    }

    /// Run the decision procedure.
    pub fn check(&mut self) -> SolveResult {
        // 1. Lower every assertion into CNF over (theory atoms + opaque bools).
        let _clauses: Vec<Vec<Lit>> = Vec::new();
        let had_unknown_reason: Option<UnknownReason> = None;
        let assertions = self.assertions.clone();
        for assertion in &assertions {
            if let Some(l) = self.tseitin(assertion, 0) {
                self.sat.add_clause([l]);
            } else {
                return SolveResult::Unknown(UnknownReason::OpaqueTerm);
            }
        }

        if !self.sat.solve(self.config.max_decisions) {
            // SAT couldn't satisfy the boolean structure under any
            // *atom-as-Boolean* assignment ⇒ UNSAT regardless of theory.
            if had_unknown_reason.is_some() {
                return SolveResult::Unknown(UnknownReason::DecisionBudget);
            }
            return SolveResult::Unsat;
        }

        // 2. Read out which atoms the SAT solver chose to make true; ask
        //    the theory to find a model consistent with that selection.
        let mut store = IntervalStore::default();
        for (name, width) in &self.declared {
            store.declare(name.clone(), *width);
        }

        let mut had_opaque = had_unknown_reason.is_some();

        for (atom, var) in &self.atom_to_var {
            let val = self.sat.value(*var);
            let activated_atom = match val {
                Value::True => atom.clone(),
                Value::False => negate_atom(atom),
                Value::Unassigned => continue,
            };
            match apply_atom(&activated_atom, &mut store) {
                Some(true) => {}
                Some(false) => return SolveResult::Unsat,
                None => {
                    had_opaque = true;
                }
            }
        }

        // 3. Iterate propagation until stable or budget exhausted.
        let mut iters = 0;
        loop {
            iters += 1;
            if iters >= self.config.max_propagations {
                return SolveResult::Unknown(UnknownReason::DecisionBudget);
            }
            if !check_intervals_consistent(&store) {
                return SolveResult::Unsat;
            }
            // Reapply atoms now that intervals have changed.
            let mut changed = false;
            for (atom, var) in &self.atom_to_var {
                let val = self.sat.value(*var);
                let activated_atom = match val {
                    Value::True => atom.clone(),
                    Value::False => negate_atom(atom),
                    Value::Unassigned => continue,
                };
                let snapshot = store.intervals.clone();
                match apply_atom(&activated_atom, &mut store) {
                    Some(true) => {
                        if snapshot != store.intervals {
                            changed = true;
                        }
                    }
                    Some(false) => return SolveResult::Unsat,
                    None => {}
                }
            }
            if !changed {
                break;
            }
        }

        if had_opaque {
            return SolveResult::Unknown(UnknownReason::OpaqueTerm);
        }

        let mut model = Model::from_store(&store);
        for (name, w) in &self.declared {
            model.declare(name.clone(), *w);
        }
        SolveResult::Sat(model)
    }

    /// Intern an atom — give it a SAT variable.
    fn intern_atom(&mut self, atom: &TheoryAtom) -> Var {
        // We can't `Hash` TheoryAtom (LinTerm contains FxHashMap), so do
        // linear lookup. For the formula sizes we see this is fine.
        if let Some((_, v)) = self
            .atom_to_var
            .iter()
            .find(|(existing, _)| atoms_equal(existing, atom))
        {
            return *v;
        }
        let v = self.sat.new_var();
        self.atom_to_var.push((atom.clone(), v));
        v
    }

    /// Translate a `BoolExpr` into a representative SAT literal using Tseitin encoding.
    /// Returns `None` if the formula is too deep.
    fn tseitin(&mut self, expr: &BoolExpr, depth: u32) -> Option<Lit> {
        if depth >= self.config.max_cnf_depth {
            return None;
        }
        match expr {
            BoolExpr::True => Some(Lit::pos(self.true_var)),
            BoolExpr::False => Some(Lit::neg(self.true_var)),
            BoolExpr::Atom { .. } => {
                let atom = reduce_atom(expr);
                if matches!(atom, TheoryAtom::Opaque) {
                    Some(Lit::pos(self.sat.new_var()))
                } else {
                    Some(Lit::pos(self.intern_atom(&atom)))
                }
            }
            BoolExpr::Connective { op, args } => match op {
                BoolOp::Not => {
                    let l = self.tseitin(&args[0], depth + 1)?;
                    Some(l.negate())
                }
                BoolOp::And => {
                    let res = self.sat.new_var();
                    let l_res = Lit::pos(res);
                    let mut children = Vec::new();
                    for a in args {
                        let l = self.tseitin(a, depth + 1)?;
                        children.push(l);
                        // res -> l  (¬res ∨ l)
                        self.sat.add_clause([l_res.negate(), l]);
                    }
                    // (l1 ∧ l2 ∧ ... ∧ ln) -> res  (¬l1 ∨ ¬l2 ∨ ... ∨ ¬ln ∨ res)
                    let mut big_clause: Vec<Lit> = children.iter().map(|l| l.negate()).collect();
                    big_clause.push(l_res);
                    self.sat.add_clause(big_clause);
                    Some(l_res)
                }
                BoolOp::Or => {
                    let res = self.sat.new_var();
                    let l_res = Lit::pos(res);
                    let mut children = Vec::new();
                    for a in args {
                        let l = self.tseitin(a, depth + 1)?;
                        children.push(l);
                        // l -> res  (¬l ∨ res)
                        self.sat.add_clause([l.negate(), l_res]);
                    }
                    // res -> (l1 ∨ l2 ∨ ... ∨ ln)  (¬res ∨ l1 ∨ l2 ∨ ... ∨ ln)
                    let mut big_clause = children;
                    big_clause.push(l_res.negate());
                    self.sat.add_clause(big_clause);
                    Some(l_res)
                }
                BoolOp::Implies => {
                    // a -> b  ≡  (¬a ∨ b)
                    let la = self.tseitin(&args[0], depth + 1)?;
                    let lb = self.tseitin(&args[1], depth + 1)?;
                    let res = self.sat.new_var();
                    let l_res = Lit::pos(res);
                    // (a -> b) -> res  ≡  ¬(¬a ∨ b) ∨ res  ≡  (a ∧ ¬b) ∨ res  ≡  (a ∨ res) ∧ (¬b ∨ res)
                    self.sat.add_clause([la, l_res]);
                    self.sat.add_clause([lb.negate(), l_res]);
                    // res -> (a -> b)  ≡  ¬res ∨ ¬a ∨ b
                    self.sat.add_clause([l_res.negate(), la.negate(), lb]);
                    Some(l_res)
                }
                BoolOp::Iff => {
                    let la = self.tseitin(&args[0], depth + 1)?;
                    let lb = self.tseitin(&args[1], depth + 1)?;
                    let res = self.sat.new_var();
                    let l_res = Lit::pos(res);
                    // res <-> (la <-> lb)
                    // res -> (la <-> lb)  ≡  (¬res ∨ ¬la ∨ lb) ∧ (¬res ∨ ¬lb ∨ la)
                    self.sat.add_clause([l_res.negate(), la.negate(), lb]);
                    self.sat.add_clause([l_res.negate(), lb.negate(), la]);
                    // (la <-> lb) -> res  ≡  ((la ∧ lb) ∨ (¬la ∧ ¬lb)) -> res
                    // ≡  (¬la ∨ ¬lb ∨ res) ∧ (la ∨ lb ∨ res)
                    self.sat.add_clause([la.negate(), lb.negate(), l_res]);
                    self.sat.add_clause([la, lb, l_res]);
                    Some(l_res)
                }
                _ => None,
            },
        }
    }
}

/// Logically negate a `TheoryAtom`.
fn negate_atom(atom: &TheoryAtom) -> TheoryAtom {
    match atom {
        TheoryAtom::EqZero(t) => TheoryAtom::NeZero(t.clone()),
        TheoryAtom::NeZero(t) => TheoryAtom::EqZero(t.clone()),
        TheoryAtom::SleZero(t) => {
            // ¬(t ≤ 0) ⇔ t > 0 ⇔ −t < 0
            let mut t = t.clone();
            t.scalar_mul(-1);
            TheoryAtom::SltZero(t)
        }
        TheoryAtom::SltZero(t) => {
            let mut t = t.clone();
            t.scalar_mul(-1);
            TheoryAtom::SleZero(t)
        }
        TheoryAtom::UleZero(t) => {
            let mut t = t.clone();
            t.scalar_mul(-1);
            TheoryAtom::UltZero(t)
        }
        TheoryAtom::UltZero(t) => {
            let mut t = t.clone();
            t.scalar_mul(-1);
            TheoryAtom::UleZero(t)
        }
        TheoryAtom::Opaque => TheoryAtom::Opaque,
    }
}

/// Structural equality for `TheoryAtom`. Used for atom interning.
fn atoms_equal(a: &TheoryAtom, b: &TheoryAtom) -> bool {
    match (a, b) {
        (TheoryAtom::EqZero(x), TheoryAtom::EqZero(y))
        | (TheoryAtom::NeZero(x), TheoryAtom::NeZero(y))
        | (TheoryAtom::SleZero(x), TheoryAtom::SleZero(y))
        | (TheoryAtom::SltZero(x), TheoryAtom::SltZero(y))
        | (TheoryAtom::UleZero(x), TheoryAtom::UleZero(y))
        | (TheoryAtom::UltZero(x), TheoryAtom::UltZero(y)) => lin_eq(x, y),
        (TheoryAtom::Opaque, TheoryAtom::Opaque) => false, // each opaque atom unique
        _ => false,
    }
}

fn lin_eq(a: &crate::propagator::LinTerm, b: &crate::propagator::LinTerm) -> bool {
    a.constant == b.constant && a.coeffs == b.coeffs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_eq_is_sat() {
        let mut s = Solver::new();
        let x = s.fresh_bv("x", 32);
        let c = BvExpr::con(5, 32);
        s.assert(BoolExpr::eq(x, c));
        match s.check() {
            SolveResult::Sat(m) => assert_eq!(m.eval_i64("x"), Some(5)),
            other => panic!("expected SAT, got {:?}", other),
        }
    }

    #[test]
    fn conflicting_eqs_is_unsat() {
        let mut s = Solver::new();
        let x = s.fresh_bv("x", 32);
        s.assert(BoolExpr::eq(x.clone(), BvExpr::con(5, 32)));
        s.assert(BoolExpr::eq(x, BvExpr::con(7, 32)));
        let result = s.check();
        assert!(matches!(result, SolveResult::Unsat));
    }

    #[test]
    fn bound_constraint_is_sat() {
        let mut s = Solver::new();
        let x = s.fresh_bv("x", 32);
        // x >= 0 ∧ x < 10
        s.assert(BoolExpr::sge(x.clone(), BvExpr::con(0, 32)));
        s.assert(BoolExpr::slt(x, BvExpr::con(10, 32)));
        match s.check() {
            SolveResult::Sat(m) => {
                let v = m.eval_i64("x").expect("x bound");
                assert!((0..10).contains(&v), "x = {v}");
            }
            other => panic!("expected SAT, got {other:?}"),
        }
    }

    #[test]
    fn negated_atom_is_handled() {
        let mut s = Solver::new();
        let x = s.fresh_bv("x", 32);
        // NOT (x == 7) ⇒ x != 7 ⇒ SAT
        s.assert(BoolExpr::not(BoolExpr::eq(x.clone(), BvExpr::con(7, 32))));
        s.assert(BoolExpr::sle(x.clone(), BvExpr::con(7, 32)));
        s.assert(BoolExpr::sge(x.clone(), BvExpr::con(0, 32)));
        let r = s.check();
        assert!(r.is_sat(), "{r:?}");
    }

    #[test]
    fn unsigned_range_constraint() {
        let mut s = Solver::new();
        let x = s.fresh_bv("x", 16);
        s.assert(BoolExpr::ule(x.clone(), BvExpr::con(100, 16)));
        s.assert(BoolExpr::sge(x.clone(), BvExpr::con(50, 16)));
        match s.check() {
            SolveResult::Sat(m) => {
                let v = m.eval_i64("x").expect("x");
                assert!((50..=100).contains(&v), "x = {v}");
            }
            other => panic!("expected SAT, got {other:?}"),
        }
    }

    #[test]
    fn multi_var_addition_is_unknown_or_sat() {
        // We don't implement Gauss-Jordan multi-var equality yet, but the
        // solver should at least not crash on it. Expected: Unknown.
        let mut s = Solver::new();
        let x = s.fresh_bv("x", 32);
        let y = s.fresh_bv("y", 32);
        s.assert(BoolExpr::eq(
            BvExpr::add(x.clone(), y.clone()),
            BvExpr::con(10, 32),
        ));
        let r = s.check();
        assert!(r.is_sat() || r.is_unknown(), "{r:?}");
    }
}
