//! Minimal DPLL SAT engine — used by the SMT layer to handle the boolean
//! structure of assertions.
//!
//! Variables are u32, literals are `Lit(2 * var | pol)` (LSB = sign), clauses
//! are slabs of literals. Unit propagation walks the clauses directly — we
//! deliberately skip watched-literal bookkeeping because the formulas the
//! symbolic executor produces are small (< 10k clauses, < 1k vars).
//!
//! The solver returns:
//! - `Some(assignment)` — a satisfying assignment if SAT,
//! - `None`             — UNSAT.
//!
//! No timeouts; the caller should bound the call externally (see
//! [`SolverConfig::max_decisions`](crate::SolverConfig)).

/// A propositional variable identifier.
pub type Var = u32;

/// A literal — packs `(var, sign)` into a single `u32`.
///
/// Bit 0 = sign (0 ⇒ positive, 1 ⇒ negative), bits 1..32 = variable id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Lit(u32);

impl Lit {
    /// Build a positive literal `+v`.
    #[must_use]
    pub const fn pos(v: Var) -> Self {
        Self(v << 1)
    }

    /// Build a negative literal `-v`.
    #[must_use]
    pub const fn neg(v: Var) -> Self {
        Self((v << 1) | 1)
    }

    /// Build a literal from `(var, sign)`.
    #[must_use]
    pub const fn from(v: Var, sign: bool) -> Self {
        if sign { Self::neg(v) } else { Self::pos(v) }
    }

    /// The variable referenced by this literal.
    #[must_use]
    pub const fn var(self) -> Var {
        self.0 >> 1
    }

    /// `true` if this literal is negated.
    #[must_use]
    pub const fn is_neg(self) -> bool {
        (self.0 & 1) == 1
    }

    /// Logical negation: `+x ↔ -x`.
    #[must_use]
    pub const fn negate(self) -> Self {
        Self(self.0 ^ 1)
    }
}

/// A clause is a disjunction of literals.
pub type Clause = Vec<Lit>;

/// The truth value of a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// `true`.
    True,
    /// `false`.
    False,
    /// Currently unassigned.
    Unassigned,
}

impl Value {
    /// True iff this matches `+lit` (i.e. the literal evaluates to `true`).
    fn satisfies(self, lit: Lit) -> bool {
        matches!(
            (self, lit.is_neg()),
            (Self::True, false) | (Self::False, true)
        )
    }
}

/// Minimal DPLL SAT solver.
#[derive(Debug, Default)]
pub struct SatSolver {
    /// All clauses.
    clauses: Vec<Clause>,
    /// Per-variable assignment.
    pub(crate) assignment: Vec<Value>,
    /// Assignment trail (decisions + propagations, ordered).
    trail: Vec<Lit>,
    /// Trail position at which each decision level started.
    level_starts: Vec<usize>,
    /// Decisions made so far (≥ propagations).
    decisions: u64,
}

impl SatSolver {
    /// Create an empty solver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh propositional variable.
    pub fn new_var(&mut self) -> Var {
        let v = self.assignment.len() as Var;
        self.assignment.push(Value::Unassigned);
        v
    }

    /// Number of variables allocated so far.
    #[must_use]
    pub fn num_vars(&self) -> usize {
        self.assignment.len()
    }

    /// Add a clause. An empty clause makes the problem UNSAT.
    pub fn add_clause(&mut self, lits: impl IntoIterator<Item = Lit>) {
        let clause: Clause = lits.into_iter().collect();
        self.clauses.push(clause);
    }

    /// Current truth value of a variable.
    #[must_use]
    pub fn value(&self, v: Var) -> Value {
        self.assignment[v as usize]
    }

    /// Solve. Returns `true` if SAT.
    ///
    /// `max_decisions` bounds the work; if exceeded, returns `false`
    /// conservatively (the caller should treat this as `Unknown`).
    pub fn solve(&mut self, max_decisions: u64) -> bool {
        if !self.propagate() {
            return false;
        }
        loop {
            if self.decisions >= max_decisions {
                return false;
            }
            let Some(v) = self.pick_branching_var() else {
                return true; // all assigned ⇒ SAT
            };
            // Try +v first
            self.level_starts.push(self.trail.len());
            self.assign(Lit::pos(v));
            self.decisions += 1;

            if self.propagate() {
                continue;
            }

            // Backtrack: undo decision, try -v
            self.backtrack_one_level();
            self.level_starts.push(self.trail.len());
            self.assign(Lit::neg(v));

            if self.propagate() {
                continue;
            }

            // Both branches failed → backjump
            self.backtrack_one_level();
            if !self.backjump_to_open_decision() {
                return false; // exhausted search
            }
        }
    }

    /// Pick the first unassigned variable (deterministic — good enough
    /// for the small formulas we see).
    fn pick_branching_var(&self) -> Option<Var> {
        self.assignment
            .iter()
            .enumerate()
            .find_map(|(i, v)| (*v == Value::Unassigned).then_some(i as Var))
    }

    /// Assign a literal and push it on the trail.
    fn assign(&mut self, lit: Lit) {
        let val = if lit.is_neg() {
            Value::False
        } else {
            Value::True
        };
        self.assignment[lit.var() as usize] = val;
        self.trail.push(lit);
    }

    /// Boolean Constraint Propagation. Returns `false` on conflict.
    fn propagate(&mut self) -> bool {
        loop {
            let mut new_units: Vec<Lit> = Vec::new();
            for i in 0..self.clauses.len() {
                let status = self.classify(&self.clauses[i]);
                match status {
                    ClauseStatus::Conflict => return false,
                    ClauseStatus::Unit(lit) => {
                        // Avoid double-assigning the same var in this sweep
                        if self.assignment[lit.var() as usize] == Value::Unassigned
                            && !new_units.iter().any(|l| l.var() == lit.var())
                        {
                            new_units.push(lit);
                        }
                    }
                    ClauseStatus::Satisfied | ClauseStatus::Pending => {}
                }
            }
            if new_units.is_empty() {
                return true;
            }
            for lit in new_units {
                if self.assignment[lit.var() as usize] == Value::Unassigned {
                    self.assign(lit);
                }
            }
        }
    }

    fn classify(&self, clause: &Clause) -> ClauseStatus {
        let mut unassigned = None;
        let mut unassigned_count = 0;
        for &lit in clause {
            let val = self.assignment[lit.var() as usize];
            if val.satisfies(lit) {
                return ClauseStatus::Satisfied;
            }
            if val == Value::Unassigned {
                unassigned = Some(lit);
                unassigned_count += 1;
                if unassigned_count > 1 {
                    return ClauseStatus::Pending;
                }
            }
        }
        match unassigned_count {
            0 => ClauseStatus::Conflict,
            1 => ClauseStatus::Unit(unassigned.unwrap()),
            _ => ClauseStatus::Pending,
        }
    }

    fn backtrack_one_level(&mut self) {
        let start = self.level_starts.pop().unwrap_or(0);
        for lit in self.trail.drain(start..) {
            self.assignment[lit.var() as usize] = Value::Unassigned;
        }
    }

    /// Walk back through decision levels until we find one we tried only
    /// once. Returns `false` if no such level exists.
    fn backjump_to_open_decision(&mut self) -> bool {
        // Pure DPLL: undo one more decision level and let the outer loop
        // re-pick a variable. Returns `false` only when we've exhausted
        // every level (i.e. the problem is UNSAT).
        let Some(start) = self.level_starts.pop() else {
            return false;
        };
        for lit in self.trail.drain(start..) {
            self.assignment[lit.var() as usize] = Value::Unassigned;
        }
        true
    }

    /// All clauses in the problem.
    #[must_use]
    pub fn clauses(&self) -> &[Clause] {
        &self.clauses
    }
}

#[derive(Debug)]
enum ClauseStatus {
    Satisfied,
    Conflict,
    Unit(Lit),
    Pending,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_problem_is_sat() {
        let mut s = SatSolver::new();
        assert!(s.solve(1));
    }

    #[test]
    fn unit_clause_propagates() {
        let mut s = SatSolver::new();
        let a = s.new_var();
        s.add_clause([Lit::pos(a)]);
        assert!(s.solve(10));
        assert_eq!(s.value(a), Value::True);
    }

    #[test]
    fn detects_unsat_unit_conflict() {
        let mut s = SatSolver::new();
        let a = s.new_var();
        s.add_clause([Lit::pos(a)]);
        s.add_clause([Lit::neg(a)]);
        assert!(!s.solve(10));
    }

    #[test]
    fn pigeonhole_2_into_1_is_unsat() {
        // 2 pigeons, 1 hole: encode that two pigeons can't both be in hole h0.
        // p1_h0, p2_h0 — each pigeon must be in the hole (unit), but they
        // can't both be in it (binary clause).
        let mut s = SatSolver::new();
        let p1 = s.new_var();
        let p2 = s.new_var();
        s.add_clause([Lit::pos(p1)]); // pigeon 1 in hole 0
        s.add_clause([Lit::pos(p2)]); // pigeon 2 in hole 0
        s.add_clause([Lit::neg(p1), Lit::neg(p2)]); // not both
        assert!(!s.solve(100));
    }

    #[test]
    fn or_of_three_sat() {
        // (a ∨ b ∨ c) ∧ (¬a) ∧ (¬b)
        // → forces c = true
        let mut s = SatSolver::new();
        let a = s.new_var();
        let b = s.new_var();
        let c = s.new_var();
        s.add_clause([Lit::pos(a), Lit::pos(b), Lit::pos(c)]);
        s.add_clause([Lit::neg(a)]);
        s.add_clause([Lit::neg(b)]);
        assert!(s.solve(100));
        assert_eq!(s.value(c), Value::True);
    }

    #[test]
    fn lit_encoding_roundtrip() {
        for v in [0u32, 1, 7, 12345] {
            let p = Lit::pos(v);
            let n = Lit::neg(v);
            assert_eq!(p.var(), v);
            assert_eq!(n.var(), v);
            assert!(!p.is_neg());
            assert!(n.is_neg());
            assert_eq!(p.negate(), n);
            assert_eq!(n.negate(), p);
        }
    }
}
