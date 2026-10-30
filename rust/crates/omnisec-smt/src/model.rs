//! Solver model — the concrete value assignment that satisfies an SMT
//! formula.
//!
//! Models are sparse: only the variables that the solver had to commit
//! to are present. Unmentioned variables can take any value in their
//! declared range; the [`Model::eval`] method picks the bound corresponding
//! to the variable's lower interval bound, so the model is always
//! self-consistent.

use std::rc::Rc;

use omnisec_json::ToJson;
use std::collections::HashMap as FxHashMap;

use crate::ast::Width;
use crate::propagator::{Interval, IntervalStore};

/// A satisfying assignment.
#[derive(Debug, Clone, Default, ToJson)]
pub struct Model {
    /// `name → concrete signed value`.
    pub values: FxHashMap<String, i128>,
    /// `name → bit width`.
    pub widths: FxHashMap<String, Width>,
    /// `name → final interval` (for ranges).
    pub intervals: FxHashMap<String, (i128, i128)>,
}

impl Model {
    /// Build a model from a propagator interval store.
    ///
    /// For each bounded variable, the smallest in-range witness that is
    /// not in the variable's `forbidden` list is chosen. This gives a
    /// canonical, deterministic model that satisfies all `≠` atoms the
    /// solver registered.
    #[must_use]
    pub fn from_store(store: &IntervalStore) -> Self {
        let mut values = FxHashMap::default();
        let mut widths = FxHashMap::default();
        let mut intervals = FxHashMap::default();
        for (name, interval) in &store.intervals {
            let key = name.as_ref().to_string();
            intervals.insert(key.clone(), (interval.lo, interval.hi));
            let witness = store.witness(name).unwrap_or(interval.lo);
            values.insert(key.clone(), witness);
            if let Some(w) = store.widths.get(name) {
                widths.insert(key, *w);
            }
        }
        // Variables declared but never bounded: pick 0, unless forbidden.
        for (name, width) in &store.widths {
            let key = name.as_ref().to_string();
            let default_value = match store.forbidden.get(name) {
                Some(forbidden) if forbidden.contains(&0) => {
                    // Pick the smallest non-forbidden value ≥ 0
                    let mut candidate = 1i128;
                    while forbidden.contains(&candidate) {
                        candidate += 1;
                    }
                    candidate
                }
                _ => 0,
            };
            values.entry(key.clone()).or_insert(default_value);
            widths.entry(key.clone()).or_insert(*width);
            intervals
                .entry(key)
                .or_insert((Interval::signed(*width).lo, Interval::signed(*width).hi));
        }
        Self {
            values,
            widths,
            intervals,
        }
    }

    /// Evaluate a variable as `i64`. Returns `None` if the value won't fit.
    #[must_use]
    pub fn eval_i64(&self, name: &str) -> Option<i64> {
        let v = self.values.get(name).copied()?;
        i64::try_from(v).ok()
    }

    /// Evaluate a variable as `u64` (modular). Returns `None` for missing vars.
    #[must_use]
    pub fn eval_u64(&self, name: &str) -> Option<u64> {
        let v = self.values.get(name).copied()?;
        let w = self.widths.get(name).copied().unwrap_or(64);
        let modulus = if w >= 64 {
            u64::MAX as u128 + 1
        } else {
            1u128 << w
        };
        let raw = ((v % modulus as i128) + modulus as i128) % modulus as i128;
        Some(raw as u64)
    }

    /// Read a variable's `(lo, hi)` interval. Defaults to (0, 0) when absent.
    #[must_use]
    pub fn range(&self, name: &str) -> (i128, i128) {
        self.intervals.get(name).copied().unwrap_or((0, 0))
    }

    /// Register an explicit value (e.g. when concolic seed wiring inserts
    /// a hand-picked variable into the model).
    pub fn insert(&mut self, name: impl Into<String>, value: i128, width: Width) {
        let key = name.into();
        self.values.insert(key.clone(), value);
        self.widths.insert(key.clone(), width);
        self.intervals.insert(key, (value, value));
    }

    /// Number of bound variables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// `true` if no variables bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Internal — used by [`Solver`](crate::solver::Solver) when finalising.
    pub(crate) fn declare(&mut self, name: Rc<str>, width: Width) {
        self.widths.insert(name.as_ref().to_string(), width);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::propagator::IntervalStore;
    use std::rc::Rc;

    #[test]
    fn model_picks_lower_bound() {
        let mut s = IntervalStore::default();
        s.declare(Rc::from("x"), 32);
        let _ = s.tighten(&Rc::from("x"), Interval { lo: 7, hi: 100 });
        let m = Model::from_store(&s);
        assert_eq!(m.eval_i64("x"), Some(7));
    }

    #[test]
    fn eval_u64_handles_negative_signed() {
        let mut m = Model::default();
        m.insert("x", -1, 8); // 0xFF as u8
        assert_eq!(m.eval_u64("x"), Some(0xFF));
    }
}
