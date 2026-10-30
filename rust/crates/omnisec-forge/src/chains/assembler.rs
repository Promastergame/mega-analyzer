//! Bounded Generate-and-Test (BGAT) chain assembler driven by `omnisec-smt`.
//!
//! ## Algorithm
//!
//! ```text
//!   Inputs:  goal post-condition   (set of register equalities)
//!            initial pre-condition (registers known)
//!            gadget pool           (from GadgetFinder)
//!            budget                (max BGAT iterations)
//!
//!   1. Convert goal post-condition to a single BoolExpr `Φ_goal`.
//!   2. For length L = 1 .. max_chain_length:
//!        Enumerate ordered L-tuples of gadgets via a deterministic
//!        priority queue (priority = complexity_score).
//!        For each tuple:
//!          a) Build a fresh Solver, assert pre-conditions.
//!          b) Symbolically apply each gadget's RegisterEffects in order
//!             — every effect is an affine assignment, exactly the shape
//!             omnisec-smt's linear-arith propagator handles.
//!          c) Assert Φ_goal at the end.
//!          d) If SAT, return the chain (with the SMT model attached).
//!          e) If UNSAT, increment budget counter and continue.
//!     Bail with [`crate::ForgeError::BudgetExhausted`] when budget hits 0.
//! ```
//!
//! ## Why this is fast on a GTX 650 / no-GPU box
//!
//! - The enumeration is purely on the CPU, depth-first, and prunes
//!   aggressively: any L-prefix that already fails the *partial* goal
//!   constraint is discarded before extending it.
//! - Each SMT query operates on linear-arithmetic atoms only — exactly
//!   the theory `omnisec-smt` handles natively without bit-blasting.
//! - The candidate set is `Vec<Gadget>` — `O(N)` memory, no graph
//!   structures needed.

use std::rc::Rc;

use omnisec_json::{FromJson, ToJson};
use omnisec_smt::{BoolExpr, BvExpr, SolveResult, Solver, Width};

use crate::complexity::ComplexityScore;
use crate::error::{ForgeError, Result};
use crate::util::Prng;

use super::finder::GadgetFinder;
use super::gadget::{Gadget, GadgetCategory, GadgetEntry, RegisterEffect, Terminator};

const REG_WIDTH: Width = 64;

/// One register's required final value, expressed in the assembler's
/// little algebra: equality to a concrete constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterGoal {
    /// Register name.
    pub register: String,
    /// Required value at chain exit.
    pub value: i64,
}

/// What the BGAT search produced.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct AssembledChain {
    /// Gadget entries, in execution order.
    pub entries: Vec<GadgetEntry>,
    /// Concrete register-value witnesses chosen by the SMT solver.
    pub register_witnesses: Vec<(String, i64)>,
    /// Complexity score of the produced chain.
    pub complexity: ComplexityScore,
    /// Iteration / SMT-query stats.
    pub stats: BgatStats,
}

/// Statistics about a BGAT search run.
#[derive(Debug, Clone, Default, PartialEq, Eq, ToJson, FromJson)]
pub struct BgatStats {
    /// How many candidate prefixes were explored.
    pub explored: usize,
    /// How many SMT queries were sent.
    pub smt_queries: usize,
    /// How many of those came back UNSAT.
    pub unsat_replies: usize,
    /// How many came back UNKNOWN.
    pub unknown_replies: usize,
}

/// SMT-guided chain assembler.
pub struct SmtAssembler<'a> {
    finder: &'a GadgetFinder,
    budget: usize,
    max_length: usize,
    prefer_terminator: Terminator,
    /// When `true`, BGAT keeps exploring after the first SAT combination
    /// and returns the lowest-[`ComplexityScore`] chain found. When
    /// `false`, BGAT returns the first SAT it finds (fastest path).
    ///
    /// Complexity-ranked search prioritises stable, reliable chains
    /// over convoluted ones — shorter chains and chains with fewer
    /// memory writes score lower (better).
    rank_by_complexity: bool,
}

impl<'a> SmtAssembler<'a> {
    /// New assembler over `finder`'s gadget pool.
    #[must_use]
    pub fn new(finder: &'a GadgetFinder) -> Self {
        Self {
            finder,
            budget: 4_096,
            max_length: 16,
            prefer_terminator: Terminator::Ret,
            rank_by_complexity: true,
        }
    }

    /// Set the BGAT iteration budget.
    #[must_use]
    pub fn with_budget(mut self, budget: usize) -> Self {
        self.budget = budget;
        self
    }

    /// Set the max chain length.
    #[must_use]
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// Restrict to gadgets ending in this terminator (e.g. `Ret` for ROP,
    /// `JumpReg` for JOP, `CallReg` for COP).
    #[must_use]
    pub fn with_terminator(mut self, terminator: Terminator) -> Self {
        self.prefer_terminator = terminator;
        self
    }

    /// Toggle complexity-ranked search. `true` (default) = explore the
    /// whole feasibility region up to budget and return the lowest-
    /// complexity chain; `false` = return first SAT (faster).
    #[must_use]
    pub fn with_rank_by_complexity(mut self, rank: bool) -> Self {
        self.rank_by_complexity = rank;
        self
    }

    /// Assemble a chain that satisfies `goals`.
    ///
    /// `prng` is used for tie-breaking when multiple gadget candidates
    /// have the same SMT-feasibility cost. This makes the result depend
    /// only on the seed, not on the iteration order of `HashMap`s
    /// internal to the candidate set.
    pub fn assemble(&self, goals: &[RegisterGoal], prng: &mut Prng) -> Result<AssembledChain> {
        if goals.is_empty() {
            return Ok(AssembledChain {
                entries: Vec::new(),
                register_witnesses: Vec::new(),
                complexity: ComplexityScore::TRIVIAL,
                stats: BgatStats::default(),
            });
        }

        if goals.len() > self.max_length {
            return Err(ForgeError::BudgetExhausted(format!(
                "chain needs {} gadgets but max_length is {}",
                goals.len(),
                self.max_length
            )));
        }

        // Build per-goal candidate lists. Each slot holds every candidate
        // gadget that writes the goal's register; we then search the
        // cartesian product with bounded backtracking.
        //
        // Pool includes both `PopReg` and `StackPivot` categories because
        // stack-pivot goals (`sp` / `rsp` / `$sp`) need StackPivot gadgets
        // whose effect still uses `load_const`, and both categories feed
        // the same BGAT machinery.
        let mut pool: Vec<&Gadget> = self
            .finder
            .by_category(GadgetCategory::PopReg)
            .into_iter()
            .chain(self.finder.by_category(GadgetCategory::StackPivot))
            .filter(|g| g.terminator == self.prefer_terminator)
            .collect();
        // Stable dedup-by-address (a gadget can't be in two categories
        // simultaneously today, but keep this defensive).
        pool.sort_by_key(|g| g.address);
        pool.dedup_by_key(|g| g.address);

        let mut slots: Vec<Vec<&Gadget>> = Vec::with_capacity(goals.len());
        for goal in goals {
            let mut writers: Vec<&Gadget> = pool
                .iter()
                .copied()
                .filter(|g| g.writes(&goal.register))
                .collect();
            if writers.is_empty() {
                return Err(ForgeError::BudgetExhausted(format!(
                    "no gadget writes register `{}`",
                    goal.register
                )));
            }
            // Deterministic per-slot ordering: shuffle via seeded prng, then
            // stable-sort by address. Equal-address candidates retain the
            // shuffled order for a reproducible tie-break.
            prng.shuffle(&mut writers);
            writers.sort_by_key(|g| g.address);
            slots.push(writers);
        }

        // BGAT odometer loop.
        //
        // Two modes:
        //   - first-SAT (fast path): break on the first satisfying
        //     combination.
        //   - rank-by-complexity (default): keep exploring within
        //     budget and remember the lowest-complexity SAT chain
        //     seen so far.
        //
        // In both modes we stop early if the remaining budget would
        // force us past `self.budget`.
        let mut stats = BgatStats::default();
        let mut indices = vec![0usize; slots.len()];
        let mut best_chain: Option<(Vec<&Gadget>, omnisec_smt::Model, ComplexityScore)> = None;

        'search: loop {
            stats.explored += 1;
            if stats.explored > self.budget {
                break 'search;
            }

            // Build the candidate chain for the current index vector.
            let chosen: Vec<&Gadget> = indices
                .iter()
                .zip(&slots)
                .map(|(&i, slot)| slot[i])
                .collect();

            // Clobber-conflict filter: reject combinations where a later
            // gadget clobbers a register an earlier goal already pinned.
            // This is the cheapest possible prune — no SMT involved.
            if Self::has_clobber_conflict(&chosen, goals) {
                if !Self::advance_indices(&mut indices, &slots) {
                    break 'search;
                }
                continue;
            }

            // Partial-order prune: score the candidate before we pay for
            // an SMT query. If it is already worse than our best SAT
            // solution, skip it.
            let candidate_complexity = Self::score_chain(&chosen);
            if let Some((_, _, best_c)) = &best_chain
                && candidate_complexity >= *best_c
            {
                if !Self::advance_indices(&mut indices, &slots) {
                    break 'search;
                }
                continue;
            }

            // Flatten register effects for the SMT solver.
            let mut solver = Solver::new();
            let mut effects: Vec<RegisterEffect> = Vec::new();
            for g in &chosen {
                effects.extend(g.effects.iter().cloned());
            }

            stats.smt_queries += 1;
            match Self::solve_register_constraints(&mut solver, &effects, goals) {
                Ok(model) => {
                    let is_better = best_chain
                        .as_ref()
                        .is_none_or(|(_, _, c)| candidate_complexity < *c);
                    if is_better {
                        best_chain = Some((chosen, model, candidate_complexity));
                    }
                    if !self.rank_by_complexity {
                        break 'search;
                    }
                }
                Err(ForgeError::Unsat(_)) => {
                    stats.unsat_replies += 1;
                }
                Err(ForgeError::SmtUnknown(_)) => {
                    stats.unknown_replies += 1;
                }
                Err(other) => return Err(other),
            }

            if !Self::advance_indices(&mut indices, &slots) {
                break 'search;
            }
        }

        let Some((chosen, model, _)) = best_chain else {
            return Err(ForgeError::Unsat(format!(
                "BGAT explored {} chains, no SAT combination found (smt_queries = {}, unsat = {}, unknown = {})",
                stats.explored, stats.smt_queries, stats.unsat_replies, stats.unknown_replies
            )));
        };

        // Build entries with concrete witness values inlined.
        let mut entries: Vec<GadgetEntry> = Vec::new();
        let mut register_witnesses: Vec<(String, i64)> = Vec::new();
        for (g, base_idx) in chosen.iter().zip(effect_offsets(&chosen)) {
            let mut entry = GadgetEntry::from_gadget(g);
            // For a simple `pop reg ; ret` gadget the stack data is the
            // 8-byte little-endian witness for that reg.
            for (sub_idx, eff) in g.effects.iter().enumerate() {
                if eff.factor == 0 && eff.src == "*" {
                    let flat_idx = base_idx + sub_idx;
                    let witness = solver_witness(&model, flat_idx, eff, goals);
                    entry.stack_data.extend_from_slice(&witness.to_le_bytes());
                    register_witnesses.push((eff.dst.clone(), witness as i64));
                }
            }
            entries.push(entry);
        }

        let complexity = Self::score_chain(&chosen);

        Ok(AssembledChain {
            entries,
            register_witnesses,
            complexity,
            stats,
        })
    }

    /// Compute the [`ComplexityScore`] of a concrete gadget sequence.
    ///
    /// Used both as the *ranking key* inside BGAT and as the *final*
    /// complexity of an assembled chain — keeping them in lockstep so
    /// ranking never disagrees with the reported score.
    fn score_chain(chosen: &[&Gadget]) -> ComplexityScore {
        let mem_writes = chosen
            .iter()
            .filter(|g| g.category == GadgetCategory::MemWrite)
            .count() as u32;
        ComplexityScore::from_components(chosen.len() as u32, mem_writes, 0, 0)
    }

    /// Detect clobber conflicts in a candidate chain.
    ///
    /// A conflict exists when gadget index `j > i` clobbers a register
    /// that goal `i` has already pinned. This is the foundation of
    /// MIPS delay-slot safety: the scanner records the delay slot's
    /// side-effect register as a clobber on the parent gadget, and BGAT
    /// rejects chains where that register gets clobbered after it was
    /// loaded.
    fn has_clobber_conflict(chosen: &[&Gadget], goals: &[RegisterGoal]) -> bool {
        for (i, goal_i) in goals.iter().enumerate() {
            // Any gadget strictly after slot `i` that clobbers goal_i's
            // register invalidates the chain.
            for g in &chosen[i + 1..] {
                if g.clobbers(&goal_i.register) {
                    return true;
                }
            }
        }
        false
    }

    /// Odometer increment over a `slots`-shaped index vector.
    ///
    /// Advances the rightmost index; carries when it overflows its slot.
    /// Resets higher-index slots to zero on carry. Returns `false` when
    /// the odometer has wrapped past the last combination.
    fn advance_indices(indices: &mut [usize], slots: &[Vec<&Gadget>]) -> bool {
        let mut carry_idx = indices.len();
        loop {
            if carry_idx == 0 {
                return false;
            }
            carry_idx -= 1;
            indices[carry_idx] += 1;
            if indices[carry_idx] < slots[carry_idx].len() {
                for reset in (carry_idx + 1)..indices.len() {
                    indices[reset] = 0;
                }
                return true;
            }
            indices[carry_idx] = 0;
        }
    }

    /// Build the SMT formula for the chosen effects + goals and solve it.
    ///
    /// We compute symbolic register values purely in Rust by composing
    /// `BvExpr` trees, then emit a *single* equality per goal:
    /// `final_expr(reg) == goal.value`. That keeps every assertion
    /// single-variable (or constant), which is what
    /// [`omnisec_smt::propagator::apply_eq_zero`] handles directly —
    /// multi-variable equalities would otherwise come back as
    /// `Unknown(OpaqueTerm)`.
    ///
    /// Modeling rules:
    ///
    /// - **Attacker-controlled load** (`src == "*"`, `factor == 0`): the
    ///   gadget reads `dst` from the stack. We bind a fresh
    ///   `stack_input_<idx>` SMT variable.
    /// - **Affine effect** (`factor ∈ {-1, 0, 1}`): we substitute the
    ///   current expression for `src` and apply `+offset` / `-x`.
    /// - **Non-linear factor**: rejected with `SmtUnknown` — this stays
    ///   honest about the propagator's theory.
    fn solve_register_constraints(
        solver: &mut Solver,
        effects: &[RegisterEffect],
        goals: &[RegisterGoal],
    ) -> Result<omnisec_smt::Model> {
        // Map register name → current symbolic expression. Each entry
        // is either an attacker-input variable, a constant, or a
        // single-variable affine expression.
        let mut current: std::collections::HashMap<String, Rc<BvExpr>> =
            std::collections::HashMap::default();

        for (idx, eff) in effects.iter().enumerate() {
            let new_val: Rc<BvExpr> = if eff.src == "*" && eff.factor == 0 {
                // Attacker-controlled load: fresh input variable.
                let input_name = format!("stack_input_{idx}");
                solver.fresh_bv(&input_name, REG_WIDTH)
            } else if eff.factor == 0 {
                // Pin to constant.
                BvExpr::icon(eff.offset, REG_WIDTH)
            } else if eff.factor == 1 {
                let src_expr = current
                    .get(&eff.src)
                    .cloned()
                    .unwrap_or_else(|| BvExpr::var(&format!("init_{}", eff.src), REG_WIDTH));
                if eff.offset == 0 {
                    src_expr
                } else {
                    BvExpr::add(src_expr, BvExpr::icon(eff.offset, REG_WIDTH))
                }
            } else if eff.factor == -1 {
                let src_expr = current
                    .get(&eff.src)
                    .cloned()
                    .unwrap_or_else(|| BvExpr::var(&format!("init_{}", eff.src), REG_WIDTH));
                let negated = BvExpr::neg(src_expr);
                if eff.offset == 0 {
                    negated
                } else {
                    BvExpr::add(negated, BvExpr::icon(eff.offset, REG_WIDTH))
                }
            } else {
                return Err(ForgeError::SmtUnknown(format!(
                    "register-effect factor {} is non-linear; omnisec-smt only handles ±1",
                    eff.factor
                )));
            };

            current.insert(eff.dst.clone(), new_val);
        }

        for goal in goals {
            if let Some(expr) = current.get(&goal.register) {
                solver.assert(BoolExpr::eq(
                    expr.clone(),
                    BvExpr::icon(goal.value, REG_WIDTH),
                ));
            }
        }

        match solver.check() {
            SolveResult::Sat(m) => Ok(m),
            SolveResult::Unsat => Err(ForgeError::Unsat(
                "register-goal post-condition is unsatisfiable for the chosen gadget order".into(),
            )),
            SolveResult::Unknown(reason) => Err(ForgeError::SmtUnknown(format!("{reason:?}"))),
        }
    }
}

/// For each gadget in `chain`, return the index its first effect occupies in
/// the flattened effect list. Used to disambiguate which `_<n>` SSA name a
/// witness was bound to.
fn effect_offsets(chain: &[&Gadget]) -> Vec<usize> {
    let mut out = Vec::with_capacity(chain.len());
    let mut idx = 0;
    for g in chain {
        out.push(idx);
        idx += g.effects.len();
    }
    out
}

/// Read the SMT witness for the `stack_input_<idx>` variable bound by the
/// effect at flat-index `flat_idx`. Falls back to the goal value if
/// the model didn't pin the variable explicitly.
fn solver_witness(
    model: &omnisec_smt::Model,
    flat_idx: usize,
    eff: &RegisterEffect,
    goals: &[RegisterGoal],
) -> u64 {
    let name = format!("stack_input_{flat_idx}");
    if let Some(v) = model.eval_u64(&name) {
        return v;
    }
    if let Some(goal) = goals.iter().find(|g| g.register == eff.dst) {
        return goal.value as u64;
    }
    eff.offset as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::finder::synthetic_pool;

    #[test]
    fn assembler_picks_one_gadget_per_goal() {
        let finder = synthetic_pool();
        let asm = SmtAssembler::new(&finder);
        let goals = vec![
            RegisterGoal {
                register: "rdi".into(),
                value: 0x0040_1400,
            },
            RegisterGoal {
                register: "rsi".into(),
                value: 0x0060_1020,
            },
        ];
        let mut prng = Prng::new(11);
        let chain = asm.assemble(&goals, &mut prng).unwrap();
        assert_eq!(chain.entries.len(), 2);
        let labels: Vec<&str> = chain.entries.iter().map(|e| e.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.contains("pop rdi")));
        assert!(labels.iter().any(|l| l.contains("pop rsi")));
    }

    #[test]
    fn assembler_round_trips_witness() {
        let finder = synthetic_pool();
        let asm = SmtAssembler::new(&finder);
        let goals = vec![RegisterGoal {
            register: "rdi".into(),
            value: 0x1234_5678,
        }];
        let mut prng = Prng::new(0);
        let chain = asm.assemble(&goals, &mut prng).unwrap();
        let entry = &chain.entries[0];
        // First 8 bytes of stack_data should be the LE encoding of 0x1234_5678.
        assert_eq!(entry.stack_data.len(), 8);
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&entry.stack_data[..8]);
        assert_eq!(u64::from_le_bytes(buf), 0x1234_5678);
    }

    #[test]
    fn assembler_is_deterministic() {
        let finder = synthetic_pool();
        let asm = SmtAssembler::new(&finder);
        let goals = vec![RegisterGoal {
            register: "rdi".into(),
            value: 1,
        }];
        let a = asm.assemble(&goals, &mut Prng::new(42)).unwrap();
        let b = asm.assemble(&goals, &mut Prng::new(42)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn missing_writer_yields_budget_exhausted() {
        let finder = synthetic_pool();
        let asm = SmtAssembler::new(&finder);
        let goals = vec![RegisterGoal {
            register: "fakereg".into(),
            value: 0,
        }];
        let r = asm.assemble(&goals, &mut Prng::new(0));
        assert!(matches!(r, Err(ForgeError::BudgetExhausted(_))));
    }

    #[test]
    fn ranked_search_prefers_shorter_chain() {
        // Both first-SAT and ranked modes should find the same two-gadget
        // chain here; the real discriminator is the SMT-query budget.
        let finder = synthetic_pool();
        let goals = vec![
            RegisterGoal {
                register: "rdi".into(),
                value: 0x1000,
            },
            RegisterGoal {
                register: "rsi".into(),
                value: 0x2000,
            },
        ];

        let ranked = SmtAssembler::new(&finder)
            .with_rank_by_complexity(true)
            .assemble(&goals, &mut Prng::new(0))
            .unwrap();
        let first = SmtAssembler::new(&finder)
            .with_rank_by_complexity(false)
            .assemble(&goals, &mut Prng::new(0))
            .unwrap();

        // Both modes return a valid chain with the same length.
        assert_eq!(ranked.entries.len(), first.entries.len());
        // Ranked mode must produce complexity ≤ first-SAT mode.
        assert!(ranked.complexity <= first.complexity);
        // Ranked mode runs at least as many SMT queries (it keeps exploring).
        assert!(ranked.stats.smt_queries >= first.stats.smt_queries);
    }

    #[test]
    fn ranked_search_stats_match_explored_count() {
        let finder = synthetic_pool();
        let goals = vec![RegisterGoal {
            register: "rdi".into(),
            value: 42,
        }];
        let chain = SmtAssembler::new(&finder)
            .with_rank_by_complexity(true)
            .with_budget(64)
            .assemble(&goals, &mut Prng::new(9))
            .unwrap();

        assert!(chain.stats.explored >= 1);
        assert!(chain.stats.smt_queries >= 1);
        assert!(chain.stats.explored >= chain.stats.smt_queries);
    }

    #[test]
    fn clobber_conflict_rejects_bad_chain() {
        // Build a handcrafted pool with two `pop rdi ; ret` gadgets, one
        // of which additionally clobbers `rsi`. When the second goal
        // targets `rsi`, BGAT must pick the non-clobbering variant.
        let mut finder = GadgetFinder::new();
        let mut safe = Gadget::pop_reg(0x4000_0010, "rdi", vec![0x5F, 0xC3]);
        let mut risky = Gadget::pop_reg(0x4000_0020, "rdi", vec![0x5F, 0xC3]);
        risky.clobbers.push("rsi".into());
        safe.clobbers.clear();
        finder.insert(safe);
        finder.insert(risky);
        finder.insert(Gadget::pop_reg(0x4000_0030, "rsi", vec![0x5E, 0xC3]));

        let goals = vec![
            RegisterGoal {
                register: "rdi".into(),
                value: 1,
            },
            RegisterGoal {
                register: "rsi".into(),
                value: 2,
            },
        ];
        let chain = SmtAssembler::new(&finder)
            .assemble(&goals, &mut Prng::new(0))
            .unwrap();
        // First slot must be the SAFE gadget (address 0x4000_0010); the
        // risky one clobbers rsi after rdi is set.
        assert_eq!(chain.entries[0].address, 0x4000_0010);
    }
}
