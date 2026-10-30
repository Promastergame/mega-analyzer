//! Concolic (concrete + symbolic) executor.
//!
//! Pure symbolic execution forks at every symbolic branch and explodes
//! exponentially with the number of conditionals. **Concolic** execution
//! sidesteps that: it always picks one concrete path (driven by an input
//! seed), records the symbolic path constraints along the way, and
//! generates new seeds by negating one branch at a time and asking the
//! SMT solver for a satisfying input.
//!
//! ```text
//!     ┌──────── seed_0 ────────┐
//!     │  concrete forward run  │  →  trace[0]: branches + path constraints
//!     └────────────────────────┘
//!                │
//!                │  for each branch i in trace[0]:
//!                │     1. negate branch i's predicate
//!                │     2. SMT-solve → seed_i
//!                │     3. if SAT, enqueue seed_i
//!                ▼
//!     ┌──────── seed_1 ────────┐
//!     │  concrete forward run  │  →  trace[1]
//!     └────────────────────────┘
//!                ⋮
//! ```
//!
//! This bounds path-count by `max_iterations` rather than by branch fan-out,
//! and gives complete coverage when the SMT theory is complete on the
//! formula (which `omnisec-smt` is, on linear-arithmetic atoms).
//!
//! ## Limitations
//!
//! - The MIR `Mul` / `Div` / bitwise ops are kept as concrete-only for the
//!   symbolic side when both operands aren't constants — the SMT solver
//!   would return `Unknown` on a non-linear atom anyway.
//! - Memory is modeled as a flat string-keyed map (same as the existing
//!   pure-symbolic path).

use std::rc::Rc;

use omnisec_json::ToJson;
use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

use omnisec_smt::{BoolExpr, BvExpr, BvOp, SolveResult, Solver, Width};

use crate::executor::{MirInsn, MirOp, SymBlock};
use crate::prioritize::{BranchPriority, PriorityQueue};

/// A concolic value: a concrete `i64` plus an optional symbolic [`BvExpr`].
///
/// We keep the symbolic side optional so that constants, freshly-loaded
/// concrete values, and concrete arithmetic results don't pay the cost
/// of carrying a tree.
#[derive(Debug, Clone)]
pub struct ConcolicValue {
    /// Current concrete value (always present).
    pub concrete: i64,
    /// Symbolic expression, if this value was tainted by a symbolic input.
    pub symbolic: Option<Rc<BvExpr>>,
    /// Bitvector width (typically 32 or 64).
    pub width: Width,
}

impl ConcolicValue {
    /// A pure concrete value.
    #[must_use]
    pub fn concrete(value: i64, width: Width) -> Self {
        Self {
            concrete: value,
            symbolic: None,
            width,
        }
    }

    /// A fresh symbolic input.
    #[must_use]
    pub fn fresh_input(name: &str, seed: i64, width: Width) -> Self {
        Self {
            concrete: seed,
            symbolic: Some(BvExpr::var(name, width)),
            width,
        }
    }

    /// Symbolic expression: returns the concrete value as a constant if
    /// the value is purely concrete.
    pub fn as_bv(&self) -> Rc<BvExpr> {
        match &self.symbolic {
            Some(s) => s.clone(),
            None => BvExpr::icon(self.concrete, self.width),
        }
    }

    /// `true` if this value carries a symbolic expression.
    #[must_use]
    pub const fn is_symbolic(&self) -> bool {
        self.symbolic.is_some()
    }
}

/// Per-input concrete value seed.
#[derive(Debug, Clone, Default)]
pub struct ConcolicSeed {
    /// Concrete value of each named symbolic input.
    pub inputs: FxHashMap<String, i64>,
}

impl ConcolicSeed {
    /// Empty seed (every input defaults to 0).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the concrete value of an input.
    pub fn set(&mut self, name: impl Into<String>, value: i64) {
        self.inputs.insert(name.into(), value);
    }

    /// Read the concrete value of an input, defaulting to 0.
    #[must_use]
    pub fn get(&self, name: &str) -> i64 {
        self.inputs.get(name).copied().unwrap_or(0)
    }
}

/// A branch decision recorded along a concolic path.
#[derive(Debug, Clone, ToJson)]
pub struct ConcolicBranch {
    /// Block id where the branch was made.
    pub block_id: usize,
    /// Instruction index within the block.
    pub insn_index: usize,
    /// Whether the *true* branch was taken.
    pub taken: bool,
    /// Stringified branch predicate (for display / forensics).
    pub predicate: String,
    /// Successor block id chosen.
    pub successor: usize,
    /// Optional alternative successor (for negation).
    pub alternative: Option<usize>,
    #[json(skip)]
    pub(crate) condition: Option<Rc<BoolExpr>>,
}

/// One concrete trace recorded by [`ConcolicExecutor::run_one`].
#[derive(Debug, Clone, ToJson)]
pub struct ConcolicTrace {
    /// Seed used for this trace.
    pub seed: FxHashMap<String, i64>,
    /// Branch decisions, in order.
    pub branches: Vec<ConcolicBranch>,
    /// Total instructions executed.
    pub instructions_executed: usize,
    /// Did the trace terminate normally (no successor) or hit a depth
    /// budget?
    pub terminated_cleanly: bool,
    /// Termination reason.
    pub termination_reason: String,
}

/// Aggregate result of a concolic exploration session.
#[derive(Debug, Clone, ToJson)]
pub struct ConcolicResult {
    /// All distinct traces explored.
    pub traces: Vec<ConcolicTrace>,
    /// Concrete inputs the solver found that drive previously-unseen paths.
    pub generated_seeds: Vec<FxHashMap<String, i64>>,
    /// Number of SMT queries issued.
    pub smt_queries: usize,
    /// Number of UNSAT replies (path was infeasible).
    pub unsat_replies: usize,
    /// Number of UNKNOWN replies (solver gave up — non-linear, etc.).
    pub unknown_replies: usize,
    /// Did exploration hit `max_iterations`?
    pub iteration_budget_exhausted: bool,
}

/// The concolic executor.
pub struct ConcolicExecutor {
    blocks: Vec<SymBlock>,
    entry_id: usize,
    /// Maximum total instructions per single trace.
    pub max_depth: usize,
    /// Maximum number of concrete-trace iterations.
    pub max_iterations: usize,
    /// Width to model registers at.
    pub register_width: Width,
}

impl ConcolicExecutor {
    /// Build a new executor.
    #[must_use]
    pub fn new(blocks: Vec<SymBlock>, entry_id: usize) -> Self {
        Self {
            blocks,
            entry_id,
            max_depth: 256,
            max_iterations: 32,
            register_width: 64,
        }
    }

    /// Set max trace depth (instructions per concrete trace).
    pub fn set_max_depth(&mut self, depth: usize) {
        self.max_depth = depth;
    }

    /// Set max concolic iterations.
    pub fn set_max_iterations(&mut self, iters: usize) {
        self.max_iterations = iters;
    }

    /// Run an exploration starting from `initial_seed`.
    ///
    /// Equivalent to [`Self::explore_with_priority`] using
    /// `BranchPriority::Normal` for every flip — i.e. FIFO order.
    pub fn explore(&self, initial_seed: ConcolicSeed) -> ConcolicResult {
        self.explore_with_priority(initial_seed, |_, _| BranchPriority::Normal)
    }

    /// Run an exploration with an HDC-aware priority function.
    ///
    /// `prioritize` is invoked for every branch we consider flipping,
    /// passing it the current trace and the index of the branch being
    /// flipped. The returned [`BranchPriority`] determines exploration
    /// order: `Vulnerability(score)` items run before `Normal` runs
    /// before `Background`.
    ///
    /// The function should be cheap — it's called once per generated
    /// seed and shouldn't allocate heavily.
    pub fn explore_with_priority<F>(
        &self,
        initial_seed: ConcolicSeed,
        mut prioritize: F,
    ) -> ConcolicResult
    where
        F: FnMut(&ConcolicTrace, usize) -> BranchPriority,
    {
        let mut visited: FxHashSet<Vec<bool>> = FxHashSet::default();
        let mut worklist = PriorityQueue::new();
        worklist.push(initial_seed, BranchPriority::Normal, "seed-0");
        let mut traces = Vec::new();
        let mut generated = Vec::new();
        let mut smt_queries = 0;
        let mut unsat_replies = 0;
        let mut unknown_replies = 0;

        for _ in 0..self.max_iterations {
            let Some(item) = worklist.pop() else { break };
            let seed = item.seed;
            let trace = self.run_one(&seed);
            let signature: Vec<bool> = trace.branches.iter().map(|b| b.taken).collect();
            if !visited.insert(signature) {
                continue;
            }
            // The trace's recorded seed includes EVERY input the executor
            // had to materialise (registers v0..v15 plus any field/memory
            // names). Use those names — not the original seed's keys —
            // so that empty initial seeds can still produce new flips.
            let input_names: Vec<String> = trace.seed.keys().cloned().collect();
            for i in 0..trace.branches.len() {
                let mut s = Solver::new();
                for name in &input_names {
                    let _ = s.fresh_bv(name, self.register_width);
                }
                for j in 0..i {
                    if let Some(cond) = trace.branches[j].condition.clone() {
                        if trace.branches[j].taken {
                            s.assert(cond);
                        } else {
                            s.assert(BoolExpr::not(cond));
                        }
                    }
                }
                let Some(target) = trace.branches[i].condition.clone() else {
                    continue;
                };
                if trace.branches[i].taken {
                    s.assert(BoolExpr::not(target));
                } else {
                    s.assert(target);
                }
                smt_queries += 1;
                match s.check() {
                    SolveResult::Sat(model) => {
                        let mut new_seed = ConcolicSeed::new();
                        for name in &input_names {
                            let v = model.eval_i64(name).unwrap_or(0);
                            new_seed.set(name.clone(), v);
                        }
                        generated.push(new_seed.inputs.clone());
                        let priority = prioritize(&trace, i);
                        worklist.push(
                            new_seed,
                            priority,
                            format!("flip-{}-branch-{i}", trace.branches[i].block_id),
                        );
                    }
                    SolveResult::Unsat => unsat_replies += 1,
                    SolveResult::Unknown(_) => unknown_replies += 1,
                }
            }
            traces.push(trace);
        }
        let budget_hit = !worklist.is_empty();

        ConcolicResult {
            traces,
            generated_seeds: generated,
            smt_queries,
            unsat_replies,
            unknown_replies,
            iteration_budget_exhausted: budget_hit,
        }
    }

    /// Run a single concrete trace from `seed`.
    pub fn run_one(&self, seed: &ConcolicSeed) -> ConcolicTrace {
        let mut regs: FxHashMap<i16, ConcolicValue> = FxHashMap::default();
        let mut memory: FxHashMap<String, ConcolicValue> = FxHashMap::default();

        // Initialize each register r{i} as a fresh symbolic input "v{i}".
        // Concrete value comes from the seed (default 0).
        let mut input_names: Vec<String> = Vec::new();
        for r in 0..16i16 {
            // ELF/x86_64 has at least 16 general-purpose regs we care about.
            let name = format!("v{r}");
            input_names.push(name.clone());
            let concrete = seed.get(&name);
            regs.insert(
                r,
                ConcolicValue::fresh_input(&name, concrete, self.register_width),
            );
        }
        for name in seed.inputs.keys() {
            // For non-register-prefixed seeded inputs, expose them as well
            // (they may correspond to memory locations).
            if !input_names.iter().any(|n| n == name) {
                input_names.push(name.clone());
            }
        }

        let mut branches = Vec::new();
        let mut depth = 0usize;
        let mut block_id = self.entry_id;
        let mut visited_blocks = 0usize;
        let max_blocks = self.blocks.len() * 4 + 32; // generous re-entry allowance

        let termination_reason: String;
        let terminated_cleanly: bool;
        let total_instructions: usize;

        let mut total_count = 0usize;
        loop {
            if depth >= self.max_depth {
                termination_reason = "depth limit".into();
                terminated_cleanly = false;
                total_instructions = total_count;
                break;
            }
            if visited_blocks >= max_blocks {
                termination_reason = "block re-entry budget".into();
                terminated_cleanly = false;
                total_instructions = total_count;
                break;
            }
            visited_blocks += 1;

            let Some(block) = self.blocks.iter().find(|b| b.id == block_id) else {
                termination_reason = format!("block {block_id} not found");
                terminated_cleanly = false;
                total_instructions = total_count;
                break;
            };

            let mut next_block: Option<usize> = block.succs.first().copied();
            let mut hit_branch = false;
            for (insn_index, insn) in block.insns.iter().enumerate() {
                self.execute_concolic_insn(insn, &mut regs, &mut memory);
                depth += 1;
                total_count += 1;

                if insn.kind == MirOp::If {
                    hit_branch = true;
                    let cond_value = regs.get(&insn.src1).cloned();
                    let (taken, predicate, condition_expr) =
                        evaluate_branch(insn, cond_value.as_ref());
                    let succ_true = block.succs.first().copied().unwrap_or(block_id);
                    let succ_false = block.succs.get(1).copied().unwrap_or(succ_true);
                    let (chosen, alt) = if taken {
                        (succ_true, Some(succ_false))
                    } else {
                        (succ_false, Some(succ_true))
                    };
                    next_block = Some(chosen);
                    branches.push(ConcolicBranch {
                        block_id,
                        insn_index,
                        taken,
                        predicate,
                        successor: chosen,
                        alternative: alt,
                        condition: condition_expr,
                    });
                    break;
                }
            }

            if let Some(next) = next_block {
                if next == block_id && !hit_branch {
                    // No progress (single-block program with no successors)
                    termination_reason = "self-loop without branch".into();
                    terminated_cleanly = true;
                    total_instructions = total_count;
                    break;
                }
                block_id = next;
            } else {
                termination_reason = "no successors".into();
                terminated_cleanly = true;
                total_instructions = total_count;
                break;
            }
        }

        let mut seed_map = FxHashMap::default();
        for name in &input_names {
            seed_map.insert(name.clone(), seed.get(name));
        }

        ConcolicTrace {
            seed: seed_map,
            branches,
            instructions_executed: total_instructions,
            terminated_cleanly,
            termination_reason,
        }
    }

    fn execute_concolic_insn(
        &self,
        insn: &MirInsn,
        regs: &mut FxHashMap<i16, ConcolicValue>,
        memory: &mut FxHashMap<String, ConcolicValue>,
    ) {
        let w = self.register_width;
        match insn.kind {
            MirOp::Const => {
                if insn.dst >= 0 {
                    regs.insert(insn.dst, ConcolicValue::concrete(insn.imm, w));
                }
            }
            MirOp::Move => {
                if let Some(src) = regs.get(&insn.src1).cloned()
                    && insn.dst >= 0
                {
                    regs.insert(insn.dst, src);
                }
            }
            MirOp::Add | MirOp::Sub | MirOp::Mul => {
                let (Some(a), Some(b)) =
                    (regs.get(&insn.src1).cloned(), regs.get(&insn.src2).cloned())
                else {
                    return;
                };
                let concrete = match insn.kind {
                    MirOp::Add => a.concrete.wrapping_add(b.concrete),
                    MirOp::Sub => a.concrete.wrapping_sub(b.concrete),
                    MirOp::Mul => a.concrete.wrapping_mul(b.concrete),
                    _ => unreachable!(),
                };
                let symbolic = if a.is_symbolic() || b.is_symbolic() {
                    let op = match insn.kind {
                        MirOp::Add => BvOp::Add,
                        MirOp::Sub => BvOp::Sub,
                        MirOp::Mul => BvOp::Mul,
                        _ => unreachable!(),
                    };
                    Some(BvExpr::binop(op, a.as_bv(), b.as_bv()))
                } else {
                    None
                };
                if insn.dst >= 0 {
                    regs.insert(
                        insn.dst,
                        ConcolicValue {
                            concrete,
                            symbolic,
                            width: w,
                        },
                    );
                }
            }
            MirOp::And | MirOp::Or | MirOp::Xor => {
                let (Some(a), Some(b)) =
                    (regs.get(&insn.src1).cloned(), regs.get(&insn.src2).cloned())
                else {
                    return;
                };
                let concrete = match insn.kind {
                    MirOp::And => a.concrete & b.concrete,
                    MirOp::Or => a.concrete | b.concrete,
                    MirOp::Xor => a.concrete ^ b.concrete,
                    _ => unreachable!(),
                };
                // Bitwise ops are non-linear in our SMT theory: keep
                // symbolic only when both sides happen to be concrete or
                // when it's a bit-mask with constant.
                let symbolic = if a.is_symbolic() && !b.is_symbolic() {
                    let op = match insn.kind {
                        MirOp::And => BvOp::And,
                        MirOp::Or => BvOp::Or,
                        MirOp::Xor => BvOp::Xor,
                        _ => unreachable!(),
                    };
                    Some(BvExpr::binop(op, a.as_bv(), b.as_bv()))
                } else {
                    None
                };
                if insn.dst >= 0 {
                    regs.insert(
                        insn.dst,
                        ConcolicValue {
                            concrete,
                            symbolic,
                            width: w,
                        },
                    );
                }
            }
            MirOp::Not => {
                if let Some(src) = regs.get(&insn.src1).cloned() {
                    let symbolic = src.symbolic.as_ref().map(|s| BvExpr::bvnot(s.clone()));
                    if insn.dst >= 0 {
                        regs.insert(
                            insn.dst,
                            ConcolicValue {
                                concrete: !src.concrete,
                                symbolic,
                                width: w,
                            },
                        );
                    }
                }
            }
            MirOp::FieldGet => {
                let key = format!("field_{}", insn.ref_idx);
                let val = memory.get(&key).cloned().unwrap_or_else(|| {
                    ConcolicValue::fresh_input(&format!("mem_{}", insn.ref_idx), 0, w)
                });
                if insn.dst >= 0 {
                    regs.insert(insn.dst, val);
                }
            }
            MirOp::FieldPut => {
                let key = format!("field_{}", insn.ref_idx);
                if let Some(val) = regs.get(&insn.src1).cloned() {
                    memory.insert(key, val);
                }
            }
            _ => { /* If/Goto/Switch handled by run_one; the rest are no-ops */ }
        }
    }
}

/// Translate a `(value, cond_code)` pair into a (taken, predicate-string,
/// symbolic-condition).
fn evaluate_branch(
    insn: &MirInsn,
    val: Option<&ConcolicValue>,
) -> (bool, String, Option<Rc<BoolExpr>>) {
    let Some(value) = val else {
        return (true, "missing operand".into(), None);
    };
    // Concrete decision: `value.concrete (op) 0`.
    // Codes aligned with omnisec_ir::Condition enum discriminants.
    let taken = match insn.cond {
        0 => true,                         // Always
        1 => false,                        // Never
        2 | 19 => value.concrete == 0,     // Equal / Zero
        3 | 20 => value.concrete != 0,     // NotEqual / NotZero
        4 => value.concrete < 0,           // SignedLess
        5 => value.concrete <= 0,          // SignedLessEq
        6 => value.concrete > 0,           // SignedGreater
        7 => value.concrete >= 0,          // SignedGreaterEq
        10 => (value.concrete as u64) > 0, // UnsignedGreater
        _ => value.concrete != 0,
    };
    let pred = format!(
        "v{src} {op} 0 ⇒ {taken}",
        src = insn.src1,
        op = cond_str(insn.cond),
    );

    // Symbolic decision: build the BoolExpr atom only if the value
    // carries a symbolic side.
    let cond = value.symbolic.as_ref().and_then(|s| {
        let zero = BvExpr::icon(0, value.width);
        match insn.cond {
            0 => None, // Unconditional
            1 => None, // Unconditional
            2 | 19 => Some(BoolExpr::eq(s.clone(), zero)),
            3 | 20 => Some(BoolExpr::ne(s.clone(), zero)),
            4 => Some(BoolExpr::slt(s.clone(), zero)),
            5 => Some(BoolExpr::sle(s.clone(), zero)),
            6 => Some(BoolExpr::sgt(s.clone(), zero)),
            7 => Some(BoolExpr::sge(s.clone(), zero)),
            10 => Some(BoolExpr::ugt(s.clone(), zero)),
            _ => Some(BoolExpr::ne(s.clone(), zero)),
        }
    });
    (taken, pred, cond)
}

const fn cond_str(c: u8) -> &'static str {
    match c {
        0 => "always",
        1 => "never",
        2 | 19 => "==",
        3 | 20 => "!=",
        4 => "<",
        5 => "<=",
        6 => ">",
        7 => ">=",
        10 => "u>",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{MirInsn, MirOp, SymBlock};

    fn make_const(dst: i16, imm: i64) -> MirInsn {
        MirInsn {
            kind: MirOp::Const,
            cond: 0,
            dst,
            src1: 0,
            src2: 0,
            imm,
            ref_idx: 0,
        }
    }
    fn make_add(dst: i16, src1: i16, src2: i16) -> MirInsn {
        MirInsn {
            kind: MirOp::Add,
            cond: 0,
            dst,
            src1,
            src2,
            imm: 0,
            ref_idx: 0,
        }
    }
    fn make_if(src: i16, cond: u8) -> MirInsn {
        MirInsn {
            kind: MirOp::If,
            cond,
            dst: 0,
            src1: src,
            src2: 0,
            imm: 0,
            ref_idx: 0,
        }
    }

    #[test]
    fn straight_line_concolic_runs_no_branches() {
        // Block 0: r2 = 1; r3 = 2; r4 = r2 + r3
        let blocks = vec![SymBlock {
            id: 0,
            insns: vec![make_const(2, 1), make_const(3, 2), make_add(4, 2, 3)],
            succs: vec![],
        }];
        let exec = ConcolicExecutor::new(blocks, 0);
        let trace = exec.run_one(&ConcolicSeed::new());
        assert!(trace.branches.is_empty(), "no branches expected");
        assert_eq!(trace.instructions_executed, 3);
    }

    #[test]
    fn branch_on_symbolic_input_produces_path_constraint() {
        // Block 0: if v0 != 0 → block 1 else block 2
        // We seed v0 = 5: branch is taken (true).
        let blocks = vec![
            SymBlock {
                id: 0,
                insns: vec![make_if(0, 3)],
                succs: vec![1, 2],
            },
            SymBlock {
                id: 1,
                insns: vec![],
                succs: vec![],
            },
            SymBlock {
                id: 2,
                insns: vec![],
                succs: vec![],
            },
        ];
        let exec = ConcolicExecutor::new(blocks, 0);
        let mut seed = ConcolicSeed::new();
        seed.set("v0", 5);
        let trace = exec.run_one(&seed);
        assert_eq!(trace.branches.len(), 1);
        assert!(trace.branches[0].taken);
        assert!(trace.branches[0].condition.is_some());
        assert_eq!(trace.branches[0].successor, 1);
    }

    #[test]
    fn explore_flips_branch_via_smt() {
        // Block 0: if v0 == 0 → 1 else 2
        let blocks = vec![
            SymBlock {
                id: 0,
                insns: vec![make_if(0, 2)],
                succs: vec![1, 2],
            },
            SymBlock {
                id: 1,
                insns: vec![],
                succs: vec![],
            },
            SymBlock {
                id: 2,
                insns: vec![],
                succs: vec![],
            },
        ];
        let mut exec = ConcolicExecutor::new(blocks, 0);
        exec.set_max_iterations(8);
        let mut seed = ConcolicSeed::new();
        seed.set("v0", 0); // start with v0 == 0 → branch taken
        let result = exec.explore(seed);
        // We should explore at least 2 distinct paths (taken + not taken).
        assert!(result.traces.len() >= 2, "{:?}", result.traces);
        assert!(
            result.smt_queries >= 1,
            "should have queried the solver at least once"
        );
    }

    #[test]
    fn unsat_branch_does_not_generate_seed() {
        // Block 0: r2 = const 5; unconditional branch (Always) to block 1.
        // Because the branch is unconditional, there is no symbolic condition
        // to flip, so explore should stop after the first trace.
        let blocks = vec![
            SymBlock {
                id: 0,
                insns: vec![make_const(2, 5), make_if(2, 0)],
                succs: vec![1, 2],
            },
            SymBlock {
                id: 1,
                insns: vec![],
                succs: vec![],
            },
            SymBlock {
                id: 2,
                insns: vec![],
                succs: vec![],
            },
        ];
        let mut exec = ConcolicExecutor::new(blocks, 0);
        exec.set_max_iterations(4);
        let result = exec.explore(ConcolicSeed::new());
        // No condition to flip → exactly 1 trace.
        assert_eq!(result.traces.len(), 1);
    }
}
