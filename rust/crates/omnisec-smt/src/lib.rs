//! # OmniSec SMT — Lightweight SAT / SMT solver
//!
//! A small custom decision procedure used by `omnisec-analysis-symbolic`'s
//! concolic engine and by the Aetrium exploit pipeline. The goal is **not**
//! to compete with Z3 or CVC5; the goal is to be **fast enough on the kinds
//! of constraints symbolic execution produces** while remaining a pure-Rust,
//! `forbid(unsafe_code)`, zero-network dependency that compiles on every
//! target OmniSec runs on.
//!
//! ## Theories supported
//!
//! - **Linear integer arithmetic over fixed-width signed/unsigned bitvectors**
//!   (`BV_LIA`): `+`, `-`, unary `−`, integer comparisons.
//! - **Equality / disequality** between linear terms.
//! - **Bitwise constants** (`AND`, `OR`, `XOR`, `SHL`, `LSHR`) when one
//!   side reduces to a constant.
//!
//! Anything richer (full bit-blasting, non-linear multiplication, arrays,
//! quantifiers) returns [`SolveResult::Unknown`] — sound but incomplete.
//!
//! ## Algorithm
//!
//! ```text
//!   AST (BvExpr / BoolExpr)
//!       │
//!       │ CNF + theory atoms
//!       ▼
//!   DPLL SAT engine ◄────► Theory propagator
//!       │                    (intervals + Gauss-Jordan on equalities)
//!       ▼
//!   Sat(Model) | Unsat | Unknown
//! ```
//!
//! The SAT engine uses watched-literal unit propagation and chronological
//! backtracking. CDCL is intentionally **not** implemented — the constraint
//! systems we see are small enough that the extra bookkeeping costs more
//! than it saves.
//!
//! ## High-level API
//!
//! ```ignore
//! use omnisec_smt::{Solver, SolveResult, BoolExpr, BvExpr};
//!
//! let mut s = Solver::new();
//! let x = s.fresh_bv("x", 32);
//! let y = s.fresh_bv("y", 32);
//! // assert: x + y == 10 ∧ x > 0 ∧ y > 0
//! s.assert(BoolExpr::eq(BvExpr::add(x.clone(), y.clone()), BvExpr::con(10, 32)));
//! s.assert(BoolExpr::sgt(x.clone(), BvExpr::con(0, 32)));
//! s.assert(BoolExpr::sgt(y.clone(), BvExpr::con(0, 32)));
//! match s.check() {
//!     SolveResult::Sat(m) => println!("x = {}, y = {}", m.eval_i64("x").unwrap(), m.eval_i64("y").unwrap()),
//!     SolveResult::Unsat => println!("no solution"),
//!     SolveResult::Unknown(_) => println!("solver gave up"),
//! }
//! ```

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod ast;
pub mod model;
pub mod propagator;
pub mod sat;
pub mod solver;

pub use ast::{BoolExpr, BoolOp, BvExpr, BvOp, Width};
pub use model::Model;
pub use solver::{SolveResult, Solver, SolverConfig, UnknownReason};
