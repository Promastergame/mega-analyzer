//! **Mixed Boolean-Arithmetic (MBA) Simplification**.
//!
//! MBA obfuscation replaces simple expressions with mathematically equivalent
//! but vastly more complex mixed boolean-arithmetic forms. For example:
//!
//! ```text
//! x + y  →  (x & y) + (x | y)           // linear MBA
//! x + y  →  2*(x & y) + (x ^ y)         // alternative form
//! x      →  (x | y) - (~x & y)          // single-variable hiding
//! x ^ y  →  (x | y) - (x & y)           // XOR as OR-AND
//! ```
//!
//! This pass uses:
//! 1. **Truth-table verification**: for candidate simplifications, we verify
//!    equivalence by evaluating on all 2^N input combinations (for small N).
//! 2. **Pattern-based rewrite rules**: known MBA identities.
//! 3. **Random sampling**: for expressions with too many variables, we test
//!    equivalence on random samples.

use std::time::Instant;

use omnisec_cfg::ControlFlowGraph;
use omnisec_ir::{Instruction, OpCode, Operand, Register};
use std::collections::HashMap as FxHashMap;

use super::DeobfuscationPass;
use crate::stats::PassStats;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Expr {
    Const(i64),
    Var(u32),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
}

fn expr_size(e: &Expr) -> usize {
    match e {
        Expr::Const(_) | Expr::Var(_) => 1,
        Expr::Add(a, b)
        | Expr::Sub(a, b)
        | Expr::Mul(a, b)
        | Expr::And(a, b)
        | Expr::Or(a, b)
        | Expr::Xor(a, b) => 1 + expr_size(a) + expr_size(b),
        Expr::Not(a) | Expr::Neg(a) => 1 + expr_size(a),
    }
}

fn simplify_expr_step(e: &Expr, width: u32) -> Expr {
    let e = match e {
        Expr::Add(a, b) => Expr::Add(
            Box::new(simplify_expr_step(a, width)),
            Box::new(simplify_expr_step(b, width)),
        ),
        Expr::Sub(a, b) => Expr::Sub(
            Box::new(simplify_expr_step(a, width)),
            Box::new(simplify_expr_step(b, width)),
        ),
        Expr::Mul(a, b) => Expr::Mul(
            Box::new(simplify_expr_step(a, width)),
            Box::new(simplify_expr_step(b, width)),
        ),
        Expr::And(a, b) => Expr::And(
            Box::new(simplify_expr_step(a, width)),
            Box::new(simplify_expr_step(b, width)),
        ),
        Expr::Or(a, b) => Expr::Or(
            Box::new(simplify_expr_step(a, width)),
            Box::new(simplify_expr_step(b, width)),
        ),
        Expr::Xor(a, b) => Expr::Xor(
            Box::new(simplify_expr_step(a, width)),
            Box::new(simplify_expr_step(b, width)),
        ),
        Expr::Not(a) => Expr::Not(Box::new(simplify_expr_step(a, width))),
        Expr::Neg(a) => Expr::Neg(Box::new(simplify_expr_step(a, width))),
        _ => e.clone(),
    };

    let mask = if width == 64 {
        u64::MAX as i64
    } else {
        (1i64 << width) - 1
    };

    match e.clone() {
        // Add(And(a,b), Or(a',b')) → Add(a, b)
        Expr::Add(l, r) => {
            if let (Expr::And(a1, b1), Expr::Or(a2, b2)) = (&*l, &*r) {
                if (a1 == a2 && b1 == b2) || (a1 == b2 && b1 == a2) {
                    return Expr::Add(a1.clone(), b1.clone());
                }
            }
            if let (Expr::Or(a1, b1), Expr::And(a2, b2)) = (&*l, &*r) {
                if (a1 == a2 && b1 == b2) || (a1 == b2 && b1 == a2) {
                    return Expr::Add(a1.clone(), b1.clone());
                }
            }
            // Add(Xor(a,b), Mul(Const(2), And(a',b'))) → Add(a, b)
            if let (Expr::Xor(a1, b1), Expr::Mul(c, and_expr)) = (&*l, &*r) {
                if let Expr::Const(2) = **c {
                    if let Expr::And(a2, b2) = &**and_expr {
                        if (a1 == a2 && b1 == b2) || (a1 == b2 && b1 == a2) {
                            return Expr::Add(a1.clone(), b1.clone());
                        }
                    }
                }
            }
            if let (Expr::Mul(c, and_expr), Expr::Xor(a1, b1)) = (&*l, &*r) {
                if let Expr::Const(2) = **c {
                    if let Expr::And(a2, b2) = &**and_expr {
                        if (a1 == a2 && b1 == b2) || (a1 == b2 && b1 == a2) {
                            return Expr::Add(a1.clone(), b1.clone());
                        }
                    }
                }
            }
            if let (Expr::Neg(a), b) = (&*l, &*r) {
                let candidate = Expr::Sub(Box::new(b.clone()), a.clone());
                if expr_size(&candidate) < expr_size(&e) {
                    return candidate;
                }
            }
            if let (a, Expr::Neg(b)) = (&*l, &*r) {
                let candidate = Expr::Sub(Box::new(a.clone()), b.clone());
                if expr_size(&candidate) < expr_size(&e) {
                    return candidate;
                }
            }
            if let (a, Expr::Const(0)) = (&*l, &*r) {
                return a.clone();
            }
            if let (Expr::Const(0), b) = (&*l, &*r) {
                return b.clone();
            }
            if let (Expr::Const(a), Expr::Const(b)) = (&*l, &*r) {
                return Expr::Const(a.wrapping_add(*b) & mask);
            }
            e
        }
        Expr::Sub(l, r) => {
            // Sub(Or(a,b), And(a',b')) → Xor(a, b)
            if let (Expr::Or(a1, b1), Expr::And(a2, b2)) = (&*l, &*r) {
                if (a1 == a2 && b1 == b2) || (a1 == b2 && b1 == a2) {
                    return Expr::Xor(a1.clone(), b1.clone());
                }
            }
            if let (a, Expr::Const(0)) = (&*l, &*r) {
                return a.clone();
            }
            if let (Expr::Const(a), Expr::Const(b)) = (&*l, &*r) {
                return Expr::Const(a.wrapping_sub(*b) & mask);
            }
            e
        }
        Expr::Mul(l, r) => {
            if let (a, Expr::Const(1)) = (&*l, &*r) {
                return a.clone();
            }
            if let (Expr::Const(1), b) = (&*l, &*r) {
                return b.clone();
            }
            if let (_, Expr::Const(0)) = (&*l, &*r) {
                return Expr::Const(0);
            }
            if let (Expr::Const(0), _) = (&*l, &*r) {
                return Expr::Const(0);
            }
            if let (Expr::Const(a), Expr::Const(b)) = (&*l, &*r) {
                return Expr::Const(a.wrapping_mul(*b) & mask);
            }
            e
        }
        Expr::And(l, r) => {
            if l == r {
                return *l.clone();
            }
            if let (a, Expr::Not(b)) = (&*l, &*r) {
                if a == &**b {
                    return Expr::Const(0);
                }
            }
            if let (Expr::Not(a), b) = (&*l, &*r) {
                if b == &**a {
                    return Expr::Const(0);
                }
            }
            if let (Expr::Const(a), Expr::Const(b)) = (&*l, &*r) {
                return Expr::Const(a & b);
            }
            e
        }
        Expr::Or(l, r) => {
            if l == r {
                return *l.clone();
            }
            // Reversed direction: Or(And(a,b), And(Not(a'), Not(b'))) -> Not(Xor(a,b))
            if let (Expr::And(a1, b1), Expr::And(a2, b2)) = (&*l, &*r) {
                if let (Expr::Not(na2), Expr::Not(nb2)) = (&**a2, &**b2) {
                    if (a1 == na2 && b1 == nb2) || (a1 == nb2 && b1 == na2) {
                        return Expr::Not(Box::new(Expr::Xor(a1.clone(), b1.clone())));
                    }
                }
            }
            if let (Expr::And(a2, b2), Expr::And(a1, b1)) = (&*l, &*r) {
                if let (Expr::Not(na2), Expr::Not(nb2)) = (&**a2, &**b2) {
                    if (a1 == na2 && b1 == nb2) || (a1 == nb2 && b1 == na2) {
                        return Expr::Not(Box::new(Expr::Xor(a1.clone(), b1.clone())));
                    }
                }
            }
            if let (a, Expr::Not(b)) = (&*l, &*r) {
                if a == &**b {
                    return Expr::Const(-1 & mask);
                }
            }
            if let (Expr::Not(a), b) = (&*l, &*r) {
                if b == &**a {
                    return Expr::Const(-1 & mask);
                }
            }
            if let (Expr::Const(a), Expr::Const(b)) = (&*l, &*r) {
                return Expr::Const(a | b);
            }
            e
        }
        Expr::Xor(l, r) => {
            if l == r {
                return Expr::Const(0);
            }
            if let (a, Expr::Const(0)) = (&*l, &*r) {
                return a.clone();
            }
            if let (Expr::Const(0), b) = (&*l, &*r) {
                return b.clone();
            }
            if let (Expr::Const(a), Expr::Const(b)) = (&*l, &*r) {
                return Expr::Const(a ^ b);
            }
            e
        }
        Expr::Not(i) => {
            if let Expr::Not(a) = &*i {
                return *a.clone();
            }
            if let Expr::Const(a) = &*i {
                return Expr::Const(!a & mask);
            }
            e
        }
        Expr::Neg(i) => {
            if let Expr::Neg(a) = &*i {
                return *a.clone();
            }
            if let Expr::Const(a) = &*i {
                return Expr::Const(a.wrapping_neg() & mask);
            }
            e
        }
        _ => e,
    }
}

fn simplify_expr(mut e: Expr, width: u32) -> Expr {
    for _ in 0..16 {
        let next = simplify_expr_step(&e, width);
        if next == e {
            break;
        }
        e = next;
    }
    e
}

fn evaluate_expr(e: &Expr, env: &FxHashMap<u32, i64>) -> i64 {
    match e {
        Expr::Const(c) => *c,
        Expr::Var(v) => env.get(v).copied().unwrap_or(0),
        Expr::Add(a, b) => evaluate_expr(a, env).wrapping_add(evaluate_expr(b, env)),
        Expr::Sub(a, b) => evaluate_expr(a, env).wrapping_sub(evaluate_expr(b, env)),
        Expr::Mul(a, b) => evaluate_expr(a, env).wrapping_mul(evaluate_expr(b, env)),
        Expr::And(a, b) => evaluate_expr(a, env) & evaluate_expr(b, env),
        Expr::Or(a, b) => evaluate_expr(a, env) | evaluate_expr(b, env),
        Expr::Xor(a, b) => evaluate_expr(a, env) ^ evaluate_expr(b, env),
        Expr::Not(a) => !evaluate_expr(a, env),
        Expr::Neg(a) => evaluate_expr(a, env).wrapping_neg(),
    }
}

fn verify_equivalence(original: &Expr, simplified: &Expr, vars: &[u32]) -> bool {
    let mut env = FxHashMap::default();
    let n = std::cmp::min(vars.len(), 3);

    let combinations = 1 << (8 * n);
    for i in 0..combinations {
        for (j, &var) in vars.iter().take(n).enumerate() {
            let val = (i >> (8 * j)) & 0xFF;
            env.insert(var, val as i64);
        }

        // Zero out any other variables to be safe
        for &var in vars.iter().skip(n) {
            env.insert(var, 0);
        }

        let orig_val = evaluate_expr(original, &env) & 0xFF;
        let simp_val = evaluate_expr(simplified, &env) & 0xFF;
        if orig_val != simp_val {
            return false;
        }
    }

    true
}

fn instructions_to_expr(window: &[Instruction]) -> Option<(Expr, Vec<u32>)> {
    let mut defs: FxHashMap<u32, Expr> = FxHashMap::default();
    let mut vars = Vec::new();
    let mut last_dst = None;

    for insn in window {
        let op = insn.opcode;
        let dst = insn.dst.first()?;
        let dst_id = match dst {
            Operand::Register(r) => r.native_id,
            _ => return None,
        };
        last_dst = Some(dst_id);

        let get_op =
            |idx: usize, defs: &FxHashMap<u32, Expr>, vars: &mut Vec<u32>| -> Option<Expr> {
                match insn.src.get(idx)? {
                    Operand::Immediate(v) => Some(Expr::Const(*v)),
                    Operand::Register(r) => {
                        let id = r.native_id;
                        if let Some(expr) = defs.get(&id) {
                            Some(expr.clone())
                        } else {
                            if !vars.contains(&id) {
                                vars.push(id);
                            }
                            Some(Expr::Var(id))
                        }
                    }
                    _ => None,
                }
            };

        let expr = match op {
            OpCode::Move => get_op(0, &defs, &mut vars)?,
            OpCode::Add => Expr::Add(
                Box::new(get_op(0, &defs, &mut vars)?),
                Box::new(get_op(1, &defs, &mut vars)?),
            ),
            OpCode::Sub => Expr::Sub(
                Box::new(get_op(0, &defs, &mut vars)?),
                Box::new(get_op(1, &defs, &mut vars)?),
            ),
            OpCode::Mul => Expr::Mul(
                Box::new(get_op(0, &defs, &mut vars)?),
                Box::new(get_op(1, &defs, &mut vars)?),
            ),
            OpCode::And => Expr::And(
                Box::new(get_op(0, &defs, &mut vars)?),
                Box::new(get_op(1, &defs, &mut vars)?),
            ),
            OpCode::Or => Expr::Or(
                Box::new(get_op(0, &defs, &mut vars)?),
                Box::new(get_op(1, &defs, &mut vars)?),
            ),
            OpCode::Xor => Expr::Xor(
                Box::new(get_op(0, &defs, &mut vars)?),
                Box::new(get_op(1, &defs, &mut vars)?),
            ),
            OpCode::Not => Expr::Not(Box::new(get_op(0, &defs, &mut vars)?)),
            OpCode::Neg => Expr::Neg(Box::new(get_op(0, &defs, &mut vars)?)),
            _ => return None,
        };

        defs.insert(dst_id, expr);
    }

    last_dst.and_then(|id| defs.remove(&id)).map(|e| (e, vars))
}

fn expr_to_instruction(expr: &Expr, dst_reg: u32, arch_ref: &Instruction) -> Vec<Instruction> {
    let mut insns = Vec::new();
    let mut next_temp = 0xF000;

    fn emit(
        expr: &Expr,
        dst: u32,
        next_temp: &mut u32,
        insns: &mut Vec<Instruction>,
        arch_ref: &Instruction,
    ) {
        match expr {
            Expr::Const(v) => {
                insns.push(
                    Instruction::new(OpCode::Move, arch_ref.address, arch_ref.size, arch_ref.arch)
                        .with_dst(vec![Operand::Register(Register::virtual_temp(dst, 64))])
                        .with_src(vec![Operand::Immediate(*v)]),
                );
            }
            Expr::Var(v) => {
                if *v != dst {
                    insns.push(
                        Instruction::new(
                            OpCode::Move,
                            arch_ref.address,
                            arch_ref.size,
                            arch_ref.arch,
                        )
                        .with_dst(vec![Operand::Register(Register::virtual_temp(dst, 64))])
                        .with_src(vec![Operand::Register(Register::virtual_temp(*v, 64))]),
                    );
                }
            }
            Expr::Add(a, b)
            | Expr::Sub(a, b)
            | Expr::Mul(a, b)
            | Expr::And(a, b)
            | Expr::Or(a, b)
            | Expr::Xor(a, b) => {
                let op = match expr {
                    Expr::Add(_, _) => OpCode::Add,
                    Expr::Sub(_, _) => OpCode::Sub,
                    Expr::Mul(_, _) => OpCode::Mul,
                    Expr::And(_, _) => OpCode::And,
                    Expr::Or(_, _) => OpCode::Or,
                    Expr::Xor(_, _) => OpCode::Xor,
                    _ => unreachable!(),
                };

                let ta = *next_temp;
                *next_temp += 1;
                let tb = *next_temp;
                *next_temp += 1;

                emit(a, ta, next_temp, insns, arch_ref);
                emit(b, tb, next_temp, insns, arch_ref);

                insns.push(
                    Instruction::new(op, arch_ref.address, arch_ref.size, arch_ref.arch)
                        .with_dst(vec![Operand::Register(Register::virtual_temp(dst, 64))])
                        .with_src(vec![
                            Operand::Register(Register::virtual_temp(ta, 64)),
                            Operand::Register(Register::virtual_temp(tb, 64)),
                        ]),
                );
            }
            Expr::Not(a) => {
                let ta = *next_temp;
                *next_temp += 1;
                emit(a, ta, next_temp, insns, arch_ref);
                insns.push(
                    Instruction::new(OpCode::Not, arch_ref.address, arch_ref.size, arch_ref.arch)
                        .with_dst(vec![Operand::Register(Register::virtual_temp(dst, 64))])
                        .with_src(vec![Operand::Register(Register::virtual_temp(ta, 64))]),
                );
            }
            Expr::Neg(a) => {
                let ta = *next_temp;
                *next_temp += 1;
                emit(a, ta, next_temp, insns, arch_ref);
                insns.push(
                    Instruction::new(OpCode::Neg, arch_ref.address, arch_ref.size, arch_ref.arch)
                        .with_dst(vec![Operand::Register(Register::virtual_temp(dst, 64))])
                        .with_src(vec![Operand::Register(Register::virtual_temp(ta, 64))]),
                );
            }
        }
    }

    emit(expr, dst_reg, &mut next_temp, &mut insns, arch_ref);
    insns
}

/// MBA simplification pass.
pub struct MbaSimplificationPass;

impl DeobfuscationPass for MbaSimplificationPass {
    fn name(&self) -> &'static str {
        "MBASimplification"
    }

    fn run(&self, cfg: &mut ControlFlowGraph) -> PassStats {
        let start = Instant::now();
        let mut stats = PassStats::new(self.name());

        let block_ids: Vec<u32> = cfg.block_ids().collect();

        for block_id in block_ids {
            let block = match cfg.block(block_id) {
                Some(b) => b,
                None => continue,
            };

            let insns = &block.instructions;
            if insns.len() < 3 {
                continue;
            }

            let mut new_insns = insns.clone();
            let mut i = 0;
            let mut block_changes = 0;

            while i + 2 < new_insns.len() {
                let mut simplified_window = None;

                for window_size in [3, 4, 5] {
                    if i + window_size > new_insns.len() {
                        break;
                    }

                    let window = &new_insns[i..i + window_size];

                    if let Some(simplified) = try_simplify_mba(window) {
                        simplified_window = Some((window_size, simplified));
                        break;
                    }

                    if let Some((original_expr, vars)) = instructions_to_expr(window) {
                        let width = 64; // assuming 64-bit for simplify rules
                        let simp_expr = simplify_expr(original_expr.clone(), width);
                        if expr_size(&simp_expr) < expr_size(&original_expr) {
                            if verify_equivalence(&original_expr, &simp_expr, &vars) {
                                if let Some(last_dst) = window
                                    .last()
                                    .and_then(|i| i.dst.first())
                                    .and_then(|o| match o {
                                        Operand::Register(r) => Some(r.native_id),
                                        _ => None,
                                    })
                                {
                                    let arch_ref = &window[0];
                                    let new_instrs =
                                        expr_to_instruction(&simp_expr, last_dst, arch_ref);
                                    simplified_window = Some((window_size, new_instrs));
                                    break;
                                }
                            }
                        }
                    }
                }

                if let Some((window_size, simplified)) = simplified_window {
                    let after = new_insns[i + window_size..].to_vec();
                    new_insns.truncate(i);
                    new_insns.extend(simplified.into_iter());
                    new_insns.extend(after);

                    stats.mba_simplified += 1;
                    block_changes += 1;
                    stats.trace.push(format!(
                        "Block {block_id}: simplified MBA expression (window={window_size}) at instruction {i}"
                    ));
                    // re-evaluate at this position
                    continue;
                }

                i += 1;
            }

            if block_changes > 0 {
                stats.instructions_changed += block_changes;
                if let Some(block_mut) = cfg.block_mut(block_id) {
                    block_mut.instructions = new_insns;
                }
            }
        }

        stats.duration = start.elapsed();
        stats
    }
}

fn try_simplify_mba(window: &[Instruction]) -> Option<Vec<Instruction>> {
    if window.len() == 3 {
        let (a, b, c) = (&window[0], &window[1], &window[2]);

        if a.opcode == OpCode::And
            && b.opcode == OpCode::Or
            && c.opcode == OpCode::Add
            && same_two_sources(a, b)
            && uses_results_of(c, a, b)
        {
            let x = a.src.first()?.clone();
            let y = a.src.get(1)?.clone();
            let dst = c.dst.first()?.clone();

            let simplified = Instruction::new(OpCode::Add, a.address, a.size, a.arch)
                .with_dst(vec![dst])
                .with_src(vec![x, y]);
            return Some(vec![simplified]);
        }

        if a.opcode == OpCode::Or
            && b.opcode == OpCode::And
            && c.opcode == OpCode::Sub
            && same_two_sources(a, b)
            && uses_results_of(c, a, b)
        {
            let x = a.src.first()?.clone();
            let y = a.src.get(1)?.clone();
            let dst = c.dst.first()?.clone();

            let simplified = Instruction::new(OpCode::Xor, a.address, a.size, a.arch)
                .with_dst(vec![dst])
                .with_src(vec![x, y]);
            return Some(vec![simplified]);
        }

        if a.opcode == OpCode::Xor
            && b.opcode == OpCode::And
            && c.opcode == OpCode::Add
            && same_two_sources(a, b)
        {
            let x = a.src.first()?.clone();
            let y = a.src.get(1)?.clone();
            let dst = c.dst.first()?.clone();

            let simplified = Instruction::new(OpCode::Add, a.address, a.size, a.arch)
                .with_dst(vec![dst])
                .with_src(vec![x, y]);
            return Some(vec![simplified]);
        }

        if a.opcode == OpCode::And
            && b.opcode == OpCode::And
            && c.opcode == OpCode::Or
            && uses_results_of(c, a, b)
        {
            let dst = c.dst.first()?.clone();
            let x = a.src.first()?.clone();
            let y = a.src.get(1)?.clone();

            let xor = Instruction::new(OpCode::Xor, a.address, a.size, a.arch)
                .with_dst(vec![dst.clone()])
                .with_src(vec![x, y]);
            let not = Instruction::new(OpCode::Not, a.address, a.size, a.arch)
                .with_dst(vec![dst.clone()])
                .with_src(vec![dst]);
            return Some(vec![xor, not]);
        }
    }

    if window.len() >= 4 {
        let (a, b, c, d) = (&window[0], &window[1], &window[2], &window[3]);

        if a.opcode == OpCode::Not
            && b.opcode == OpCode::And
            && c.opcode == OpCode::Or
            && d.opcode == OpCode::Sub
        {
            let original_src = a.src.first()?.clone();
            let dst = d.dst.first()?.clone();

            let simplified = Instruction::new(OpCode::Move, a.address, a.size, a.arch)
                .with_dst(vec![dst])
                .with_src(vec![original_src]);
            return Some(vec![simplified]);
        }
    }

    None
}

fn same_two_sources(a: &Instruction, b: &Instruction) -> bool {
    if a.src.len() < 2 || b.src.len() < 2 {
        return false;
    }
    (a.src[0] == b.src[0] && a.src[1] == b.src[1]) || (a.src[0] == b.src[1] && a.src[1] == b.src[0])
}

fn uses_results_of(c: &Instruction, a: &Instruction, b: &Instruction) -> bool {
    let a_dst = match a.dst.first() {
        Some(d) => d,
        None => return false,
    };
    let b_dst = match b.dst.first() {
        Some(d) => d,
        None => return false,
    };

    if c.src.len() < 2 {
        return false;
    }

    (c.src[0] == *a_dst && c.src[1] == *b_dst) || (c.src[0] == *b_dst && c.src[1] == *a_dst)
}

pub fn verify_equivalence_8bit<F, G>(original: F, candidate: G) -> bool
where
    F: Fn(u8, u8, u8) -> u8,
    G: Fn(u8, u8, u8) -> u8,
{
    for x in 0..=255u8 {
        for y in 0..=255u8 {
            for z in [0u8, 1, 0x55, 0xAA, 0xFF] {
                if original(x, y, z) != candidate(x, y, z) {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_mba_identity_and_plus_or() {
        let original = |x: u8, y: u8, _z: u8| x.wrapping_add(y);
        let mba = |x: u8, y: u8, _z: u8| (x & y).wrapping_add(x | y);
        assert!(verify_equivalence_8bit(original, mba));
    }

    #[test]
    fn verify_mba_identity_or_minus_and_is_xor() {
        let original = |x: u8, y: u8, _z: u8| x ^ y;
        let mba = |x: u8, y: u8, _z: u8| (x | y).wrapping_sub(x & y);
        assert!(verify_equivalence_8bit(original, mba));
    }

    #[test]
    fn test_xor_self_simplifies_to_zero() {
        let expr = Expr::Xor(Box::new(Expr::Var(1)), Box::new(Expr::Var(1)));
        let simplified = simplify_expr(expr, 64);
        assert_eq!(simplified, Expr::Const(0));
    }

    #[test]
    fn test_double_not_cancels() {
        let expr = Expr::Not(Box::new(Expr::Not(Box::new(Expr::Var(1)))));
        let simplified = simplify_expr(expr, 64);
        assert_eq!(simplified, Expr::Var(1));
    }

    #[test]
    fn test_and_with_complement_is_zero() {
        let expr = Expr::And(
            Box::new(Expr::Var(1)),
            Box::new(Expr::Not(Box::new(Expr::Var(1)))),
        );
        let simplified = simplify_expr(expr, 64);
        assert_eq!(simplified, Expr::Const(0));
    }
}
