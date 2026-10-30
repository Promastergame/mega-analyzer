//! **Opaque Predicate Removal** — the anti-obfuscation sniper.
//!
//! Opaque predicates are conditional branches whose outcome is statically
//! deterministic (always-true or always-false), but whose condition is
//! designed to look complex to a human or simple analyzer.

use std::time::Instant;

use omnisec_cfg::ControlFlowGraph;
use omnisec_ir::{Condition, Instruction, OpCode, Operand};
use std::collections::HashMap as FxHashMap;

use super::DeobfuscationPass;
use crate::lattice::AbstractValue;
use crate::stats::PassStats;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IntervalValue {
    lo: i64,
    hi: i64,
}

impl IntervalValue {
    fn top() -> Self {
        Self {
            lo: i64::MIN,
            hi: i64::MAX,
        }
    }
    fn exact(v: i64) -> Self {
        Self { lo: v, hi: v }
    }
    fn meet(self, other: Self) -> Self {
        Self {
            lo: self.lo.min(other.lo),
            hi: self.hi.max(other.hi),
        }
    }
    fn refutes_condition(&self, cond: Condition, other: &IntervalValue) -> Option<bool> {
        match cond {
            Condition::SignedLess => {
                if self.hi < other.lo {
                    Some(true)
                } else if self.lo >= other.hi {
                    Some(false)
                } else {
                    None
                }
            }
            Condition::SignedGreater => {
                if self.lo > other.hi {
                    Some(true)
                } else if self.hi <= other.lo {
                    Some(false)
                } else {
                    None
                }
            }
            Condition::SignedLessEq => {
                if self.hi <= other.lo {
                    Some(true)
                } else if self.lo > other.hi {
                    Some(false)
                } else {
                    None
                }
            }
            Condition::SignedGreaterEq => {
                if self.lo >= other.hi {
                    Some(true)
                } else if self.hi < other.lo {
                    Some(false)
                } else {
                    None
                }
            }
            Condition::Equal => {
                if self.lo == self.hi && other.lo == other.hi && self.lo == other.lo {
                    Some(true)
                } else if self.hi < other.lo || self.lo > other.hi {
                    Some(false)
                } else {
                    None
                }
            }
            Condition::NotEqual => {
                if self.hi < other.lo || self.lo > other.hi {
                    Some(true)
                } else if self.lo == self.hi && other.lo == other.hi && self.lo == other.lo {
                    Some(false)
                } else {
                    None
                }
            }
            Condition::Zero => {
                if self.lo == 0 && self.hi == 0 {
                    Some(true)
                } else if self.hi < 0 || self.lo > 0 {
                    Some(false)
                } else {
                    None
                }
            }
            Condition::NotZero => {
                if self.hi < 0 || self.lo > 0 {
                    Some(true)
                } else if self.lo == 0 && self.hi == 0 {
                    Some(false)
                } else {
                    None
                }
            }
            Condition::Negative => {
                if self.hi < 0 {
                    Some(true)
                } else if self.lo >= 0 {
                    Some(false)
                } else {
                    None
                }
            }
            Condition::NonNegative => {
                if self.lo >= 0 {
                    Some(true)
                } else if self.hi < 0 {
                    Some(false)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KnownBits {
    zeros: u64,
    ones: u64,
}

impl KnownBits {
    fn top() -> Self {
        Self { zeros: 0, ones: 0 }
    }
    fn exact(v: u64) -> Self {
        Self { zeros: !v, ones: v }
    }
    fn meet(self, other: Self) -> Self {
        Self {
            zeros: self.zeros & other.zeros,
            ones: self.ones & other.ones,
        }
    }
    fn refutes_and_eq_zero(&self, mask: u64) -> Option<bool> {
        if self.zeros & mask == mask {
            Some(true)
        } else if self.ones & mask != 0 {
            Some(false)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Congruence {
    residue: i64,
    modulus: u64,
}

impl Congruence {
    fn top() -> Self {
        Self {
            residue: 0,
            modulus: 0,
        }
    }
    fn exact(v: i64) -> Self {
        Self {
            residue: v,
            modulus: 1,
        }
    }
    fn even() -> Self {
        Self {
            residue: 0,
            modulus: 2,
        }
    }
    fn meet(self, other: Self) -> Self {
        if self.modulus == 0 {
            return other;
        }
        if other.modulus == 0 {
            return self;
        }
        if self.modulus == other.modulus && self.residue == other.residue {
            self
        } else {
            Self::top()
        }
    }
    fn refutes_eq_zero_mod_n(&self, n: u64) -> Option<bool> {
        if self.modulus == 0 {
            return None;
        }
        if n == 0 {
            return None;
        }
        if self.modulus % n == 0 {
            Some(self.residue as u64 % n == 0)
        } else {
            None
        }
    }
}

/// Opaque predicate removal pass.
pub struct OpaquePredicatePass;

impl DeobfuscationPass for OpaquePredicatePass {
    fn name(&self) -> &'static str {
        "OpaquePredicateRemoval"
    }

    fn run(&self, cfg: &mut ControlFlowGraph) -> PassStats {
        let start = Instant::now();
        let mut stats = PassStats::new(self.name());

        let rpo = cfg.reverse_postorder();
        let mut block_states: FxHashMap<u32, FxHashMap<u32, AbstractValue>> = FxHashMap::default();
        let mut interval_states: FxHashMap<u32, FxHashMap<u32, IntervalValue>> =
            FxHashMap::default();
        let mut known_bits_states: FxHashMap<u32, FxHashMap<u32, KnownBits>> = FxHashMap::default();
        let mut congruence_states: FxHashMap<u32, FxHashMap<u32, Congruence>> =
            FxHashMap::default();

        for &block_id in &rpo {
            let block = match cfg.block(block_id) {
                Some(b) => b,
                None => continue,
            };

            let preds = cfg.predecessors(block_id);
            let mut state: FxHashMap<u32, AbstractValue> = FxHashMap::default();
            let mut intervals: FxHashMap<u32, IntervalValue> = FxHashMap::default();
            let mut known_bits: FxHashMap<u32, KnownBits> = FxHashMap::default();
            let mut congruences: FxHashMap<u32, Congruence> = FxHashMap::default();

            if !preds.is_empty() {
                // To do intersection correctly, we initialize with the first predecessor
                let mut first = true;
                for &pred_id in preds {
                    if let Some(pred_state) = block_states.get(&pred_id) {
                        if first {
                            state = pred_state.clone();
                        } else {
                            for (reg, val) in pred_state {
                                let entry = state.entry(*reg).or_insert(AbstractValue::Top);
                                *entry = entry.meet(*val);
                            }
                        }
                    }
                    if let Some(pred_intervals) = interval_states.get(&pred_id) {
                        if first {
                            intervals = pred_intervals.clone();
                        } else {
                            for (reg, val) in pred_intervals {
                                let entry = intervals.entry(*reg).or_insert(IntervalValue::top());
                                *entry = entry.meet(*val);
                            }
                        }
                    }
                    if let Some(pred_kb) = known_bits_states.get(&pred_id) {
                        if first {
                            known_bits = pred_kb.clone();
                        } else {
                            for (reg, val) in pred_kb {
                                let entry = known_bits.entry(*reg).or_insert(KnownBits::top());
                                *entry = entry.meet(*val);
                            }
                        }
                    }
                    if let Some(pred_cong) = congruence_states.get(&pred_id) {
                        if first {
                            congruences = pred_cong.clone();
                        } else {
                            for (reg, val) in pred_cong {
                                let entry = congruences.entry(*reg).or_insert(Congruence::top());
                                *entry = entry.meet(*val);
                            }
                        }
                    }
                    first = false;
                }
            }

            for insn in &block.instructions {
                update_state_extended(
                    insn,
                    &mut state,
                    &mut intervals,
                    &mut known_bits,
                    &mut congruences,
                );
            }

            block_states.insert(block_id, state);
            interval_states.insert(block_id, intervals);
            known_bits_states.insert(block_id, known_bits);
            congruence_states.insert(block_id, congruences);
        }

        let block_ids: Vec<u32> = cfg.block_ids().collect();
        for block_id in block_ids {
            let block = match cfg.block(block_id) {
                Some(b) => b,
                None => continue,
            };

            let state = block_states.get(&block_id).cloned().unwrap_or_default();
            let intervals = interval_states.get(&block_id).cloned().unwrap_or_default();
            let known_bits = known_bits_states
                .get(&block_id)
                .cloned()
                .unwrap_or_default();
            let _congruences = congruence_states
                .get(&block_id)
                .cloned()
                .unwrap_or_default();

            let terminator = match block.terminator() {
                Some(t) if t.opcode == OpCode::BranchIf => t.clone(),
                _ => continue,
            };

            let mut resolution = resolve_branch(&terminator, &state);

            // Fallback to advanced domains
            if resolution == BranchResolution::Unknown {
                if let Some(cond) = terminator.condition {
                    // Try intervals
                    let a_interval = terminator.src.first().and_then(|op| match op {
                        Operand::Immediate(v) => Some(IntervalValue::exact(*v)),
                        Operand::Register(r) => intervals.get(&r.native_id).copied(),
                        _ => None,
                    });
                    let b_interval = terminator
                        .src
                        .get(1)
                        .and_then(|op| match op {
                            Operand::Immediate(v) => Some(IntervalValue::exact(*v)),
                            Operand::Register(r) => intervals.get(&r.native_id).copied(),
                            _ => None,
                        })
                        .unwrap_or_else(|| IntervalValue::exact(0)); // Default to 0 for unary conditions

                    if let Some(a_int) = a_interval {
                        if let Some(res) = a_int.refutes_condition(cond, &b_interval) {
                            resolution = if res {
                                BranchResolution::AlwaysTrue
                            } else {
                                BranchResolution::AlwaysFalse
                            };
                            stats
                                .trace
                                .push(format!("Resolved by Interval Domain at block {block_id}"));
                        }
                    }

                    // Try known bits (e.g. AND with mask == 0)
                    if resolution == BranchResolution::Unknown {
                        if cond == Condition::Zero || cond == Condition::Equal {
                            let a_kb = terminator.src.first().and_then(|op| match op {
                                Operand::Immediate(v) => Some(KnownBits::exact(*v as u64)),
                                Operand::Register(r) => known_bits.get(&r.native_id).copied(),
                                _ => None,
                            });
                            // Usually this implies checking against 0 or a mask
                            // Here we just do a simplified check for mask == 0 if b is 0
                            let b_val = terminator
                                .src
                                .get(1)
                                .and_then(|op| match op {
                                    Operand::Immediate(v) => Some(*v),
                                    _ => None,
                                })
                                .unwrap_or(0);

                            if b_val == 0 {
                                if let Some(akb) = a_kb {
                                    if akb.ones != 0 {
                                        resolution = BranchResolution::AlwaysFalse;
                                        stats.trace.push(format!(
                                            "Resolved by KnownBits Domain at block {block_id}"
                                        ));
                                    } else if akb.zeros == u64::MAX {
                                        resolution = BranchResolution::AlwaysTrue;
                                        stats.trace.push(format!(
                                            "Resolved by KnownBits Domain at block {block_id}"
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            match resolution {
                BranchResolution::AlwaysTrue => {
                    stats.opaque_predicates_removed += 1;
                    stats.instructions_changed += 1;
                    stats.trace.push(format!(
                        "Opaque predicate at block {block_id}: always TRUE → unconditional jump"
                    ));

                    if let Some(block_mut) = cfg.block_mut(block_id) {
                        if let Some(last) = block_mut.instructions.last_mut() {
                            let target = last.src.iter().find(|o| o.is_label()).cloned();
                            *last =
                                Instruction::new(OpCode::Jump, last.address, last.size, last.arch);
                            if let Some(t) = target {
                                last.src = [t].into_iter().collect();
                            }
                        }
                    }
                }
                BranchResolution::AlwaysFalse => {
                    stats.opaque_predicates_removed += 1;
                    stats.instructions_changed += 1;
                    stats.trace.push(format!(
                        "Opaque predicate at block {block_id}: always FALSE → fallthrough (NOP)"
                    ));

                    if let Some(block_mut) = cfg.block_mut(block_id) {
                        if let Some(last) = block_mut.instructions.last_mut() {
                            *last =
                                Instruction::new(OpCode::Nop, last.address, last.size, last.arch);
                        }
                    }
                }
                BranchResolution::Unknown => {
                    if let Some(identity) = detect_algebraic_identity(&terminator) {
                        stats.opaque_predicates_removed += 1;
                        stats.instructions_changed += 1;
                        stats.trace.push(format!(
                            "Algebraic opaque predicate at block {block_id}: {identity}"
                        ));
                    }
                }
            }
        }

        stats.duration = start.elapsed();
        stats
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchResolution {
    AlwaysTrue,
    AlwaysFalse,
    Unknown,
}

fn resolve_branch(insn: &Instruction, state: &FxHashMap<u32, AbstractValue>) -> BranchResolution {
    let condition = match insn.condition {
        Some(c) => c,
        None => return BranchResolution::Unknown,
    };

    match condition {
        Condition::Always => return BranchResolution::AlwaysTrue,
        Condition::Never => return BranchResolution::AlwaysFalse,
        _ => {}
    }

    let a = insn.src.first().and_then(|op| resolve_value(op, state));
    let b = insn.src.get(1).and_then(|op| resolve_value(op, state));

    match (a, b) {
        (Some(va), Some(vb)) => {
            let result = evaluate_condition(condition, va, vb);
            if result {
                BranchResolution::AlwaysTrue
            } else {
                BranchResolution::AlwaysFalse
            }
        }
        (Some(va), None) => match condition {
            Condition::Zero => {
                if va == 0 {
                    BranchResolution::AlwaysTrue
                } else {
                    BranchResolution::AlwaysFalse
                }
            }
            Condition::NotZero => {
                if va != 0 {
                    BranchResolution::AlwaysTrue
                } else {
                    BranchResolution::AlwaysFalse
                }
            }
            Condition::Negative => {
                if va < 0 {
                    BranchResolution::AlwaysTrue
                } else {
                    BranchResolution::AlwaysFalse
                }
            }
            Condition::NonNegative => {
                if va >= 0 {
                    BranchResolution::AlwaysTrue
                } else {
                    BranchResolution::AlwaysFalse
                }
            }
            _ => BranchResolution::Unknown,
        },
        _ => BranchResolution::Unknown,
    }
}

fn resolve_value(op: &Operand, state: &FxHashMap<u32, AbstractValue>) -> Option<i64> {
    match op {
        Operand::Immediate(v) => Some(*v),
        Operand::Register(r) => state.get(&r.native_id).and_then(|v| v.as_const()),
        _ => None,
    }
}

fn evaluate_condition(cond: Condition, a: i64, b: i64) -> bool {
    match cond {
        Condition::Always => true,
        Condition::Never => false,
        Condition::Equal => a == b,
        Condition::NotEqual => a != b,
        Condition::SignedLess => a < b,
        Condition::SignedLessEq => a <= b,
        Condition::SignedGreater => a > b,
        Condition::SignedGreaterEq => a >= b,
        Condition::UnsignedLess => (a as u64) < (b as u64),
        Condition::UnsignedLessEq => (a as u64) <= (b as u64),
        Condition::UnsignedGreater => (a as u64) > (b as u64),
        Condition::UnsignedGreaterEq => (a as u64) >= (b as u64),
        Condition::Zero => a == 0,
        Condition::NotZero => a != 0,
        Condition::Negative => a < 0,
        Condition::NonNegative => a >= 0,
        Condition::Carry | Condition::NoCarry | Condition::Overflow | Condition::NoOverflow => {
            false
        }
    }
}

fn detect_algebraic_identity(insn: &Instruction) -> Option<String> {
    let condition = insn.condition?;

    if insn.src.len() >= 2 && insn.src[0] == insn.src[1] {
        return match condition {
            Condition::Equal
            | Condition::SignedLessEq
            | Condition::SignedGreaterEq
            | Condition::UnsignedLessEq
            | Condition::UnsignedGreaterEq => {
                Some("x cmp x → always true (identity comparison)".into())
            }
            Condition::NotEqual
            | Condition::SignedLess
            | Condition::SignedGreater
            | Condition::UnsignedLess
            | Condition::UnsignedGreater => {
                Some("x cmp x → always false (identity comparison)".into())
            }
            _ => None,
        };
    }

    None
}

fn update_state_extended(
    insn: &Instruction,
    state: &mut FxHashMap<u32, AbstractValue>,
    intervals: &mut FxHashMap<u32, IntervalValue>,
    known_bits: &mut FxHashMap<u32, KnownBits>,
    congruences: &mut FxHashMap<u32, Congruence>,
) {
    let dst_reg = match insn.dst.first() {
        Some(Operand::Register(r)) => r.native_id,
        _ => return,
    };

    match insn.opcode {
        OpCode::Move => {
            if let Some(op) = insn.src.first() {
                match op {
                    Operand::Immediate(v) => {
                        state.insert(dst_reg, AbstractValue::Const(*v));
                        intervals.insert(dst_reg, IntervalValue::exact(*v));
                        known_bits.insert(dst_reg, KnownBits::exact(*v as u64));
                        congruences.insert(dst_reg, Congruence::exact(*v));
                    }
                    Operand::Register(r) => {
                        let id = r.native_id;
                        state.insert(
                            dst_reg,
                            state.get(&id).copied().unwrap_or(AbstractValue::Top),
                        );
                        intervals.insert(
                            dst_reg,
                            intervals.get(&id).copied().unwrap_or(IntervalValue::top()),
                        );
                        known_bits.insert(
                            dst_reg,
                            known_bits.get(&id).copied().unwrap_or(KnownBits::top()),
                        );
                        congruences.insert(
                            dst_reg,
                            congruences.get(&id).copied().unwrap_or(Congruence::top()),
                        );
                    }
                    _ => {
                        state.insert(dst_reg, AbstractValue::Bottom);
                        intervals.insert(dst_reg, IntervalValue::top());
                        known_bits.insert(dst_reg, KnownBits::top());
                        congruences.insert(dst_reg, Congruence::top());
                    }
                }
            }
        }
        OpCode::Add => {
            if insn.src.len() == 2 {
                if let (Operand::Immediate(a), Operand::Immediate(b)) = (&insn.src[0], &insn.src[1])
                {
                    let sum = a.wrapping_add(*b);
                    state.insert(dst_reg, AbstractValue::Const(sum));
                    intervals.insert(dst_reg, IntervalValue::exact(sum));
                    known_bits.insert(dst_reg, KnownBits::exact(sum as u64));
                    congruences.insert(dst_reg, Congruence::exact(sum));
                } else {
                    state.insert(dst_reg, AbstractValue::Bottom);
                    intervals.insert(dst_reg, IntervalValue::top());
                    known_bits.insert(dst_reg, KnownBits::top());
                    congruences.insert(dst_reg, Congruence::top());
                }
            }
        }
        OpCode::And => {
            if insn.src.len() == 2 {
                let id = match &insn.src[0] {
                    Operand::Register(r) => Some(r.native_id),
                    _ => None,
                };
                if let (Some(r), Operand::Immediate(mask)) = (id, &insn.src[1]) {
                    let mut kb = known_bits.get(&r).copied().unwrap_or(KnownBits::top());
                    kb.zeros |= !(*mask as u64);
                    kb.ones &= *mask as u64;
                    known_bits.insert(dst_reg, kb);
                } else {
                    known_bits.insert(dst_reg, KnownBits::top());
                }
                state.insert(dst_reg, AbstractValue::Bottom);
                intervals.insert(dst_reg, IntervalValue::top());
                congruences.insert(dst_reg, Congruence::top());
            }
        }
        OpCode::Or => {
            if insn.src.len() == 2 {
                let id = match &insn.src[0] {
                    Operand::Register(r) => Some(r.native_id),
                    _ => None,
                };
                if let (Some(r), Operand::Immediate(mask)) = (id, &insn.src[1]) {
                    let mut kb = known_bits.get(&r).copied().unwrap_or(KnownBits::top());
                    kb.ones |= *mask as u64;
                    known_bits.insert(dst_reg, kb);
                } else {
                    known_bits.insert(dst_reg, KnownBits::top());
                }
                state.insert(dst_reg, AbstractValue::Bottom);
                intervals.insert(dst_reg, IntervalValue::top());
                congruences.insert(dst_reg, Congruence::top());
            }
        }
        OpCode::Xor => {
            if insn.src.len() == 2 && insn.src[0] == insn.src[1] {
                // Xor(x, x) -> 0
                state.insert(dst_reg, AbstractValue::Const(0));
                intervals.insert(dst_reg, IntervalValue::exact(0));
                known_bits.insert(dst_reg, KnownBits::exact(0));
                congruences.insert(dst_reg, Congruence::exact(0));
            } else {
                state.insert(dst_reg, AbstractValue::Bottom);
                intervals.insert(dst_reg, IntervalValue::top());
                known_bits.insert(dst_reg, KnownBits::top());
                congruences.insert(dst_reg, Congruence::top());
            }
        }
        OpCode::Mul => {
            if insn.src.len() == 2 && insn.src[0] == insn.src[1] {
                // Mul(x, x) -> square, always >= 0
                state.insert(dst_reg, AbstractValue::Bottom);
                intervals.insert(
                    dst_reg,
                    IntervalValue {
                        lo: 0,
                        hi: i64::MAX,
                    },
                );
                known_bits.insert(dst_reg, KnownBits::top());
                congruences.insert(dst_reg, Congruence::top());
            } else {
                state.insert(dst_reg, AbstractValue::Bottom);
                intervals.insert(dst_reg, IntervalValue::top());
                known_bits.insert(dst_reg, KnownBits::top());
                congruences.insert(dst_reg, Congruence::top());
            }
        }
        _ => {
            state.insert(dst_reg, AbstractValue::Bottom);
            intervals.insert(dst_reg, IntervalValue::top());
            known_bits.insert(dst_reg, KnownBits::top());
            congruences.insert(dst_reg, Congruence::top());
        }
    }
}
