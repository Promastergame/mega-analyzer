//! Obfuscation pattern library.
//!
//! Each pattern is a self-contained recognizer + replacer that operates on
//! a window of OmniIR instructions within a basic block.
//!
//! ## Adding a new pattern
//!
//! 1. Implement [`ObfuscationPattern`] for your struct.
//! 2. Register it in [`PatternLibrary::default_patterns`].
//! 3. Done — the pipeline will pick it up automatically.

use omnisec_ir::{Instruction, OpCode, Operand};

/// Result of a pattern match on a slice of instructions.
#[derive(Debug, Clone)]
pub struct PatternMatchResult {
    /// Index of the first instruction in the matched window.
    pub start_idx: usize,
    /// Number of instructions consumed by this match.
    pub match_len: usize,
    /// Replacement instructions (may be fewer than `match_len` — that's the point).
    pub replacement: Vec<Instruction>,
    /// Human-readable annotation of what was simplified.
    pub annotation: String,
    /// Confidence score (0–100).
    pub confidence: u8,
}

/// Trait for obfuscation pattern recognizers.
pub trait ObfuscationPattern: Send + Sync {
    /// Unique identifier for this pattern.
    fn id(&self) -> &str;
    /// Human-readable name.
    fn name(&self) -> &str;
    /// Category (arithmetic, control_flow, boolean, etc.)
    fn category(&self) -> &str;

    /// Try to match the pattern starting at `insns[start_idx..]`.
    /// Returns `Some(result)` on a match, `None` otherwise.
    fn try_match(&self, insns: &[Instruction], start_idx: usize) -> Option<PatternMatchResult>;
}

/// The pattern library holds all registered patterns.
pub struct PatternLibrary {
    patterns: Vec<Box<dyn ObfuscationPattern>>,
}

impl Default for PatternLibrary {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternLibrary {
    /// Create a new library with all built-in patterns.
    #[must_use]
    pub fn new() -> Self {
        let mut lib = Self {
            patterns: Vec::new(),
        };
        lib.register_defaults();
        lib
    }

    /// Register all built-in patterns.
    fn register_defaults(&mut self) {
        // ── Arithmetic Identity ─────────────────────────────────
        self.register(Box::new(DeadArithmeticPattern));
        self.register(Box::new(ArithmeticIdentityPattern));
        self.register(Box::new(DoubleNegationPattern));
        self.register(Box::new(RedundantMovePattern));
        self.register(Box::new(ConstantFoldingPattern));
        self.register(Box::new(StrengthReductionPattern));
        self.register(Box::new(MbaLinearPattern));
        self.register(Box::new(NopSlidePattern));
        self.register(Box::new(IdentityBitwisePattern));
        self.register(Box::new(SubToNegAddPattern));
    }

    /// Register a custom pattern.
    pub fn register(&mut self, pattern: Box<dyn ObfuscationPattern>) {
        self.patterns.push(pattern);
    }

    /// Run all patterns against the instruction slice and return non-overlapping
    /// matches, sorted by start index.
    pub fn scan(&self, insns: &[Instruction]) -> Vec<PatternMatchResult> {
        let mut all_matches = Vec::new();

        for start in 0..insns.len() {
            for pattern in &self.patterns {
                if let Some(m) = pattern.try_match(insns, start) {
                    all_matches.push(m);
                }
            }
        }

        // Sort by confidence (descending), then by start index
        all_matches.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.start_idx.cmp(&b.start_idx))
        });

        // Remove overlapping matches (greedy: highest confidence wins)
        let mut taken = vec![false; insns.len()];
        let mut result = Vec::new();

        for m in all_matches {
            let end = m.start_idx + m.match_len;
            if end <= insns.len() && !taken[m.start_idx..end].iter().any(|&t| t) {
                for slot in &mut taken[m.start_idx..end] {
                    *slot = true;
                }
                result.push(m);
            }
        }

        // Sort by start index for stable application
        result.sort_by_key(|m| m.start_idx);
        result
    }

    /// Number of registered patterns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Whether the library is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILT-IN PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

/// **Dead Arithmetic**: `x + 0`, `x * 1`, `x ^ 0`, `x | 0`, `x & -1` → `mov dst, x`.
pub struct DeadArithmeticPattern;

impl ObfuscationPattern for DeadArithmeticPattern {
    fn id(&self) -> &'static str {
        "dead_arithmetic"
    }
    fn name(&self) -> &'static str {
        "Dead Arithmetic"
    }
    fn category(&self) -> &'static str {
        "arithmetic"
    }

    fn try_match(&self, insns: &[Instruction], start: usize) -> Option<PatternMatchResult> {
        let insn = insns.get(start)?;
        let identity_val = match insn.opcode {
            OpCode::Add | OpCode::Or | OpCode::Xor => 0i64, // x + 0, x | 0, x ^ 0
            OpCode::Mul | OpCode::Div => 1i64,              // x * 1, x / 1
            OpCode::And => -1i64,                           // x & -1
            OpCode::Shl | OpCode::Shr | OpCode::Sar => 0i64, // x << 0, x >> 0
            _ => return None,
        };

        // Check if the second source operand is the identity value
        let is_identity = insn.src.get(1).is_some_and(|op| match op {
            Operand::Immediate(v) => *v == identity_val,
            _ => false,
        });

        if !is_identity {
            return None;
        }

        // Replace with: mov dst, src0
        let dst = insn.dst.first()?.clone();
        let src = insn.src.first()?.clone();
        let replacement = Instruction::new(OpCode::Move, insn.address, insn.size, insn.arch)
            .with_dst([dst])
            .with_src([src]);

        Some(PatternMatchResult {
            start_idx: start,
            match_len: 1,
            replacement: vec![replacement],
            annotation: format!("{} with identity value → move", self.name()),
            confidence: 95,
        })
    }
}

/// **Arithmetic Identity**: `x - x = 0`, `x ^ x = 0`, `x & 0 = 0`.
pub struct ArithmeticIdentityPattern;

impl ObfuscationPattern for ArithmeticIdentityPattern {
    fn id(&self) -> &'static str {
        "arithmetic_identity"
    }
    fn name(&self) -> &'static str {
        "Arithmetic Identity"
    }
    fn category(&self) -> &'static str {
        "arithmetic"
    }

    fn try_match(&self, insns: &[Instruction], start: usize) -> Option<PatternMatchResult> {
        let insn = insns.get(start)?;

        match insn.opcode {
            // x - x = 0, x ^ x = 0
            OpCode::Sub | OpCode::Xor => {
                if insn.src.len() >= 2
                    && insn.src[0] == insn.src[1]
                    && let Some(dst) = insn.dst.first()
                {
                    let replacement =
                        Instruction::new(OpCode::Move, insn.address, insn.size, insn.arch)
                            .with_dst([dst.clone()])
                            .with_src([Operand::Immediate(0)]);
                    return Some(PatternMatchResult {
                        start_idx: start,
                        match_len: 1,
                        replacement: vec![replacement],
                        annotation: format!(
                            "x {} x → 0",
                            if insn.opcode == OpCode::Sub { "-" } else { "^" }
                        ),
                        confidence: 98,
                    });
                }
            }
            // x & 0 = 0
            OpCode::And => {
                let has_zero = insn
                    .src
                    .iter()
                    .any(|op| matches!(op, Operand::Immediate(0)));
                if has_zero && let Some(dst) = insn.dst.first() {
                    let replacement =
                        Instruction::new(OpCode::Move, insn.address, insn.size, insn.arch)
                            .with_dst([dst.clone()])
                            .with_src([Operand::Immediate(0)]);
                    return Some(PatternMatchResult {
                        start_idx: start,
                        match_len: 1,
                        replacement: vec![replacement],
                        annotation: "x & 0 → 0".into(),
                        confidence: 98,
                    });
                }
            }
            _ => {}
        }

        None
    }
}

/// **Double Negation**: `neg(neg(x))` or `not(not(x))` → `mov dst, x`.
pub struct DoubleNegationPattern;

impl ObfuscationPattern for DoubleNegationPattern {
    fn id(&self) -> &'static str {
        "double_negation"
    }
    fn name(&self) -> &'static str {
        "Double Negation"
    }
    fn category(&self) -> &'static str {
        "logical"
    }

    fn try_match(&self, insns: &[Instruction], start: usize) -> Option<PatternMatchResult> {
        if start + 1 >= insns.len() {
            return None;
        }

        let first = &insns[start];
        let second = &insns[start + 1];

        // Both must be the same unary op (neg/neg or not/not)
        if first.opcode != second.opcode {
            return None;
        }
        if !matches!(first.opcode, OpCode::Neg | OpCode::Not) {
            return None;
        }

        // The output of the first must be the input of the second
        let first_dst = first.dst.first()?;
        let second_src = second.src.first()?;
        if first_dst != second_src {
            return None;
        }

        let original_src = first.src.first()?.clone();
        let final_dst = second.dst.first()?.clone();
        let replacement = Instruction::new(OpCode::Move, first.address, first.size, first.arch)
            .with_dst([final_dst])
            .with_src([original_src]);

        Some(PatternMatchResult {
            start_idx: start,
            match_len: 2,
            replacement: vec![replacement],
            annotation: format!(
                "{}({1}(x)) → x",
                if first.opcode == OpCode::Neg {
                    "neg"
                } else {
                    "not"
                },
                if first.opcode == OpCode::Neg {
                    "neg"
                } else {
                    "not"
                }
            ),
            confidence: 96,
        })
    }
}

/// **Redundant Move**: `mov x, y; mov x, z` → just `mov x, z`
/// (first move is dead — overwritten before use).
pub struct RedundantMovePattern;

impl ObfuscationPattern for RedundantMovePattern {
    fn id(&self) -> &'static str {
        "redundant_move"
    }
    fn name(&self) -> &'static str {
        "Redundant Move"
    }
    fn category(&self) -> &'static str {
        "assignment"
    }

    fn try_match(&self, insns: &[Instruction], start: usize) -> Option<PatternMatchResult> {
        if start + 1 >= insns.len() {
            return None;
        }

        let first = &insns[start];
        let second = &insns[start + 1];

        if first.opcode != OpCode::Move || second.opcode != OpCode::Move {
            return None;
        }

        // Same destination, so the first write is dead
        let first_dst = first.dst.first()?;
        let second_dst = second.dst.first()?;

        if first_dst != second_dst {
            return None;
        }

        // Also make sure the second instruction doesn't read from the same register
        let second_reads_first = second.src.iter().any(|s| s == first_dst);
        if second_reads_first {
            return None; // mov x, 5; mov x, x+1 — first is NOT dead
        }

        Some(PatternMatchResult {
            start_idx: start,
            match_len: 1, // Just remove the first one
            replacement: vec![],
            annotation: "Redundant move (overwritten) → removed".into(),
            confidence: 92,
        })
    }
}

/// **Constant Folding**: `mov r, C1; add r, C2` → `mov r, C1+C2`.
pub struct ConstantFoldingPattern;

impl ObfuscationPattern for ConstantFoldingPattern {
    fn id(&self) -> &'static str {
        "constant_folding"
    }
    fn name(&self) -> &'static str {
        "Constant Folding"
    }
    fn category(&self) -> &'static str {
        "arithmetic"
    }

    fn try_match(&self, insns: &[Instruction], start: usize) -> Option<PatternMatchResult> {
        if start + 1 >= insns.len() {
            return None;
        }

        let first = &insns[start];
        let second = &insns[start + 1];

        // First must be: mov reg, immediate
        if first.opcode != OpCode::Move {
            return None;
        }
        let dst_reg = first.dst.first()?;
        let c1 = match first.src.first()? {
            Operand::Immediate(v) => *v,
            _ => return None,
        };

        // Second must be: binop reg, reg, immediate (same dst/src1)
        let binop = crate::lattice::opcode_to_binop(second.opcode)?;
        let second_dst = second.dst.first()?;
        if second_dst != dst_reg {
            return None;
        }

        // src0 must be the same register, src1 must be immediate
        let second_src0 = second.src.first()?;
        if second_src0 != dst_reg {
            return None;
        }
        let c2 = match second.src.get(1)? {
            Operand::Immediate(v) => *v,
            _ => return None,
        };

        // Fold!
        let av = crate::lattice::AbstractValue::Const(c1);
        let bv = crate::lattice::AbstractValue::Const(c2);
        let result = av.eval_binop(binop, bv).as_const()?;

        let replacement = Instruction::new(OpCode::Move, first.address, first.size, first.arch)
            .with_dst([dst_reg.clone()])
            .with_src([Operand::Immediate(result)]);

        Some(PatternMatchResult {
            start_idx: start,
            match_len: 2,
            replacement: vec![replacement],
            annotation: format!("mov {c1:#x}; op {c2:#x} → mov {result:#x}"),
            confidence: 99,
        })
    }
}

/// **Strength Reduction**: `mul x, 2` → `shl x, 1` (and similar power-of-two cases).
pub struct StrengthReductionPattern;

impl ObfuscationPattern for StrengthReductionPattern {
    fn id(&self) -> &'static str {
        "strength_reduction"
    }
    fn name(&self) -> &'static str {
        "Strength Reduction"
    }
    fn category(&self) -> &'static str {
        "arithmetic"
    }

    fn try_match(&self, insns: &[Instruction], start: usize) -> Option<PatternMatchResult> {
        let insn = insns.get(start)?;

        if insn.opcode != OpCode::Mul {
            return None;
        }

        // Check for multiplication by a power of 2
        let imm = match insn.src.get(1)? {
            Operand::Immediate(v) if *v > 0 && (*v as u64).is_power_of_two() => *v,
            _ => return None,
        };

        let shift = (imm as u64).trailing_zeros() as i64;
        let dst = insn.dst.first()?.clone();
        let src = insn.src.first()?.clone();

        let replacement = Instruction::new(OpCode::Shl, insn.address, insn.size, insn.arch)
            .with_dst([dst])
            .with_src([src, Operand::Immediate(shift)]);

        Some(PatternMatchResult {
            start_idx: start,
            match_len: 1,
            replacement: vec![replacement],
            annotation: format!("mul {imm} → shl {shift}"),
            confidence: 90,
        })
    }
}

/// **Linear MBA Simplification**: `(x & y) + (x | y)` → `x + y`.
///
/// Mixed Boolean-Arithmetic (MBA) expressions are a common obfuscation technique.
/// This pattern recognizes the simplest linear MBA identities.
pub struct MbaLinearPattern;

impl ObfuscationPattern for MbaLinearPattern {
    fn id(&self) -> &'static str {
        "mba_linear"
    }
    fn name(&self) -> &'static str {
        "MBA Linear Identity"
    }
    fn category(&self) -> &'static str {
        "mba"
    }

    fn try_match(&self, insns: &[Instruction], start: usize) -> Option<PatternMatchResult> {
        // We need at least 3 instructions:
        //   t1 = x & y
        //   t2 = x | y
        //   result = t1 + t2
        if start + 2 >= insns.len() {
            return None;
        }

        let i0 = &insns[start];
        let i1 = &insns[start + 1];
        let i2 = &insns[start + 2];

        if i0.opcode != OpCode::And || i1.opcode != OpCode::Or || i2.opcode != OpCode::Add {
            return None;
        }

        // Check operands: AND and OR must have the same two source operands
        if i0.src.len() < 2 || i1.src.len() < 2 {
            return None;
        }
        if i0.src[0] != i1.src[0] || i0.src[1] != i1.src[1] {
            return None;
        }

        // ADD must use the results of AND and OR
        let and_dst = i0.dst.first()?;
        let or_dst = i1.dst.first()?;

        let add_uses_both = i2.src.len() >= 2
            && ((i2.src[0] == *and_dst && i2.src[1] == *or_dst)
                || (i2.src[0] == *or_dst && i2.src[1] == *and_dst));

        if !add_uses_both {
            return None;
        }

        // Replace with: result = x + y
        let final_dst = i2.dst.first()?.clone();
        let x = i0.src[0].clone();
        let y = i0.src[1].clone();

        let replacement = Instruction::new(OpCode::Add, i0.address, i0.size, i0.arch)
            .with_dst([final_dst])
            .with_src([x, y]);

        Some(PatternMatchResult {
            start_idx: start,
            match_len: 3,
            replacement: vec![replacement],
            annotation: "(x & y) + (x | y) → x + y".into(),
            confidence: 94,
        })
    }
}

/// **NOP Slide**: sequences of `Nop` instructions → removed entirely.
pub struct NopSlidePattern;

impl ObfuscationPattern for NopSlidePattern {
    fn id(&self) -> &'static str {
        "nop_slide"
    }
    fn name(&self) -> &'static str {
        "NOP Slide"
    }
    fn category(&self) -> &'static str {
        "junk_code"
    }

    fn try_match(&self, insns: &[Instruction], start: usize) -> Option<PatternMatchResult> {
        let insn = insns.get(start)?;
        if insn.opcode != OpCode::Nop {
            return None;
        }

        // Count consecutive NOPs
        let mut count = 1;
        while start + count < insns.len() && insns[start + count].opcode == OpCode::Nop {
            count += 1;
        }

        Some(PatternMatchResult {
            start_idx: start,
            match_len: count,
            replacement: vec![],
            annotation: format!("{count} consecutive NOPs removed"),
            confidence: 100,
        })
    }
}

/// **Identity Bitwise**: `x | x = x`, `x & x = x`.
pub struct IdentityBitwisePattern;

impl ObfuscationPattern for IdentityBitwisePattern {
    fn id(&self) -> &'static str {
        "identity_bitwise"
    }
    fn name(&self) -> &'static str {
        "Identity Bitwise"
    }
    fn category(&self) -> &'static str {
        "bitwise"
    }

    fn try_match(&self, insns: &[Instruction], start: usize) -> Option<PatternMatchResult> {
        let insn = insns.get(start)?;

        match insn.opcode {
            OpCode::Or | OpCode::And if insn.src.len() >= 2 && insn.src[0] == insn.src[1] => {
                let dst = insn.dst.first()?.clone();
                let src = insn.src[0].clone();
                let replacement =
                    Instruction::new(OpCode::Move, insn.address, insn.size, insn.arch)
                        .with_dst([dst])
                        .with_src([src]);
                return Some(PatternMatchResult {
                    start_idx: start,
                    match_len: 1,
                    replacement: vec![replacement],
                    annotation: format!(
                        "x {} x → x",
                        if insn.opcode == OpCode::Or { "|" } else { "&" }
                    ),
                    confidence: 97,
                });
            }
            _ => {}
        }

        None
    }
}

/// **Subtraction to Negate-Add**: detect `x + (-y)` pattern used to hide subtraction.
pub struct SubToNegAddPattern;

impl ObfuscationPattern for SubToNegAddPattern {
    fn id(&self) -> &'static str {
        "sub_to_neg_add"
    }
    fn name(&self) -> &'static str {
        "Hidden Subtraction"
    }
    fn category(&self) -> &'static str {
        "arithmetic"
    }

    fn try_match(&self, insns: &[Instruction], start: usize) -> Option<PatternMatchResult> {
        if start + 1 >= insns.len() {
            return None;
        }

        let first = &insns[start];
        let second = &insns[start + 1];

        // neg tmp, y
        if first.opcode != OpCode::Neg {
            return None;
        }
        // add dst, x, tmp
        if second.opcode != OpCode::Add {
            return None;
        }

        let neg_dst = first.dst.first()?;
        let neg_src = first.src.first()?.clone();

        // The add must use the negated value
        let add_uses_neg = second.src.iter().any(|s| s == neg_dst);
        if !add_uses_neg {
            return None;
        }

        // The other source of the add is our `x`
        let x = second.src.iter().find(|s| *s != neg_dst)?.clone();
        let final_dst = second.dst.first()?.clone();

        let replacement = Instruction::new(OpCode::Sub, first.address, first.size, first.arch)
            .with_dst([final_dst])
            .with_src([x, neg_src]);

        Some(PatternMatchResult {
            start_idx: start,
            match_len: 2,
            replacement: vec![replacement],
            annotation: "neg y; add x, -y → sub x, y".into(),
            confidence: 93,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_core::Arch;
    use omnisec_ir::operand::{Register, RegisterClass};

    fn make_reg(id: u32) -> Register {
        Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: id,
            bit_width: 64,
            name: format!("r{id}"),
        }
    }

    #[test]
    fn dead_arithmetic_add_zero() {
        let r0 = make_reg(0);
        let insn = Instruction::new(OpCode::Add, 0, 4, Arch::X86_64)
            .with_dst([Operand::Register(r0.clone())])
            .with_src([Operand::Register(r0.clone()), Operand::Immediate(0)]);

        let pattern = DeadArithmeticPattern;
        let result = pattern.try_match(&[insn], 0).unwrap();
        assert_eq!(result.replacement.len(), 1);
        assert_eq!(result.replacement[0].opcode, OpCode::Move);
    }

    #[test]
    fn arithmetic_identity_xor_self() {
        let r0 = make_reg(0);
        let insn = Instruction::new(OpCode::Xor, 0, 4, Arch::X86_64)
            .with_dst([Operand::Register(r0.clone())])
            .with_src([Operand::Register(r0.clone()), Operand::Register(r0.clone())]);

        let pattern = ArithmeticIdentityPattern;
        let result = pattern.try_match(&[insn], 0).unwrap();
        assert_eq!(result.replacement.len(), 1);
        // dst should be 0
        assert!(matches!(
            result.replacement[0].src.first(),
            Some(Operand::Immediate(0))
        ));
    }

    #[test]
    fn nop_slide_removal() {
        let nops: Vec<_> = (0..5)
            .map(|i| Instruction::new(OpCode::Nop, i, 1, Arch::X86_64))
            .collect();

        let pattern = NopSlidePattern;
        let result = pattern.try_match(&nops, 0).unwrap();
        assert_eq!(result.match_len, 5);
        assert!(result.replacement.is_empty());
    }

    #[test]
    fn library_scans_all_patterns() {
        let lib = PatternLibrary::new();
        assert!(lib.len() >= 10, "Should have at least 10 built-in patterns");

        let r0 = make_reg(0);
        let insns = vec![
            Instruction::new(OpCode::Nop, 0, 1, Arch::X86_64),
            Instruction::new(OpCode::Nop, 1, 1, Arch::X86_64),
            Instruction::new(OpCode::Add, 2, 4, Arch::X86_64)
                .with_dst([Operand::Register(r0.clone())])
                .with_src([Operand::Register(r0.clone()), Operand::Immediate(0)]),
        ];

        let matches = lib.scan(&insns);
        assert!(matches.len() >= 2, "Should match NOPs and dead arithmetic");
    }
}
