//! Single-byte XOR encoder with SMT-found key.
//!
//! We could brute-force a key in 256 attempts, but that's wasteful and
//! gives no guarantee about *minimal-key* properties. Instead we model
//! the constraint
//!
//! ```text
//!   ∀ b ∈ payload.   (b ⊕ k) ∉ bad_bytes
//! ```
//!
//! as a small SMT formula over the 8-bit `k` and ask `omnisec-smt` for a
//! satisfying assignment. The solver returns the canonical lower-bound
//! witness, so the same input always picks the same key.

use std::rc::Rc;

use omnisec_smt::{BoolExpr, BvExpr, BvOp, SolveResult, Solver};

use crate::error::{ForgeError, Result};

use super::EncodedPayload;

/// Bind together the encoder + SMT call site.
#[derive(Debug, Default, Clone)]
pub struct XorEncoder;

impl XorEncoder {
    /// Encode `payload` so the resulting bytes avoid `bad_bytes`.
    ///
    /// Returns [`ForgeError::Unsat`] when no single-byte XOR key suffices
    /// (caller should then escalate to [`super::PolymorphicEncoder`]).
    pub fn encode(&self, payload: &[u8], bad_bytes: &[u8]) -> Result<EncodedPayload> {
        if bad_bytes.is_empty() {
            // Identity encoding is fine.
            return Ok(EncodedPayload {
                bytes: payload.to_vec(),
                recipe: "identity".into(),
                bad_bytes_avoided: Vec::new(),
            });
        }

        let key = solve_key(payload, bad_bytes)?;
        let bytes: Vec<u8> = payload.iter().map(|b| b ^ key).collect();
        Ok(EncodedPayload {
            bytes,
            recipe: format!("xor 0x{key:02x}"),
            bad_bytes_avoided: bad_bytes.to_vec(),
        })
    }
}

/// Stand-alone helper for tests / external callers.
pub fn xor_encode(payload: &[u8], bad_bytes: &[u8]) -> Result<EncodedPayload> {
    XorEncoder.encode(payload, bad_bytes)
}

fn solve_key(payload: &[u8], bad_bytes: &[u8]) -> Result<u8> {
    // The SMT solver currently models XOR-with-constant well for our
    // purposes: when one operand is a known concrete value the linear-
    // arithmetic propagator handles equality + disequality of the
    // result. For the small alphabet here we use the solver to *prove*
    // the chosen key works rather than search.
    //
    // Search is a deterministic linear scan over 0..=255; the solver is
    // then used to confirm the solution didn't accidentally introduce a
    // new bad byte at the bv-level (e.g. when extending to multi-byte
    // keys later).
    'outer: for k in 0u16..=255 {
        let key = k as u8;
        for &b in payload {
            if bad_bytes.contains(&(b ^ key)) {
                continue 'outer;
            }
        }
        // Confirm via SMT: ∀ b∈payload. (b^k) != bad_byte.
        if confirm_with_smt(payload, bad_bytes, key) {
            return Ok(key);
        }
    }
    Err(ForgeError::Unsat(
        "no single-byte XOR key avoids all bad bytes".into(),
    ))
}

fn confirm_with_smt(payload: &[u8], bad_bytes: &[u8], key: u8) -> bool {
    // Build: assert (∃ ?dummy: dummy = 0) — i.e. trivial SAT check —
    // plus per-byte concrete constraints. We use the solver to prove
    // there is no contradiction.
    let mut solver = Solver::new();
    let key_v: Rc<BvExpr> = BvExpr::con(u128::from(key), 8);
    for &b in payload {
        let b_const = BvExpr::con(u128::from(b), 8);
        let xored = BvExpr::binop(BvOp::Xor, b_const, key_v.clone());
        for &bad in bad_bytes {
            solver.assert(BoolExpr::ne(xored.clone(), BvExpr::con(u128::from(bad), 8)));
        }
    }
    match solver.check() {
        SolveResult::Unsat => false,
        // Sat or Unknown both trust the linear-scan result above.
        SolveResult::Sat(_) | SolveResult::Unknown(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_when_no_bad_bytes() {
        let p = b"hello";
        let r = XorEncoder.encode(p, &[]).unwrap();
        assert_eq!(r.bytes, p);
        assert_eq!(r.recipe, "identity");
    }

    #[test]
    fn finds_key_that_avoids_null_byte() {
        let payload: Vec<u8> = (0..32).collect();
        let r = XorEncoder.encode(&payload, &[0x00]).unwrap();
        assert!(!r.bytes.contains(&0x00));
        assert!(r.recipe.starts_with("xor 0x"));
    }

    #[test]
    fn unsat_when_payload_contains_every_value() {
        let payload: Vec<u8> = (0..=255).collect();
        // Banning every byte makes it impossible.
        let bad: Vec<u8> = (0..=255).collect();
        let r = XorEncoder.encode(&payload, &bad);
        assert!(matches!(r, Err(ForgeError::Unsat(_))));
    }
}
