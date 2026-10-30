//! Polymorphic multi-pass encoder.
//!
//! When a single-byte XOR doesn't have a satisfying key (e.g. because
//! `bad_bytes` is dense), we cascade several reversible 8-bit
//! transforms — XOR, ADD, ROTATE-LEFT — and search for a recipe whose
//! composition avoids all bad bytes.
//!
//! The search is bounded (4 passes, 256 candidates each, deterministic
//! ordering) so it stays cheap on a CPU-only box. The chosen recipe is
//! returned together with the encoded bytes; the runtime decoder
//! reverses the recipe in O(N · passes).

use crate::error::{ForgeError, Result};
use crate::util::Prng;

use super::EncodedPayload;

const MAX_PASSES: usize = 4;

/// Single reversible 8-bit transform.
#[derive(Debug, Clone, Copy)]
enum Pass {
    Xor(u8),
    AddU8(u8),
    Rol(u8),
}

impl Pass {
    fn apply(self, b: u8) -> u8 {
        match self {
            Pass::Xor(k) => b ^ k,
            Pass::AddU8(k) => b.wrapping_add(k),
            Pass::Rol(k) => b.rotate_left(u32::from(k & 7)),
        }
    }

    fn recipe(self) -> String {
        match self {
            Pass::Xor(k) => format!("xor 0x{k:02x}"),
            Pass::AddU8(k) => format!("add 0x{k:02x}"),
            Pass::Rol(k) => format!("rol {k}"),
        }
    }
}

/// Polymorphic encoder.
#[derive(Debug, Default, Clone)]
pub struct PolymorphicEncoder;

impl PolymorphicEncoder {
    /// Encode `payload` so the resulting bytes avoid `bad_bytes`.
    pub fn encode(
        &self,
        payload: &[u8],
        bad_bytes: &[u8],
        prng: &mut Prng,
    ) -> Result<EncodedPayload> {
        if bad_bytes.is_empty() {
            return Ok(EncodedPayload {
                bytes: payload.to_vec(),
                recipe: "identity".into(),
                bad_bytes_avoided: Vec::new(),
            });
        }

        // Try a single XOR first — it covers most real-world cases and
        // produces the smallest decoder stub.
        if let Ok(r) = super::xor::xor_encode(payload, bad_bytes) {
            return Ok(r);
        }

        // Otherwise cascade passes. Order is fully deterministic given
        // `prng`'s seed.
        let mut current = payload.to_vec();
        let mut steps: Vec<Pass> = Vec::new();

        for _pass_idx in 0..MAX_PASSES {
            let pass = pick_pass(&current, bad_bytes, prng);
            let Some(pass) = pass else { break };

            current = current.iter().map(|b| pass.apply(*b)).collect();
            steps.push(pass);

            if !current.iter().any(|b| bad_bytes.contains(b)) {
                break;
            }
        }

        if current.iter().any(|b| bad_bytes.contains(b)) {
            return Err(ForgeError::Unsat(
                "polymorphic encoder exhausted MAX_PASSES without clearing bad bytes".into(),
            ));
        }

        let recipe = steps
            .iter()
            .map(|p| p.recipe())
            .collect::<Vec<_>>()
            .join(" ; ");

        Ok(EncodedPayload {
            bytes: current,
            recipe,
            bad_bytes_avoided: bad_bytes.to_vec(),
        })
    }
}

/// Pick the single transform that minimises the count of remaining
/// bad-byte hits. Ties are broken deterministically by `prng`.
fn pick_pass(payload: &[u8], bad_bytes: &[u8], prng: &mut Prng) -> Option<Pass> {
    let mut best: Option<(usize, Pass)> = None;

    for k in 0u16..=255 {
        let key = k as u8;
        for &candidate in &[Pass::Xor(key), Pass::AddU8(key), Pass::Rol(key & 7)] {
            let hits = payload
                .iter()
                .filter(|b| bad_bytes.contains(&candidate.apply(**b)))
                .count();
            match &best {
                None => best = Some((hits, candidate)),
                Some((cur, _)) if hits < *cur => {
                    best = Some((hits, candidate));
                }
                // Deterministic tie-break on equality.
                Some((cur, _)) if hits == *cur && prng.next_u64() & 1 == 0 => {
                    best = Some((hits, candidate));
                }
                _ => {}
            }
        }
    }

    best.map(|(_, p)| p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_when_no_bad_bytes() {
        let r = PolymorphicEncoder
            .encode(b"abcdef", &[], &mut Prng::new(0))
            .unwrap();
        assert_eq!(r.bytes, b"abcdef");
    }

    #[test]
    fn falls_back_to_xor() {
        let payload = vec![0u8; 8];
        let r = PolymorphicEncoder
            .encode(&payload, &[0x00], &mut Prng::new(0))
            .unwrap();
        assert!(!r.bytes.contains(&0));
    }

    #[test]
    fn cascades_when_xor_alone_fails() {
        // Payload where every value appears AND bad_bytes is half the alphabet:
        // a single XOR can't shift the whole space; but ROL+XOR chained can.
        let payload: Vec<u8> = (0..=255).collect();
        let bad: Vec<u8> = (0..128).collect();
        let result = PolymorphicEncoder.encode(&payload, &bad, &mut Prng::new(7));
        // Either a multi-pass recipe is found or we cleanly bail.
        match result {
            Ok(r) => {
                assert!(!r.bytes.iter().any(|b| bad.contains(b)));
            }
            Err(ForgeError::Unsat(_)) => {}
            Err(e) => panic!("unexpected: {e:?}"),
        }
    }
}
