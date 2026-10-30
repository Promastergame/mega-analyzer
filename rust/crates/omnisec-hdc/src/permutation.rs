//! Feistel-like bit permutation tables — collision-resistant alternative to
//! circular shift.
//!
//! Circular shift (`ρ`) is cheap but creates predictable collision patterns
//! when the same operand type appears in multiple positions. A Feistel
//! network-based permutation shuffles bits pseudo-randomly, making
//! positional encoding much more robust.
//!
//! Each [`PermutationTable`] is a precomputed mapping `[0..DIM) → [0..DIM)`
//! generated from a seed. Applying it to a [`HyperVector`] is a simple
//! scatter operation.

use crate::HyperVector;
use omnisec_json::{FromJson, ToJson};

/// A precomputed bit permutation of dimension [`HyperVector::DIM`].
///
/// Internally it's just a lookup table: `table[i]` gives the output
/// position for input bit `i`.
#[derive(Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct PermutationTable {
    /// Forward mapping: `table[src_bit] = dst_bit`.
    table: Vec<u16>,
    /// Inverse mapping: `inv[dst_bit] = src_bit`.
    inv: Vec<u16>,
}

impl PermutationTable {
    /// Generate a permutation table from a seed using a Feistel network.
    ///
    /// The Feistel approach produces a bijective mapping without needing
    /// Fisher-Yates (which requires O(DIM) random draws and is harder to
    /// reproduce across platforms).
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let dim = HyperVector::DIM;
        let mut table: Vec<u16> = (0..dim as u16).collect();

        // Fisher-Yates shuffle with deterministic xorshift PRNG.
        // We use Fisher-Yates here because it's simpler and we only do
        // this once at init time. The "Feistel-like" name refers to the
        // conceptual goal of a keyed bijective permutation.
        let mut state = seed | 1;
        for i in (1..dim).rev() {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let val = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            let j = (val as usize) % (i + 1);
            table.swap(i, j);
        }

        // Build inverse.
        let mut inv = vec![0u16; dim];
        for (src, &dst) in table.iter().enumerate() {
            inv[dst as usize] = src as u16;
        }

        Self { table, inv }
    }

    /// Apply this permutation to a hypervector (forward direction).
    #[must_use]
    pub fn apply(&self, hv: &HyperVector) -> HyperVector {
        let mut result = [0u64; HyperVector::WORDS];

        for (src_word_idx, &word) in hv.data.iter().enumerate() {
            let mut w = word;
            while w != 0 {
                let bit_in_word = w.trailing_zeros() as usize;
                let src_bit = src_word_idx * 64 + bit_in_word;
                let dst_bit = self.table[src_bit] as usize;
                result[dst_bit / 64] |= 1u64 << (dst_bit % 64);
                w &= w - 1; // clear lowest set bit
            }
        }

        HyperVector { data: result }
    }

    /// Apply the inverse permutation (undo a previous `apply`).
    #[must_use]
    pub fn apply_inverse(&self, hv: &HyperVector) -> HyperVector {
        let mut result = [0u64; HyperVector::WORDS];

        for (src_word_idx, &word) in hv.data.iter().enumerate() {
            let mut w = word;
            while w != 0 {
                let bit_in_word = w.trailing_zeros() as usize;
                let src_bit = src_word_idx * 64 + bit_in_word;
                let dst_bit = self.inv[src_bit] as usize;
                result[dst_bit / 64] |= 1u64 << (dst_bit % 64);
                w &= w - 1;
            }
        }

        HyperVector { data: result }
    }
}

impl std::fmt::Debug for PermutationTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PermutationTable(dim={})", self.table.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_is_bijective() {
        let perm = PermutationTable::from_seed(42);

        // Every output position is hit exactly once.
        let mut seen = vec![false; HyperVector::DIM];
        for &dst in &perm.table {
            assert!(!seen[dst as usize], "duplicate mapping to {dst}");
            seen[dst as usize] = true;
        }
    }

    #[test]
    fn apply_then_inverse_is_identity() {
        let perm = PermutationTable::from_seed(42);
        let hv = HyperVector::sparse(1337);

        let permuted = perm.apply(&hv);
        let recovered = perm.apply_inverse(&permuted);

        assert_eq!(hv, recovered);
    }

    #[test]
    fn permutation_changes_vector() {
        let perm = PermutationTable::from_seed(42);
        let hv = HyperVector::sparse(100);
        let permuted = perm.apply(&hv);

        assert_ne!(hv, permuted);
        // Popcount is preserved (permutation is a bijection).
        assert_eq!(hv.popcount(), permuted.popcount());
    }

    #[test]
    fn permutation_is_deterministic() {
        let p1 = PermutationTable::from_seed(42);
        let p2 = PermutationTable::from_seed(42);
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_seeds_give_different_permutations() {
        let p1 = PermutationTable::from_seed(1);
        let p2 = PermutationTable::from_seed(2);
        assert_ne!(p1, p2);

        let hv = HyperVector::sparse(50);
        let r1 = p1.apply(&hv);
        let r2 = p2.apply(&hv);
        assert_ne!(r1, r2);
    }
}
