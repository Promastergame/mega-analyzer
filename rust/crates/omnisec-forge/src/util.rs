//! Crate-internal utilities.
//!
//! Everything in this module is deterministic and CPU-only — no `rand`,
//! no `std::time`, no system entropy.

/// xorshift64\* deterministic PRNG.
///
/// Same algorithm as `omnisec-hdc`'s codebook generator, kept here as a
/// crate-private copy so we don't have to plumb the HDC PRNG through every
/// Forge module. Two `Prng`s seeded with the same value produce identical
/// streams forever.
#[derive(Debug, Clone)]
pub struct Prng {
    state: u64,
}

impl Prng {
    /// Build a PRNG from `seed`. A zero seed is upgraded to `1` so the
    /// xorshift recurrence never gets stuck.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        let s = if seed == 0 { 1 } else { seed };
        Self { state: s }
    }

    /// Draw the next 64-bit word.
    pub fn next_u64(&mut self) -> u64 {
        let mut s = self.state;
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        self.state = s;
        s.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Draw the next byte.
    pub fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }

    /// Draw a `u64` uniformly in `[lo, hi]` (inclusive). Returns `lo` when
    /// the range is degenerate.
    pub fn range_u64(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        let span = hi.wrapping_sub(lo).wrapping_add(1);
        lo.wrapping_add(self.next_u64() % span)
    }

    /// Yates-style shuffle of `slice` using this PRNG. Stable: same seed,
    /// same permutation.
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        if slice.len() < 2 {
            return;
        }
        for i in (1..slice.len()).rev() {
            let j = (self.next_u64() % (i as u64 + 1)) as usize;
            slice.swap(i, j);
        }
    }
}

/// Mix a string label into a 64-bit seed. Used so that "seed=42, label=arm64"
/// and "seed=42, label=x86_64" produce different sub-streams while still
/// being deterministic.
#[must_use]
pub fn mix_seed(base: u64, label: &str) -> u64 {
    // FNV-1a 64.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in label.as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    base ^ hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_is_deterministic() {
        let mut a = Prng::new(0xDEAD_BEEF);
        let mut b = Prng::new(0xDEAD_BEEF);
        for _ in 0..32 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn zero_seed_is_safe() {
        let mut p = Prng::new(0);
        // Must not return identical zeros forever.
        let v = p.next_u64();
        assert_ne!(v, 0);
    }

    #[test]
    fn shuffle_is_stable() {
        let mut a: Vec<u32> = (0..16).collect();
        let mut b = a.clone();
        Prng::new(7).shuffle(&mut a);
        Prng::new(7).shuffle(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn mix_seed_distinguishes_labels() {
        assert_ne!(mix_seed(42, "arm64"), mix_seed(42, "x86_64"));
        assert_eq!(mix_seed(42, "arm64"), mix_seed(42, "arm64"));
    }
}
