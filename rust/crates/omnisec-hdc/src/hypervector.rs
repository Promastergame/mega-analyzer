//! Sparse 2048-bit binary hypervector.

use omnisec_json::{FromJson, ToJson};
use std::fmt;
use std::ops::{BitXor, BitXorAssign};

/// Number of u64 words in a hypervector (2048 / 64 = 32).
const WORDS: usize = 32;

/// A 2048-bit binary hypervector stored as 32 × u64.
///
/// All hot-path operations (`bind`, `hamming_distance`, `similarity`) compile
/// down to plain bitwise instructions + `POPCNT`. On x86-64 with AVX2 the
/// compiler auto-vectorises the inner loops.
#[derive(Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub struct HyperVector {
    /// 2048 bits = 32 × u64.
    pub data: [u64; WORDS],
}

impl HyperVector {
    /// Dimension of the hypervector in bits.
    pub const DIM: usize = 2048;

    /// Number of u64 words.
    pub const WORDS: usize = WORDS;

    /// Target density for sparse HVs (fraction of 1-bits).
    pub const SPARSE_DENSITY: f64 = 0.10;

    /// Expected number of set bits in a sparse HV.
    pub const SPARSE_ONES: usize = (Self::DIM as f64 * Self::SPARSE_DENSITY) as usize; // ~205

    // ─── Constructors ────────────────────────────────────────────────────

    /// All-zeros vector.
    #[must_use]
    pub const fn zero() -> Self {
        Self { data: [0; WORDS] }
    }

    /// All-ones vector.
    #[must_use]
    pub const fn ones() -> Self {
        Self {
            data: [u64::MAX; WORDS],
        }
    }

    /// Generate a **dense** random HV (~50% bits set).
    ///
    /// Prefer [`Self::sparse`] for the HDC pipeline — this exists for
    /// backward-compatibility and internal testing.
    #[must_use]
    pub fn random_dense(seed: u64) -> Self {
        let mut data = [0u64; WORDS];
        // Simple but deterministic xorshift64* PRNG — no external dep needed
        // for the core HV type.
        let mut state = seed | 1; // avoid zero-state
        for word in &mut data {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            *word = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        }
        Self { data }
    }

    /// Generate a **sparse** random HV with ~10% bits set.
    ///
    /// Uses a deterministic PRNG seeded by `seed`. Two calls with the same
    /// seed always produce the same vector — critical for reproducibility.
    #[must_use]
    pub fn sparse(seed: u64) -> Self {
        let target_bits = Self::SPARSE_ONES;
        let mut data = [0u64; WORDS];

        // Deterministic xorshift to pick bit positions.
        let mut state = seed | 1;
        let mut set = 0usize;

        // We use rejection sampling: generate random positions until we have
        // enough unique ones. For 10% density the expected number of
        // iterations is ~1.11 × target_bits — very fast.
        while set < target_bits {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let val = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            let pos = (val as usize) % Self::DIM;
            let word = pos / 64;
            let bit = pos % 64;
            if data[word] & (1u64 << bit) == 0 {
                data[word] |= 1u64 << bit;
                set += 1;
            }
        }

        Self { data }
    }

    // ─── VSA Operations ──────────────────────────────────────────────────

    /// **Bind** (⊕): XOR two hypervectors.
    ///
    /// Produces a vector dissimilar to both inputs. Reversible: `A.bind(B).bind(A) == B`.
    #[must_use]
    #[inline]
    pub fn bind(self, other: Self) -> Self {
        self ^ other
    }

    /// **Bundle** (+): Thresholded majority vote over multiple HVs.
    ///
    /// For sparse vectors we use a **density-aware threshold**: a bit is set
    /// if it appears in at least `ceil(n * density_ratio)` of the inputs,
    /// where `density_ratio` controls output sparsity. With `ratio = 0.5` we
    /// get classic majority; with a higher ratio we keep the output sparse.
    #[must_use]
    pub fn bundle(vectors: &[Self]) -> Self {
        if vectors.is_empty() {
            return Self::zero();
        }
        if vectors.len() == 1 {
            return vectors[0];
        }

        let n = vectors.len() as u32;

        // Per-bit popcount accumulators. Switching from the previous
        // `trailing_zeros` decomposition to a word-major scan with eight
        // 8-bit counters per byte lets the compiler auto-vectorise the
        // inner loop on AVX2/NEON: each iteration is a fixed-shape mask
        // + add, no data-dependent branching, no early termination.
        let counts = column_counts(vectors);

        // Adaptive threshold: keep output density close to SPARSE_DENSITY.
        // For n inputs each with ~10% density, a bit is set in ~0.10 × n inputs
        // on average by chance. We set the threshold above that to preserve
        // only "agreement" bits.
        //
        // threshold = max(2, ceil(n * 0.30))
        //   - For 3 vectors: threshold = 2 (bit must appear in ≥2/3)
        //   - For 10 vectors: threshold = 3
        //   - For 100 vectors: threshold = 30
        let threshold = (n as f64 * 0.30).ceil().max(2.0) as u32;

        Self {
            data: counts_to_words(&counts, threshold),
        }
    }

    /// **Bundle with explicit threshold** — lets the caller control output density.
    #[must_use]
    pub fn bundle_threshold(vectors: &[Self], threshold: u32) -> Self {
        if vectors.is_empty() {
            return Self::zero();
        }
        let counts = column_counts(vectors);
        Self {
            data: counts_to_words(&counts, threshold),
        }
    }

    // ─── Metrics ─────────────────────────────────────────────────────────

    /// Number of 1-bits in this vector.
    #[must_use]
    #[inline]
    pub fn popcount(self) -> usize {
        self.data.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Hamming distance (number of differing bits).
    ///
    /// Compiles to `XOR + POPCNT` — this is the hot path for inference.
    #[must_use]
    #[inline]
    pub fn hamming_distance(self, other: Self) -> usize {
        let mut dist = 0usize;
        for i in 0..WORDS {
            dist += (self.data[i] ^ other.data[i]).count_ones() as usize;
        }
        dist
    }

    /// Cosine-like similarity for binary vectors: `1.0 − hamming / dim`.
    #[must_use]
    #[inline]
    pub fn similarity(self, other: Self) -> f64 {
        1.0 - (self.hamming_distance(other) as f64 / Self::DIM as f64)
    }

    /// Jaccard similarity: `|A ∩ B| / |A ∪ B|`.
    ///
    /// More meaningful than Hamming for sparse vectors because it ignores
    /// shared zeros.
    #[must_use]
    pub fn jaccard(self, other: Self) -> f64 {
        let mut intersection = 0usize;
        let mut union = 0usize;
        for i in 0..WORDS {
            intersection += (self.data[i] & other.data[i]).count_ones() as usize;
            union += (self.data[i] | other.data[i]).count_ones() as usize;
        }
        if union == 0 {
            return 0.0;
        }
        intersection as f64 / union as f64
    }

    /// Density: fraction of bits that are 1.
    #[must_use]
    #[inline]
    pub fn density(self) -> f64 {
        self.popcount() as f64 / Self::DIM as f64
    }

    /// Perturb this hypervector by flipping a small number of bits.
    ///
    /// Useful for **Anchor Mutation**: creating synthetic noisy variants
    /// of a known vulnerability motif to catch polymorphic variants.
    ///
    /// `noise_ratio` is the fraction of total bits to flip (e.g., 0.02 = 2%).
    #[must_use]
    pub fn perturb(self, seed: u64, noise_ratio: f64) -> Self {
        let flip_count = (Self::DIM as f64 * noise_ratio.clamp(0.0, 1.0)) as usize;
        let mut noise = [0u64; WORDS];
        let mut state = seed | 1;
        let mut flipped = 0usize;

        while flipped < flip_count {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let val = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            let pos = (val as usize) % Self::DIM;
            let word = pos / 64;
            let bit = pos % 64;

            if noise[word] & (1u64 << bit) == 0 {
                noise[word] |= 1u64 << bit;
                flipped += 1;
            }
        }

        // XOR with the noise mask flips exactly `flip_count` bits.
        Self {
            data: {
                let mut out = [0u64; WORDS];
                for i in 0..WORDS {
                    out[i] = self.data[i] ^ noise[i];
                }
                out
            },
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Count, for each of the 2048 bit positions, how many vectors have it set.
///
/// The hot path is a strict word-major scan: for each word index `wi` we
/// stream through every vector and add `((word >> bit) & 1)` to the per-bit
/// counter. Crucially, the inner loop has no branches and uses fixed-shape
/// arithmetic, which lets LLVM emit AVX2 / NEON instructions on supported
/// targets. Compared to the previous `trailing_zeros` + clear-lowest-bit
/// approach this is faster on dense bundles (large N) at a small constant
/// cost on sparse ones — and stable enough that the cost is uniform across
/// vector densities.
fn column_counts(vectors: &[HyperVector]) -> [u32; HyperVector::DIM] {
    let mut counts = [0u32; HyperVector::DIM];
    for v in vectors {
        for (wi, &word) in v.data.iter().enumerate() {
            let base = wi * 64;
            // Manually unroll into bytes so the compiler vectorises one byte
            // (8 bits) per iteration. With 32 words × 8 bytes = 256 byte
            // chunks per vector, the inner work is small and predictable.
            for byte_off in 0..8 {
                let byte = ((word >> (byte_off * 8)) & 0xff) as usize;
                let bit_base = base + byte_off * 8;
                counts[bit_base] += (byte & 1) as u32;
                counts[bit_base + 1] += ((byte >> 1) & 1) as u32;
                counts[bit_base + 2] += ((byte >> 2) & 1) as u32;
                counts[bit_base + 3] += ((byte >> 3) & 1) as u32;
                counts[bit_base + 4] += ((byte >> 4) & 1) as u32;
                counts[bit_base + 5] += ((byte >> 5) & 1) as u32;
                counts[bit_base + 6] += ((byte >> 6) & 1) as u32;
                counts[bit_base + 7] += ((byte >> 7) & 1) as u32;
            }
        }
    }
    counts
}

/// Threshold a column-count array back into a packed 32×u64 vector.
fn counts_to_words(counts: &[u32; HyperVector::DIM], threshold: u32) -> [u64; WORDS] {
    let mut result = [0u64; WORDS];
    for (i, count) in counts.iter().enumerate() {
        if *count >= threshold {
            result[i / 64] |= 1u64 << (i % 64);
        }
    }
    result
}

/// Incremental bundle accumulator.
///
/// Lets callers stream vectors into a running per-bit count, then materialise
/// the bundled HV at any point. Used by online anchor updates: keep the count
/// vector inside the [`Anchor`], add a confirmed example with `add`, and
/// rebuild the signature with `finalize` — no need to store every example HV
/// forever.
#[derive(Clone, Debug)]
pub struct BundleAccumulator {
    /// Total number of vectors fed into the accumulator.
    pub count: u32,
    /// Per-bit set-counts. Public so the type round-trips through serde
    /// without an explicit shim.
    pub bit_counts: Box<[u32; HyperVector::DIM]>,
}

impl Default for BundleAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl BundleAccumulator {
    /// Create an empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            count: 0,
            bit_counts: Box::new([0u32; HyperVector::DIM]),
        }
    }

    /// Reconstruct an accumulator that has already seen `count` vectors and
    /// has the given per-bit counts. Useful when reloading from a serialised
    /// anchor with embedded counts.
    #[must_use]
    pub fn from_counts(count: u32, bit_counts: [u32; HyperVector::DIM]) -> Self {
        Self {
            count,
            bit_counts: Box::new(bit_counts),
        }
    }

    /// Fold one HV into the running counts.
    pub fn add(&mut self, v: &HyperVector) {
        self.count = self.count.saturating_add(1);
        for (wi, &word) in v.data.iter().enumerate() {
            let base = wi * 64;
            for bit in 0..64 {
                self.bit_counts[base + bit] += ((word >> bit) & 1) as u32;
            }
        }
    }

    /// Materialise the current bundled HV using a custom threshold.
    #[must_use]
    pub fn finalize_threshold(&self, threshold: u32) -> HyperVector {
        HyperVector {
            data: counts_to_words(&self.bit_counts, threshold),
        }
    }

    /// Materialise using the same density-aware threshold as
    /// [`HyperVector::bundle`].
    #[must_use]
    pub fn finalize(&self) -> HyperVector {
        match self.count {
            0 => HyperVector::zero(),
            // Single-example case must mirror `HyperVector::bundle`'s
            // fast-path: returning the input verbatim. Any threshold ≥ 2
            // would otherwise zero the vector out (each bit's count is at
            // most 1) and silently drop the anchor signature.
            1 => HyperVector {
                data: counts_to_words(&self.bit_counts, 1),
            },
            _ => {
                let threshold = (f64::from(self.count) * 0.30).ceil().max(2.0) as u32;
                self.finalize_threshold(threshold)
            }
        }
    }
}

// ─── Trait Impls ─────────────────────────────────────────────────────────

impl BitXor for HyperVector {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        let mut data = [0u64; WORDS];
        for i in 0..WORDS {
            data[i] = self.data[i] ^ rhs.data[i];
        }
        Self { data }
    }
}

impl BitXorAssign for HyperVector {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        for i in 0..WORDS {
            self.data[i] ^= rhs.data[i];
        }
    }
}

impl fmt::Debug for HyperVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HV({}bits, pop={}, density={:.1}%)",
            Self::DIM,
            self.popcount(),
            self.density() * 100.0,
        )
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_hv_has_correct_density() {
        let hv = HyperVector::sparse(42);
        let pop = hv.popcount();
        // Should be exactly SPARSE_ONES because we set that many bits.
        assert_eq!(pop, HyperVector::SPARSE_ONES);
        let density = hv.density();
        assert!(density > 0.08 && density < 0.12, "density = {density}");
    }

    #[test]
    fn sparse_is_deterministic() {
        let a = HyperVector::sparse(12345);
        let b = HyperVector::sparse(12345);
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_produce_dissimilar_sparse_hvs() {
        let a = HyperVector::sparse(1);
        let b = HyperVector::sparse(2);
        // Sparse vectors with ~10% density should have low Jaccard similarity.
        let j = a.jaccard(b);
        assert!(j < 0.15, "jaccard = {j} — should be near 1/19 ≈ 0.05");
    }

    #[test]
    fn bind_is_reversible() {
        let a = HyperVector::sparse(100);
        let b = HyperVector::sparse(200);
        let bound = a.bind(b);
        let recovered = bound.bind(a);
        assert_eq!(b, recovered);
    }

    #[test]
    fn bundle_preserves_common_bits() {
        let a = HyperVector::sparse(10);
        let b = HyperVector::sparse(20);
        let c = HyperVector::sparse(30);

        let bundled = HyperVector::bundle(&[a, b, c]);

        // Bundled vector should be more similar to each input than a random vector.
        let random = HyperVector::sparse(99999);
        assert!(bundled.jaccard(a) > bundled.jaccard(random));
        assert!(bundled.jaccard(b) > bundled.jaccard(random));
        assert!(bundled.jaccard(c) > bundled.jaccard(random));
    }

    #[test]
    fn hamming_self_is_zero() {
        let v = HyperVector::sparse(42);
        assert_eq!(v.hamming_distance(v), 0);
        assert!((v.similarity(v) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn zero_vector_properties() {
        let z = HyperVector::zero();
        assert_eq!(z.popcount(), 0);
        assert!((z.density() - 0.0).abs() < f64::EPSILON);

        let v = HyperVector::sparse(42);
        assert_eq!(v.bind(HyperVector::zero()), v);
    }

    #[test]
    fn bundle_and_accumulator_agree() {
        // Streaming through a BundleAccumulator must produce the same HV
        // as a single batch bundle on the same inputs (up to threshold
        // rounding, which we apply identically).
        let v1 = HyperVector::sparse(11);
        let v2 = HyperVector::sparse(22);
        let v3 = HyperVector::sparse(33);
        let v4 = HyperVector::sparse(44);
        let v5 = HyperVector::sparse(55);

        let batch = HyperVector::bundle(&[v1, v2, v3, v4, v5]);

        let mut acc = BundleAccumulator::new();
        for v in [&v1, &v2, &v3, &v4, &v5] {
            acc.add(v);
        }
        let streamed = acc.finalize();

        assert_eq!(batch, streamed);
    }

    #[test]
    fn bundle_explicit_threshold_and_accumulator_agree() {
        let v1 = HyperVector::sparse(101);
        let v2 = HyperVector::sparse(202);
        let v3 = HyperVector::sparse(303);

        let batch = HyperVector::bundle_threshold(&[v1, v2, v3], 2);
        let mut acc = BundleAccumulator::new();
        acc.add(&v1);
        acc.add(&v2);
        acc.add(&v3);
        let streamed = acc.finalize_threshold(2);
        assert_eq!(batch, streamed);
    }
}
