//! Optional ML runtime backend integration.

use crate::HyperVector;

#[cfg(feature = "zig-runtime")]
const EXPECTED_ZIG_RUNTIME_ABI_VERSION: u32 = 1;

/// Hamming backend used for batched search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HammingBackend {
    /// Pure Rust POPCNT implementation.
    Rust,
    /// Zig C-ABI runtime implementation.
    Zig,
}

/// Return the active hamming backend for this build.
#[must_use]
pub const fn active_hamming_backend() -> HammingBackend {
    if cfg!(feature = "zig-runtime") {
        HammingBackend::Zig
    } else {
        HammingBackend::Rust
    }
}

/// Compute Hamming distance using the active backend.
#[must_use]
pub fn hamming_distance(a: &HyperVector, b: &HyperVector) -> usize {
    hamming_distance_words(&a.data, &b.data)
}

/// Compute Hamming distance over packed u64 words using the active backend.
#[must_use]
pub fn hamming_distance_words(a: &[u64], b: &[u64]) -> usize {
    assert_eq!(a.len(), b.len(), "hamming inputs must have equal length");

    #[cfg(feature = "zig-runtime")]
    {
        if zig::runtime_available() {
            let dist = zig::hamming_distance_words(a, b);
            if dist != usize::MAX {
                return dist;
            }
        }
    }

    rust_hamming_distance_words(a, b)
}

/// Compute XNOR-GEMM scores using the active backend.
pub fn xnor_gemm(a: &[u64], b: &[u64], c: &mut [u32], m: usize, n: usize, k_words: usize) {
    assert_eq!(a.len(), m * k_words, "A must be M×K_words");
    assert_eq!(b.len(), n * k_words, "B must be N×K_words column-major");
    assert_eq!(c.len(), m * n, "C must be M×N");

    #[cfg(feature = "zig-runtime")]
    {
        if zig::runtime_available() && zig::xnor_gemm(a, b, c, m, n, k_words) {
            return;
        }
    }

    rust_xnor_gemm(a, b, c, m, n, k_words);
}

fn rust_hamming_distance_words(a: &[u64], b: &[u64]) -> usize {
    a.iter()
        .zip(b)
        .map(|(left, right)| (left ^ right).count_ones() as usize)
        .sum()
}

fn rust_xnor_gemm(a: &[u64], b: &[u64], c: &mut [u32], m: usize, n: usize, k_words: usize) {
    for i in 0..m {
        for j in 0..n {
            let mut sum = 0u32;
            for k in 0..k_words {
                let a_word = a[i * k_words + k];
                let b_word = b[j * k_words + k];
                sum += (!(a_word ^ b_word)).count_ones();
            }
            c[i * n + j] = sum;
        }
    }
}

#[cfg(feature = "zig-runtime")]
#[allow(unsafe_code)]
mod zig {
    unsafe extern "C" {
        fn omnisec_ml_runtime_abi_version() -> u32;
        fn omnisec_hamming_distance(a: *const u64, b: *const u64, words: usize) -> usize;
        fn omnisec_xnor_gemm(
            a: *const u64,
            b: *const u64,
            c: *mut u32,
            m: usize,
            n: usize,
            k_words: usize,
        ) -> bool;
    }

    pub(super) fn runtime_available() -> bool {
        unsafe { omnisec_ml_runtime_abi_version() == super::EXPECTED_ZIG_RUNTIME_ABI_VERSION }
    }

    pub(super) fn hamming_distance_words(a: &[u64], b: &[u64]) -> usize {
        unsafe { omnisec_hamming_distance(a.as_ptr(), b.as_ptr(), a.len()) }
    }

    pub(super) fn xnor_gemm(
        a: &[u64],
        b: &[u64],
        c: &mut [u32],
        m: usize,
        n: usize,
        k_words: usize,
    ) -> bool {
        unsafe { omnisec_xnor_gemm(a.as_ptr(), b.as_ptr(), c.as_mut_ptr(), m, n, k_words) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_hamming_matches_hypervector() {
        let a = HyperVector::sparse(1);
        let b = HyperVector::sparse(2);

        assert_eq!(hamming_distance(&a, &b), a.hamming_distance(b));
    }

    #[test]
    fn xnor_gemm_scores_identical_vectors_as_full_width() {
        let a = [u64::MAX];
        let b = [u64::MAX];
        let mut c = [0u32];

        xnor_gemm(&a, &b, &mut c, 1, 1, 1);

        assert_eq!(c[0], 64);
    }
}
