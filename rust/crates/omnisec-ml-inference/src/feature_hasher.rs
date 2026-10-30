//! Feature Hasher — converts raw analysis signals into HDC hypervectors.
//!
//! The Go ML pipeline produces feature maps like:
//!   { "permission:SMS": 1, "api:DexClassLoader": 3, "string:pastebin.com": 1 }
//!
//! This module hashes those features into dense binary hypervectors suitable
//! for fast similarity search via the HDC engine.

use std::collections::HashMap as FxHashMap;

/// Dimension of the hypervector space (must match omnisec-hdc).
const HDC_DIM: usize = 8192;
/// Number of u64 words per hypervector.
const HDC_WORDS: usize = HDC_DIM / 64;

/// Feature hasher that converts string-keyed feature maps into HDC vectors.
pub struct FeatureHasher {
    /// Cached hash seeds per feature name for deterministic projection.
    seeds: FxHashMap<String, u64>,
    /// Base seed for new features.
    base_seed: u64,
}

impl FeatureHasher {
    /// Create a new feature hasher with the given base seed.
    #[must_use]
    pub fn new(base_seed: u64) -> Self {
        Self {
            seeds: FxHashMap::default(),
            base_seed,
        }
    }

    /// Hash a set of features into a binary hypervector.
    ///
    /// Features are bundled (majority-vote) into a single representative vector.
    /// Each feature name is deterministically projected into a random hypervector,
    /// scaled by its count, and accumulated into the result.
    pub fn hash_features(&mut self, features: &FxHashMap<String, u32>) -> Vec<u64> {
        if features.is_empty() {
            return vec![0u64; HDC_WORDS];
        }

        // Accumulator: signed counts per bit position
        let mut accum = vec![0i32; HDC_DIM];

        for (name, &count) in features {
            let seed = self.get_or_create_seed(name);
            let weight = count as i32;

            // Generate deterministic pseudo-random vector from seed
            let mut state = seed;
            for bit in 0..HDC_DIM {
                // Simple xorshift64 PRNG
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;

                // Bipolar encoding: +weight or -weight
                if state & 1 == 0 {
                    accum[bit] += weight;
                } else {
                    accum[bit] -= weight;
                }
            }
        }

        // Threshold: positive → 1, non-positive → 0
        let mut result = vec![0u64; HDC_WORDS];
        for (i, &val) in accum.iter().enumerate() {
            if val > 0 {
                result[i / 64] |= 1u64 << (i % 64);
            }
        }

        result
    }

    /// Get or create a deterministic seed for a feature name.
    fn get_or_create_seed(&mut self, name: &str) -> u64 {
        if let Some(&seed) = self.seeds.get(name) {
            return seed;
        }

        // FNV-1a hash of the feature name mixed with base seed
        let mut hash = self.base_seed ^ 0xcbf2_9ce4_8422_2325;
        for byte in name.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }

        self.seeds.insert(name.to_string(), hash);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_features_produce_zero_vector() {
        let mut hasher = FeatureHasher::new(42);
        let features = FxHashMap::default();
        let result = hasher.hash_features(&features);
        assert_eq!(result.len(), HDC_WORDS);
        assert!(result.iter().all(|&w| w == 0));
    }

    #[test]
    fn same_features_produce_same_vector() {
        let mut hasher = FeatureHasher::new(42);
        let mut features = FxHashMap::default();
        features.insert("permission:SMS".to_string(), 1);
        features.insert("api:DexClassLoader".to_string(), 3);

        let v1 = hasher.hash_features(&features);
        let v2 = hasher.hash_features(&features);
        assert_eq!(
            v1, v2,
            "deterministic hashing must produce identical vectors"
        );
    }

    #[test]
    fn different_features_produce_different_vectors() {
        let mut hasher = FeatureHasher::new(42);

        let mut f1 = FxHashMap::default();
        f1.insert("permission:SMS".to_string(), 1);
        let v1 = hasher.hash_features(&f1);

        let mut f2 = FxHashMap::default();
        f2.insert("api:Runtime.exec".to_string(), 1);
        let v2 = hasher.hash_features(&f2);

        assert_ne!(v1, v2, "different features should map to different vectors");
    }
}
