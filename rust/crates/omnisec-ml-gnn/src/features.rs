//! Feature extraction from OmniIR code graphs.
//!
//! Converts raw CFG/PDG structures into node feature vectors
//! suitable for GNN inference.

use crate::graph_tensor::NodeFeatures;

/// Extracts node features from code analysis results.
pub struct FeatureExtractor {
    /// Maximum block size for normalization
    max_block_size: f32,
    /// Maximum loop depth for normalization
    max_loop_depth: f32,
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self {
            max_block_size: 100.0,
            max_loop_depth: 10.0,
        }
    }
}

impl FeatureExtractor {
    /// Create a new feature extractor with custom normalization bounds.
    pub fn new(max_block_size: f32, max_loop_depth: f32) -> Self {
        Self {
            max_block_size,
            max_loop_depth,
        }
    }

    /// Extract features for a basic block from raw statistics.
    ///
    /// This is the primary interface for Go → Rust FFI: Go sends
    /// per-block stats, Rust builds the feature vector. The trailing
    /// `api_*` / `str_*` flags are the v3 semantic slots (28-35) and must
    /// match `gnngraph` slot order exactly.
    #[allow(clippy::fn_params_excessive_bools)]
    #[allow(clippy::too_many_arguments)]
    pub fn extract_block_features(
        &self,
        opcode_histogram: &[u32; 16],
        operand_count: u32,
        is_branch: bool,
        is_call: bool,
        is_memory: bool,
        is_comparison: bool,
        in_degree: u32,
        out_degree: u32,
        block_size: u32,
        loop_depth: u32,
        dominance_score: f32,
        is_error_path: bool,
        is_entry: bool,
        api_license: bool,
        api_reflection: bool,
        api_dynload: bool,
        api_crypto: bool,
        api_pkg_sig: bool,
        api_native: bool,
        str_url: bool,
        str_license_kw: bool,
    ) -> NodeFeatures {
        // Normalize opcode histogram to sum to 1.0
        let total: u32 = opcode_histogram.iter().sum();
        let mut opcode_category = [0.0_f32; 16];
        if total > 0 {
            for (i, &count) in opcode_histogram.iter().enumerate() {
                opcode_category[i] = count as f32 / total as f32;
            }
        }

        NodeFeatures {
            opcode_category,
            operand_count: (operand_count as f32).min(10.0) / 10.0,
            is_branch: if is_branch { 1.0 } else { 0.0 },
            is_call: if is_call { 1.0 } else { 0.0 },
            is_memory_access: if is_memory { 1.0 } else { 0.0 },
            is_comparison: if is_comparison { 1.0 } else { 0.0 },
            in_degree: (in_degree as f32).min(20.0) / 20.0,
            out_degree: (out_degree as f32).min(20.0) / 20.0,
            block_size: (block_size as f32).min(self.max_block_size) / self.max_block_size,
            loop_depth: (loop_depth as f32).min(self.max_loop_depth) / self.max_loop_depth,
            dominance_score: dominance_score.clamp(0.0, 1.0),
            is_error_path: if is_error_path { 1.0 } else { 0.0 },
            is_entry: if is_entry { 1.0 } else { 0.0 },
            api_license: if api_license { 1.0 } else { 0.0 },
            api_reflection: if api_reflection { 1.0 } else { 0.0 },
            api_dynload: if api_dynload { 1.0 } else { 0.0 },
            api_crypto: if api_crypto { 1.0 } else { 0.0 },
            api_pkg_sig: if api_pkg_sig { 1.0 } else { 0.0 },
            api_native: if api_native { 1.0 } else { 0.0 },
            str_url: if str_url { 1.0 } else { 0.0 },
            str_license_kw: if str_license_kw { 1.0 } else { 0.0 },
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests intentionally compare against exact, representable constants
    // (0.0, 1.0, hand-computed values); the lint would only add noise here.
    #![allow(clippy::float_cmp)]
    use super::*;

    #[test]
    fn extract_normalizes_features() {
        let extractor = FeatureExtractor::default();
        let hist = [10, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]; // total = 20

        let features = extractor.extract_block_features(
            &hist, 3, true, false, true, false, 2, 1, 50, 2, 0.8, false, true, false, false, false,
            false, false, false, false, false,
        );

        assert!((features.opcode_category[0] - 0.5).abs() < 1e-5);
        assert!((features.operand_count - 0.3).abs() < 1e-5);
        assert_eq!(features.is_branch, 1.0);
        assert_eq!(features.is_call, 0.0);
        assert!((features.block_size - 0.5).abs() < 1e-5);
        assert_eq!(features.is_entry, 1.0);
        assert_eq!(NodeFeatures::DIMS, 36);
        assert_eq!(features.to_vec().len(), 36);
    }

    #[test]
    fn extract_carries_semantic_flags_to_v3_slots() {
        let extractor = FeatureExtractor::default();
        let hist = [0; 16];
        let features = extractor.extract_block_features(
            &hist, 1, false, true, false, false, 0, 1, 3, 0, 0.0, false, false, true, false, true,
            false, false, false, false, true,
        );
        let v = features.to_vec();
        assert_eq!(v.len(), 36);
        // Slots 28-35: license=1, reflection=0, dynload=1, crypto=0,
        // pkgsig=0, native=0, url=0, license_kw=1.
        assert_eq!(&v[28..], &[1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0]);
    }
}
