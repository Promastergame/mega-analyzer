//! Hotspot Ranker — scores code regions by malicious potential.
//!
//! Takes feature vectors from the Go pipeline and ranks methods/classes
//! by their similarity to known-malicious patterns using HDC distance.

use omnisec_json::{FromJson, ToJson};

/// A code hotspot with its computed threat score.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Hotspot {
    /// Identifier (class name or method signature).
    pub id: String,
    /// Computed threat score (0.0 - 1.0).
    pub score: f64,
    /// Top matching anchor names.
    pub matching_anchors: Vec<String>,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f64,
}

/// Ranked list of hotspots.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct RankingResult {
    /// Sorted hotspots (highest threat first).
    pub hotspots: Vec<Hotspot>,
    /// Total methods analyzed.
    pub total_analyzed: usize,
    /// Methods flagged as suspicious.
    pub flagged_count: usize,
    /// Average threat score across all methods.
    pub avg_score: f64,
}

/// Hotspot ranker using HDC similarity.
pub struct HotspotRanker {
    /// Anchor vectors (known-malicious patterns).
    anchors: Vec<AnchorEntry>,
    /// Minimum score threshold to flag a hotspot.
    threshold: f64,
}

/// A named anchor vector for comparison.
struct AnchorEntry {
    name: String,
    vector: Vec<u64>,
    weight: f64,
}

impl HotspotRanker {
    /// Create a new ranker with the given threshold.
    #[must_use]
    pub fn new(threshold: f64) -> Self {
        Self {
            anchors: Vec::new(),
            threshold,
        }
    }

    /// Add an anchor (known-malicious pattern) to the ranker.
    pub fn add_anchor(&mut self, name: String, vector: Vec<u64>, weight: f64) {
        self.anchors.push(AnchorEntry {
            name,
            vector,
            weight,
        });
    }

    /// Rank a batch of candidate vectors against all anchors.
    ///
    /// Returns a `RankingResult` with hotspots sorted by threat score (descending).
    pub fn rank(&self, candidates: &[(String, Vec<u64>)]) -> RankingResult {
        let mut hotspots = Vec::with_capacity(candidates.len());
        let mut total_score = 0.0;

        for (id, vector) in candidates {
            let mut max_score = 0.0f64;
            let mut matching = Vec::new();

            for anchor in &self.anchors {
                let similarity = cosine_binary(&anchor.vector, vector);
                let weighted = similarity * anchor.weight;

                if weighted > self.threshold {
                    matching.push(anchor.name.clone());
                }
                max_score = max_score.max(weighted);
            }

            let confidence = if self.anchors.is_empty() {
                0.0
            } else {
                (matching.len() as f64 / self.anchors.len() as f64).min(1.0)
            };

            total_score += max_score;

            hotspots.push(Hotspot {
                id: id.clone(),
                score: max_score,
                matching_anchors: matching,
                confidence,
            });
        }

        // Sort by score descending
        hotspots.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let flagged_count = hotspots.iter().filter(|h| h.score > self.threshold).count();
        let avg_score = if candidates.is_empty() {
            0.0
        } else {
            total_score / candidates.len() as f64
        };

        RankingResult {
            hotspots,
            total_analyzed: candidates.len(),
            flagged_count,
            avg_score,
        }
    }
}

/// Compute cosine similarity between two binary hypervectors.
///
/// For binary vectors, cosine similarity reduces to:
///   sim = 1.0 - 2.0 * hamming_distance / dimension
fn cosine_binary(a: &[u64], b: &[u64]) -> f64 {
    let dim = a.len() * 64;
    if dim == 0 {
        return 0.0;
    }

    let mut hamming = 0u32;
    for (wa, wb) in a.iter().zip(b.iter()) {
        hamming += (wa ^ wb).count_ones();
    }

    1.0 - 2.0 * f64::from(hamming) / dim as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_vectors_have_max_similarity() {
        let v = vec![0xDEAD_BEEF_CAFE_BABEu64; 128];
        let sim = cosine_binary(&v, &v);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    #[test]
    fn opposite_vectors_have_min_similarity() {
        let a = vec![0xFFFF_FFFF_FFFF_FFFFu64; 128];
        let b = vec![0x0000_0000_0000_0000u64; 128];
        let sim = cosine_binary(&a, &b);
        assert!(
            sim < 0.0,
            "opposite vectors should have negative similarity"
        );
    }

    #[test]
    fn ranker_flags_suspicious() {
        let mut ranker = HotspotRanker::new(0.3);

        // Add a known-malicious anchor
        let anchor = vec![0xFFFF_FFFF_FFFF_FFFFu64; 128];
        ranker.add_anchor("malware_pattern_1".into(), anchor.clone(), 1.0);

        // Candidate similar to anchor
        let candidates = vec![
            (
                "suspicious_method".into(),
                vec![0xFFFF_FFFF_FFFF_FFFFu64; 128],
            ),
            ("safe_method".into(), vec![0x0000_0000_0000_0000u64; 128]),
        ];

        let result = ranker.rank(&candidates);
        assert_eq!(result.total_analyzed, 2);
        assert_eq!(result.flagged_count, 1);
        assert_eq!(result.hotspots[0].id, "suspicious_method");
    }
}
