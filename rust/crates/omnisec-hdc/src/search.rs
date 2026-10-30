//! Multi-Index Hamming Search — "FAISS for binary PDG".
//!
//! For fast approximate nearest-neighbor search over a large database of
//! subgraph HVs, we split each 2048-bit HV into chunks and build inverted
//! indexes per chunk. At query time, we only compute full Hamming distance
//! for candidates that share at least one chunk with the query.
//!
//! This is based on the **Multi-Index Hashing** paper (Norouzi et al., 2012)
//! adapted for our sparse 2048-bit HVs.
//!
//! # Complexity
//!
//! - **Insert**: O(num_chunks) per vector
//! - **Query**: O(candidates × dim/64) — but `candidates ≪ database_size`
//! - **Memory**: O(database_size × num_chunks) for the index

use crate::{HyperVector, runtime};
use std::collections::HashMap as FxHashMap;

/// Number of chunks to split a HyperVector into.
/// 2048 bits / 8 chunks = 256 bits (4 × u64) per chunk.
const NUM_CHUNKS: usize = 8;
/// Number of u64 words per chunk.
const WORDS_PER_CHUNK: usize = HyperVector::WORDS / NUM_CHUNKS; // 32 / 8 = 4

/// A chunk key: the exact bit pattern of one 256-bit chunk.
/// We use `[u64; 4]` since each chunk is 256 bits.
type ChunkKey = [u64; WORDS_PER_CHUNK];

/// Multi-Index Hamming Search engine.
///
/// Stores a database of HVs and supports fast approximate nearest-neighbor
/// queries using inverted chunk indexes.
pub struct HammingIndex {
    /// All stored vectors (the source of truth).
    vectors: Vec<HyperVector>,
    /// Optional tags for each vector (e.g. vulnerability type).
    tags: Vec<u64>,
    /// Inverted indexes: one per chunk.
    /// `chunk_indexes[c][chunk_key] = list of vector IDs sharing that chunk`.
    chunk_indexes: Vec<FxHashMap<ChunkKey, Vec<u32>>>,
}

impl HammingIndex {
    /// Create a new empty index.
    #[must_use]
    pub fn new() -> Self {
        let mut chunk_indexes = Vec::with_capacity(NUM_CHUNKS);
        for _ in 0..NUM_CHUNKS {
            chunk_indexes.push(FxHashMap::default());
        }
        Self {
            vectors: Vec::new(),
            tags: Vec::new(),
            chunk_indexes,
        }
    }

    /// Insert a vector into the index.
    ///
    /// Returns the assigned ID.
    pub fn insert(&mut self, hv: HyperVector, tag: u64) -> u32 {
        let id = self.vectors.len() as u32;
        self.vectors.push(hv);
        self.tags.push(tag);

        // Index each chunk.
        for c in 0..NUM_CHUNKS {
            let key = extract_chunk(&hv, c);
            self.chunk_indexes[c].entry(key).or_default().push(id);
        }

        id
    }

    /// Query: find the K nearest neighbors by Hamming distance.
    ///
    /// Uses the multi-index trick: only vectors sharing at least one exact
    /// chunk are considered as candidates, dramatically reducing the search
    /// space.
    ///
    /// For very sparse HVs, many chunks will be all-zeros, so we also
    /// include a fallback: if too few candidates are found via chunk matching,
    /// we fall back to brute-force over a random sample.
    #[must_use]
    pub fn query(&self, query: &HyperVector, k: usize) -> Vec<SearchResult> {
        if self.vectors.is_empty() || k == 0 {
            return Vec::new();
        }

        // 1. Collect candidate IDs from chunk matches.
        let mut candidate_set = std::collections::HashSet::new();
        for c in 0..NUM_CHUNKS {
            let key = extract_chunk(query, c);
            if let Some(ids) = self.chunk_indexes[c].get(&key) {
                candidate_set.extend(ids.iter().copied());
            }
        }

        // 2. If no chunk matches (common with sparse HVs), do approximate
        //    search: scan chunks with small hamming distance.
        if candidate_set.is_empty() {
            // Fallback: brute-force over all vectors.
            // For a production system, we'd do locality-sensitive hashing here.
            for (i, _) in self.vectors.iter().enumerate() {
                candidate_set.insert(i as u32);
                if candidate_set.len() >= 1000 {
                    break; // Cap to keep it fast.
                }
            }
        }

        // 3. Compute exact Hamming distance for all candidates.
        let mut results: Vec<SearchResult> = candidate_set
            .iter()
            .map(|&id| {
                let dist = runtime::hamming_distance(query, &self.vectors[id as usize]);
                SearchResult {
                    id,
                    tag: self.tags[id as usize],
                    hamming_distance: dist,
                    similarity: 1.0 - (dist as f64 / HyperVector::DIM as f64),
                    jaccard: query.jaccard(self.vectors[id as usize]),
                }
            })
            .collect();

        // 4. Sort by Hamming distance (ascending = most similar first).
        results.sort_by_key(|r| r.hamming_distance);
        results.truncate(k);
        results
    }

    /// Query with a minimum similarity threshold (returns only matches above it).
    #[must_use]
    pub fn query_threshold(&self, query: &HyperVector, min_jaccard: f64) -> Vec<SearchResult> {
        self.query(query, self.vectors.len())
            .into_iter()
            .filter(|r| r.jaccard >= min_jaccard)
            .collect()
    }

    /// Number of vectors in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vectors.len()
    }

    /// Whether the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vectors.is_empty()
    }

    /// Get a stored vector by ID.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&HyperVector> {
        self.vectors.get(id as usize)
    }
}

impl Default for HammingIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a nearest-neighbor search.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// ID of the matched vector.
    pub id: u32,
    /// Tag associated with the vector.
    pub tag: u64,
    /// Hamming distance (lower = more similar).
    pub hamming_distance: usize,
    /// Hamming similarity (1 - normalized distance).
    pub similarity: f64,
    /// Jaccard similarity.
    pub jaccard: f64,
}

/// Extract chunk `c` (0..NUM_CHUNKS) from a HyperVector.
fn extract_chunk(hv: &HyperVector, c: usize) -> ChunkKey {
    let start = c * WORDS_PER_CHUNK;
    let mut key = [0u64; WORDS_PER_CHUNK];
    key.copy_from_slice(&hv.data[start..start + WORDS_PER_CHUNK]);
    key
}

impl std::fmt::Debug for HammingIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HammingIndex(vectors={}, chunks={})",
            self.vectors.len(),
            NUM_CHUNKS,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_exact_match() {
        let mut index = HammingIndex::new();
        let hv = HyperVector::sparse(42);
        let id = index.insert(hv, 0);

        let results = index.query(&hv, 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, id);
        assert_eq!(results[0].hamming_distance, 0);
    }

    #[test]
    fn nearest_neighbor_is_correct() {
        let mut index = HammingIndex::new();

        // Insert 10 random vectors.
        for i in 0..10 {
            index.insert(HyperVector::sparse(i * 1000), i);
        }

        // Query with one of the inserted vectors.
        let query = HyperVector::sparse(3000); // Same as ID=3
        let results = index.query(&query, 3);

        assert!(!results.is_empty());
        assert_eq!(
            results[0].hamming_distance, 0,
            "exact match should be first"
        );
    }

    #[test]
    fn threshold_query_filters() {
        let mut index = HammingIndex::new();

        let base = HyperVector::sparse(1000);
        index.insert(base, 1);

        // Insert something very different.
        index.insert(HyperVector::sparse(99999), 2);

        // Query with base — should match itself with high jaccard.
        let results = index.query_threshold(&base, 0.5);
        assert!(results.iter().any(|r| r.tag == 1));
    }

    #[test]
    fn index_len_and_empty() {
        let mut index = HammingIndex::new();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);

        index.insert(HyperVector::sparse(1), 0);
        assert!(!index.is_empty());
        assert_eq!(index.len(), 1);
    }
}
