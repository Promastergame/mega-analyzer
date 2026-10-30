//! Anchor-based vulnerability matching — the MVP detection engine.
//!
//! An [`Anchor`] is a "golden signature hypervector" for a known vulnerability
//! pattern (e.g. Use-After-Free, Stack Buffer Overflow, Double Free).
//!
//! The detection pipeline:
//! 1. Encode a suspicious sub-PDG into a single HV (via bundle of node HVs).
//! 2. Compute Hamming distance / Jaccard similarity to each anchor.
//! 3. If similarity exceeds threshold → Alert.
//!
//! This works **without any neural network or training**. HDC algebraic
//! properties guarantee that structurally similar subgraphs produce similar
//! HVs. The anchors are built from manually-curated or synthetic examples.

use crate::HyperVector;
use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap as FxHashMap;

/// Current serialized anchor-store schema version.
pub const ANCHOR_STORE_SCHEMA_VERSION: u32 = 1;

/// A known vulnerability pattern represented as a hypervector.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Anchor {
    /// Human-readable name (e.g. "use_after_free", "stack_buffer_overflow").
    pub name: String,
    /// Optional description / CWE ID.
    pub description: String,
    /// The signature hypervector — majority vote of N example subgraphs.
    pub signature: HyperVector,
    /// Minimum Jaccard similarity for a match (e.g. 0.25 for sparse HVs).
    pub threshold: f64,
    /// Severity (0.0 = info, 1.0 = critical).
    pub severity: f64,
    /// Number of example subgraphs bundled into this anchor.
    pub example_count: usize,
    /// Known motifs (sub-patterns) for explainable reporting.
    /// E.g., ["invalid lifetime dependency", "free/use topology motif"].
    pub motifs: Vec<String>,

    /// Optional **online learning state**: per-bit set-counts of every
    /// example bundled into this anchor. When present, [`AnchorStore::reinforce`]
    /// can absorb a confirmed match and rebuild the signature without
    /// regenerating from synthetic graphs.
    ///
    /// `#[json(default)]` so legacy JSON anchor stores (which omit the
    /// field) deserialise cleanly. Length must equal `HyperVector::DIM` when
    /// present — guarded by [`AnchorStore::reinforce`].
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub bit_counts: Option<Vec<u32>>,
}

/// Result of matching a subgraph HV against an anchor.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct MatchResult {
    /// Name of the matched anchor.
    pub anchor_name: String,
    /// Jaccard similarity score.
    pub jaccard: f64,
    /// Hamming similarity score (1 - normalized hamming).
    pub hamming_sim: f64,
    /// Whether the match exceeds the anchor's threshold.
    pub is_match: bool,
    /// Severity of the matched vulnerability.
    pub severity: f64,
    /// Matched motifs (for explainable reporting).
    pub matched_motifs: Vec<String>,
}

/// Metadata embedded in serialized Aetrium anchor databases.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct AnchorStoreMetadata {
    /// Serialized anchor-store schema version.
    #[json(default = "default_schema_version")]
    pub schema_version: u32,
    /// Engine identifier for this anchor database.
    #[json(default = "default_engine")]
    pub engine: String,
    /// Tool or module that generated this anchor database.
    #[json(default = "default_generator")]
    pub generator: String,
    /// Deterministic HDC codebook seed used for synthetic generation.
    #[json(default)]
    pub codebook_seed: Option<u64>,
    /// Exact topology examples generated per vulnerability family.
    #[json(default)]
    pub examples_per_kind: Option<usize>,
    /// Noisy variants generated per exact topology example.
    #[json(default)]
    pub variants_per_example: Option<usize>,
    /// Bit-flip ratio used for anchor mutation.
    #[json(default)]
    pub noise_ratio: Option<f64>,
}

impl Default for AnchorStoreMetadata {
    fn default() -> Self {
        Self {
            schema_version: ANCHOR_STORE_SCHEMA_VERSION,
            engine: "ml-aetrium".to_string(),
            generator: "omnisec-hdc".to_string(),
            codebook_seed: None,
            examples_per_kind: None,
            variants_per_example: None,
            noise_ratio: None,
        }
    }
}

fn default_schema_version() -> u32 {
    ANCHOR_STORE_SCHEMA_VERSION
}

fn default_engine() -> String {
    "ml-aetrium".to_string()
}

fn default_generator() -> String {
    "omnisec-hdc".to_string()
}

/// A store of vulnerability anchors for matching.
#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct AnchorStore {
    metadata: AnchorStoreMetadata,
    anchors: FxHashMap<String, Anchor>,
}

#[derive(Debug, Clone, ToJson, FromJson)]
struct AnchorStoreDocument {
    #[json(flatten)]
    metadata: AnchorStoreMetadata,
    anchors: Vec<Anchor>,
}

impl AnchorStore {
    /// Create an empty anchor store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an anchor to the store.
    pub fn add(&mut self, anchor: Anchor) {
        self.anchors.insert(anchor.name.clone(), anchor);
    }

    /// Metadata attached to this anchor database.
    #[must_use]
    pub const fn metadata(&self) -> &AnchorStoreMetadata {
        &self.metadata
    }

    /// Replace metadata attached to this anchor database.
    pub fn set_metadata(&mut self, metadata: AnchorStoreMetadata) {
        self.metadata = metadata;
    }

    /// Build an anchor from a set of example subgraph HVs.
    ///
    /// The signature is the thresholded majority vote (bundle) of all examples.
    pub fn build_anchor(
        name: impl Into<String>,
        description: impl Into<String>,
        examples: &[HyperVector],
        threshold: f64,
        severity: f64,
        motifs: Vec<String>,
    ) -> Anchor {
        // Build the signature *and* keep the per-bit counts so the anchor
        // can be reinforced online with confirmed matches.
        let mut acc = crate::BundleAccumulator::new();
        for ex in examples {
            acc.add(ex);
        }
        let signature = if examples.is_empty() {
            HyperVector::zero()
        } else {
            acc.finalize()
        };
        Anchor {
            name: name.into(),
            description: description.into(),
            signature,
            threshold,
            example_count: examples.len(),
            severity,
            motifs,
            bit_counts: Some(acc.bit_counts.to_vec()),
        }
    }

    /// Build a **Synthetic Noisy Anchor** via Anchor Mutation.
    ///
    /// This takes a set of exact motif examples, generates `variants_per_example`
    /// slightly perturbed copies (noise = `noise_ratio`), and bundles them all.
    /// The resulting anchor is robust against polymorphic variations of the bug.
    pub fn build_mutated_anchor(
        name: impl Into<String>,
        description: impl Into<String>,
        examples: &[HyperVector],
        variants_per_example: usize,
        noise_ratio: f64,
        threshold: f64,
        severity: f64,
        motifs: Vec<String>,
    ) -> Anchor {
        let name = name.into();
        let description = description.into();
        let mut all_variants = Vec::with_capacity(examples.len() * (1 + variants_per_example));

        // Deterministic PRNG for mutations based on anchor name hash.
        let mut seed = deterministic_seed(&name);

        for example in examples {
            // Keep the exact original
            all_variants.push(*example);

            // Generate noisy variants
            for _ in 0..variants_per_example {
                seed ^= seed >> 12;
                seed ^= seed << 25;
                seed ^= seed >> 27;
                let perturbed = example.perturb(seed, noise_ratio);
                all_variants.push(perturbed);
            }
        }

        let signature = HyperVector::bundle(&all_variants);
        let mut acc = crate::BundleAccumulator::new();
        for v in &all_variants {
            acc.add(v);
        }
        Anchor {
            name,
            description,
            signature,
            threshold,
            example_count: all_variants.len(),
            severity,
            motifs,
            bit_counts: Some(acc.bit_counts.to_vec()),
        }
    }

    /// Serialize this store as compact JSON bytes.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut anchors: Vec<Anchor> = self.anchors.values().cloned().collect();
        anchors.sort_by(|a, b| a.name.cmp(&b.name));
        omnisec_json::to_json_vec(&AnchorStoreDocument {
            metadata: self.metadata.clone(),
            anchors,
        })
    }

    /// Serialize this store as compact JSON text.
    pub fn to_json_string(&self) -> String {
        let mut anchors: Vec<Anchor> = self.anchors.values().cloned().collect();
        anchors.sort_by(|a, b| a.name.cmp(&b.name));
        omnisec_json::to_json_string(&AnchorStoreDocument {
            metadata: self.metadata.clone(),
            anchors,
        })
    }

    /// Deserialize an anchor store from JSON bytes.
    pub fn from_json_slice(bytes: &[u8]) -> omnisec_json::JsonResult<Self> {
        let document: AnchorStoreDocument = omnisec_json::from_json_slice(bytes)?;
        Ok(migrate(Self::from_document(document)))
    }

    /// Deserialize an anchor store from JSON text.
    pub fn from_json_str(json: &str) -> omnisec_json::JsonResult<Self> {
        let document: AnchorStoreDocument = omnisec_json::from_json_str(json)?;
        Ok(migrate(Self::from_document(document)))
    }

    /// Match a subgraph HV against all anchors.
    ///
    /// Returns matches sorted by similarity (highest first).
    #[must_use]
    pub fn match_all(&self, subgraph_hv: &HyperVector) -> Vec<MatchResult> {
        let mut results: Vec<MatchResult> = self
            .anchors
            .values()
            .map(|anchor| {
                let jaccard = subgraph_hv.jaccard(anchor.signature);
                let hamming_sim = subgraph_hv.similarity(anchor.signature);
                MatchResult {
                    anchor_name: anchor.name.clone(),
                    jaccard,
                    hamming_sim,
                    is_match: jaccard >= anchor.threshold,
                    severity: anchor.severity,
                    matched_motifs: if jaccard >= anchor.threshold {
                        anchor.motifs.clone()
                    } else {
                        Vec::new()
                    },
                }
            })
            .collect();

        results.sort_by(|a, b| {
            b.jaccard
                .partial_cmp(&a.jaccard)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// Match and return only hits above threshold.
    #[must_use]
    pub fn detect(&self, subgraph_hv: &HyperVector) -> Vec<MatchResult> {
        self.match_all(subgraph_hv)
            .into_iter()
            .filter(|r| r.is_match)
            .collect()
    }

    /// **Reinforce** an anchor with a confirmed (true-positive) example.
    ///
    /// This is the online-learning path: when a downstream consumer (the
    /// analyst, the active-learning loop, or a verified ground-truth label)
    /// confirms that `subgraph_hv` truly represents the vulnerability named
    /// `anchor_name`, fold its bits into the anchor's running counts and
    /// rebuild the signature. No need to keep every historical example HV
    /// around or to retrain from scratch.
    ///
    /// Returns `true` when the anchor existed and was updated, `false`
    /// when the name is unknown. Anchors loaded from a legacy JSON store
    /// without `bit_counts` are migrated lazily: their existing signature
    /// is treated as the count "1" baseline and folded in alongside the
    /// new example. This is approximate — counts will lag the true history
    /// — but lets the path work without a one-time mass-retrain.
    pub fn reinforce(&mut self, anchor_name: &str, subgraph_hv: &HyperVector) -> bool {
        let Some(anchor) = self.anchors.get_mut(anchor_name) else {
            return false;
        };

        // Hydrate the accumulator. If the anchor was loaded without the
        // counts field, seed it with the existing signature so the new
        // example contributes alongside the historical bundle.
        let mut acc = match anchor.bit_counts.take() {
            Some(counts) if counts.len() == HyperVector::DIM => {
                let mut arr = [0u32; HyperVector::DIM];
                arr.copy_from_slice(&counts);
                crate::BundleAccumulator::from_counts(anchor.example_count as u32, arr)
            }
            _ => {
                let mut acc = crate::BundleAccumulator::new();
                acc.add(&anchor.signature);
                acc
            }
        };
        acc.add(subgraph_hv);
        anchor.signature = acc.finalize();
        anchor.example_count = acc.count as usize;
        anchor.bit_counts = Some(acc.bit_counts.to_vec());
        true
    }

    /// Number of anchors in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Get an anchor by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Anchor> {
        self.anchors.get(name)
    }

    /// Iterate over all anchors.
    pub fn iter(&self) -> impl Iterator<Item = &Anchor> {
        self.anchors.values()
    }

    fn from_document(document: AnchorStoreDocument) -> Self {
        let mut store = Self::new();
        store.set_metadata(document.metadata);
        for anchor in document.anchors {
            store.add(anchor);
        }
        store
    }
}

fn deterministic_seed(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in value.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Apply forward-only migrations to bring a freshly-loaded store up to
/// [`ANCHOR_STORE_SCHEMA_VERSION`]. Migrations are deliberately additive:
/// each step only fills in fields that newer schema versions introduced,
/// preserving anchor signatures and metadata that older writers produced.
///
/// Today the supported migrations are:
///
///   - **v0 / unversioned → v1**: ensure metadata.schema_version is set and
///     hydrate `bit_counts` from the existing signature so online updates
///     work on legacy stores. This is approximate — counts will lag the
///     true history — but the alternative is to require a full re-forge
///     after every schema bump.
fn migrate(mut store: AnchorStore) -> AnchorStore {
    let version = store.metadata.schema_version;
    if version == 0 {
        // Treat absent / 0 as "no version was set" — pre-versioning data.
        store.metadata.schema_version = 1;
    }
    if version < ANCHOR_STORE_SCHEMA_VERSION {
        // Forward-fill bit_counts for anchors that don't have them yet.
        // The seed is the existing signature with weight 1 — `reinforce`
        // will accumulate from there. The alternative (refusing to load)
        // would brick every deployment that has an older anchors JSON.
        for anchor in store.anchors.values_mut() {
            if anchor.bit_counts.is_none() {
                let mut counts = vec![0u32; HyperVector::DIM];
                for (wi, &word) in anchor.signature.data.iter().enumerate() {
                    let base = wi * 64;
                    for bit in 0..64 {
                        counts[base + bit] = ((word >> bit) & 1) as u32;
                    }
                }
                anchor.bit_counts = Some(counts);
            }
        }
    }
    store.metadata.schema_version = ANCHOR_STORE_SCHEMA_VERSION;
    store
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a "family" of similar sparse HVs by XOR-ing a base
    /// with small random perturbations.
    fn make_family(base_seed: u64, count: usize, perturbation_seeds: &[u64]) -> Vec<HyperVector> {
        let base = HyperVector::sparse(base_seed);
        let mut family = vec![base];
        for &pseed in perturbation_seeds.iter().take(count - 1) {
            // XOR with a very sparse perturbation (~2% bits set) to stay close.
            let perturbation = base.perturb(pseed, 0.02);
            family.push(perturbation);
        }
        family
    }

    #[test]
    fn anchor_detects_similar_subgraph() {
        let uaf_examples = make_family(1000, 5, &[2000, 3000, 4000, 5000]);
        let anchor = AnchorStore::build_anchor(
            "use_after_free",
            "CWE-416: Use After Free",
            &uaf_examples,
            0.15,
            0.9,
            vec!["free/use topology motif".to_string()],
        );

        let mut store = AnchorStore::new();
        store.add(anchor);

        let new_uaf = make_family(1000, 2, &[6000])[1];
        let results = store.detect(&new_uaf);

        assert!(!results.is_empty(), "should detect UAF-like subgraph");
        assert_eq!(results[0].anchor_name, "use_after_free");
        assert_eq!(results[0].matched_motifs.len(), 1);
    }

    #[test]
    fn anchor_rejects_unrelated_subgraph() {
        let uaf_examples = make_family(1000, 5, &[2000, 3000, 4000, 5000]);
        let anchor = AnchorStore::build_anchor(
            "use_after_free",
            "CWE-416",
            &uaf_examples,
            0.15,
            0.9,
            vec![],
        );

        let mut store = AnchorStore::new();
        store.add(anchor);

        let unrelated = HyperVector::sparse(99999);
        let results = store.detect(&unrelated);

        assert!(results.is_empty(), "should NOT match an unrelated subgraph");
    }

    #[test]
    fn multiple_anchors_discriminate() {
        let uaf_examples = make_family(1000, 3, &[1001, 1002]);
        let bof_examples = make_family(9000, 3, &[9001, 9002]);

        let mut store = AnchorStore::new();
        store.add(AnchorStore::build_anchor(
            "uaf",
            "Use-After-Free",
            &uaf_examples,
            0.15,
            0.9,
            vec![],
        ));
        store.add(AnchorStore::build_anchor(
            "bof",
            "Buffer Overflow",
            &bof_examples,
            0.15,
            0.8,
            vec![],
        ));

        let test_uaf = make_family(1000, 2, &[1003])[1];
        let results = store.match_all(&test_uaf);
        let uaf_match = results.iter().find(|r| r.anchor_name == "uaf").unwrap();
        let bof_match = results.iter().find(|r| r.anchor_name == "bof").unwrap();
        assert!(
            uaf_match.jaccard > bof_match.jaccard,
            "UAF subgraph should be more similar to UAF anchor (uaf={:.3}, bof={:.3})",
            uaf_match.jaccard,
            bof_match.jaccard,
        );
    }

    #[test]
    fn mutated_anchor_detects_variants() {
        let examples = vec![HyperVector::sparse(123)];
        // Build a mutated anchor with 10 noisy variants per example.
        let anchor = AnchorStore::build_mutated_anchor(
            "mutated",
            "Test Mutated",
            &examples,
            10,
            0.05,
            0.15,
            0.5,
            vec![],
        );
        let mut store = AnchorStore::new();
        store.add(anchor);

        // Perturb the original example to simulate a variant.
        let variant = examples[0].perturb(999, 0.05);
        let results = store.detect(&variant);
        assert!(
            !results.is_empty(),
            "Mutated anchor should catch the variant"
        );
    }

    #[test]
    fn store_operations() {
        let mut store = AnchorStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        let anchor = AnchorStore::build_anchor(
            "test",
            "test anchor",
            &[HyperVector::sparse(1)],
            0.2,
            0.5,
            vec![],
        );
        store.add(anchor);

        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
        assert!(store.get("test").is_some());
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn anchor_store_json_roundtrip() {
        let mut store = AnchorStore::new();
        store.add(AnchorStore::build_anchor(
            "use_after_free",
            "CWE-416",
            &[HyperVector::sparse(1)],
            0.2,
            0.9,
            vec!["free/use topology motif".to_string()],
        ));

        let bytes = store.to_json_bytes();
        let loaded = AnchorStore::from_json_slice(&bytes).unwrap();

        assert_eq!(loaded.len(), 1);
        let anchor = loaded.get("use_after_free").unwrap();
        assert_eq!(anchor.description, "CWE-416");
        assert_eq!(anchor.signature, HyperVector::sparse(1));
        assert_eq!(anchor.motifs, vec!["free/use topology motif"]);
    }

    #[test]
    fn reinforce_pulls_signature_toward_confirmed_example() {
        // Build an anchor far from `target`, then reinforce it 30 times
        // with `target`. The signature must converge toward `target`.
        let original_examples = vec![HyperVector::sparse(1), HyperVector::sparse(2)];
        let mut store = AnchorStore::new();
        store.add(AnchorStore::build_anchor(
            "tunable",
            "online learning",
            &original_examples,
            0.1,
            0.5,
            vec![],
        ));

        let target = HyperVector::sparse(9999);
        let initial_sim = store.get("tunable").unwrap().signature.jaccard(target);

        for _ in 0..30 {
            assert!(store.reinforce("tunable", &target));
        }
        let final_sim = store.get("tunable").unwrap().signature.jaccard(target);

        assert!(
            final_sim > initial_sim,
            "reinforcement should pull the signature toward the confirmed example: \
             initial={initial_sim:.3} final={final_sim:.3}"
        );
    }

    #[test]
    fn reinforce_returns_false_for_unknown_anchor() {
        let mut store = AnchorStore::new();
        assert!(!store.reinforce("nonexistent", &HyperVector::sparse(1)));
    }
}
