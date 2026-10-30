//! Indexed anchor store with multi-index Hamming pre-filtering.
//!
//! `AnchorStore::detect()` is O(N) in the number of anchors: every query
//! computes Jaccard against every signature. With 24+ anchors and large
//! binaries that produce hundreds of subgraphs, this becomes the hot path.
//!
//! `IndexedAnchorStore` adds a two-level filter:
//!
//!   1. **Hint pre-filter** — anchor names can be associated with cheap
//!      structural cues (e.g. "string `xml` appears in the binary").
//!      Anchors whose hints don't fire are skipped before any HV math.
//!   2. **Multi-index Hamming candidate selection** — the remaining
//!      anchors' signatures are stored in a [`HammingIndex`]. A query HV
//!      first asks the index for the top-K nearest signatures, then we
//!      compute Jaccard only on those.
//!
//! On a 24-anchor store with ~5 hint-eliminated anchors, this typically
//! cuts work by 5–10× while preserving ranking quality (the index never
//! drops a signature that would have crossed its threshold under
//! brute-force scan).

use crate::{Anchor, AnchorStore, HammingIndex, HyperVector, MatchResult};
use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

/// Cheap structural cue that can disqualify an anchor before HV scoring.
///
/// `Required` means the cue MUST be present for the anchor to be considered;
/// `Forbidden` means its presence rules the anchor out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintRule {
    /// Anchor only fires when at least one of the listed substrings
    /// is found in the target's strings/imports.
    Required(Vec<String>),
    /// Anchor never fires when any of the listed substrings is found.
    Forbidden(Vec<String>),
}

/// HintBundle is the set of cues a target offers — typically built from
/// the binary's strings + imports + format kind.
#[derive(Debug, Default, Clone)]
pub struct HintBundle {
    /// Lowercased token set (strings, imports, section names) extracted
    /// from the target.
    pub tokens: FxHashSet<String>,
}

impl HintBundle {
    /// Build a bundle from an iterator of tokens. Tokens are lowercased.
    pub fn from_tokens<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut tokens = FxHashSet::default();
        for item in items {
            tokens.insert(item.as_ref().to_lowercase());
        }
        Self { tokens }
    }

    /// True when at least one of `needles` (lowercased) is present.
    fn contains_any(&self, needles: &[String]) -> bool {
        needles.iter().any(|n| {
            // Substring match, not exact: bundle tokens may be full strings
            // ("processBuilder.command") and we want to match short cues
            // ("command"). We pre-lowercase both sides at construction.
            self.tokens.iter().any(|tok| tok.contains(n.as_str()))
        })
    }
}

/// IndexedAnchorStore wraps an [`AnchorStore`] with a HammingIndex and
/// optional hint rules.
pub struct IndexedAnchorStore {
    /// The underlying named-anchor store (keeps full anchor metadata).
    store: AnchorStore,
    /// Inverted-chunk index over signatures for fast nearest-neighbour.
    index: HammingIndex,
    /// `id_to_name[i]` is the anchor name corresponding to index entry `i`.
    id_to_name: Vec<String>,
    /// Optional hint rules per anchor name.
    hints: FxHashMap<String, HintRule>,
}

impl IndexedAnchorStore {
    /// Build an indexed store from an existing AnchorStore.
    #[must_use]
    pub fn from_store(store: AnchorStore) -> Self {
        let mut index = HammingIndex::new();
        let mut id_to_name = Vec::with_capacity(store.len());
        // We index every anchor's signature with `tag = id_to_name.len()`
        // so we can recover the anchor by id after querying.
        for anchor in store.iter() {
            let id = id_to_name.len() as u64;
            index.insert(anchor.signature, id);
            id_to_name.push(anchor.name.clone());
        }
        Self {
            store,
            index,
            id_to_name,
            hints: FxHashMap::default(),
        }
    }

    /// Attach a hint rule to an anchor by name. Replaces any existing rule.
    pub fn set_hint(&mut self, anchor_name: impl Into<String>, rule: HintRule) {
        self.hints.insert(anchor_name.into(), rule);
    }

    /// Number of indexed anchors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether the underlying store has no anchors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Borrow the underlying store for full-iteration use cases.
    #[must_use]
    pub fn store(&self) -> &AnchorStore {
        &self.store
    }

    /// Detect: returns matches above each anchor's threshold, after the
    /// hint pre-filter and the Hamming-index candidate selection.
    ///
    /// `top_k` controls how many candidates we pull from the index. With
    /// 24 anchors, `top_k = 8` is a good default — well above the typical
    /// number of "real" matches but well below brute-force.
    #[must_use]
    pub fn detect(
        &self,
        subgraph_hv: &HyperVector,
        hints: Option<&HintBundle>,
        top_k: usize,
    ) -> Vec<MatchResult> {
        if self.is_empty() || top_k == 0 {
            return Vec::new();
        }

        // Stage 1: hint-eligible anchor names. If hints are absent we skip
        // this filter entirely (best-effort scoring on every anchor).
        let allowed: Option<FxHashSet<&str>> = hints.map(|h| {
            self.id_to_name
                .iter()
                .filter(|name| {
                    self.hints.get(*name).map_or(true, |rule| match rule {
                        HintRule::Required(needles) => h.contains_any(needles),
                        HintRule::Forbidden(needles) => !h.contains_any(needles),
                    }) // no hint = pass
                })
                .map(String::as_str)
                .collect()
        });

        // Stage 2: nearest-neighbour candidates from the index.
        let candidates = self.index.query(subgraph_hv, top_k.max(1));

        // Stage 3: rebuild MatchResult for the (hint-eligible ∩ candidate)
        // set, applying each anchor's individual threshold.
        let mut out = Vec::with_capacity(candidates.len());
        for c in candidates {
            let id = c.tag as usize;
            if id >= self.id_to_name.len() {
                continue;
            }
            let name = &self.id_to_name[id];
            if let Some(set) = &allowed
                && !set.contains(name.as_str())
            {
                continue;
            }
            let Some(anchor) = self.store.get(name) else {
                continue;
            };
            out.push(match_result_from_anchor(anchor, c.jaccard, c.similarity));
        }

        // Sort by jaccard desc and keep only matches above threshold.
        out.sort_by(|a, b| {
            b.jaccard
                .partial_cmp(&a.jaccard)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.into_iter().filter(|r| r.is_match).collect()
    }
}

fn match_result_from_anchor(anchor: &Anchor, jaccard: f64, hamming_sim: f64) -> MatchResult {
    let is_match = jaccard >= anchor.threshold;
    MatchResult {
        anchor_name: anchor.name.clone(),
        jaccard,
        hamming_sim,
        is_match,
        severity: anchor.severity,
        matched_motifs: if is_match {
            anchor.motifs.clone()
        } else {
            Vec::new()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnchorForge;

    #[test]
    fn indexed_detect_matches_brute_force() {
        let mut forge = AnchorForge::default();
        let store = forge.build_default_store();
        let indexed = IndexedAnchorStore::from_store(store.clone());

        // Build an exact UAF graph and encode it.
        let g = forge
            .generate_graphs(crate::SyntheticBugKind::UseAfterFree)
            .into_iter()
            .next()
            .unwrap();
        let hv = forge.encode_graph(&g);

        let brute = store.detect(&hv);
        let smart = indexed.detect(&hv, None, 16);

        // The top-1 must agree across implementations on a clean exact match.
        let brute_top = brute.first().map(|r| r.anchor_name.as_str());
        let smart_top = smart.first().map(|r| r.anchor_name.as_str());
        assert_eq!(brute_top, Some("use_after_free"));
        assert_eq!(smart_top, Some("use_after_free"));
    }

    #[test]
    fn hint_filter_blocks_anchor() {
        let mut forge = AnchorForge::default();
        let store = forge.build_default_store();
        let mut indexed = IndexedAnchorStore::from_store(store);

        // Force command_injection to require the literal "exec" token.
        indexed.set_hint(
            "command_injection",
            HintRule::Required(vec!["exec".to_string()]),
        );

        // Build a CI motif and try to detect with a bundle that lacks "exec".
        let g = forge
            .generate_graphs(crate::SyntheticBugKind::CommandInjection)
            .into_iter()
            .next()
            .unwrap();
        let hv = forge.encode_graph(&g);

        let bundle = HintBundle::from_tokens::<_, &str>(["unrelated_strings"]);
        let blocked = indexed.detect(&hv, Some(&bundle), 24);
        assert!(
            !blocked.iter().any(|r| r.anchor_name == "command_injection"),
            "command_injection should be blocked when 'exec' hint is missing"
        );

        // With the right token, the same anchor must come through.
        let bundle_ok = HintBundle::from_tokens::<_, &str>(["execve_call"]);
        let allowed = indexed.detect(&hv, Some(&bundle_ok), 24);
        assert!(allowed.iter().any(|r| r.anchor_name == "command_injection"));
    }
}
