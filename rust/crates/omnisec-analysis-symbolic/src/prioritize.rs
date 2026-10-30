//! Path-explosion mitigation: state merging + branch prioritization.
//!
//! Two complementary techniques are exposed here:
//!
//! 1. [`merge_traces`] — post-hoc state merging. After a concolic exploration
//!    finishes, traces sharing a common branch prefix are merged into a
//!    single [`MergedPath`] that records the divergence point and the
//!    set of paths that pass through it. This compresses huge trace sets
//!    into something a human report can show.
//!
//! 2. [`PriorityQueue`] — an HDC-guided worklist used by the concolic
//!    explorer. Each seed is assigned a *priority score* — by default
//!    based on how similar the seed's target subgraph is to known
//!    vulnerability anchors. Seeds that look like vulnerabilities are
//!    explored first.
//!
//! The two are independent; either can be used without the other.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use omnisec_json::ToJson;
use std::collections::HashMap as FxHashMap;

use crate::concolic::{ConcolicSeed, ConcolicTrace};

/// A compact, mergeable view of a [`ConcolicTrace`].
///
/// The trace is collapsed into a single path of branches, so two traces
/// whose branches diverge at index `i` are grouped under a `MergedPath`
/// at index `i - 1`.
#[derive(Debug, Clone, ToJson)]
pub struct MergedPath {
    /// The shared branch prefix (every member trace took these decisions).
    pub prefix: Vec<bool>,
    /// Index in the original trace list, plus its full branch signature.
    pub member_traces: Vec<(usize, Vec<bool>)>,
    /// Total instructions executed across all member traces.
    pub total_instructions: usize,
    /// `true` iff at least one trace in this group reached a clean
    /// termination (no successor / return).
    pub has_clean_termination: bool,
}

/// Result of merging a set of [`ConcolicTrace`]s.
#[derive(Debug, Clone, ToJson)]
pub struct MergeReport {
    /// All merged paths, sorted longest-prefix first.
    pub paths: Vec<MergedPath>,
    /// Total distinct branch signatures.
    pub distinct_signatures: usize,
    /// Compression ratio (input traces / output paths).
    pub compression_ratio: f64,
}

/// Merge traces with a shared branch prefix.
///
/// The algorithm is straightforward — walk every prefix length from
/// shortest to longest, group traces whose prefix matches, and emit a
/// `MergedPath` for every group with > 1 member at that prefix length.
///
/// Traces that don't share a prefix are emitted as singleton paths.
#[must_use]
pub fn merge_traces(traces: &[ConcolicTrace]) -> MergeReport {
    use std::collections::HashSet as FxHashSet;

    if traces.is_empty() {
        return MergeReport {
            paths: Vec::new(),
            distinct_signatures: 0,
            compression_ratio: 1.0,
        };
    }

    // Group by entire branch signature first to dedup identical traces.
    let mut signature_groups: FxHashMap<Vec<bool>, Vec<usize>> = FxHashMap::default();
    for (i, trace) in traces.iter().enumerate() {
        let sig: Vec<bool> = trace.branches.iter().map(|b| b.taken).collect();
        signature_groups.entry(sig).or_default().push(i);
    }

    // Build a prefix tree: for each unique signature S, walk every prefix
    // and stash (S, prefix-length).
    let mut prefix_groups: FxHashMap<Vec<bool>, Vec<usize>> = FxHashMap::default();
    for signature in signature_groups.keys() {
        for k in 0..=signature.len() {
            let prefix = signature[..k].to_vec();
            // Index by prefix; we'll fill in member traces later.
            prefix_groups.entry(prefix).or_default();
        }
    }

    // Assign each trace to every prefix it contains, but emit only
    // *maximal* shared prefixes — i.e. the longest prefix shared by
    // ≥ 2 distinct trace signatures.
    let mut emitted_prefixes: FxHashSet<Vec<bool>> = FxHashSet::default();
    let mut paths = Vec::new();

    let mut signatures: Vec<&Vec<bool>> = signature_groups.keys().collect();
    signatures.sort_by_key(|s| std::cmp::Reverse(s.len()));

    for sig in &signatures {
        for k in (0..=sig.len()).rev() {
            let prefix = sig[..k].to_vec();
            // Count distinct signatures with this prefix.
            let mut members: Vec<(usize, Vec<bool>)> = Vec::new();
            for (other_sig, indices) in &signature_groups {
                if other_sig.starts_with(&prefix) {
                    for idx in indices {
                        members.push((*idx, other_sig.clone()));
                    }
                }
            }
            if members.len() < 2 {
                continue;
            }
            if !emitted_prefixes.insert(prefix.clone()) {
                continue;
            }
            // Skip if a strictly-longer prefix was already emitted that
            // already covers all the same members.
            let already_covered = paths.iter().any(|p: &MergedPath| {
                p.prefix.starts_with(&prefix)
                    && p.member_traces
                        .iter()
                        .map(|(i, _)| *i)
                        .collect::<FxHashSet<_>>()
                        == members.iter().map(|(i, _)| *i).collect::<FxHashSet<_>>()
            });
            if already_covered {
                continue;
            }
            let total_instructions: usize = members
                .iter()
                .map(|(i, _)| traces[*i].instructions_executed)
                .sum();
            let has_clean_termination = members.iter().any(|(i, _)| traces[*i].terminated_cleanly);
            paths.push(MergedPath {
                prefix,
                member_traces: members,
                total_instructions,
                has_clean_termination,
            });
            break; // longest first
        }
    }

    // Singletons: traces with a unique signature get their own path.
    for (signature, indices) in &signature_groups {
        if indices.len() == 1 {
            // Was this signature already covered by a multi-trace path?
            let covered = paths.iter().any(|p| {
                signature.starts_with(&p.prefix)
                    && p.member_traces.iter().any(|(i, _)| *i == indices[0])
            });
            if !covered {
                paths.push(MergedPath {
                    prefix: signature.clone(),
                    member_traces: vec![(indices[0], signature.clone())],
                    total_instructions: traces[indices[0]].instructions_executed,
                    has_clean_termination: traces[indices[0]].terminated_cleanly,
                });
            }
        }
    }

    paths.sort_by_key(|p| std::cmp::Reverse(p.prefix.len()));

    let compression_ratio = if paths.is_empty() {
        1.0
    } else {
        traces.len() as f64 / paths.len() as f64
    };

    MergeReport {
        paths,
        distinct_signatures: signature_groups.len(),
        compression_ratio,
    }
}

/// A priority assignment for a worklist item.
///
/// Higher priority items are explored first. The default ordering is:
///
/// - `Vulnerability(score)` — items that look like vulnerabilities,
///   ordered by descending score.
/// - `Normal` — default priority for items with no special signal.
/// - `Background` — items that are unlikely to be productive (e.g.
///   pure plumbing branches with no symbolic dependence on inputs).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BranchPriority {
    /// Looks like a vulnerability path (HDC similarity ≥ 0).
    Vulnerability(f64),
    /// Default.
    Normal,
    /// Unlikely-to-be-productive branch.
    Background,
}

impl BranchPriority {
    /// Convert to a numeric priority key (higher = explore first).
    fn key(&self) -> i64 {
        match self {
            Self::Vulnerability(s) => 1_000_000 + (s * 10_000.0) as i64,
            Self::Normal => 0,
            Self::Background => -1_000_000,
        }
    }
}

impl Eq for BranchPriority {}

impl PartialOrd for BranchPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BranchPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

/// A worklist item: a seed paired with its priority and an optional
/// "tag" that survives the priority queue (useful for forensics).
#[derive(Debug, Clone)]
pub struct WorkItem {
    /// Seed for the next concolic run.
    pub seed: ConcolicSeed,
    /// Priority — higher is explored first.
    pub priority: BranchPriority,
    /// Free-form tag (e.g. "uaf-flip-block-7").
    pub tag: String,
    /// Insertion order — used as the tiebreaker so the queue is stable.
    pub serial: u64,
}

impl PartialEq for WorkItem {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.serial == other.serial
    }
}

impl Eq for WorkItem {}

impl PartialOrd for WorkItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WorkItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first. Tiebreak: lower serial = older = first.
        self.priority
            .cmp(&other.priority)
            .then(other.serial.cmp(&self.serial))
    }
}

/// HDC-aware priority queue for concolic-explorer worklists.
///
/// Wraps a [`BinaryHeap`] with a stable insertion-order tiebreaker so
/// equal-priority items pop in FIFO order.
#[derive(Debug, Default)]
pub struct PriorityQueue {
    heap: BinaryHeap<WorkItem>,
    next_serial: u64,
}

impl PriorityQueue {
    /// New empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a seed with a priority.
    pub fn push(&mut self, seed: ConcolicSeed, priority: BranchPriority, tag: impl Into<String>) {
        let item = WorkItem {
            seed,
            priority,
            tag: tag.into(),
            serial: self.next_serial,
        };
        self.next_serial += 1;
        self.heap.push(item);
    }

    /// Pop the highest-priority item.
    pub fn pop(&mut self) -> Option<WorkItem> {
        self.heap.pop()
    }

    /// `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Number of items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Drain all items (no priority order).
    pub fn drain(&mut self) -> impl Iterator<Item = WorkItem> + '_ {
        self.heap.drain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concolic::ConcolicTrace;

    fn make_trace(branches: &[bool], insns: usize, clean: bool) -> ConcolicTrace {
        ConcolicTrace {
            seed: FxHashMap::default(),
            branches: branches
                .iter()
                .enumerate()
                .map(|(i, &taken)| crate::concolic::ConcolicBranch {
                    block_id: 0,
                    insn_index: i,
                    taken,
                    predicate: String::new(),
                    successor: 1,
                    alternative: Some(2),
                    condition: None,
                })
                .collect(),
            instructions_executed: insns,
            terminated_cleanly: clean,
            termination_reason: String::new(),
        }
    }

    #[test]
    fn empty_traces_yield_empty_report() {
        let r = merge_traces(&[]);
        assert!(r.paths.is_empty());
        assert_eq!(r.distinct_signatures, 0);
    }

    #[test]
    fn identical_traces_compress_to_one() {
        let traces = vec![
            make_trace(&[true, false, true], 10, true),
            make_trace(&[true, false, true], 10, true),
        ];
        let r = merge_traces(&traces);
        assert_eq!(r.paths.len(), 1);
        assert_eq!(r.paths[0].member_traces.len(), 2);
    }

    #[test]
    fn diverging_traces_share_prefix() {
        let traces = vec![
            make_trace(&[true, false, true], 10, true),
            make_trace(&[true, false, false], 8, true),
        ];
        let r = merge_traces(&traces);
        // We expect at least one path with the common prefix [true, false]
        let has_shared_prefix = r.paths.iter().any(|p| p.prefix == vec![true, false]);
        assert!(has_shared_prefix, "{r:?}");
    }

    #[test]
    fn priority_ordering_is_correct() {
        assert!(BranchPriority::Vulnerability(0.95) > BranchPriority::Vulnerability(0.50));
        assert!(BranchPriority::Vulnerability(0.50) > BranchPriority::Normal);
        assert!(BranchPriority::Normal > BranchPriority::Background);
    }

    #[test]
    fn priority_queue_pops_high_priority_first() {
        let mut q = PriorityQueue::new();
        q.push(ConcolicSeed::new(), BranchPriority::Normal, "n1");
        q.push(
            ConcolicSeed::new(),
            BranchPriority::Vulnerability(0.9),
            "v1",
        );
        q.push(ConcolicSeed::new(), BranchPriority::Background, "b1");
        q.push(
            ConcolicSeed::new(),
            BranchPriority::Vulnerability(0.5),
            "v2",
        );

        let order: Vec<String> = std::iter::from_fn(|| q.pop().map(|w| w.tag)).collect();
        assert_eq!(order, vec!["v1", "v2", "n1", "b1"]);
    }

    #[test]
    fn priority_queue_is_stable_within_priority() {
        let mut q = PriorityQueue::new();
        q.push(ConcolicSeed::new(), BranchPriority::Normal, "first");
        q.push(ConcolicSeed::new(), BranchPriority::Normal, "second");
        q.push(ConcolicSeed::new(), BranchPriority::Normal, "third");
        let order: Vec<String> = std::iter::from_fn(|| q.pop().map(|w| w.tag)).collect();
        assert_eq!(order, vec!["first", "second", "third"]);
    }
}
