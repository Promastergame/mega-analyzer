//! Trace DB — persistent execution trace with ML annotations.
//!
//! Stores every step annotated by the ML engine so the AI can:
//!   - post-process a full run
//!   - train / update HDC anchors
//!   - query "show me all steps where risk > 0.8"
//!   - checkpoint → save a slice of trace + full state

use std::collections::BTreeMap;

use omnisec_emu_x86::CpuState;

use crate::engine::StopReason;
use crate::ml_annotator::MLAnnotation;

// ═══════════════════════════════════════════════════════════════════════════════
// TRACE ENTRY
// ═══════════════════════════════════════════════════════════════════════════════

/// One traced execution step.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    /// Global instruction sequence number.
    pub seq: u64,
    /// Instruction pointer (RIP) at execution time.
    pub rip: u64,
    /// Mnemonic text of the instruction.
    pub instruction: Option<String>,
    /// Raw instruction bytes.
    pub raw: Vec<u8>,
    /// ML annotation (risk score, patterns, etc.).
    pub annotation: MLAnnotation,
    /// CPU state before execution.
    pub state: CpuState,
    /// Reason why the execution stopped after this step.
    pub stop_reason: StopReason,
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECKPOINT
// ═══════════════════════════════════════════════════════════════════════════════

/// A named snapshot of execution state + trace slice.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Checkpoint identifier.
    pub id: u32,
    /// User-friendly name.
    pub name: String,
    /// Start sequence number of the checkpointed trace slice.
    pub seq_start: u64,
    /// End sequence number of the checkpointed trace slice.
    pub seq_end: u64,
    /// CPU state at the checkpoint save.
    pub cpu_state: CpuState,
    /// ML annotation details at the checkpoint save.
    pub annotation_at_save: MLAnnotation,
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRACE DATABASE
// ═══════════════════════════════════════════════════════════════════════════════

/// Database containing traced execution entries and checkpoints.
#[derive(Debug)]
pub struct TraceDB {
    entries: Vec<TraceEntry>,
    checkpoints: BTreeMap<u32, Checkpoint>,
    next_checkpoint_id: u32,
}

impl Default for TraceDB {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceDB {
    /// Creates a new, empty `TraceDB`.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            checkpoints: BTreeMap::new(),
            next_checkpoint_id: 1,
        }
    }

    /// Pushes a new execution trace entry into the database.
    pub fn push(&mut self, entry: TraceEntry) {
        self.entries.push(entry);
    }

    /// Returns the number of trace entries in the database.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the database contains no trace entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // ── Queries ────────────────────────────────────────────────────────────────

    /// Iterates over all trace entries in chronological order.
    pub fn iter(&self) -> impl Iterator<Item = &TraceEntry> {
        self.entries.iter()
    }

    /// Iterates over trace entries with a risk score at or above the given threshold.
    pub fn iter_risk_above(&self, threshold: f64) -> impl Iterator<Item = &TraceEntry> {
        self.entries
            .iter()
            .filter(move |e| e.annotation.risk_score >= threshold)
    }

    /// Iterates over trace entries containing the specified pattern ID hit.
    pub fn iter_pattern(&self, pattern_id: &str) -> impl Iterator<Item = &TraceEntry> {
        self.entries
            .iter()
            .filter(move |e| e.annotation.pattern_hits.iter().any(|p| p == pattern_id))
    }

    /// Iterates over trace entries matching the specified HDC anchor.
    pub fn iter_hdc_anchor(&self, anchor: &str) -> impl Iterator<Item = &TraceEntry> {
        self.entries
            .iter()
            .filter(move |e| e.annotation.hdc_anchor.as_deref() == Some(anchor))
    }

    /// Returns a reference to the last recorded trace entry, if any.
    pub fn last(&self) -> Option<&TraceEntry> {
        self.entries.last()
    }

    /// Statistics across the whole trace.
    pub fn stats(&self) -> TraceStats {
        let total = self.entries.len();
        if total == 0 {
            return TraceStats::default();
        }
        let max_risk = self
            .entries
            .iter()
            .map(|e| e.annotation.risk_score)
            .fold(0.0, f64::max);
        let avg_risk = self
            .entries
            .iter()
            .map(|e| e.annotation.risk_score)
            .sum::<f64>()
            / total as f64;
        let max_entropy = self
            .entries
            .iter()
            .map(|e| e.annotation.entropy)
            .fold(0.0, f64::max);
        let total_patterns: usize = self
            .entries
            .iter()
            .map(|e| e.annotation.pattern_hits.len())
            .sum();
        let checkpoint_count = self.checkpoints.len();
        TraceStats {
            total,
            max_risk,
            avg_risk,
            max_entropy,
            total_patterns,
            checkpoint_count,
        }
    }

    // ── Checkpoints ────────────────────────────────────────────────────────────

    /// Saves a new checkpoint with the given name, CPU state, and annotation.
    pub fn save_checkpoint(
        &mut self,
        name: &str,
        cpu_state: CpuState,
        annotation: MLAnnotation,
    ) -> u32 {
        let id = self.next_checkpoint_id;
        self.next_checkpoint_id += 1;
        let seq_end = self.entries.last().map_or(0, |e| e.seq);
        let cp = Checkpoint {
            id,
            name: name.into(),
            seq_start: 0,
            seq_end,
            cpu_state,
            annotation_at_save: annotation,
        };
        self.checkpoints.insert(id, cp);
        id
    }

    /// Restores a saved checkpoint by its ID.
    pub fn restore_checkpoint(&self, id: u32) -> Option<&Checkpoint> {
        self.checkpoints.get(&id)
    }

    /// Deletes a saved checkpoint by its ID.
    pub fn delete_checkpoint(&mut self, id: u32) -> Option<Checkpoint> {
        self.checkpoints.remove(&id)
    }

    /// Iterates over all saved checkpoints.
    pub fn iter_checkpoints(&self) -> impl Iterator<Item = &Checkpoint> {
        self.checkpoints.values()
    }

    // ── Export ─────────────────────────────────────────────────────────────────

    /// Exports a slice of trace entries as a JSON string.
    pub fn export_json_slice(&self, start: usize, end: usize) -> String {
        use omnisec_json::json;
        let slice = &self.entries[start..end.min(self.entries.len())];
        let arr: Vec<_> = slice
            .iter()
            .map(|e| {
                json!({
                    "seq": e.seq,
                    "rip": e.rip,
                    "instruction": e.instruction,
                    "risk": e.annotation.risk_score,
                    "entropy": e.annotation.entropy,
                    "hdc_similarity": e.annotation.hdc_similarity,
                    "hdc_anchor": e.annotation.hdc_anchor,
                    "pattern_hits": e.annotation.pattern_hits,
                    "reason": e.annotation.reason,
                    "confidence": e.annotation.confidence,
                })
            })
            .collect();
        omnisec_json::to_json_pretty(&arr)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRACE STATS
// ═══════════════════════════════════════════════════════════════════════════════

/// Summary statistics for execution trace runs.
#[derive(Debug, Clone, Default)]
pub struct TraceStats {
    /// Total number of instructions traced.
    pub total: usize,
    /// Maximum risk score recorded.
    pub max_risk: f64,
    /// Average risk score across all steps.
    pub avg_risk: f64,
    /// Maximum Shannon entropy recorded.
    pub max_entropy: f64,
    /// Total number of pattern hits recorded.
    pub total_patterns: usize,
    /// Total number of checkpoints saved.
    pub checkpoint_count: usize,
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    // Tests intentionally compare against exact, representable constants
    // (0.0, 1.0, hand-computed values); the lint would only add noise here.
    #![allow(clippy::float_cmp)]
    use super::*;
    use omnisec_emu_x86::Register;

    fn dummy_entry(seq: u64, risk: f64) -> TraceEntry {
        let mut state = CpuState::default();
        state.set(Register::RIP, 0x1000 + seq);
        TraceEntry {
            seq,
            rip: 0x1000 + seq,
            instruction: Some("nop".into()),
            raw: vec![0x90],
            annotation: MLAnnotation {
                risk_score: risk,
                entropy: 0.0,
                hdc_similarity: 0.0,
                ..Default::default()
            },
            state,
            stop_reason: StopReason::MaxInstructions,
        }
    }

    #[test]
    fn risk_filtering() {
        let mut db = TraceDB::new();
        db.push(dummy_entry(0, 0.1));
        db.push(dummy_entry(1, 0.9));
        db.push(dummy_entry(2, 0.5));

        let high: Vec<_> = db.iter_risk_above(0.8).collect();
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].seq, 1);
    }

    #[test]
    fn checkpoint_roundtrip() {
        let mut db = TraceDB::new();
        db.push(dummy_entry(0, 0.2));
        db.push(dummy_entry(1, 0.8));

        let state = CpuState::default();
        let ann = MLAnnotation {
            risk_score: 0.8,
            ..Default::default()
        };
        let id = db.save_checkpoint("crypto_loop_start", state.clone(), ann.clone());

        let cp = db.restore_checkpoint(id).unwrap();
        assert_eq!(cp.name, "crypto_loop_start");
        assert_eq!(cp.annotation_at_save.risk_score, 0.8);
    }
}
