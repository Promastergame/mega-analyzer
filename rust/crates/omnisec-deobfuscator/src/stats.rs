//! Deobfuscation statistics and metrics tracking.
//!
//! Every pass reports what it did via [`PassStats`]. The pipeline aggregates
//! them into [`DeobfuscationStats`] — a single object that tells you exactly
//! how much cleaner the code got.

use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

/// Statistics for a single deobfuscation pass execution.
#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct PassStats {
    /// Human-readable name of the pass (e.g. "ConstantPropagation").
    pub pass_name: String,
    /// Number of instructions changed / removed / folded.
    pub instructions_changed: usize,
    /// Number of basic blocks removed (dead code, merged).
    pub blocks_removed: usize,
    /// Number of edges removed from the CFG.
    pub edges_removed: usize,
    /// Number of constants resolved.
    pub constants_resolved: usize,
    /// Number of strings decrypted.
    pub strings_decrypted: usize,
    /// Number of opaque predicates eliminated.
    pub opaque_predicates_removed: usize,
    /// Number of pattern matches applied.
    pub patterns_applied: usize,
    /// Number of MBA expressions simplified.
    pub mba_simplified: usize,
    /// Execution time of this pass.
    #[json(with = "duration_serde")]
    pub duration: Duration,
    /// Free-form trace messages for debugging.
    #[json(skip_serializing_if = "Vec::is_empty", default)]
    pub trace: Vec<String>,
}

impl PassStats {
    /// Create empty stats for a named pass.
    #[must_use]
    pub fn new(pass_name: impl Into<String>) -> Self {
        Self {
            pass_name: pass_name.into(),
            ..Default::default()
        }
    }

    /// Total number of changes made by this pass.
    #[must_use]
    pub fn total_changes(&self) -> usize {
        self.instructions_changed
            + self.blocks_removed
            + self.edges_removed
            + self.constants_resolved
            + self.strings_decrypted
            + self.opaque_predicates_removed
            + self.patterns_applied
            + self.mba_simplified
    }
}

/// Aggregated statistics across all passes and iterations.
#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct DeobfuscationStats {
    /// Total number of fixed-point iterations run.
    pub iterations: usize,
    /// Per-pass statistics for each iteration.
    /// Key: `"{pass_name}:iter{N}"`.
    pub pass_stats: HashMap<String, PassStats>,
    /// Total wall-clock time for the entire pipeline.
    #[json(with = "duration_serde")]
    pub total_duration: Duration,

    // ── Aggregated counters ─────────────────────────────────────────
    /// Total instructions changed across all passes.
    pub total_instructions_changed: usize,
    /// Total blocks removed.
    pub total_blocks_removed: usize,
    /// Total constants resolved.
    pub total_constants_resolved: usize,
    /// Total strings decrypted.
    pub total_strings_decrypted: usize,
    /// Total opaque predicates removed.
    pub total_opaque_predicates_removed: usize,
    /// Total patterns applied.
    pub total_patterns_applied: usize,
    /// Total MBA expressions simplified.
    pub total_mba_simplified: usize,

    // ── Before / After metrics ──────────────────────────────────────
    /// Number of instructions before deobfuscation.
    pub instructions_before: usize,
    /// Number of instructions after deobfuscation.
    pub instructions_after: usize,
    /// Number of basic blocks before deobfuscation.
    pub blocks_before: usize,
    /// Number of basic blocks after deobfuscation.
    pub blocks_after: usize,
}

impl DeobfuscationStats {
    /// Record the result of a single pass execution.
    pub fn record_pass(&mut self, iteration: usize, stats: PassStats) {
        self.total_instructions_changed += stats.instructions_changed;
        self.total_blocks_removed += stats.blocks_removed;
        self.total_constants_resolved += stats.constants_resolved;
        self.total_strings_decrypted += stats.strings_decrypted;
        self.total_opaque_predicates_removed += stats.opaque_predicates_removed;
        self.total_patterns_applied += stats.patterns_applied;
        self.total_mba_simplified += stats.mba_simplified;

        let key = format!("{}:iter{}", stats.pass_name, iteration);
        self.pass_stats.insert(key, stats);
    }

    /// Complexity reduction percentage.
    #[must_use]
    pub fn reduction_percent(&self) -> f64 {
        if self.instructions_before == 0 {
            return 0.0;
        }
        let removed = self
            .instructions_before
            .saturating_sub(self.instructions_after);
        (removed as f64 / self.instructions_before as f64) * 100.0
    }

    /// Total number of meaningful changes across all passes.
    #[must_use]
    pub fn total_changes(&self) -> usize {
        self.total_instructions_changed
            + self.total_blocks_removed
            + self.total_constants_resolved
            + self.total_strings_decrypted
            + self.total_opaque_predicates_removed
            + self.total_patterns_applied
            + self.total_mba_simplified
    }
}

impl fmt::Display for DeobfuscationStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "╔══════════════════════════════════════════════════╗")?;
        writeln!(f, "║       OmniSec Deobfuscation Report               ║")?;
        writeln!(f, "╠══════════════════════════════════════════════════╣")?;
        writeln!(f, "║  Iterations:           {:<25}║", self.iterations)?;
        writeln!(
            f,
            "║  Duration:             {:<25}║",
            format!("{:.2?}", self.total_duration)
        )?;
        writeln!(f, "╠══════════════════════════════════════════════════╣")?;
        writeln!(
            f,
            "║  Instructions:  {} → {} ({:.1}% reduction){}║",
            self.instructions_before,
            self.instructions_after,
            self.reduction_percent(),
            " ".repeat(8)
        )?;
        writeln!(
            f,
            "║  Blocks:        {} → {}{}║",
            self.blocks_before,
            self.blocks_after,
            " ".repeat(26)
        )?;
        writeln!(f, "╠══════════════════════════════════════════════════╣")?;
        writeln!(
            f,
            "║  Constants resolved:   {:<25}║",
            self.total_constants_resolved
        )?;
        writeln!(
            f,
            "║  Opaque preds removed: {:<25}║",
            self.total_opaque_predicates_removed
        )?;
        writeln!(
            f,
            "║  Patterns applied:     {:<25}║",
            self.total_patterns_applied
        )?;
        writeln!(
            f,
            "║  Strings decrypted:    {:<25}║",
            self.total_strings_decrypted
        )?;
        writeln!(
            f,
            "║  MBA simplified:       {:<25}║",
            self.total_mba_simplified
        )?;
        writeln!(f, "╚══════════════════════════════════════════════════╝")?;
        Ok(())
    }
}

/// JSON helper for `Duration` (fractional seconds).
mod duration_serde {
    use omnisec_json::{JsonError, JsonValue};
    use std::time::Duration;

    /// Serialize a Duration as fractional seconds.
    pub fn to_json(d: &Duration) -> JsonValue {
        JsonValue::Float(d.as_secs_f64())
    }

    /// Deserialize a Duration from fractional seconds.
    pub fn from_json(v: &JsonValue) -> Result<Duration, JsonError> {
        let secs = v
            .as_f64()
            .ok_or_else(|| JsonError("expected number".into()))?;
        Ok(Duration::from_secs_f64(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction_percent_works() {
        let stats = DeobfuscationStats {
            instructions_before: 1000,
            instructions_after: 300,
            ..Default::default()
        };
        assert!((stats.reduction_percent() - 70.0).abs() < 0.01);
    }

    #[test]
    fn record_pass_aggregates() {
        let mut stats = DeobfuscationStats::default();
        let mut pass1 = PassStats::new("ConstProp");
        pass1.constants_resolved = 50;
        pass1.instructions_changed = 30;

        let mut pass2 = PassStats::new("DCE");
        pass2.blocks_removed = 10;
        pass2.instructions_changed = 20;

        stats.record_pass(0, pass1);
        stats.record_pass(0, pass2);

        assert_eq!(stats.total_constants_resolved, 50);
        assert_eq!(stats.total_blocks_removed, 10);
        assert_eq!(stats.total_instructions_changed, 50);
        assert_eq!(stats.pass_stats.len(), 2);
    }
}
