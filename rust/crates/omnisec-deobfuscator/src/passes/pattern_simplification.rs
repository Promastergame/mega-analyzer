//! **Pattern-Based Simplification** pass.
//!
//! Delegates to the [`crate::patterns::PatternLibrary`] to find and replace
//! known obfuscation idioms within each basic block.

use std::time::Instant;

use omnisec_cfg::ControlFlowGraph;

use super::DeobfuscationPass;
use crate::patterns::PatternLibrary;
use crate::stats::PassStats;

/// Pattern simplification pass.
pub struct PatternSimplificationPass {
    library: PatternLibrary,
}

impl Default for PatternSimplificationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternSimplificationPass {
    /// Create a new pass with the default pattern library.
    #[must_use]
    pub fn new() -> Self {
        Self {
            library: PatternLibrary::new(),
        }
    }

    /// Create with a custom pattern library.
    #[must_use]
    pub fn with_library(library: PatternLibrary) -> Self {
        Self { library }
    }
}

impl DeobfuscationPass for PatternSimplificationPass {
    fn name(&self) -> &'static str {
        "PatternSimplification"
    }

    fn run(&self, cfg: &mut ControlFlowGraph) -> PassStats {
        let start = Instant::now();
        let mut stats = PassStats::new(self.name());

        let block_ids: Vec<u32> = cfg.block_ids().collect();

        for block_id in block_ids {
            let block = match cfg.block(block_id) {
                Some(b) => b,
                None => continue,
            };

            if block.instructions.is_empty() {
                continue;
            }

            // Scan for pattern matches
            let matches = self.library.scan(&block.instructions);
            if matches.is_empty() {
                continue;
            }

            // Apply matches in reverse order to maintain indices
            let mut new_insns = block.instructions.clone();
            let mut offset: i64 = 0;

            for m in &matches {
                let adjusted_start = (m.start_idx as i64 + offset) as usize;
                let adjusted_end = adjusted_start + m.match_len;

                if adjusted_end <= new_insns.len() {
                    let before = new_insns[..adjusted_start].to_vec();
                    let after = new_insns[adjusted_end..].to_vec();

                    new_insns = before;
                    new_insns.extend(m.replacement.iter().cloned());
                    new_insns.extend(after);

                    let len_diff = m.replacement.len() as i64 - m.match_len as i64;
                    offset += len_diff;

                    stats.patterns_applied += 1;
                    stats.instructions_changed += m.match_len;
                    stats.trace.push(format!(
                        "Block {block_id}: {} (confidence: {}%)",
                        m.annotation, m.confidence
                    ));
                }
            }

            if stats.patterns_applied > 0
                && let Some(block_mut) = cfg.block_mut(block_id)
            {
                block_mut.instructions = new_insns;
            }
        }

        stats.duration = start.elapsed();
        stats
    }
}
