//! Generic dataflow analysis framework.

use omnisec_cfg::ControlFlowGraph;

/// Analysis direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Forward analysis (from entry to exit).
    Forward,
    /// Backward analysis (from exit to entry).
    Backward,
}

/// Meet operator for combining dataflow facts.
pub trait MeetOperator<T>: Send + Sync {
    /// Combine two facts.
    fn meet(&self, a: &T, b: &T) -> T;
}

/// Generic dataflow analysis trait.
pub trait DataflowAnalysis<T>: Send + Sync
where
    T: Clone + PartialEq,
{
    /// Direction of this analysis.
    fn direction(&self) -> Direction;

    /// Initial fact at the entry (for forward) or exit (for backward).
    fn initial_fact(&self) -> T;

    /// Transfer function for a single basic block.
    fn transfer(&self, block_id: u32, fact: T) -> T;

    /// Meet operator for this analysis.
    fn meet(&self) -> Box<dyn MeetOperator<T>>;

    /// Run the analysis on a CFG.
    fn analyze(&self, cfg: &ControlFlowGraph) -> AnalysisResult<T> {
        let block_ids: Vec<u32> = cfg.block_ids().collect();
        let mut in_facts: std::collections::HashMap<u32, T> = std::collections::HashMap::default();
        let mut out_facts: std::collections::HashMap<u32, T> = std::collections::HashMap::default();

        let meet_op = self.meet();
        let initial = self.initial_fact();

        // Initialize facts.
        for &id in &block_ids {
            in_facts.insert(id, initial.clone());
            out_facts.insert(id, initial.clone());
        }

        // Set entry/exit initial fact.
        let entry = cfg.entry();
        match self.direction() {
            Direction::Forward => {
                in_facts.insert(entry, initial.clone());
            }
            Direction::Backward => {
                // For backward analysis, exit blocks get initial fact.
                for &id in &block_ids {
                    let block = cfg.block(id).unwrap();
                    if block.terminator().is_some() {
                        out_facts.insert(id, initial.clone());
                    }
                }
            }
        }

        // Fixed-point iteration.
        let mut changed = true;
        let mut iterations = 0;
        while changed && iterations < 1000 {
            changed = false;
            iterations += 1;

            let order = match self.direction() {
                Direction::Forward => cfg.reverse_postorder(),
                Direction::Backward => cfg.reverse_postorder().into_iter().rev().collect(),
            };

            for id in order {
                let (new_in, new_out) = match self.direction() {
                    Direction::Forward => {
                        let preds = cfg.predecessors(id);
                        let new_in = if preds.is_empty() {
                            in_facts[&entry].clone()
                        } else {
                            preds.iter().fold(initial.clone(), |acc, &pred| {
                                meet_op.meet(&acc, &out_facts[&pred])
                            })
                        };
                        let new_out = self.transfer(id, new_in.clone());
                        (new_in, new_out)
                    }
                    Direction::Backward => {
                        let succs = cfg.successors(id);
                        let new_out = if succs.is_empty() {
                            initial.clone()
                        } else {
                            succs.iter().fold(initial.clone(), |acc, &succ| {
                                meet_op.meet(&acc, &in_facts[&succ])
                            })
                        };
                        let new_in = self.transfer(id, new_out.clone());
                        (new_in, new_out)
                    }
                };

                // Check for changes.
                if new_in != in_facts[&id] || new_out != out_facts[&id] {
                    in_facts.insert(id, new_in);
                    out_facts.insert(id, new_out);
                    changed = true;
                }
            }
        }

        AnalysisResult {
            in_facts,
            out_facts,
        }
    }
}

/// Result of a dataflow analysis.
#[derive(Debug, Clone)]
pub struct AnalysisResult<T> {
    /// In fact for each basic block.
    pub in_facts: std::collections::HashMap<u32, T>,
    /// Out fact for each basic block.
    pub out_facts: std::collections::HashMap<u32, T>,
}

impl<T> AnalysisResult<T> {
    /// Get the in fact for a block.
    #[must_use]
    pub fn in_fact(&self, block_id: u32) -> Option<&T> {
        self.in_facts.get(&block_id)
    }

    /// Get the out fact for a block.
    #[must_use]
    pub fn out_fact(&self, block_id: u32) -> Option<&T> {
        self.out_facts.get(&block_id)
    }
}
