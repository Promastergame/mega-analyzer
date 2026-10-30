//! Program Dependence Graph (PDG) construction and topology-aware encoding.
//!
//! A PDG combines control dependencies and data dependencies into a single graph
//! where nodes are instructions and edges represent dependencies. Each node
//! carries a sparse HyperVector, and the graph can be encoded into a single
//! topology-preserving HV for similarity matching.

pub mod encoder;

use encoder::SymbolicEncoder;
use omnisec_cfg::{BlockId, ControlFlowGraph};
use omnisec_dataflow::analyses::{Definition, ReachingDefinitions};
use omnisec_dataflow::framework::DataflowAnalysis;
use omnisec_graph::NodeIndex;
use omnisec_graph::StableDiGraph;
use omnisec_hdc::codebook::{LifecycleStage, SyscallProximity};
use omnisec_hdc::subgraph::EdgeType;
use omnisec_hdc::{HyperVector, SubgraphEncoder};
use omnisec_ir::{Instruction, OpCode, Operand};

use std::collections::HashMap as FxHashMap;

/// A node in the Program Dependence Graph.
#[derive(Debug, Clone)]
pub struct PdgNode {
    /// Instruction address (0 for entry node).
    pub address: u64,
    /// Semantic hypervector.
    pub hv: HyperVector,
}

/// Type of dependency between nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DependencyKind {
    /// Data dependency (Def-Use chain).
    Data,
    /// Control dependency.
    Control,
    /// Sequential execution order.
    Sequential,
    /// Heap alias / lifetime relationship.
    HeapAlias,
}

/// The Program Dependence Graph.
pub struct ProgramDependenceGraph {
    /// The underlying directed graph.
    graph: StableDiGraph<PdgNode, DependencyKind>,
    /// Map from (BlockId, InstructionIndex) to NodeIndex.
    instruction_nodes: FxHashMap<(BlockId, usize), NodeIndex>,
}

impl ProgramDependenceGraph {
    /// Build a PDG from a CFG.
    pub fn build(cfg: &ControlFlowGraph) -> Self {
        let mut graph = StableDiGraph::new();
        let mut instruction_nodes = FxHashMap::default();
        let mut encoder = SymbolicEncoder::new(42);

        // 1. Create nodes for all instructions with heuristic context analysis.
        for (block_id, block) in cfg.iter() {
            let mut seen_free = false;
            for (idx, inst) in block.instructions.iter().enumerate() {
                let lifecycle = heuristic_lifecycle(inst, seen_free);
                let syscall_prox = heuristic_syscall_prox(inst);

                let hv = encoder.encode(inst, lifecycle, syscall_prox);
                let node_idx = graph.add_node(PdgNode {
                    address: inst.address,
                    hv,
                });
                instruction_nodes.insert((block_id, idx), node_idx);

                // Update state for subsequent instructions in the same block.
                if lifecycle == LifecycleStage::Freed {
                    seen_free = true;
                }
            }
        }

        let mut pdg = Self {
            graph,
            instruction_nodes,
        };

        // 2. Add data dependencies.
        pdg.add_data_dependencies(cfg);

        // 3. Add control dependencies.
        pdg.add_control_dependencies(cfg);

        // 4. Add sequential edges to capture temporal order within blocks.
        pdg.add_sequential_edges(cfg);

        // 5. Add heap alias edges for simple pointer tracking.
        pdg.add_heap_alias_edges(cfg);

        pdg
    }

    // ── Topology-Preserving Encoding ─────────────────────────────────────

    /// Encode the **entire** PDG into a single topology-preserving HV.
    ///
    /// Uses edge binding so that graph structure is captured, not just the
    /// set of nodes.
    #[must_use]
    pub fn encode(&self) -> HyperVector {
        let sg_encoder = SubgraphEncoder::new();

        let (node_hvs, edges) = self.to_encoder_input();
        sg_encoder.encode_subgraph(&node_hvs, &edges)
    }

    /// Encode the PDG with weighted edges (topology gets extra weight).
    #[must_use]
    pub fn encode_weighted(&self, edge_weight: usize) -> HyperVector {
        let sg_encoder = SubgraphEncoder::new();
        let (node_hvs, edges) = self.to_encoder_input();
        sg_encoder.encode_subgraph_weighted(&node_hvs, &edges, edge_weight)
    }

    /// Extract a sub-PDG around a specific node (radius = number of hops)
    /// and encode it into a topology-preserving HV.
    ///
    /// This is the primary entry point for vulnerability detection:
    /// the heuristic engine finds a suspicious instruction, then we extract
    /// its neighborhood and compare against anchors.
    #[must_use]
    pub fn encode_neighborhood(&self, center: NodeIndex, radius: usize) -> HyperVector {
        let (node_hvs, edges) = self.extract_neighborhood(center, radius);
        let sg_encoder = SubgraphEncoder::new();
        sg_encoder.encode_subgraph_weighted(&node_hvs, &edges, 2)
    }

    /// Extract the neighborhood of a node as (node_hvs, edges) suitable for
    /// the SubgraphEncoder.
    fn extract_neighborhood(
        &self,
        center: NodeIndex,
        radius: usize,
    ) -> (Vec<HyperVector>, Vec<(usize, usize, EdgeType)>) {
        use omnisec_graph::EdgeRef;
        use std::collections::HashSet as FxHashSet;

        // BFS to find all nodes within `radius` hops.
        let mut visited = FxHashSet::new();
        let mut frontier = vec![center];
        visited.insert(center);

        for _ in 0..radius {
            let mut next_frontier = Vec::new();
            for &node in &frontier {
                // Follow both incoming and outgoing edges.
                for edge in self.graph.edges(node) {
                    let target = edge.target();
                    if visited.insert(target) {
                        next_frontier.push(target);
                    }
                }
                for edge in self
                    .graph
                    .edges_directed(node, omnisec_graph::Direction::Incoming)
                {
                    let source = edge.source();
                    if visited.insert(source) {
                        next_frontier.push(source);
                    }
                }
            }
            frontier = next_frontier;
        }

        // Build node list and index mapping.
        let visited_vec: Vec<NodeIndex> = visited.into_iter().collect();
        let mut node_to_idx: FxHashMap<NodeIndex, usize> = FxHashMap::default();
        let mut node_hvs = Vec::with_capacity(visited_vec.len());
        for (i, &ni) in visited_vec.iter().enumerate() {
            node_to_idx.insert(ni, i);
            node_hvs.push(self.graph[ni].hv);
        }

        // Collect edges within the subgraph.
        let mut edges = Vec::new();
        for &ni in &visited_vec {
            for edge in self.graph.edges(ni) {
                let target = edge.target();
                if let (Some(&src_idx), Some(&dst_idx)) =
                    (node_to_idx.get(&ni), node_to_idx.get(&target))
                {
                    let etype = match edge.weight() {
                        DependencyKind::Data => EdgeType::Data,
                        DependencyKind::Control => EdgeType::Control,
                        DependencyKind::Sequential => EdgeType::Sequential,
                        DependencyKind::HeapAlias => EdgeType::HeapAlias,
                    };
                    edges.push((src_idx, dst_idx, etype));
                }
            }
        }

        (node_hvs, edges)
    }

    /// Convert the entire PDG into the format expected by SubgraphEncoder.
    fn to_encoder_input(&self) -> (Vec<HyperVector>, Vec<(usize, usize, EdgeType)>) {
        use omnisec_graph::EdgeRef;

        // Map NodeIndex → sequential index.
        let mut node_indices: Vec<NodeIndex> = self.graph.node_indices().collect();
        node_indices.sort();
        let mut idx_map: FxHashMap<NodeIndex, usize> = FxHashMap::default();
        let mut node_hvs = Vec::with_capacity(node_indices.len());
        for (i, &ni) in node_indices.iter().enumerate() {
            idx_map.insert(ni, i);
            node_hvs.push(self.graph[ni].hv);
        }

        // Collect all edges.
        let mut edges = Vec::new();
        for edge in self.graph.edge_references() {
            if let (Some(&src), Some(&dst)) =
                (idx_map.get(&edge.source()), idx_map.get(&edge.target()))
            {
                let etype = match edge.weight() {
                    DependencyKind::Data => EdgeType::Data,
                    DependencyKind::Control => EdgeType::Control,
                    DependencyKind::Sequential => EdgeType::Sequential,
                    DependencyKind::HeapAlias => EdgeType::HeapAlias,
                };
                edges.push((src, dst, etype));
            }
        }

        (node_hvs, edges)
    }

    fn add_sequential_edges(&mut self, cfg: &ControlFlowGraph) {
        for (block_id, block) in cfg.iter() {
            for i in 0..block.instructions.len().saturating_sub(1) {
                if let (Some(&src), Some(&dst)) = (
                    self.instruction_nodes.get(&(block_id, i)),
                    self.instruction_nodes.get(&(block_id, i + 1)),
                ) {
                    self.graph.add_edge(src, dst, DependencyKind::Sequential);
                }
            }
        }
    }

    fn add_heap_alias_edges(&mut self, cfg: &ControlFlowGraph) {
        for (block_id, block) in cfg.iter() {
            let mut last_alloc = None;
            let mut last_free = None;
            for (idx, inst) in block.instructions.iter().enumerate() {
                let current_node = self.instruction_nodes[&(block_id, idx)];
                let lifecycle = heuristic_lifecycle(inst, last_free.is_some());

                if lifecycle == LifecycleStage::Allocated {
                    last_alloc = Some(current_node);
                }

                if let Some(alloc) = last_alloc
                    && matches!(
                        lifecycle,
                        LifecycleStage::InUse | LifecycleStage::Freed | LifecycleStage::PostFreeUse
                    )
                {
                    self.graph
                        .add_edge(alloc, current_node, DependencyKind::HeapAlias);
                }

                if lifecycle == LifecycleStage::Freed {
                    last_free = Some(current_node);
                }

                if let Some(free) = last_free
                    && lifecycle == LifecycleStage::PostFreeUse
                {
                    self.graph
                        .add_edge(free, current_node, DependencyKind::HeapAlias);
                }
            }
        }
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// Number of nodes in the PDG.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of edges in the PDG.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Get a node by its graph index.
    #[must_use]
    pub fn node(&self, idx: NodeIndex) -> Option<&PdgNode> {
        self.graph.node_weight(idx)
    }

    /// Iterate over all node indices.
    pub fn node_indices(&self) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.node_indices()
    }

    /// Get the node index for a specific (block, instruction) pair.
    #[must_use]
    pub fn instruction_node(&self, block_id: BlockId, instr_idx: usize) -> Option<NodeIndex> {
        self.instruction_nodes.get(&(block_id, instr_idx)).copied()
    }

    // ── Internal: dependency construction ────────────────────────────────

    fn add_data_dependencies(&mut self, cfg: &ControlFlowGraph) {
        let analysis = ReachingDefinitions::new(cfg);
        let results = analysis.analyze(cfg);

        for (block_id, block) in cfg.iter() {
            let mut current_defs = results.in_fact(block_id).cloned().unwrap_or_default();

            for (idx, inst) in block.instructions.iter().enumerate() {
                let current_node = self.instruction_nodes[&(block_id, idx)];

                let reads = omnisec_dataflow::analyses::registers_read_by(inst);

                for read_reg in reads {
                    for def in &current_defs {
                        if def.variable == read_reg
                            && let Some(&def_node) = self
                                .instruction_nodes
                                .get(&(def.block_id, def.instruction_index))
                        {
                            self.graph
                                .add_edge(def_node, current_node, DependencyKind::Data);
                        }
                    }
                }

                let writes = omnisec_dataflow::analyses::registers_defined_by(inst);
                for write_reg in writes {
                    current_defs.retain(|d| d.variable != write_reg);
                    current_defs.insert(Definition {
                        variable: write_reg,
                        block_id,
                        instruction_index: idx,
                        address: inst.address,
                    });
                }
            }
        }
    }

    fn add_control_dependencies(&mut self, cfg: &ControlFlowGraph) {
        let pdom = omnisec_cfg::dominators::PostDominatorTree::compute(cfg);

        for (u, block) in cfg.iter() {
            for &v in cfg.successors(u) {
                if pdom.post_dominates(v, u) {
                    continue;
                }

                let mut curr = Some(v);
                let stop = pdom.immediate_post_dominator(u);

                while curr.is_some() && curr != stop {
                    let node_id = curr.unwrap();

                    if let Some(target_block) = cfg.block(node_id) {
                        for (idx, _) in target_block.instructions.iter().enumerate() {
                            let target_node = self.instruction_nodes[&(node_id, idx)];

                            if !block.instructions.is_empty() {
                                let branch_idx = block.instructions.len() - 1;
                                let source_node = self.instruction_nodes[&(u, branch_idx)];
                                self.graph.add_edge(
                                    source_node,
                                    target_node,
                                    DependencyKind::Control,
                                );
                            }
                        }
                    }

                    curr = pdom.immediate_post_dominator(node_id);
                }
            }
        }
    }
}

fn heuristic_lifecycle(inst: &Instruction, seen_free: bool) -> LifecycleStage {
    match inst.opcode {
        OpCode::Call | OpCode::IndirectCall => {
            for op in &inst.src {
                if let Operand::Symbol(s) = op {
                    let s_lower = s.to_lowercase();
                    if s_lower.contains("free") {
                        return LifecycleStage::Freed;
                    }
                    if s_lower.contains("alloc") || s_lower.contains("malloc") {
                        return LifecycleStage::Allocated;
                    }
                }
            }
            if seen_free {
                LifecycleStage::PostFreeUse
            } else {
                LifecycleStage::InUse
            }
        }
        OpCode::Load | OpCode::Store => {
            if seen_free {
                LifecycleStage::PostFreeUse
            } else {
                LifecycleStage::InUse
            }
        }
        OpCode::Move | OpCode::Add | OpCode::Sub => {
            if seen_free {
                LifecycleStage::PostFreeUse
            } else {
                LifecycleStage::InUse
            }
        }
        _ => LifecycleStage::Unknown,
    }
}

fn heuristic_syscall_prox(inst: &Instruction) -> SyscallProximity {
    match inst.opcode {
        OpCode::SystemCall => SyscallProximity::IsSyscall,
        _ => SyscallProximity::FarFromSyscall,
    }
}
