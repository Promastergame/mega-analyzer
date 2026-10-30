//! Zero-dependency directed graphs + algorithms (replaces `petgraph`).
//!
//! Provides [`DiGraph`] (swap-remove indices) and [`StableDiGraph`] (stable
//! indices with tombstones), [`Direction`], [`EdgeRef`] and the algorithms
//! used across OmniSec: Tarjan SCC, topological sort, Dijkstra, reachability.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::hash::Hash;

use omnisec_json::{FromJson, JsonError, JsonValue, ToJson};

/// Node handle (index into graph storage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeIndex(pub u32);

impl NodeIndex {
    /// New index.
    #[must_use]
    pub const fn new(i: usize) -> Self {
        Self(i as u32)
    }
    /// Index as usize.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl ToJson for NodeIndex {
    fn to_json(&self) -> JsonValue {
        JsonValue::UInt(u64::from(self.0))
    }
}

impl FromJson for NodeIndex {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        Ok(Self(u32::from_json(v)?))
    }
}

/// Edge direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outgoing edges.
    Outgoing,
    /// Incoming edges.
    Incoming,
}

/// Edge reference (petgraph-shaped).
#[derive(Debug, Clone, Copy)]
pub struct EdgeReference<'a, E> {
    id: usize,
    source: NodeIndex,
    target: NodeIndex,
    weight: &'a E,
}

/// Edge reference trait.
pub trait EdgeRef {
    /// Edge id.
    fn id(&self) -> usize;
    /// Source node.
    fn source(&self) -> NodeIndex;
    /// Target node.
    fn target(&self) -> NodeIndex;
}

impl<E> EdgeRef for EdgeReference<'_, E> {
    fn id(&self) -> usize {
        self.id
    }
    fn source(&self) -> NodeIndex {
        self.source
    }
    fn target(&self) -> NodeIndex {
        self.target
    }
}

impl<'a, E> EdgeReference<'a, E> {
    /// Edge weight.
    #[must_use]
    pub const fn weight(&self) -> &'a E {
        self.weight
    }
}

#[derive(Debug, Clone)]
struct Edge<E> {
    source: NodeIndex,
    target: NodeIndex,
    weight: E,
}

/// Directed graph with swap-remove node storage.
#[derive(Debug, Clone)]
pub struct DiGraph<N, E> {
    nodes: Vec<Option<N>>,
    edges: Vec<Option<Edge<E>>>,
    out: Vec<Vec<usize>>,
    inc: Vec<Vec<usize>>,
}

impl<N, E> DiGraph<N, E> {
    /// Empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            out: Vec::new(),
            inc: Vec::new(),
        }
    }

    /// Node count (alive).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_some()).count()
    }

    /// Edge count (alive).
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.iter().filter(|e| e.is_some()).count()
    }

    /// Add node, return index.
    pub fn add_node(&mut self, w: N) -> NodeIndex {
        // Reuse a vacant slot if any.
        for (i, slot) in self.nodes.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(w);
                return NodeIndex::new(i);
            }
        }
        let i = self.nodes.len();
        self.nodes.push(Some(w));
        self.out.push(Vec::new());
        self.inc.push(Vec::new());
        NodeIndex::new(i)
    }

    /// Add edge, return id.
    pub fn add_edge(&mut self, a: NodeIndex, b: NodeIndex, w: E) -> usize {
        let id = self.edges.len();
        self.edges.push(Some(Edge {
            source: a,
            target: b,
            weight: w,
        }));
        self.out[a.index()].push(id);
        self.inc[b.index()].push(id);
        id
    }

    /// Node weight.
    #[must_use]
    pub fn node_weight(&self, n: NodeIndex) -> Option<&N> {
        self.nodes.get(n.index())?.as_ref()
    }

    /// Node weight mutably.
    pub fn node_weight_mut(&mut self, n: NodeIndex) -> Option<&mut N> {
        self.nodes.get_mut(n.index())?.as_mut()
    }

    /// Edge weight.
    #[must_use]
    pub fn edge_weight(&self, id: usize) -> Option<&E> {
        self.edges.get(id)?.as_ref().map(|e| &e.weight)
    }

    /// All alive node indices.
    pub fn nodes(&self) -> impl Iterator<Item = NodeIndex> + '_ {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.is_some())
            .map(|(i, _)| NodeIndex::new(i))
    }

    /// All alive node indices (petgraph-compat alias for [`DiGraph::nodes`]).
    pub fn node_indices(&self) -> impl Iterator<Item = NodeIndex> + '_ {
        self.nodes()
    }

    /// All edges (petgraph-compat alias).
    pub fn edge_references(&self) -> impl Iterator<Item = EdgeReference<'_, E>> + '_ {
        self.edge_references_all()
    }

    /// Outgoing neighbours (petgraph `Graph::neighbors` shape).
    pub fn neighbors(&self, a: NodeIndex) -> impl Iterator<Item = NodeIndex> + '_ {
        self.neighbors_directed(a, Direction::Outgoing)
    }

    /// Neighbours in direction.
    pub fn neighbors_directed(
        &self,
        n: NodeIndex,
        dir: Direction,
    ) -> impl Iterator<Item = NodeIndex> + '_ {
        let list = match dir {
            Direction::Outgoing => &self.out[n.index()],
            Direction::Incoming => &self.inc[n.index()],
        };
        list.iter().filter_map(move |&eid| {
            let e = self.edges[eid].as_ref()?;
            Some(match dir {
                Direction::Outgoing => e.target,
                Direction::Incoming => e.source,
            })
        })
    }

    /// Edges in direction with weights.
    pub fn edges_directed(
        &self,
        n: NodeIndex,
        dir: Direction,
    ) -> impl Iterator<Item = EdgeReference<'_, E>> + '_ {
        let list = match dir {
            Direction::Outgoing => &self.out[n.index()],
            Direction::Incoming => &self.inc[n.index()],
        };
        list.iter().filter_map(move |&eid| {
            let e = self.edges[eid].as_ref()?;
            Some(EdgeReference {
                id: eid,
                source: e.source,
                target: e.target,
                weight: &e.weight,
            })
        })
    }

    /// All edges.
    pub fn edge_references_all(&self) -> impl Iterator<Item = EdgeReference<'_, E>> + '_ {
        self.edges.iter().enumerate().filter_map(|(id, e)| {
            let e = e.as_ref()?;
            Some(EdgeReference {
                id,
                source: e.source,
                target: e.target,
                weight: &e.weight,
            })
        })
    }

    /// Outgoing edges of `a` (petgraph `Graph::edges` shape).
    pub fn edges(&self, a: NodeIndex) -> impl Iterator<Item = EdgeReference<'_, E>> + '_ {
        self.edges_directed(a, Direction::Outgoing)
    }

    /// Find edge id.
    #[must_use]
    pub fn find_edge(&self, a: NodeIndex, b: NodeIndex) -> Option<usize> {
        self.out[a.index()]
            .iter()
            .copied()
            .find(|&eid| self.edges[eid].as_ref().is_some_and(|e| e.target == b))
    }

    /// Remove node + incident edges.
    pub fn remove_node(&mut self, n: NodeIndex) -> Option<N> {
        let w = self.nodes.get_mut(n.index())?.take()?;
        let mut dead: Vec<usize> = Vec::new();
        dead.extend(self.out[n.index()].iter().copied());
        dead.extend(self.inc[n.index()].iter().copied());
        for eid in dead {
            self.remove_edge_id(eid);
        }
        self.out[n.index()].clear();
        self.inc[n.index()].clear();
        Some(w)
    }

    fn remove_edge_id(&mut self, eid: usize) -> Option<E> {
        let e = self.edges.get_mut(eid)?.take()?;
        self.out[e.source.index()].retain(|&x| x != eid);
        self.inc[e.target.index()].retain(|&x| x != eid);
        Some(e.weight)
    }

    /// Clear all.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.edges.clear();
        self.out.clear();
        self.inc.clear();
    }
}

impl<N: ToJson, E: ToJson> ToJson for DiGraph<N, E> {
    fn to_json(&self) -> JsonValue {
        let nodes: Vec<JsonValue> = self
            .nodes
            .iter()
            .map(|n| match n {
                Some(w) => w.to_json(),
                None => JsonValue::Null,
            })
            .collect();
        let edges: Vec<JsonValue> = self
            .edges
            .iter()
            .filter_map(|e| {
                let e = e.as_ref()?;
                Some(JsonValue::Array(vec![
                    JsonValue::UInt(u64::from(e.source.0)),
                    JsonValue::UInt(u64::from(e.target.0)),
                    e.weight.to_json(),
                ]))
            })
            .collect();
        JsonValue::Object(vec![
            ("nodes".to_string(), JsonValue::Array(nodes)),
            ("edges".to_string(), JsonValue::Array(edges)),
        ])
    }
}

impl<N: FromJson, E: FromJson> FromJson for DiGraph<N, E> {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        let mut graph = Self::new();
        let nodes = v
            .get("nodes")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| JsonError("expected graph nodes".into()))?;
        for w in nodes {
            if w.is_null() {
                graph.nodes.push(None);
                graph.out.push(Vec::new());
                graph.inc.push(Vec::new());
            } else {
                let weight = N::from_json(w)?;
                graph.nodes.push(Some(weight));
                graph.out.push(Vec::new());
                graph.inc.push(Vec::new());
            }
        }
        let edges = v
            .get("edges")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| JsonError("expected graph edges".into()))?;
        for e in edges {
            let arr = e
                .as_array()
                .ok_or_else(|| JsonError("expected edge triple".into()))?;
            if arr.len() != 3 {
                return Err(JsonError("edge triple must have 3 elements".into()));
            }
            let source = NodeIndex(u32::from_json(&arr[0])?);
            let target = NodeIndex(u32::from_json(&arr[1])?);
            let weight = E::from_json(&arr[2])?;
            let id = graph.edges.len();
            graph.edges.push(Some(Edge {
                source,
                target,
                weight,
            }));
            if let Some(slot) = graph.out.get_mut(source.index()) {
                slot.push(id);
            }
            if let Some(slot) = graph.inc.get_mut(target.index()) {
                slot.push(id);
            }
        }
        Ok(graph)
    }
}

/// Directed graph with fully stable indices (tombstones, never reused).
#[derive(Debug, Clone)]
pub struct StableDiGraph<N, E> {
    inner: DiGraph<N, E>,
    alive: Vec<bool>,
}

impl<N, E> StableDiGraph<N, E> {
    /// Empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: DiGraph::new(),
            alive: Vec::new(),
        }
    }

    /// Node count (alive).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.alive.iter().filter(|&&a| a).count()
    }

    /// Edge count.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.inner.edge_count()
    }

    /// Add node.
    pub fn add_node(&mut self, w: N) -> NodeIndex {
        let idx = self.inner.nodes.len();
        self.inner.nodes.push(Some(w));
        self.inner.out.push(Vec::new());
        self.inner.inc.push(Vec::new());
        self.alive.push(true);
        NodeIndex::new(idx)
    }

    /// Add edge.
    pub fn add_edge(&mut self, a: NodeIndex, b: NodeIndex, w: E) -> usize {
        self.inner.add_edge(a, b, w)
    }

    /// Node weight.
    #[must_use]
    pub fn node_weight(&self, n: NodeIndex) -> Option<&N> {
        if !self.alive.get(n.index()).copied().unwrap_or(false) {
            return None;
        }
        self.inner.node_weight(n)
    }

    /// Node weight mutably.
    pub fn node_weight_mut(&mut self, n: NodeIndex) -> Option<&mut N> {
        if !self.alive.get(n.index()).copied().unwrap_or(false) {
            return None;
        }
        self.inner.node_weight_mut(n)
    }

    /// Edge weight.
    #[must_use]
    pub fn edge_weight(&self, id: usize) -> Option<&E> {
        self.inner.edge_weight(id)
    }

    /// Alive nodes.
    pub fn nodes(&self) -> impl Iterator<Item = NodeIndex> + '_ {
        self.alive
            .iter()
            .enumerate()
            .filter(|(_, a)| **a)
            .map(|(i, _)| NodeIndex::new(i))
    }

    /// Alive node indices (petgraph-compat alias for [`StableDiGraph::nodes`]).
    pub fn node_indices(&self) -> impl Iterator<Item = NodeIndex> + '_ {
        self.nodes()
    }

    /// All edges (petgraph-compat alias).
    pub fn edge_references(&self) -> impl Iterator<Item = EdgeReference<'_, E>> + '_ {
        self.inner.edge_references_all()
    }

    /// Neighbours.
    pub fn neighbors_directed(
        &self,
        n: NodeIndex,
        dir: Direction,
    ) -> impl Iterator<Item = NodeIndex> + '_ {
        self.inner
            .neighbors_directed(n, dir)
            .filter(|m| self.alive.get(m.index()).copied().unwrap_or(false))
    }

    /// Edges.
    pub fn edges_directed(
        &self,
        n: NodeIndex,
        dir: Direction,
    ) -> impl Iterator<Item = EdgeReference<'_, E>> + '_ {
        self.inner.edges_directed(n, dir)
    }

    /// Outgoing edges of `a` (petgraph `Graph::edges` shape).
    pub fn edges(&self, a: NodeIndex) -> impl Iterator<Item = EdgeReference<'_, E>> + '_ {
        self.inner.edges(a)
    }

    /// Remove node (stable: index never reused).
    pub fn remove_node(&mut self, n: NodeIndex) -> Option<N> {
        if !self.alive.get(n.index()).copied().unwrap_or(false) {
            return None;
        }
        self.alive[n.index()] = false;
        self.inner.remove_node(n)
    }
}

impl<N, E> Default for DiGraph<N, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N, E> Default for StableDiGraph<N, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N, E> std::ops::Index<NodeIndex> for DiGraph<N, E> {
    type Output = N;
    fn index(&self, n: NodeIndex) -> &N {
        self.node_weight(n).expect("graph index: node not present")
    }
}

impl<N, E> std::ops::Index<NodeIndex> for StableDiGraph<N, E> {
    type Output = N;
    fn index(&self, n: NodeIndex) -> &N {
        self.node_weight(n).expect("graph index: node not present")
    }
}

/// Strongly connected components (Tarjan, deterministic order).
pub fn scc_tarjan<N, E>(g: &DiGraph<N, E>) -> Vec<Vec<NodeIndex>> {
    let mut index_of: HashMap<usize, usize> = HashMap::new();
    let mut low: HashMap<usize, usize> = HashMap::new();
    let mut on_stack: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut next = 0usize;
    let mut out: Vec<Vec<NodeIndex>> = Vec::new();

    fn strong<N, E>(
        v: usize,
        g: &DiGraph<N, E>,
        next: &mut usize,
        index_of: &mut HashMap<usize, usize>,
        low: &mut HashMap<usize, usize>,
        on_stack: &mut HashSet<usize>,
        stack: &mut Vec<usize>,
        out: &mut Vec<Vec<NodeIndex>>,
    ) {
        index_of.insert(v, *next);
        low.insert(v, *next);
        *next += 1;
        stack.push(v);
        on_stack.insert(v);
        let succ: Vec<usize> = g
            .neighbors_directed(NodeIndex::new(v), Direction::Outgoing)
            .map(|n| n.index())
            .collect();
        for w in succ {
            if !index_of.contains_key(&w) {
                strong(w, g, next, index_of, low, on_stack, stack, out);
                let lv = low[&v].min(low[&w]);
                low.insert(v, lv);
            } else if on_stack.contains(&w) {
                let lv = low[&v].min(index_of[&w]);
                low.insert(v, lv);
            }
        }
        if low[&v] == index_of[&v] {
            let mut comp = Vec::new();
            while let Some(w) = stack.pop() {
                on_stack.remove(&w);
                comp.push(NodeIndex::new(w));
                if w == v {
                    break;
                }
            }
            out.push(comp);
        }
    }

    let mut all: Vec<usize> = g.nodes().map(|n| n.index()).collect();
    all.sort_unstable();
    for v in all {
        if !index_of.contains_key(&v) {
            strong(
                v,
                g,
                &mut next,
                &mut index_of,
                &mut low,
                &mut on_stack,
                &mut stack,
                &mut out,
            );
        }
    }
    out
}

/// Cycle marker for [`topo_sort`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cycle;

/// Topological order (Kahn). `Err(Cycle)` if cyclic.
pub fn topo_sort<N, E>(g: &DiGraph<N, E>) -> Result<Vec<NodeIndex>, Cycle> {
    let mut indeg: HashMap<usize, usize> = HashMap::new();
    for n in g.nodes() {
        indeg.insert(n.index(), 0);
    }
    for e in g.edge_references_all() {
        *indeg.entry(e.target().index()).or_insert(0) += 1;
    }
    let mut ready: Vec<usize> = indeg
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(n, _)| *n)
        .collect();
    ready.sort_unstable();
    let mut order = Vec::new();
    while let Some(v) = ready.pop() {
        order.push(NodeIndex::new(v));
        let mut succ: Vec<usize> = g
            .neighbors_directed(NodeIndex::new(v), Direction::Outgoing)
            .map(|n| n.index())
            .collect();
        succ.sort_unstable();
        for w in succ {
            if let Some(d) = indeg.get_mut(&w) {
                *d -= 1;
                if *d == 0 {
                    ready.push(w);
                }
            }
        }
    }
    if order.len() == indeg.len() {
        Ok(order)
    } else {
        Err(Cycle)
    }
}

/// Dijkstra shortest distances from `src` (edge cost via closure).
pub fn dijkstra<N, E>(
    g: &DiGraph<N, E>,
    src: NodeIndex,
    mut cost: impl FnMut(usize) -> u64,
) -> HashMap<NodeIndex, u64> {
    let mut dist: HashMap<NodeIndex, u64> = HashMap::new();
    let mut heap: BinaryHeap<(std::cmp::Reverse<u64>, u32)> = BinaryHeap::new();
    dist.insert(src, 0);
    heap.push((std::cmp::Reverse(0), src.0));
    while let Some((std::cmp::Reverse(d), u)) = heap.pop() {
        let un = NodeIndex(u);
        if dist.get(&un).is_some_and(|&best| d > best) {
            continue;
        }
        for e in g.edges_directed(un, Direction::Outgoing) {
            let v = e.target();
            let nd = d.saturating_add(cost(e.id()));
            if dist.get(&v).is_none_or(|&best| nd < best) {
                dist.insert(v, nd);
                heap.push((std::cmp::Reverse(nd), v.0));
            }
        }
    }
    dist
}

/// DFS reachability from `src` (including `src`).
pub fn reachable_dfs<N, E>(g: &DiGraph<N, E>, src: NodeIndex) -> HashSet<NodeIndex> {
    let mut seen = HashSet::new();
    let mut stack = vec![src];
    while let Some(n) = stack.pop() {
        if seen.insert(n) {
            stack.extend(g.neighbors_directed(n, Direction::Outgoing));
        }
    }
    seen
}

/// `true` if `dst` reachable from `src`.
pub fn has_path<N, E>(g: &DiGraph<N, E>, src: NodeIndex, dst: NodeIndex) -> bool {
    reachable_dfs(g, src).contains(&dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scc_finds_cycle() {
        let mut g: DiGraph<(), ()> = DiGraph::new();
        let a = g.add_node(());
        let b = g.add_node(());
        let c = g.add_node(());
        g.add_edge(a, b, ());
        g.add_edge(b, a, ());
        g.add_edge(b, c, ());
        let mut scc = scc_tarjan(&g);
        for comp in &mut scc {
            comp.sort();
        }
        scc.sort();
        assert_eq!(scc.len(), 2);
    }

    #[test]
    fn topo_orders_dag() {
        let mut g: DiGraph<(), ()> = DiGraph::new();
        let a = g.add_node(());
        let b = g.add_node(());
        g.add_edge(a, b, ());
        let order = topo_sort(&g).unwrap();
        assert_eq!(order, vec![a, b]);
    }

    #[test]
    fn stable_indices_survive_remove() {
        let mut g: StableDiGraph<&str, ()> = StableDiGraph::new();
        let a = g.add_node("a");
        let b = g.add_node("b");
        g.add_edge(a, b, ());
        g.remove_node(a);
        assert!(g.node_weight(a).is_none());
        assert_eq!(g.node_weight(b), Some(&"b"));
    }
}
