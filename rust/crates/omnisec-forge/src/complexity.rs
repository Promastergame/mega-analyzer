//! [`ComplexityScore`] — a deterministic ranking that lets the chain
//! assembler prefer "stable, reliable" gadget chains over convoluted ones.
//!
//! The score is an integer (lower = simpler) so we avoid floating-point
//! comparisons that would otherwise be subject to NaN ordering pitfalls.

use omnisec_json::{FromJson, ToJson};

/// Deterministic complexity ranking for a candidate gadget chain or DOP graph.
///
/// Combines several penalties into a single `u64` so chains can be
/// totally-ordered. The lower-is-better convention matches `BinaryHeap::pop`
/// returning the smallest element when wrapped in `Reverse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ToJson, FromJson)]
pub struct ComplexityScore(pub u64);

impl ComplexityScore {
    /// Build from individual penalty components.
    ///
    /// - `gadgets`: how many gadgets the chain stitches together. Each gadget
    ///   adds a chance of failure on a given run.
    /// - `mem_writes`: how many writes the chain performs to memory the
    ///   payload doesn't fully control. Each one is a stability hazard.
    /// - `bad_byte_hits`: how many places we had to *encode around* a bad
    ///   byte. The polymorphic encoder can usually handle them but each one
    ///   inflates the payload.
    /// - `bypasses`: how many distinct mitigation bypass strategies the
    ///   chain stacks. More bypasses ⇒ more variance, hence more complex.
    #[must_use]
    pub fn from_components(
        gadgets: u32,
        mem_writes: u32,
        bad_byte_hits: u32,
        bypasses: u32,
    ) -> Self {
        // Pack each penalty into a fixed slot so very wide chains never
        // cause the ordering to flip from one component to another.
        // Layout (high → low):
        //   16 bits gadgets
        //   16 bits mem_writes
        //   16 bits bad_byte_hits
        //   16 bits bypasses
        let g = u64::from(gadgets.min(0xFFFF)) << 48;
        let m = u64::from(mem_writes.min(0xFFFF)) << 32;
        let b = u64::from(bad_byte_hits.min(0xFFFF)) << 16;
        let y = u64::from(bypasses.min(0xFFFF));
        Self(g | m | b | y)
    }

    /// "Trivial" chain — used as a sentinel when there's nothing to rank.
    pub const TRIVIAL: Self = Self(0);

    /// Numeric score. Lower is simpler.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Combine two complexity scores (saturating addition on each
    /// 16-bit field).
    #[must_use]
    pub fn saturating_add(self, other: Self) -> Self {
        let unpack = |v: u64| {
            (
                v >> 48 & 0xFFFF,
                v >> 32 & 0xFFFF,
                v >> 16 & 0xFFFF,
                v & 0xFFFF,
            )
        };
        let (a_g, a_m, a_b, a_y) = unpack(self.0);
        let (b_g, b_m, b_b, b_y) = unpack(other.0);
        Self::from_components(
            (a_g.saturating_add(b_g)).min(0xFFFF) as u32,
            (a_m.saturating_add(b_m)).min(0xFFFF) as u32,
            (a_b.saturating_add(b_b)).min(0xFFFF) as u32,
            (a_y.saturating_add(b_y)).min(0xFFFF) as u32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorter_chain_ranks_lower() {
        let short = ComplexityScore::from_components(3, 0, 0, 0);
        let long = ComplexityScore::from_components(8, 0, 0, 0);
        assert!(short < long);
    }

    #[test]
    fn fields_are_independent() {
        // gadgets dominates mem_writes
        let many_writes = ComplexityScore::from_components(2, 100, 0, 0);
        let many_gadgets = ComplexityScore::from_components(3, 0, 0, 0);
        assert!(many_writes < many_gadgets);
    }

    #[test]
    fn saturating_add_clamps() {
        let a = ComplexityScore::from_components(0xFFFF, 0, 0, 0);
        let b = ComplexityScore::from_components(0xFFFF, 0, 0, 0);
        let s = a.saturating_add(b);
        // Top field saturates, doesn't overflow into mem_writes.
        assert_eq!(s.raw() >> 48, 0xFFFF);
        assert_eq!((s.raw() >> 32) & 0xFFFF, 0);
    }
}
