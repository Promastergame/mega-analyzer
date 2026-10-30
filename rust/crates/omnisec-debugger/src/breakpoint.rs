//! Breakpoint management — software INT3 patches with original-byte storage.

use std::collections::BTreeMap;

/// Opaque breakpoint identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BreakpointId(pub u32);

/// A software breakpoint.
#[derive(Debug, Clone)]
pub struct Breakpoint {
    /// Unique id.
    pub id: BreakpointId,
    /// Virtual address where the breakpoint is installed.
    pub address: u64,
    /// Original byte overwritten by 0xCC.
    pub original_byte: u8,
    /// Is the breakpoint currently active (inserted into memory)?
    pub enabled: bool,
    /// Hit count.
    pub hit_count: u64,
    /// Optional condition expression (future: "rax == 0xdeadbeef").
    pub condition: Option<String>,
}

/// Manages all breakpoints for a session.
#[derive(Debug, Default)]
pub struct BreakpointManager {
    next_id: u32,
    breakpoints: BTreeMap<BreakpointId, Breakpoint>,
    by_address: BTreeMap<u64, BreakpointId>,
}

impl BreakpointManager {
    /// Create an empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a new breakpoint, returning its id.
    ///
    /// # Panics
    /// Panics if `address` already has a breakpoint.
    pub fn add(&mut self, address: u64, original_byte: u8) -> BreakpointId {
        assert!(
            !self.by_address.contains_key(&address),
            "breakpoint already exists at {address:#x}"
        );
        let id = BreakpointId(self.next_id);
        self.next_id += 1;
        let bp = Breakpoint {
            id,
            address,
            original_byte,
            enabled: false,
            hit_count: 0,
            condition: None,
        };
        self.breakpoints.insert(id, bp);
        self.by_address.insert(address, id);
        id
    }

    /// Remove a breakpoint by id.
    pub fn remove(&mut self, id: BreakpointId) -> Option<Breakpoint> {
        let bp = self.breakpoints.remove(&id)?;
        self.by_address.remove(&bp.address);
        Some(bp)
    }

    /// Remove a breakpoint by address.
    pub fn remove_at(&mut self, address: u64) -> Option<Breakpoint> {
        let id = self.by_address.remove(&address)?;
        self.breakpoints.remove(&id)
    }

    /// Get a breakpoint by id.
    #[must_use]
    pub fn get(&self, id: BreakpointId) -> Option<&Breakpoint> {
        self.breakpoints.get(&id)
    }

    /// Get a mutable breakpoint by id.
    pub fn get_mut(&mut self, id: BreakpointId) -> Option<&mut Breakpoint> {
        self.breakpoints.get_mut(&id)
    }

    /// Find breakpoint at an exact address.
    #[must_use]
    pub fn at(&self, address: u64) -> Option<&Breakpoint> {
        self.by_address
            .get(&address)
            .and_then(|id| self.breakpoints.get(id))
    }

    /// Find breakpoint at an exact address (mutable).
    pub fn at_mut(&mut self, address: u64) -> Option<&mut Breakpoint> {
        self.by_address
            .get(&address)
            .copied()
            .and_then(|id| self.breakpoints.get_mut(&id))
    }

    /// Iterate all breakpoints.
    pub fn iter(&self) -> impl Iterator<Item = &Breakpoint> {
        self.breakpoints.values()
    }

    /// Number of breakpoints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.breakpoints.len()
    }

    /// Is empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }

    /// Record a hit at the given address.
    pub fn record_hit(&mut self, address: u64) {
        if let Some(bp) = self.at_mut(address) {
            bp.hit_count += 1;
        }
    }
}
