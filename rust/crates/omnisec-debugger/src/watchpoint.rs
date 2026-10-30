//! Watchpoint management — traps on memory read / write.

use std::collections::BTreeMap;

/// Type of watchpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchType {
    /// Break on read.
    Read,
    /// Break on write.
    Write,
    /// Break on read or write.
    Access,
}

/// A memory watchpoint.
#[derive(Debug, Clone)]
pub struct Watchpoint {
    /// Unique id.
    pub id: u32,
    /// Start address.
    pub address: u64,
    /// Size in bytes.
    pub size: u64,
    /// Watch type.
    pub kind: WatchType,
    /// Hit count.
    pub hit_count: u64,
}

/// Manages watchpoints.
#[derive(Debug, Default)]
pub struct WatchpointManager {
    next_id: u32,
    watchpoints: BTreeMap<u32, Watchpoint>,
}

impl WatchpointManager {
    /// Create an empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new watchpoint.
    pub fn add(&mut self, address: u64, size: u64, kind: WatchType) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.watchpoints.insert(
            id,
            Watchpoint {
                id,
                address,
                size,
                kind,
                hit_count: 0,
            },
        );
        id
    }

    /// Remove a watchpoint by id.
    pub fn remove(&mut self, id: u32) -> Option<Watchpoint> {
        self.watchpoints.remove(&id)
    }

    /// Get a watchpoint by id.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&Watchpoint> {
        self.watchpoints.get(&id)
    }

    /// Iterate all watchpoints.
    pub fn iter(&self) -> impl Iterator<Item = &Watchpoint> {
        self.watchpoints.values()
    }

    /// Check if any watchpoint triggers on a memory access.
    /// Returns the id of the first matching watchpoint, or None.
    pub fn check(&self, addr: u64, size: usize, is_write: bool) -> Option<u32> {
        for wp in self.watchpoints.values() {
            // Overlap check: [addr, addr+size) intersects [wp.address, wp.address+wp.size)
            let access_end = addr + size as u64;
            let wp_end = wp.address + wp.size;
            if access_end > wp.address && addr < wp_end {
                let matches = match wp.kind {
                    WatchType::Read => !is_write,
                    WatchType::Write => is_write,
                    WatchType::Access => true,
                };
                if matches {
                    return Some(wp.id);
                }
            }
        }
        None
    }

    /// Number of watchpoints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.watchpoints.len()
    }

    /// Is empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.watchpoints.is_empty()
    }
}
