//! Virtual memory subsystem for the x86 emulator.
//!
//! Provides a flat virtual address space with page-level permissions (R/W/X).
//! Memory is backed by a sparse map of 4KB pages.

use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap;

/// Page size (4 KB).
const PAGE_SIZE: u64 = 4096;

/// Memory access permission flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
pub struct Permission {
    /// Readable
    pub read: bool,
    /// Writable
    pub write: bool,
    /// Executable
    pub execute: bool,
}

impl Permission {
    /// Read + Write
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    /// Read + Execute
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    /// Read + Write + Execute
    pub const RWX: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
    /// No access
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };
}

/// A mapped memory region.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct MemoryRegion {
    /// Start address (page-aligned)
    pub base: u64,
    /// Size in bytes
    pub size: u64,
    /// Permissions
    pub perm: Permission,
    /// Label (e.g. "stack", "code", "data")
    pub label: String,
}

/// Virtual memory with sparse page-backed storage.
#[derive(Debug)]
pub struct VirtualMemory {
    /// Page data (page_addr → data)
    pages: HashMap<u64, Vec<u8>>,
    /// Page permissions (page_addr → Permission)
    permissions: HashMap<u64, Permission>,
    /// Mapped regions (for display)
    regions: Vec<MemoryRegion>,
}

impl VirtualMemory {
    /// Create a new empty virtual memory.
    pub fn new() -> Self {
        Self {
            pages: HashMap::new(),
            permissions: HashMap::new(),
            regions: Vec::new(),
        }
    }

    /// Map a region of memory with given permissions.
    pub fn map_region(&mut self, base: u64, size: u64, perm: Permission, label: &str) {
        let aligned_base = base & !(PAGE_SIZE - 1);
        let aligned_end = (base + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        let mut addr = aligned_base;
        while addr < aligned_end {
            self.pages
                .entry(addr)
                .or_insert_with(|| vec![0u8; PAGE_SIZE as usize]);
            self.permissions.insert(addr, perm);
            addr += PAGE_SIZE;
        }

        self.regions.push(MemoryRegion {
            base,
            size,
            perm,
            label: label.to_string(),
        });
    }

    /// Write bytes to memory at the given address.
    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), MemoryError> {
        for (i, &byte) in data.iter().enumerate() {
            let effective_addr = addr + i as u64;
            let page_addr = effective_addr & !(PAGE_SIZE - 1);
            let page_offset = (effective_addr & (PAGE_SIZE - 1)) as usize;

            // Check write permission
            if let Some(perm) = self.permissions.get(&page_addr) {
                if !perm.write {
                    return Err(MemoryError::PermissionDenied {
                        addr: effective_addr,
                        access: "write",
                    });
                }
            } else {
                return Err(MemoryError::Unmapped {
                    addr: effective_addr,
                });
            }

            if let Some(page) = self.pages.get_mut(&page_addr) {
                page[page_offset] = byte;
            }
        }
        Ok(())
    }

    /// Read bytes from memory at the given address.
    pub fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let mut result = Vec::with_capacity(size);
        for i in 0..size {
            let effective_addr = addr + i as u64;
            let page_addr = effective_addr & !(PAGE_SIZE - 1);
            let page_offset = (effective_addr & (PAGE_SIZE - 1)) as usize;

            // Check read permission
            if let Some(perm) = self.permissions.get(&page_addr) {
                if !perm.read {
                    return Err(MemoryError::PermissionDenied {
                        addr: effective_addr,
                        access: "read",
                    });
                }
            } else {
                return Err(MemoryError::Unmapped {
                    addr: effective_addr,
                });
            }

            if let Some(page) = self.pages.get(&page_addr) {
                result.push(page[page_offset]);
            } else {
                result.push(0);
            }
        }
        Ok(result)
    }

    /// Debug helper: print mapped pages.
    #[allow(dead_code)]
    pub fn debug_pages(&self) {
        // [DEBUG CLEANUP]
    }

    /// Write bytes bypassing permission checks (for debugger breakpoint patches).
    pub fn write_raw(&mut self, addr: u64, data: &[u8]) -> Result<(), MemoryError> {
        for (i, &byte) in data.iter().enumerate() {
            let effective_addr = addr + i as u64;
            let page_addr = effective_addr & !(PAGE_SIZE - 1);
            let page_offset = (effective_addr & (PAGE_SIZE - 1)) as usize;

            if let Some(page) = self.pages.get_mut(&page_addr) {
                page[page_offset] = byte;
            } else {
                return Err(MemoryError::Unmapped {
                    addr: effective_addr,
                });
            }
        }
        Ok(())
    }

    /// Read a single byte.
    pub fn read_u8(&self, addr: u64) -> Result<u8, MemoryError> {
        let data = self.read(addr, 1)?;
        Ok(data[0])
    }

    /// Read a 32-bit little-endian value.
    pub fn read_u32(&self, addr: u64) -> Result<u32, MemoryError> {
        let data = self.read(addr, 4)?;
        Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Read a 64-bit little-endian value.
    pub fn read_u64(&self, addr: u64) -> Result<u64, MemoryError> {
        let data = self.read(addr, 8)?;
        Ok(u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]))
    }

    /// Write a 32-bit little-endian value.
    pub fn write_u32(&mut self, addr: u64, val: u32) -> Result<(), MemoryError> {
        self.write(addr, &val.to_le_bytes())
    }

    /// Write a 64-bit little-endian value.
    pub fn write_u64(&mut self, addr: u64, val: u64) -> Result<(), MemoryError> {
        self.write(addr, &val.to_le_bytes())
    }

    /// Check if an address is executable.
    pub fn is_executable(&self, addr: u64) -> bool {
        let page_addr = addr & !(PAGE_SIZE - 1);
        self.permissions.get(&page_addr).is_some_and(|p| p.execute)
    }

    /// Get all mapped regions.
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Extract a string from memory (null-terminated, max 4096 bytes).
    pub fn read_string(&self, addr: u64) -> Result<String, MemoryError> {
        let mut bytes = Vec::new();
        for i in 0..4096u64 {
            let b = self.read_u8(addr + i)?;
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

/// Memory access error.
#[derive(Debug)]
pub enum MemoryError {
    /// Attempted access to unmapped memory.
    Unmapped { addr: u64 },
    /// Permission violation.
    PermissionDenied { addr: u64, access: &'static str },
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unmapped { addr } => write!(f, "unmapped memory at 0x{addr:016X}"),
            Self::PermissionDenied { addr, access } => {
                write!(f, "{access} access denied at 0x{addr:016X}")
            }
        }
    }
}

impl std::error::Error for MemoryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_read_write() {
        let mut mem = VirtualMemory::new();
        mem.map_region(0x1000, 0x1000, Permission::RW, "data");

        mem.write(0x1000, &[0x41, 0x42, 0x43]).unwrap();
        let data = mem.read(0x1000, 3).unwrap();
        assert_eq!(data, vec![0x41, 0x42, 0x43]);
    }

    #[test]
    fn unmapped_read_fails() {
        let mem = VirtualMemory::new();
        assert!(mem.read(0xDEAD, 1).is_err());
    }

    #[test]
    fn write_to_readonly_fails() {
        let mut mem = VirtualMemory::new();
        mem.map_region(0x1000, 0x1000, Permission::RX, "code");
        assert!(mem.write(0x1000, &[0x90]).is_err());
    }

    #[test]
    fn u32_read_write() {
        let mut mem = VirtualMemory::new();
        mem.map_region(0x2000, 0x1000, Permission::RW, "data");

        mem.write_u32(0x2000, 0xDEAD_BEEF).unwrap();
        assert_eq!(mem.read_u32(0x2000).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn string_read() {
        let mut mem = VirtualMemory::new();
        mem.map_region(0x3000, 0x1000, Permission::RW, "strings");

        mem.write(0x3000, b"Hello\0World\0").unwrap();
        assert_eq!(mem.read_string(0x3000).unwrap(), "Hello");
        assert_eq!(mem.read_string(0x3006).unwrap(), "World");
    }
}
