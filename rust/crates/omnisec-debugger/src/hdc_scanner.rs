//! HDC (Hyperdimensional Computing) memory scanner.
//!
//! Scans the emulated address space for regions that resemble
//! known high-dimensional anchors (crypto constants, string tables,
//! unpacking stubs, etc.) using Hamming / cosine similarity.

use omnisec_json::{FromJson, ToJson};

use omnisec_emu_x86::VirtualMemory;

/// A single HDC hit found in memory.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct HDCHit {
    /// Virtual address where the hit occurred.
    pub address: u64,
    /// Name of the matched anchor.
    pub anchor_name: String,
    /// Similarity score (0.0 .. 1.0, higher is better).
    pub similarity: f64,
    /// Shannon entropy of the surrounding region.
    pub region_entropy: f64,
}

/// One HDC anchor — a byte vector the scanner hunts for.
#[derive(Debug, Clone)]
pub struct HDCAnchor {
    /// Name identifier of the anchor.
    pub name: String,
    /// Vector representation of the anchor bytes.
    pub vector: Vec<u8>,
    /// Minimum similarity threshold (0.0..1.0).
    pub threshold: f64,
}

/// HDC memory scanner.
#[derive(Debug)]
pub struct HDCScanner {
    anchors: Vec<HDCAnchor>,
    /// Window size in bytes around each probe point for entropy calc.
    window_size: usize,
    /// Step size while scanning ranges (default = 1 for byte-level).
    step: usize,
}

impl Default for HDCScanner {
    fn default() -> Self {
        Self {
            anchors: Vec::new(),
            window_size: 64,
            step: 1,
        }
    }
}

impl HDCScanner {
    /// Create an empty scanner.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the window size for regional entropy.
    pub fn with_window_size(mut self, size: usize) -> Self {
        self.window_size = size;
        self
    }

    /// Set scan step (stride).
    pub fn with_step(mut self, step: usize) -> Self {
        self.step = step.max(1);
        self
    }

    /// Register a built-in set of typical RE anchors.
    pub fn with_default_anchors(mut self) -> Self {
        // Common crypto constants
        self.add_anchor_bytes(
            "AES_Sbox",
            &[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5],
            0.70,
        );
        self.add_anchor_bytes("TEA_delta", &[0x9E, 0x37, 0x79, 0xB9], 0.90);
        self.add_anchor_bytes(
            "CRC32_table_marker",
            &[0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77],
            0.75,
        );

        // Typical unpacking / obfuscation signatures
        self.add_anchor_bytes("UPX_marker", &[0x55, 0x50, 0x58, 0x21], 0.90); // "UPX!"
        self.add_anchor_bytes("ELF_magic", &[0x7f, 0x45, 0x4c, 0x46], 0.95);
        self.add_anchor_bytes("PE_DOS", &[0x4d, 0x5a], 0.95); // "MZ"

        // JNI / Java string-table hint
        self.add_anchor_bytes("JNI_OnLoad_str", b"JNI_OnLoad", 0.85);
        self.add_anchor_bytes("Java_com_str", b"Java_com_", 0.80);

        self
    }

    /// Add a raw byte anchor.
    pub fn add_anchor_bytes(&mut self, name: &str, bytes: &[u8], threshold: f64) {
        self.anchors.push(HDCAnchor {
            name: name.to_string(),
            vector: bytes.to_vec(),
            threshold: threshold.clamp(0.0, 1.0),
        });
    }

    /// Add an anchor from a hex string (e.g. "DEADBEEF").
    pub fn add_anchor_hex(&mut self, name: &str, hex: &str, threshold: f64) {
        let bytes = hex_to_bytes(hex).unwrap_or_default();
        self.add_anchor_bytes(name, &bytes, threshold);
    }

    /// Scan memory range [addr, addr+size) and return all hits above threshold.
    pub fn scan(&self, mem: &VirtualMemory, addr: u64, size: usize, threshold: f64) -> Vec<HDCHit> {
        let mut hits = Vec::new();
        let end = addr.saturating_add(size as u64);
        let mut cur = addr;

        while cur < end {
            // Try each anchor
            for anchor in &self.anchors {
                if anchor.vector.is_empty() {
                    continue;
                }
                let probe_end = cur.saturating_add(anchor.vector.len() as u64);
                if probe_end > end {
                    continue;
                }
                let region = if let Ok(b) = mem.read(cur, anchor.vector.len()) {
                    b
                } else {
                    cur = cur.saturating_add(self.step as u64);
                    continue;
                };
                let sim = hamming_similarity(&region, &anchor.vector);
                if sim >= threshold.max(anchor.threshold) {
                    let ent = self.entropy_at(mem, cur);
                    hits.push(HDCHit {
                        address: cur,
                        anchor_name: anchor.name.clone(),
                        similarity: sim,
                        region_entropy: ent,
                    });
                }
            }
            cur = cur.saturating_add(self.step as u64);
        }

        // Deduplicate overlapping hits keeping the best similarity per address
        hits.sort_by(|a, b| {
            a.address
                .cmp(&b.address)
                .then(b.similarity.partial_cmp(&a.similarity).unwrap())
        });
        hits.dedup_by(|a, b| a.address == b.address);
        hits
    }

    /// Probe a single address against all anchors (fast path).
    pub fn probe(&self, mem: &VirtualMemory, addr: u64) -> Option<HDCHit> {
        let mut best: Option<HDCHit> = None;
        for anchor in &self.anchors {
            let region = match mem.read(addr, anchor.vector.len()) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let sim = hamming_similarity(&region, &anchor.vector);
            if sim >= anchor.threshold {
                let ent = self.entropy_at(mem, addr);
                let hit = HDCHit {
                    address: addr,
                    anchor_name: anchor.name.clone(),
                    similarity: sim,
                    region_entropy: ent,
                };
                if best.as_ref().is_none_or(|b| hit.similarity > b.similarity) {
                    best = Some(hit);
                }
            }
        }
        best
    }

    /// Shannon entropy of `window_size` bytes starting at `addr`.
    fn entropy_at(&self, mem: &VirtualMemory, addr: u64) -> f64 {
        let buf = match mem.read(addr, self.window_size) {
            Ok(b) => b,
            Err(_) => return 0.0,
        };
        shannon_entropy(&buf)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Similarity helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Hamming similarity = 1.0 - (hamming_distance / max_bits).
fn hamming_similarity(a: &[u8], b: &[u8]) -> f64 {
    let min = a.len().min(b.len());
    if min == 0 {
        return 0.0;
    }
    let mut diff = 0usize;
    for i in 0..min {
        diff += (a[i] ^ b[i]).count_ones() as usize;
    }
    let max_bits = min * 8;
    1.0 - (diff as f64 / max_bits as f64)
}

/// Shannon entropy of a byte slice (bits per byte).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex: String = hex.chars().filter(char::is_ascii_hexdigit).collect();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk).ok()?;
        bytes.push(u8::from_str_radix(s, 16).ok()?);
    }
    Some(bytes)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    // Tests intentionally compare against exact, representable constants
    // (0.0, 1.0, hand-computed values); the lint would only add noise here.
    #![allow(clippy::float_cmp)]
    use super::*;
    use omnisec_emu_x86::VirtualMemory;

    #[test]
    fn test_hamming_similarity() {
        let a = &[0xFF, 0x00, 0xAA, 0x55];
        let b = &[0xFF, 0x00, 0xAA, 0x55];
        assert!((hamming_similarity(a, b) - 1.0).abs() < 1e-9);

        let c = &[0x00, 0xFF, 0x55, 0xAA];
        assert_eq!(hamming_similarity(a, c), 0.0);

        let d = &[0xFF, 0x00, 0xAA, 0x54];
        let sim = hamming_similarity(a, d);
        assert!(sim > 0.0 && sim < 1.0);
    }

    #[test]
    fn test_shannon_entropy() {
        let uniform: Vec<u8> = (0..=255).collect();
        let ent = shannon_entropy(&uniform);
        assert!(
            ent > 7.5 && ent <= 8.0,
            "entropy should be near 8 for uniform data"
        );

        let zeros = vec![0u8; 256];
        assert_eq!(shannon_entropy(&zeros), 0.0);
    }

    #[test]
    fn test_hdc_scan() {
        let mut mem = VirtualMemory::new();
        mem.map_region(0x1000, 0x1000, omnisec_emu_x86::Permission::RWX, "test");
        let pattern = &[0x55, 0x50, 0x58, 0x21]; // UPX!
        mem.write(0x1200, pattern).unwrap();

        let scanner = HDCScanner::new().with_default_anchors();
        let hits = scanner.scan(&mem, 0x1000, 0x1000, 0.80);
        let upx_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.anchor_name == "UPX_marker")
            .collect();
        assert!(
            !upx_hits.is_empty(),
            "expected UPX_marker hit, got {:?}",
            hits
        );
        assert_eq!(upx_hits[0].address, 0x1200);
        assert!((upx_hits[0].similarity - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_hdc_probe() {
        let mut mem = VirtualMemory::new();
        mem.map_region(0x4000, 0x1000, omnisec_emu_x86::Permission::RWX, "test2");
        let pattern = &[0x7f, 0x45, 0x4c, 0x46];
        mem.write(0x4000, pattern).unwrap();

        let scanner = HDCScanner::new().with_default_anchors();
        let hit = scanner.probe(&mem, 0x4000).unwrap();
        assert_eq!(hit.anchor_name, "ELF_magic");
    }
}
