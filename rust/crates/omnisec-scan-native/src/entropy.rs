//! Section-level entropy scoring.
//!
//! High Shannon entropy in executable / loadable sections is a strong
//! tell for packed, encrypted, or compressed payloads. This module is
//! intentionally read-only — it walks the program / section headers, hashes
//! the raw bytes through a histogram, and emits findings when the entropy
//! crosses thresholds tuned on a corpus of clean and packed Android
//! `lib*.so` binaries.
//!
//! The implementation is forbid-unsafe and zero-allocation in the hot
//! loop (we reuse a fixed `[u32; 256]` histogram).

use crate::{Category, Confidence, Finding, Severity};

/// Threshold above which a section is considered packed.
const PACKED_THRESHOLD: f64 = 7.5;

/// Threshold above which a section is considered "high entropy"
/// (compressed but not necessarily encrypted).
const HIGH_THRESHOLD: f64 = 6.8;

/// Minimum section size considered for entropy scoring. Smaller sections
/// yield unreliable values.
const MIN_SECTION_BYTES: usize = 1024;

/// Sliding-window size (bytes) used to locate *localized* high-entropy regions
/// inside an otherwise low-entropy section. 4 KiB is large enough for a stable
/// Shannon estimate yet small enough to pinpoint an embedded blob.
const WINDOW_BYTES: usize = 4096;

/// Stride between windows. Half-overlap keeps a blob from straddling two
/// windows and being diluted in both.
const WINDOW_STRIDE: usize = 2048;

/// A window must reach this entropy to be reported on its own — set above the
/// whole-section PACKED threshold so we only surface genuinely suspicious
/// pockets and don't double-report uniformly packed sections.
const WINDOW_THRESHOLD: f64 = 7.7;

/// Compute Shannon entropy in bits / symbol for the supplied byte slice.
///
/// Returns 0.0 for empty input. The result is bounded to `[0, 8]`.
#[must_use]
pub fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut hist = [0u32; 256];
    for &b in bytes {
        hist[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for &c in &hist {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / n;
        h -= p * p.log2();
    }
    h.clamp(0.0, 8.0)
}

/// Slide a [`WINDOW_BYTES`] window across a section at [`WINDOW_STRIDE`] and
/// emit a finding for the *first* window whose entropy crosses
/// [`WINDOW_THRESHOLD`]. This catches a small encrypted/packed blob embedded in
/// an otherwise benign section — whole-section averaging dilutes it below the
/// section thresholds and misses it entirely.
///
/// `base_off` is the file offset of `body[0]` so the reported offset points at
/// the real on-disk location of the hot window. Only one finding per section is
/// emitted (the densest pocket) to avoid flooding on uniformly packed data.
fn scan_windows(body: &[u8], base_off: usize, name: &str, kind: &str, out: &mut Vec<Finding>) {
    if body.len() < WINDOW_BYTES * 2 {
        return; // too small to localize anything the whole-section scan didn't
    }
    let mut best: Option<(usize, f64)> = None;
    let mut start = 0usize;
    while start + WINDOW_BYTES <= body.len() {
        let h = shannon(&body[start..start + WINDOW_BYTES]);
        if h >= WINDOW_THRESHOLD && best.map_or(true, |(_, bh)| h > bh) {
            best = Some((start, h));
        }
        start += WINDOW_STRIDE;
    }
    let Some((rel, h)) = best else { return };
    let abs = base_off + rel;
    out.push(
        Finding::new(
            "section-entropy-window",
            Category::EmbeddedPayload,
            Severity::High,
            Confidence::Medium,
            "Localized high-entropy region",
            format!(
                "A {} KiB window inside {} section {} reaches Shannon entropy \
                 {:.2} bits/byte while the section as a whole stays lower. This \
                 footprint matches an embedded encrypted / packed blob.",
                WINDOW_BYTES / 1024,
                kind,
                name,
                h
            ),
            format!(
                "section={} window_entropy={:.2} window_off={}",
                name, h, abs
            ),
        )
        .with_offset(abs as u64)
        .with_remediation("Inspect the flagged offset for an embedded payload or decryption stub."),
    );
}

/// Walk ELF section headers and emit entropy findings for any section
/// whose Shannon entropy crosses [`HIGH_THRESHOLD`].
pub fn scan_elf(
    bytes: &[u8],
    elf: &omnisec_loader_elf::elfparse::ElfFile<'_>,
    out: &mut Vec<Finding>,
) {
    let strtab = &elf.shdr_strtab;
    for sh in &elf.section_headers {
        let size = sh.sh_size as usize;
        if size < MIN_SECTION_BYTES {
            continue;
        }
        let off = sh.sh_offset as usize;
        let end = off.saturating_add(size);
        if end > bytes.len() {
            continue;
        }
        let name = strtab.get_at(sh.sh_name as usize).unwrap_or("<unknown>");
        // We focus on PROGBITS / NOBITS-ish sections; SHT_PROGBITS = 1.
        if sh.sh_type != 1 {
            continue;
        }
        let entropy = shannon(&bytes[off..end]);
        if entropy < HIGH_THRESHOLD {
            // Whole-section average is calm — hunt for a localized hot pocket.
            scan_windows(&bytes[off..end], off, name, "ELF", out);
            continue;
        }
        let (severity, confidence, title) = if entropy >= PACKED_THRESHOLD {
            (
                Severity::High,
                Confidence::High,
                "Packed / encrypted section",
            )
        } else {
            (Severity::Medium, Confidence::Medium, "High-entropy section")
        };

        out.push(
            Finding::new(
                "section-entropy",
                Category::EmbeddedPayload,
                severity,
                confidence,
                title,
                format!(
                    "Section {} has Shannon entropy {:.2} bits/byte ({} bytes). \
                     Packing, compression or in-binary encryption is likely.",
                    name, entropy, size
                ),
                format!("section={} entropy={:.2}", name, entropy),
            )
            .with_offset(off as u64)
            .with_remediation("Investigate runtime decryption / unpacking routines."),
        );
    }
}

/// Walk PE section headers and emit entropy findings for any section
/// whose Shannon entropy crosses the same thresholds. The rules of thumb
/// match the ELF version because packers used in cross-platform malware
/// exhibit the same entropy footprint.
///
/// Resource (`.rsrc`) and data-only sections are excluded: their content is
/// routinely compressed by the resource compiler and legitimately reaches
/// entropy ≥ 7.5, producing high-severity false positives on benign binaries.
/// We restrict scoring to sections that contain code or are executable.
pub fn scan_pe(bytes: &[u8], pe: &omnisec_loader_pe::peparse::PeFile, out: &mut Vec<Finding>) {
    // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
    const CODE_OR_EXEC: u32 = 0x0000_0020 | 0x2000_0000;

    for sec in &pe.sections {
        let characteristics = sec.characteristics;
        // Skip sections that carry neither code nor the executable flag.
        if characteristics & CODE_OR_EXEC == 0 {
            continue;
        }

        let size = sec.size_of_raw_data as usize;
        if size < MIN_SECTION_BYTES {
            continue;
        }
        let off = sec.pointer_to_raw_data as usize;
        let end = off.saturating_add(size);
        if end > bytes.len() {
            continue;
        }
        let entropy = shannon(&bytes[off..end]);
        let name = String::from_utf8_lossy(&sec.name)
            .trim_end_matches('\0')
            .to_string();
        if entropy < HIGH_THRESHOLD {
            scan_windows(&bytes[off..end], off, &name, "PE", out);
            continue;
        }
        let (severity, confidence, title) = if entropy >= PACKED_THRESHOLD {
            (
                Severity::High,
                Confidence::High,
                "Packed / encrypted PE section",
            )
        } else {
            (
                Severity::Medium,
                Confidence::Medium,
                "High-entropy PE section",
            )
        };
        out.push(
            Finding::new(
                "pe-section-entropy",
                Category::EmbeddedPayload,
                severity,
                confidence,
                title,
                format!(
                    "PE section {} has Shannon entropy {:.2} bits/byte ({} bytes). \
                     Likely packed / compressed.",
                    name, entropy, size
                ),
                format!("section={} entropy={:.2}", name, entropy),
            )
            .with_offset(off as u64),
        );
    }
}

#[cfg(test)]
mod tests {
    // Tests intentionally compare against exact, representable constants
    // (0.0, 1.0, hand-computed values); the lint would only add noise here.
    #![allow(clippy::float_cmp)]
    use super::*;

    #[test]
    fn empty_returns_zero() {
        assert_eq!(shannon(b""), 0.0);
    }

    #[test]
    fn uniform_returns_zero() {
        assert_eq!(shannon(&[0u8; 4096]), 0.0);
    }

    #[test]
    fn random_full_alphabet_close_to_eight() {
        let mut bytes = Vec::with_capacity(256 * 32);
        for _ in 0..32 {
            for b in 0u8..=255u8 {
                bytes.push(b);
            }
        }
        let h = shannon(&bytes);
        assert!(h > 7.99, "expected entropy ≈ 8, got {}", h);
    }

    #[test]
    fn ascii_text_below_seven() {
        let body = b"the quick brown fox jumps over the lazy dog. ".repeat(64);
        let h = shannon(&body);
        assert!(h < 5.5, "ASCII text should have low entropy, got {}", h);
    }

    #[test]
    fn window_finds_embedded_blob_in_calm_section() {
        // A mostly-zero section (entropy ~0) with one 4 KiB full-alphabet blob.
        let mut body = vec![0u8; WINDOW_BYTES * 4];
        let blob_start = WINDOW_BYTES; // aligned to a stride boundary
        for (i, b) in body[blob_start..blob_start + WINDOW_BYTES]
            .iter_mut()
            .enumerate()
        {
            *b = (i % 256) as u8;
        }
        // Whole-section entropy stays low; the window scan should still fire.
        assert!(shannon(&body) < HIGH_THRESHOLD);
        let mut out = Vec::new();
        scan_windows(&body, 0x1000, ".text", "ELF", &mut out);
        assert_eq!(out.len(), 1, "expected exactly one window finding");
        assert_eq!(out[0].id, "section-entropy-window");
    }

    #[test]
    fn window_silent_on_uniform_low_entropy() {
        let body = vec![0u8; WINDOW_BYTES * 4];
        let mut out = Vec::new();
        scan_windows(&body, 0, ".bss", "ELF", &mut out);
        assert!(
            out.is_empty(),
            "uniform zeros must not trip the window scan"
        );
    }
}
