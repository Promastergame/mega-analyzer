//! Lightweight control-flow heuristics over raw machine code.
//!
//! Goal: surface signals that disassembler-driven CFG analysis cannot or
//! does not surface efficiently for our use case:
//!
//! * **Indirect-call density** — heavy use of `call rax` / `blr` style
//!   instructions is a strong correlate of vtable-style polymorphism but
//!   also of native obfuscators (CFG flattening, callsite trampolines).
//! * **String-pointer dispatch** — sequences of `lea / leaq` immediately
//!   followed by an indirect call hint at runtime resolved API tables.
//! * **Suspicious self-modification primitives** — calls to
//!   `mprotect(...PROT_EXEC...)` or `VirtualProtect` paired with `memcpy`
//!   / `WriteProcessMemory` patterns in imports.
//!
//! Implementation is byte-pattern driven: cheap, conservative, and
//! deliberately simple so it cannot regress badly. The pattern set mirrors
//! the literature on ARM64 / x86-64 obfuscators we encounter in Android
//! `lib*.so` files.

use crate::{Category, Confidence, Finding, Severity};
use omnisec_loader::LoadedBinary;

/// Threshold (per 4 KiB) above which indirect-call density is considered
/// a CFG-obfuscation indicator.
const INDIRECT_CALL_DENSITY_THRESHOLD: f64 = 12.0;

/// Number of executable bytes scanned for the density heuristic. Larger
/// than this and we sample.
const MAX_BYTES_SCANNED: usize = 4 * 1024 * 1024;

/// Run the lightweight control-flow heuristics. Always non-fatal — the
/// scanner falls back to the symbol-only path if disassembly fails.
pub fn scan(bin: &LoadedBinary, bytes: &[u8], out: &mut Vec<Finding>) {
    if bytes.is_empty() {
        return;
    }

    let counts = count_indirects(bin, bytes);
    if counts.scanned_bytes == 0 {
        return;
    }

    let per_kb = (counts.indirect_calls as f64) / ((counts.scanned_bytes as f64) / 1024.0);
    if per_kb >= INDIRECT_CALL_DENSITY_THRESHOLD {
        out.push(
            Finding::new(
                "high-indirect-call-density",
                Category::SuspiciousBehavior,
                Severity::Medium,
                Confidence::Medium,
                "High indirect-call density",
                format!(
                    "Indirect call density of {:.1} per 4KiB across {} bytes \
                     of executable code. Consistent with CFG flattening, \
                     callsite trampolines or virtual dispatch tables.",
                    per_kb * 4.0,
                    counts.scanned_bytes
                ),
                format!(
                    "indirect={} cond_branch={} bytes={}",
                    counts.indirect_calls, counts.conditional_branches, counts.scanned_bytes
                ),
            )
            .with_remediation("Cross-check with deobfuscator output if available."),
        );
    }

    // Self-modifying primitives — purely import-driven heuristic, but the
    // CFG module is a natural home for it.
    if has_pair(bin, "mprotect", "memcpy") || has_pair(bin, "VirtualProtect", "WriteProcessMemory")
    {
        out.push(Finding::new(
            "self-modify-primitives",
            Category::DynamicCode,
            Severity::High,
            Confidence::Medium,
            "Self-modification primitives present",
            "The binary imports both a memory-protection API \
             and a memory-write/copy API. Together these are the \
             canonical building blocks for runtime code rewriting.",
            "imports=mprotect+memcpy or VirtualProtect+WriteProcessMemory",
        ));
    }
}

/// Helper: returns true when both names appear among the binary imports.
fn has_pair(bin: &LoadedBinary, a: &str, b: &str) -> bool {
    let (mut sa, mut sb) = (false, false);
    for imp in &bin.imports {
        if imp.name.eq_ignore_ascii_case(a) {
            sa = true;
        }
        if imp.name.eq_ignore_ascii_case(b) {
            sb = true;
        }
        if sa && sb {
            return true;
        }
    }
    false
}

#[derive(Debug, Default)]
struct Counts {
    indirect_calls: u64,
    conditional_branches: u64,
    scanned_bytes: usize,
}

/// Cheap per-arch indirect-call counter. We do not assemble a full CFG —
/// we just count opcodes that are unambiguously indirect.
fn count_indirects(bin: &LoadedBinary, bytes: &[u8]) -> Counts {
    use omnisec_core::Arch;
    use omnisec_loader::SectionFlags;

    let mut c = Counts::default();

    // Only ever analyse *executable* regions. Scanning the whole file
    // (ELF/PE headers, .rodata, relocation tables, embedded resources,
    // string pools) turns random 0xFF / branch-shaped data bytes into
    // phantom "indirect calls" and produces a noisy, misleading density.
    let exec_regions: Vec<(usize, usize)> = bin
        .sections
        .iter()
        .filter(|s| s.flags.contains(SectionFlags::EXECUTE))
        .filter_map(|s| {
            let off = s.file_offset as usize;
            let size = s.file_size as usize;
            if off >= bytes.len() || size == 0 {
                return None;
            }
            let end = off.saturating_add(size).min(bytes.len());
            Some((off, end))
        })
        .collect();

    // No section table (fully stripped / packed): we genuinely cannot tell
    // code from data, so we DON'T guess — bail out instead of emitting a
    // fabricated signal. `scanned_bytes == 0` makes the caller skip.
    if exec_regions.is_empty() {
        return c;
    }

    // Only x86/x86_64/ARM64 have byte-pattern counters; anything else is
    // left at zero rather than backed by a guess.
    let counter: Option<fn(&[u8], &mut Counts)> = match bin.arch {
        Arch::X86_64 | Arch::X86 => Some(count_x86),
        Arch::Arm64 => Some(count_arm64),
        _ => None,
    };
    let Some(counter) = counter else {
        return c;
    };

    // Bound total work across all executable sections combined.
    let mut budget = MAX_BYTES_SCANNED;
    for (off, end) in exec_regions {
        if budget == 0 {
            break;
        }
        let take = (end - off).min(budget);
        let slice = &bytes[off..off + take];
        budget -= take;
        c.scanned_bytes += take;
        counter(slice, &mut c);
    }
    c
}

/// Count `call rax` / `jmp rax` patterns. We look for the canonical
/// `FF /2` (call r/m64) and `FF /4` (jmp r/m64) byte prefixes followed by
/// a ModR/M byte with mod==11 (register-direct), which is the dominant
/// indirect form. Additionally we count `Jcc` instructions for context.
fn count_x86(slice: &[u8], c: &mut Counts) {
    let mut i = 0;
    while i + 1 < slice.len() {
        let b = slice[i];
        match b {
            0xFF => {
                // ModR/M follows.
                let mr = slice[i + 1];
                let modf = (mr >> 6) & 0b11;
                let reg = (mr >> 3) & 0b111;
                if modf == 0b11 && (reg == 2 || reg == 4) {
                    // /2 = call r/m, /4 = jmp r/m
                    c.indirect_calls += 1;
                }
                i += 2;
                continue;
            }
            0x0F => {
                // 0F 8x = Jcc (long form)
                if i + 1 < slice.len() && (slice[i + 1] & 0xF0) == 0x80 {
                    c.conditional_branches += 1;
                    i += 2;
                    continue;
                }
            }
            0x70..=0x7F => {
                // Short Jcc.
                c.conditional_branches += 1;
            }
            _ => {}
        }
        i += 1;
    }
}

/// Count ARM64 BLR / BR (indirect branch with link / register branch).
/// Encoding: `BLR Xn` = `1101_0110_0011_1111_0000_00xx_xxx0_0000`
/// (ENC = 0xD63F0000 | Rn << 5).
/// `BR Xn`  = 0xD61F0000 | Rn << 5.
/// `B.cond` shares the top byte 0x54 — counted as conditional.
fn count_arm64(slice: &[u8], c: &mut Counts) {
    let mut i = 0;
    while i + 4 <= slice.len() {
        let inst = u32::from_le_bytes([slice[i], slice[i + 1], slice[i + 2], slice[i + 3]]);
        // Mask out Rn (bits 5..9).
        let masked = inst & 0xFFFF_FC1F;
        if masked == 0xD63F_0000 || masked == 0xD61F_0000 {
            c.indirect_calls += 1;
        }
        // B.cond: bits 31..24 == 0x54
        if (inst >> 24) == 0x54 {
            c.conditional_branches += 1;
        }
        i += 4;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_core::{Arch, Endian, Format};

    #[test]
    fn x86_counts_indirect_call() {
        // FF D0 = call rax (mod=11, reg=010, rm=000)
        // FF E0 = jmp rax  (mod=11, reg=100, rm=000)
        let mut c = Counts::default();
        count_x86(&[0xFF, 0xD0, 0x90, 0xFF, 0xE0, 0x90], &mut c);
        assert_eq!(c.indirect_calls, 2);
    }

    #[test]
    fn arm64_counts_blr() {
        let mut c = Counts::default();
        // BLR x9: 0xD63F0120 in bytes (LE)
        let blr_x9: u32 = 0xD63F_0000 | (9 << 5);
        let bytes = blr_x9.to_le_bytes();
        count_arm64(&bytes, &mut c);
        assert_eq!(c.indirect_calls, 1);
    }

    #[test]
    fn unknown_arch_returns_zero() {
        let bin = LoadedBinary::new(Format::Elf, Arch::Mips, Endian::Little, 1024);
        let counts = count_indirects(&bin, &[0u8; 4096]);
        assert_eq!(counts.scanned_bytes, 0);
    }
}
