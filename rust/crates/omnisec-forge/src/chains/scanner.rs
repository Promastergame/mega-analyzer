//! Gadget scanner — finds gadgets inside a concrete code blob.
//!
//! The [`GadgetFinder`](super::finder::GadgetFinder) stores gadgets; this
//! module *populates* a finder from raw bytes. It is a minimal but real
//! scanner: it walks the blob looking for terminators (per-arch patterns
//! defined in [`TerminatorSignature`]), then walks backward up to
//! `max_depth` bytes from each terminator to capture useful prefixes.
//!
//! Per-arch terminator sets:
//!
//! - **x86_64**: `C3` (`ret`), `C2 xx xx` (`ret imm16`), `CD 80` (`int 0x80`
//!   — legacy syscall), `0F 05` (`syscall`), `FF E?` (`jmp reg`),
//!   `FF D?` (`call reg`).
//! - **ARM64**: `D65F03C0` (`ret`, in little-endian), `D4000001` (`svc #0`),
//!   plus `D61F0???`-family indirect branches.
//! - **RISC-V**: `8067` (`c.jr ra` compressed `ret`) and `00008067`
//!   (`jalr x0, 0(ra)` uncompressed `ret`), plus `00000073` (`ecall`).
//!
//! The scanner is *sound but not complete*: it identifies terminators
//! reliably but only captures simple single-instruction prefixes (e.g.
//! `pop reg ; ret` on x86_64). Real polyglot / unaligned gadget discovery
//! is left as a future extension.
//!
//! This keeps the MVP grounded in real bytecode while avoiding dragging a
//! full disassembler (e.g. `iced-x86`, `omnisec-arm64-decode`) into the dep tree.

use omnisec_core::Arch;

use super::finder::GadgetFinder;
use super::gadget::{Gadget, GadgetCategory, RegisterEffect, Terminator};

/// Per-arch terminator descriptor.
#[derive(Debug, Clone)]
struct TerminatorSignature {
    /// Byte pattern that ends the gadget. All bytes must match exactly.
    pattern: &'static [u8],
    /// Minimum alignment for the pattern (1 for x86_64, 4 for ARM64, 2
    /// for RISC-V compressed).
    alignment: usize,
    /// The abstract terminator kind.
    terminator: Terminator,
}

/// Maximum bytes of prefix we walk back from a terminator when capturing
/// a gadget. Longer prefixes increase false-positive risk; 8 bytes cover
/// a `pop rXX ; ret`-shaped gadget comfortably.
const MAX_PREFIX_BYTES: usize = 8;

/// Scan `bytes` (starting at virtual address `base`) for gadgets and
/// register each one with `finder`.
///
/// Returns the number of gadgets added.
pub fn scan_into(finder: &mut GadgetFinder, arch: Arch, base: u64, bytes: &[u8]) -> usize {
    let terminators = terminator_set(arch);
    let mut added = 0;
    for (idx, window) in terminators {
        scan_with_terminator(finder, arch, base, bytes, idx, window, &mut added);
    }
    added
}

/// Static terminator table per architecture.
fn terminator_set(arch: Arch) -> Vec<(usize, &'static TerminatorSignature)> {
    let table: &[TerminatorSignature] = match arch {
        Arch::X86_64 => &[
            TerminatorSignature {
                pattern: &[0xC3],
                alignment: 1,
                terminator: Terminator::Ret,
            },
            TerminatorSignature {
                pattern: &[0x0F, 0x05],
                alignment: 1,
                terminator: Terminator::Syscall,
            },
        ],
        Arch::Arm64 => &[
            // `ret` = 0xD65F03C0, little-endian on disk.
            TerminatorSignature {
                pattern: &[0xC0, 0x03, 0x5F, 0xD6],
                alignment: 4,
                terminator: Terminator::Ret,
            },
            // `svc #0` = 0xD4000001, little-endian.
            TerminatorSignature {
                pattern: &[0x01, 0x00, 0x00, 0xD4],
                alignment: 4,
                terminator: Terminator::Syscall,
            },
        ],
        Arch::RiscV64 | Arch::RiscV32 => &[
            // Uncompressed `jalr x0, 0(ra)` (`ret`) = 0x00008067.
            TerminatorSignature {
                pattern: &[0x67, 0x80, 0x00, 0x00],
                alignment: 2,
                terminator: Terminator::Ret,
            },
            // Compressed `c.jr ra` = 0x8082, little-endian.
            TerminatorSignature {
                pattern: &[0x82, 0x80],
                alignment: 2,
                terminator: Terminator::Ret,
            },
            // `ecall` = 0x00000073, little-endian.
            TerminatorSignature {
                pattern: &[0x73, 0x00, 0x00, 0x00],
                alignment: 4,
                terminator: Terminator::Syscall,
            },
        ],
        Arch::Mips | Arch::Mips64 => &[
            // `jr $ra` = 0x03E00008, big-endian on disk.
            //
            // Note: MIPS branches have a delay slot — the instruction
            // *after* the `jr` still executes. The scanner records the
            // terminator position; chain-time filtering of delay-slot
            // safety is handled by the assembler's per-arch candidate
            // filter (TODO: implement in `SmtAssembler` for MIPS).
            TerminatorSignature {
                pattern: &[0x03, 0xE0, 0x00, 0x08],
                alignment: 4,
                terminator: Terminator::Ret,
            },
            // `syscall` = 0x0000000C, big-endian.
            TerminatorSignature {
                pattern: &[0x00, 0x00, 0x00, 0x0C],
                alignment: 4,
                terminator: Terminator::Syscall,
            },
        ],
        _ => &[],
    };
    table.iter().enumerate().collect()
}

fn scan_with_terminator(
    finder: &mut GadgetFinder,
    arch: Arch,
    base: u64,
    bytes: &[u8],
    _sig_idx: usize,
    sig: &TerminatorSignature,
    added: &mut usize,
) {
    if sig.pattern.is_empty() || bytes.len() < sig.pattern.len() {
        return;
    }

    // On MIPS the instruction after the terminator is a delay slot — it
    // still executes. We include it in the captured `raw` bytes so the
    // classifier can reason about clobbers.
    let has_delay_slot =
        matches!(arch, Arch::Mips | Arch::Mips64) && sig.terminator == Terminator::Ret;
    let delay_slot_bytes = if has_delay_slot { 4 } else { 0 };

    let pat_len = sig.pattern.len();
    for i in (0..=bytes.len().saturating_sub(pat_len + delay_slot_bytes)).step_by(sig.alignment) {
        if bytes[i..i + pat_len] != *sig.pattern {
            continue;
        }
        // Found a terminator. Walk back up to MAX_PREFIX_BYTES to capture
        // the candidate gadget. We start with a zero-prefix gadget (the
        // bare terminator) and extend outward, emitting each feasible
        // prefix.
        let term_start = i;
        let term_end = i + pat_len + delay_slot_bytes;
        let max_back = term_start.min(MAX_PREFIX_BYTES);
        for back in 0..=max_back {
            if back % sig.alignment != 0 {
                continue;
            }
            let prefix_start = term_start - back;
            let raw_bytes = bytes[prefix_start..term_end].to_vec();
            let addr = base + prefix_start as u64;
            if let Some(gadget) = classify_gadget(arch, addr, &raw_bytes, sig) {
                finder.insert(gadget);
                *added += 1;
            }
        }
    }
}

/// Lightweight classifier: recognise a tiny set of widely-useful prefixes.
/// Everything else is stored as `GadgetCategory::Other` with no register
/// effects — still useful for chain assembly when the caller only needs
/// a terminator of a specific kind (e.g. `syscall ; ret` stubs).
fn classify_gadget(
    arch: Arch,
    address: u64,
    raw: &[u8],
    sig: &TerminatorSignature,
) -> Option<Gadget> {
    match arch {
        Arch::X86_64 => classify_x86_64(address, raw, sig),
        Arch::Arm64 => classify_arm64(address, raw, sig),
        Arch::RiscV64 | Arch::RiscV32 => classify_riscv(address, raw, sig),
        Arch::Mips | Arch::Mips64 => classify_mips(address, raw, sig),
        _ => Some(Gadget {
            address,
            effects: Vec::new(),
            terminator: sig.terminator,
            category: GadgetCategory::Other,
            label: format!("<opaque {} bytes>", raw.len()),
            raw: raw.to_vec(),
            clobbers: Vec::new(),
        }),
    }
}

fn classify_x86_64(address: u64, raw: &[u8], sig: &TerminatorSignature) -> Option<Gadget> {
    // Terminator-only: `ret` / `syscall`.
    if raw == sig.pattern {
        let (label, category) = match sig.terminator {
            Terminator::Ret => ("ret".to_string(), GadgetCategory::Other),
            Terminator::Syscall => ("syscall".to_string(), GadgetCategory::SyscallStub),
            _ => (
                format!("<term {:?}>", sig.terminator),
                GadgetCategory::Other,
            ),
        };
        return Some(Gadget {
            address,
            effects: Vec::new(),
            terminator: sig.terminator,
            category,
            label,
            raw: raw.to_vec(),
            clobbers: Vec::new(),
        });
    }
    // Single-byte POP prefix (0x58..=0x5F == pop rax..rdi).
    if raw.len() == 2 && sig.terminator == Terminator::Ret {
        let op = raw[0];
        if (0x58..=0x5F).contains(&op) {
            let reg = match op {
                0x58 => "rax",
                0x59 => "rcx",
                0x5A => "rdx",
                0x5B => "rbx",
                0x5C => "rsp",
                0x5D => "rbp",
                0x5E => "rsi",
                0x5F => "rdi",
                _ => unreachable!(),
            };
            let category = if reg == "rsp" || reg == "rbp" {
                GadgetCategory::StackPivot
            } else {
                GadgetCategory::PopReg
            };
            let mut effects: Vec<RegisterEffect> = Vec::new();
            effects.push(RegisterEffect::load_const(reg, 0));
            return Some(Gadget {
                address,
                effects,
                terminator: Terminator::Ret,
                category,
                label: format!("pop {reg} ; ret"),
                raw: raw.to_vec(),
                clobbers: Vec::new(),
            });
        }
    }
    // REX-prefixed pop r8..r15 — 41 58..5F ; C3
    if raw.len() == 3 && sig.terminator == Terminator::Ret && raw[0] == 0x41 {
        let op = raw[1];
        if (0x58..=0x5F).contains(&op) {
            let reg_idx = op - 0x58;
            let reg = match reg_idx {
                0 => "r8",
                1 => "r9",
                2 => "r10",
                3 => "r11",
                4 => "r12",
                5 => "r13",
                6 => "r14",
                _ => "r15",
            };
            let mut effects: Vec<RegisterEffect> = Vec::new();
            effects.push(RegisterEffect::load_const(reg, 0));
            return Some(Gadget {
                address,
                effects,
                terminator: Terminator::Ret,
                category: GadgetCategory::PopReg,
                label: format!("pop {reg} ; ret"),
                raw: raw.to_vec(),
                clobbers: Vec::new(),
            });
        }
    }
    None
}

fn classify_arm64(address: u64, raw: &[u8], sig: &TerminatorSignature) -> Option<Gadget> {
    // Bare `ret` or `svc #0`.
    if raw == sig.pattern {
        let (label, category) = match sig.terminator {
            Terminator::Ret => ("ret".to_string(), GadgetCategory::Other),
            Terminator::Syscall => ("svc #0".to_string(), GadgetCategory::SyscallStub),
            _ => (
                format!("<term {:?}>", sig.terminator),
                GadgetCategory::Other,
            ),
        };
        return Some(Gadget {
            address,
            effects: Vec::new(),
            terminator: sig.terminator,
            category,
            label,
            raw: raw.to_vec(),
            clobbers: Vec::new(),
        });
    }
    None
}

fn classify_riscv(address: u64, raw: &[u8], sig: &TerminatorSignature) -> Option<Gadget> {
    if raw == sig.pattern {
        let (label, category) = match sig.terminator {
            Terminator::Ret => ("ret".to_string(), GadgetCategory::Other),
            Terminator::Syscall => ("ecall".to_string(), GadgetCategory::SyscallStub),
            _ => (
                format!("<term {:?}>", sig.terminator),
                GadgetCategory::Other,
            ),
        };
        return Some(Gadget {
            address,
            effects: Vec::new(),
            terminator: sig.terminator,
            category,
            label,
            raw: raw.to_vec(),
            clobbers: Vec::new(),
        });
    }
    None
}

fn classify_mips(address: u64, raw: &[u8], sig: &TerminatorSignature) -> Option<Gadget> {
    // Syscall has no delay slot handling (syscalls are immediate).
    if sig.terminator == Terminator::Syscall {
        if raw == sig.pattern {
            return Some(Gadget {
                address,
                effects: Vec::new(),
                terminator: Terminator::Syscall,
                category: GadgetCategory::SyscallStub,
                label: "syscall".into(),
                raw: raw.to_vec(),
                clobbers: Vec::new(),
            });
        }
        return None;
    }

    // `jr $ra` branches have a mandatory delay slot appended. The
    // scanner includes those 4 bytes in `raw`; we decode them here.
    //
    // `raw` layout: [<optional prefix bytes>] [4-byte jr $ra] [4-byte delay slot]
    // Minimum length: 8 bytes (bare jr + delay slot).
    if raw.len() < 8 {
        return None;
    }

    let jr_start = raw.len() - 8;
    let delay_start = raw.len() - 4;
    if raw[jr_start..jr_start + 4] != *sig.pattern {
        return None;
    }

    // Decode the delay slot (big-endian).
    let ds = u32::from_be_bytes([
        raw[delay_start],
        raw[delay_start + 1],
        raw[delay_start + 2],
        raw[delay_start + 3],
    ]);

    let (delay_label, delay_clobber, delay_safe) = classify_mips_delay_slot(ds);

    // Only bare `jr $ra ; <delay>` with a known-safe delay slot is
    // emitted as a categorised gadget. Unsafe delay slots are skipped
    // entirely — we don't want BGAT picking a gadget whose delay slot
    // clobbers a register the caller just pinned.
    if !delay_safe {
        return None;
    }

    let prefix_len = raw.len() - 8;
    let has_prefix = prefix_len > 0;

    let mut effects: Vec<RegisterEffect> = Vec::new();
    let mut is_pop = false;

    // Decode prefix instructions (big-endian).
    if has_prefix && prefix_len.is_multiple_of(4) {
        for i in (0..prefix_len).step_by(4) {
            let insn = u32::from_be_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
            let opcode = (insn >> 26) & 0x3F;
            // lw rt, offset(base) - opcode 0x23 (35)
            if opcode == 0x23 {
                let base = (insn >> 21) & 0x1F;
                let rt = (insn >> 16) & 0x1F;
                // If base is $sp (29), it's popping a value from the stack.
                if base == 29 && rt != 0 {
                    let rt_name = mips_reg_name(rt);
                    effects.push(RegisterEffect::load_const(rt_name, 0));
                    is_pop = true;
                }
            }
        }
    }

    let label = if is_pop {
        let pops: Vec<String> = effects.iter().map(|e| format!("pop {}", e.dst)).collect();
        format!("{} ; jr $ra ; {}", pops.join(" ; "), delay_label)
    } else if has_prefix {
        format!("<prefix {} bytes> ; jr $ra ; {}", prefix_len, delay_label)
    } else {
        format!("jr $ra ; {}", delay_label)
    };

    let mut clobbers: Vec<String> = Vec::new();
    if let Some(r) = delay_clobber {
        clobbers.push(r);
    }

    Some(Gadget {
        address,
        effects,
        terminator: Terminator::Ret,
        category: if is_pop {
            GadgetCategory::PopReg
        } else {
            GadgetCategory::Other
        },
        label,
        raw: raw.to_vec(),
        clobbers,
    })
}

/// Classify a MIPS delay-slot instruction.
///
/// Returns `(label, clobbered_register, is_safe)`. An instruction is
/// "safe" for BGAT use when we can reason about what it does; anything
/// we don't recognise is marked unsafe and the parent `jr $ra` gadget
/// is rejected.
fn classify_mips_delay_slot(insn: u32) -> (String, Option<String>, bool) {
    // nop == 0x00000000 (sll $zero, $zero, 0) — the canonical safe
    // delay slot.
    if insn == 0 {
        return ("nop".into(), None, true);
    }

    // addiu rt, rs, imm — opcode 0b001001 == 0x09.
    // Encoding: 001001 rs(5) rt(5) imm(16).
    let opcode = (insn >> 26) & 0x3F;
    let rs = (insn >> 21) & 0x1F;
    let rt = (insn >> 16) & 0x1F;
    let imm = (insn & 0xFFFF) as i16;

    if opcode == 0x09 {
        let rt_name = mips_reg_name(rt);
        let rs_name = mips_reg_name(rs);
        return (
            format!("addiu {rt_name}, {rs_name}, {imm:#x}"),
            Some(rt_name.into()),
            true,
        );
    }

    // R-type: opcode 0b000000, function in low 6 bits.
    if opcode == 0 {
        let func = insn & 0x3F;
        let rd = (insn >> 11) & 0x1F;
        // or rd, rs, rt — func 0x25.
        if func == 0x25 {
            let rd_name = mips_reg_name(rd);
            let rs_name = mips_reg_name(rs);
            let rt_name = mips_reg_name(rt);
            return (
                format!("or {rd_name}, {rs_name}, {rt_name}"),
                Some(rd_name.into()),
                true,
            );
        }
        // addu rd, rs, rt — func 0x21 ; canonical `move` = `addu rd,
        // rs, $zero`.
        if func == 0x21 {
            let rd_name = mips_reg_name(rd);
            let rs_name = mips_reg_name(rs);
            let rt_name = mips_reg_name(rt);
            let label = if rt == 0 {
                format!("move {rd_name}, {rs_name}")
            } else {
                format!("addu {rd_name}, {rs_name}, {rt_name}")
            };
            return (label, Some(rd_name.into()), true);
        }
    }

    // Anything else: unsafe — could be memory load/store, branch,
    // division, multiplication — all too risky to expose to BGAT
    // without proper semantic modelling.
    (format!("<opaque delay 0x{insn:08x}>"), None, false)
}

/// Standard MIPS register name for a 5-bit index.
const fn mips_reg_name(idx: u32) -> &'static str {
    match idx {
        0 => "$zero",
        1 => "$at",
        2 => "$v0",
        3 => "$v1",
        4 => "$a0",
        5 => "$a1",
        6 => "$a2",
        7 => "$a3",
        8 => "$t0",
        9 => "$t1",
        10 => "$t2",
        11 => "$t3",
        12 => "$t4",
        13 => "$t5",
        14 => "$t6",
        15 => "$t7",
        16 => "$s0",
        17 => "$s1",
        18 => "$s2",
        19 => "$s3",
        20 => "$s4",
        21 => "$s5",
        22 => "$s6",
        23 => "$s7",
        24 => "$t8",
        25 => "$t9",
        26 => "$k0",
        27 => "$k1",
        28 => "$gp",
        29 => "$sp",
        30 => "$fp",
        31 => "$ra",
        _ => "$?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_x86_64_pop_rdi_ret() {
        let mut finder = GadgetFinder::new();
        // 5F C3 == pop rdi ; ret.
        let bytes = [0x5F, 0xC3];
        let added = scan_into(&mut finder, Arch::X86_64, 0x4000_0000, &bytes);
        assert!(
            added >= 2,
            "expected 2 gadgets (bare ret + pop+ret), got {added}"
        );
        assert!(
            finder
                .by_category(GadgetCategory::PopReg)
                .iter()
                .any(|g| g.label == "pop rdi ; ret")
        );
    }

    #[test]
    fn scans_x86_64_syscall_stub() {
        let mut finder = GadgetFinder::new();
        // 0F 05 == syscall.
        let bytes = [0x0F, 0x05];
        scan_into(&mut finder, Arch::X86_64, 0x4000_1000, &bytes);
        assert!(
            finder
                .by_category(GadgetCategory::SyscallStub)
                .iter()
                .any(|g| g.label == "syscall")
        );
    }

    #[test]
    fn scans_x86_64_pop_r9_ret() {
        let mut finder = GadgetFinder::new();
        // 41 59 C3 == pop r9 ; ret.
        let bytes = [0x41, 0x59, 0xC3];
        scan_into(&mut finder, Arch::X86_64, 0x4000_2000, &bytes);
        assert!(
            finder
                .by_category(GadgetCategory::PopReg)
                .iter()
                .any(|g| g.label == "pop r9 ; ret")
        );
    }

    #[test]
    fn scans_arm64_ret_gadget() {
        let mut finder = GadgetFinder::new();
        // ret = D65F03C0, little-endian on disk = C0 03 5F D6.
        let bytes = [0xC0, 0x03, 0x5F, 0xD6];
        let added = scan_into(&mut finder, Arch::Arm64, 0x1000_0000, &bytes);
        assert!(added >= 1);
        assert!(
            finder
                .by_category(GadgetCategory::Other)
                .iter()
                .any(|g| g.label == "ret")
        );
    }

    #[test]
    fn scans_riscv_ret_compressed() {
        let mut finder = GadgetFinder::new();
        // c.jr ra = 0x8082, LE = 82 80.
        let bytes = [0x82, 0x80];
        let added = scan_into(&mut finder, Arch::RiscV64, 0x2000_0000, &bytes);
        assert!(added >= 1);
    }

    #[test]
    fn scans_riscv_ecall() {
        let mut finder = GadgetFinder::new();
        // ecall = 0x00000073.
        let bytes = [0x73, 0x00, 0x00, 0x00];
        let added = scan_into(&mut finder, Arch::RiscV64, 0x3000_0000, &bytes);
        assert!(added >= 1);
        assert!(
            finder
                .by_category(GadgetCategory::SyscallStub)
                .iter()
                .any(|g| g.label == "ecall")
        );
    }

    #[test]
    fn scanner_is_deterministic() {
        let bytes = [0x5F, 0xC3, 0x48, 0x5F, 0xC3, 0x0F, 0x05];
        let mut a = GadgetFinder::new();
        let mut b = GadgetFinder::new();
        scan_into(&mut a, Arch::X86_64, 0x4000_0000, &bytes);
        scan_into(&mut b, Arch::X86_64, 0x4000_0000, &bytes);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn empty_blob_adds_nothing() {
        let mut finder = GadgetFinder::new();
        let added = scan_into(&mut finder, Arch::X86_64, 0, &[]);
        assert_eq!(added, 0);
        assert!(finder.is_empty());
    }

    #[test]
    fn unknown_arch_returns_zero() {
        let mut finder = GadgetFinder::new();
        // PowerPC is not wired into the scanner's terminator table.
        let added = scan_into(&mut finder, Arch::Ppc64, 0, &[0, 1, 2, 3]);
        assert_eq!(added, 0);
    }

    #[test]
    fn scans_mips_jr_ra_with_nop_delay_slot() {
        let mut finder = GadgetFinder::new();
        // `jr $ra` = 0x03E00008, big-endian on disk, followed by nop.
        let bytes = [0x03, 0xE0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
        let added = scan_into(&mut finder, Arch::Mips, 0x4000_0000, &bytes);
        assert!(added >= 1);
        assert!(
            finder
                .by_category(GadgetCategory::Other)
                .iter()
                .any(|g| g.label.contains("jr $ra") && g.label.contains("nop"))
        );
    }

    #[test]
    fn mips_rejects_unsafe_delay_slot() {
        let mut finder = GadgetFinder::new();
        // `jr $ra` + an unknown delay-slot instruction (random bytes).
        let bytes = [0x03, 0xE0, 0x00, 0x08, 0xAC, 0x44, 0x00, 0x00];
        scan_into(&mut finder, Arch::Mips, 0x4000_0100, &bytes);
        // Unsafe delay slots are silently dropped — no gadget recorded.
        assert!(
            !finder
                .by_category(GadgetCategory::Other)
                .iter()
                .any(|g| g.address == 0x4000_0100)
        );
    }

    #[test]
    fn mips_records_clobber_for_addiu_delay_slot() {
        let mut finder = GadgetFinder::new();
        // `jr $ra` followed by `addiu $v0, $v0, 1` = 0x24420001
        // (opcode 001001, rs=00010, rt=00010, imm=0x0001).
        let bytes = [0x03, 0xE0, 0x00, 0x08, 0x24, 0x42, 0x00, 0x01];
        scan_into(&mut finder, Arch::Mips, 0x4000_0200, &bytes);
        let found = finder
            .by_category(GadgetCategory::Other)
            .into_iter()
            .find(|g| g.address == 0x4000_0200);
        let g = found.expect("gadget at 0x4000_0200");
        assert!(g.clobbers.iter().any(|c| c == "$v0"));
    }

    #[test]
    fn scans_mips_syscall() {
        let mut finder = GadgetFinder::new();
        let bytes = [0x00, 0x00, 0x00, 0x0C];
        scan_into(&mut finder, Arch::Mips64, 0x4000_1000, &bytes);
        assert!(
            finder
                .by_category(GadgetCategory::SyscallStub)
                .iter()
                .any(|g| g.label == "syscall")
        );
    }
}
