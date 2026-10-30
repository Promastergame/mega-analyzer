//! Zero-dependency ARM64 (A64) instruction decoder.
//!
//! Covers the instruction subset consumed by OmniSec lifting
//! (`omnisec-disasm-arm64`) and micro-emulation (`omnisec-emu-arm64`,
//! `omnisec-micro-emu`). Decoding is infallible for any 4-byte word —
//! A64 is fixed-width — unknown words decode to mnemonic `"UNKNOWN"`
//! (callers map that to `OpCode::Custom(0)` / skip).
//!
//! Mnemonic names intentionally match the previous decoder's `Debug`
//! spelling (`"B_cond"`, `"LDRSW"`, …) so downstream mapping tables
//! work unchanged.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// A decoded operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// Unused operand slot.
    None,
    /// General-purpose register.
    Reg {
        /// Register id 0..=30, 31 = SP/XZR/WZR.
        id: u8,
        /// Register width in bits (32 or 64).
        width: u8,
        /// Selects SP semantics where the encoding allows it.
        is_sp: bool,
    },
    /// Immediate value or absolute address (branch targets and
    /// ADR/literal addresses are resolved against the decode address).
    Imm(i64),
    /// `[base + disp]` memory reference.
    Mem {
        /// Base register id.
        base: u8,
        /// Base is the stack pointer.
        base_is_sp: bool,
        /// Byte displacement (signed).
        disp: i64,
    },
}

/// A decoded A64 instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    /// Mnemonic in previous-decoder `Debug` spelling.
    pub mnemonic: &'static str,
    /// Up to 4 operands ([`Operand::None`] pads unused slots).
    pub ops: [Operand; 4],
    /// Branch condition code for `"B_cond"` and the `CSEL`/`CCMP`
    /// families (0..=14), `0xF` otherwise.
    pub cond: u8,
}

const NONE4: [Operand; 4] = [Operand::None, Operand::None, Operand::None, Operand::None];

impl Decoded {
    fn new(mnemonic: &'static str) -> Self {
        Self {
            mnemonic,
            ops: NONE4,
            cond: 0xF,
        }
    }
}

/// Decode one little-endian 4-byte slice at `addr`.
/// Returns `None` only when fewer than 4 bytes are available.
#[must_use]
pub fn decode_bytes(bytes: &[u8], addr: u64) -> Option<(Decoded, usize)> {
    if bytes.len() < 4 {
        return None;
    }
    let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Some((decode(word, addr), 4))
}

/// Decode a single 32-bit A64 instruction word.
///
/// Infallible: unrecognized words yield mnemonic `"UNKNOWN"`.
#[must_use]
pub fn decode(word: u32, addr: u64) -> Decoded {
    let w = word;

    // ── HINT / NOP ───────────────────────────────────────────────
    if w & 0xFFFF_F01F == 0xD503_201F {
        return if w == 0xD503_201F {
            Decoded::new("NOP")
        } else {
            Decoded::new("HINT")
        };
    }

    // ── Unconditional branch (register): BR / BLR / RET (+PAuth) ──
    if w & 0xFE00_0000 == 0xD600_0000 {
        let opc4 = (w >> 21) & 0xF; // 0 = BR, 1 = BLR, 2 = RET
        let aut = w & 0xC00 != 0;
        let rn = ((w >> 5) & 31) as u8;
        let (base, paa) = match opc4 {
            0 => ("BR", "BRAA"),
            1 => ("BLR", "BLRAA"),
            2 => ("RET", "RETAA"),
            _ => return Decoded::new("UNKNOWN"),
        };
        let mut d = Decoded::new(if aut { paa } else { base });
        d.ops[0] = Operand::Reg {
            id: rn,
            width: 64,
            is_sp: false,
        };
        return d;
    }

    // ── Exception generation: SVC / HVC / SMC / BRK / HLT / DCPS ──
    if w & 0xFFE0_001F == 0xD400_0001 {
        return imm_only("SVC", ((w >> 5) & 0xFFFF) as i64);
    }
    if w & 0xFFE0_001F == 0xD400_0002 {
        return imm_only("HVC", ((w >> 5) & 0xFFFF) as i64);
    }
    if w & 0xFFE0_001F == 0xD400_0003 {
        return imm_only("SMC", ((w >> 5) & 0xFFFF) as i64);
    }
    if w & 0xFFE0_001F == 0xD420_0000 {
        return imm_only("BRK", ((w >> 5) & 0xFFFF) as i64);
    }
    if w & 0xFFE0_001F == 0xD440_0000 {
        return imm_only("HLT", ((w >> 5) & 0xFFFF) as i64);
    }
    if w == 0xD4A0_0001 {
        return Decoded::new("DCPS1");
    }
    if w == 0xD4A0_0002 {
        return Decoded::new("DCPS2");
    }
    if w == 0xD4A0_0003 {
        return Decoded::new("DCPS3");
    }

    // ── Barriers: DSB / DMB / ISB ────────────────────────────────
    if w & 0xFFFF_F0FF == 0xD503_309F {
        return Decoded::new("DSB");
    }
    if w & 0xFFFF_F0FF == 0xD503_30BF {
        return Decoded::new("DMB");
    }
    if w & 0xFFFF_F0FF == 0xD503_30DF {
        return Decoded::new("ISB");
    }

    // ── Unconditional branch (immediate): B / BL ─────────────────
    if w & 0xFC00_0000 == 0x1400_0000 || w & 0xFC00_0000 == 0x9400_0000 {
        let off = sx(w & 0x03FF_FFFF, 26) << 2;
        let mut d = Decoded::new(if w & 0x8000_0000 == 0 { "B" } else { "BL" });
        d.ops[0] = Operand::Imm(addr.wrapping_add(off as u64) as i64);
        return d;
    }

    // ── Conditional branch: B.cond ───────────────────────────────
    if w & 0xFF00_001F == 0x5400_0000 {
        let off = sx((w >> 5) & 0x7_FFFF, 19) << 2;
        let mut d = Decoded::new("B_cond");
        d.ops[0] = Operand::Imm(addr.wrapping_add(off as u64) as i64);
        d.cond = (w & 0xF) as u8;
        return d;
    }

    // ── Compare & branch: CBZ / CBNZ ─────────────────────────────
    // Top byte 0x34/0x35 (32-bit) or 0xB4/0xB5 (64-bit); op bit24 selects.
    if matches!(
        w & 0xFF00_0000,
        0x3400_0000 | 0x3500_0000 | 0xB400_0000 | 0xB500_0000
    ) {
        let is64 = w >> 31 == 1;
        let op = (w >> 24) & 1; // 0 = CBZ, 1 = CBNZ
        let off = sx((w >> 5) & 0x7_FFFF, 19) << 2;
        let mut d = Decoded::new(if op == 0 { "CBZ" } else { "CBNZ" });
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width: if is64 { 64 } else { 32 },
            is_sp: false,
        };
        d.ops[1] = Operand::Imm(addr.wrapping_add(off as u64) as i64);
        return d;
    }

    // ── Test & branch: TBZ / TBNZ ────────────────────────────────
    if w & 0x7F00_0000 == 0x3600_0000 || w & 0x7F00_0000 == 0x3700_0000 {
        let op = (w >> 24) & 1; // 0 = TBZ, 1 = TBNZ
        let bit = (((w >> 31) & 1) << 5) | ((w >> 19) & 31);
        let off = sx((w >> 5) & 0x3FFF, 14) << 2;
        let mut d = Decoded::new(if op == 0 { "TBZ" } else { "TBNZ" });
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width: 64,
            is_sp: false,
        };
        d.ops[1] = Operand::Imm(bit as i64);
        d.ops[2] = Operand::Imm(addr.wrapping_add(off as u64) as i64);
        return d;
    }

    // ── PC-relative: ADR / ADRP ──────────────────────────────────
    if w & 0x9F00_0000 == 0x1000_0000 || w & 0x9F00_0000 == 0x9000_0000 {
        let imm = sx((((w >> 5) & 0x7_FFFF) << 2) | ((w >> 29) & 3), 21);
        let target = if w & 0x8000_0000 == 0 {
            addr.wrapping_add(imm as u64) as i64
        } else {
            (addr & !0xFFF) as i64 + (imm << 12)
        };
        let mut d = Decoded::new(if w & 0x8000_0000 == 0 { "ADR" } else { "ADRP" });
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width: 64,
            is_sp: false,
        };
        d.ops[1] = Operand::Imm(target);
        return d;
    }

    // ── Add/sub (immediate) ──────────────────────────────────────
    match (w >> 24) & 0x7F {
        0x11 | 0x91 | 0x31 | 0xB1 | 0x51 | 0xD1 | 0x71 | 0xF1 => {
            let op = (w >> 30) & 1; // 0 = ADD, 1 = SUB
            let s = (w >> 29) & 1;
            let width = if w >> 31 == 1 { 64 } else { 32 };
            let rd = (w & 31) as u8;
            let rn = ((w >> 5) & 31) as u8;
            let val = (((w >> 10) & 0xFFF) << (((w >> 22) & 1) * 12)) as i64;
            let mnemonic = match (op, s, rd) {
                (0, 0, _) if val == 0 && ((w >> 22) & 1) == 0 && (rd == 31 || rn == 31) => "MOV",
                (0, 0, _) => "ADD",
                (1, 0, _) => "SUB",
                (0, 1, 31) => "CMN",
                (0, 1, _) => "ADDS",
                (1, 1, 31) => "CMP",
                _ => "SUBS",
            };
            let mut d = Decoded::new(mnemonic);
            d.ops[0] = Operand::Reg {
                id: rd,
                width,
                is_sp: rd == 31 && s == 0,
            };
            d.ops[1] = Operand::Reg {
                id: rn,
                width,
                is_sp: rn == 31,
            };
            d.ops[2] = Operand::Imm(val);
            return d;
        }
        _ => {}
    }

    // ── Logical (immediate): AND / ORR / EOR / ANDS ──────────────
    if w & 0x1F80_0000 == 0x1200_0000 {
        let opc = (w >> 29) & 3;
        let width = if w >> 31 == 1 { 64 } else { 32 };
        let rd = (w & 31) as u8;
        let rn = ((w >> 5) & 31) as u8;
        let mut val = decode_bitmask(w >> 31 == 1, (w >> 16) & 0x3F, (w >> 10) & 0x3F).unwrap_or(0);
        if width == 32 {
            val &= 0xFFFF_FFFF;
        }
        let mnemonic = match opc {
            0 => "AND",
            1 => {
                if rn == 31 {
                    "MOV"
                } else {
                    "ORR"
                }
            }
            2 => "EOR",
            _ => {
                if rd == 31 {
                    "TST"
                } else {
                    "ANDS"
                }
            }
        };
        let mut d = Decoded::new(mnemonic);
        d.ops[0] = Operand::Reg {
            id: rd,
            width,
            is_sp: false,
        };
        d.ops[1] = Operand::Reg {
            id: rn,
            width,
            is_sp: false,
        };
        d.ops[2] = Operand::Imm(val as i64);
        return d;
    }

    // ── Move wide: MOVN / MOVZ / MOVK ────────────────────────────
    if w & 0x1F80_0000 == 0x1280_0000 {
        let opc = (w >> 29) & 3;
        let mnemonic = match opc {
            0 => "MOVN",
            2 => "MOVZ",
            3 => "MOVK",
            _ => return Decoded::new("UNKNOWN"),
        };
        let width: u8 = if w >> 31 == 1 { 64 } else { 32 };
        let hw = (w >> 21) & 3;
        if hw * 16 >= u32::from(width) {
            return Decoded::new("UNKNOWN");
        }
        let val = (((w >> 5) & 0xFFFF) << (hw * 16)) as i64;
        let mut d = Decoded::new(mnemonic);
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[1] = Operand::Imm(val);
        return d;
    }

    // ── Bitfield: SBFM / UBFM (+aliases) ─────────────────────────
    if w & 0x1F80_0000 == 0x1300_0000 {
        let opc = (w >> 29) & 3;
        let sf = w >> 31;
        let nbits = if sf == 1 { 64 } else { 32 };
        if (w >> 22) & 1 != sf {
            return Decoded::new("UNKNOWN");
        }
        let immr = (w >> 16) & 0x3F;
        let imms = (w >> 10) & 0x3F;
        if immr >= nbits || imms >= nbits {
            return Decoded::new("UNKNOWN");
        }
        let rd = (w & 31) as u8;
        let rn = ((w >> 5) & 31) as u8;
        let width = nbits as u8;
        let reg = |id| Operand::Reg {
            id,
            width,
            is_sp: false,
        };
        match opc {
            0 => {
                // SBFM: ASR / SXT* aliases.
                if imms == nbits - 1 {
                    let mut d = Decoded::new("ASR");
                    d.ops[0] = reg(rd);
                    d.ops[1] = reg(rn);
                    d.ops[2] = Operand::Imm(immr as i64);
                    return d;
                }
                if immr == 0 {
                    let name = match imms {
                        7 => Some("SXTB"),
                        15 => Some("SXTH"),
                        31 => Some("SXTW"),
                        _ => None,
                    };
                    if let Some(name) = name {
                        let mut d = Decoded::new(name);
                        d.ops[0] = reg(rd);
                        d.ops[1] = reg(rn);
                        return d;
                    }
                }
                return Decoded::new("UNKNOWN");
            }
            2 => {
                // UBFM: LSR / LSL / UXT* aliases.
                if imms == nbits - 1 {
                    let mut d = Decoded::new("LSR");
                    d.ops[0] = reg(rd);
                    d.ops[1] = reg(rn);
                    d.ops[2] = Operand::Imm(immr as i64);
                    return d;
                }
                let sh = (nbits - immr) % nbits;
                if sh != 0 && imms == (nbits - 1 - sh) % nbits {
                    let mut d = Decoded::new("LSL");
                    d.ops[0] = reg(rd);
                    d.ops[1] = reg(rn);
                    d.ops[2] = Operand::Imm(sh as i64);
                    return d;
                }
                if immr == 0 {
                    let name = match imms {
                        7 => Some("UXTB"),
                        15 => Some("UXTH"),
                        31 => Some("UXTW"),
                        _ => None,
                    };
                    if let Some(name) = name {
                        let mut d = Decoded::new(name);
                        d.ops[0] = reg(rd);
                        d.ops[1] = reg(rn);
                        return d;
                    }
                }
                return Decoded::new("UNKNOWN");
            }
            _ => return Decoded::new("UNKNOWN"), // BFM
        }
    }

    // ── Extract: EXTR (+ROR alias) ───────────────────────────────
    if w & 0x1F80_0000 == 0x1380_0000 {
        let rm = ((w >> 16) & 31) as u8;
        let imms = (w >> 10) & 0x3F;
        let rn = ((w >> 5) & 31) as u8;
        let rd = (w & 31) as u8;
        let width = if w >> 31 == 1 { 64 } else { 32 };
        let reg = |id| Operand::Reg {
            id,
            width,
            is_sp: false,
        };
        if rm == rn {
            let mut d = Decoded::new("ROR");
            d.ops[0] = reg(rd);
            d.ops[1] = reg(rn);
            d.ops[2] = Operand::Imm(imms as i64);
            return d;
        }
        let mut d = Decoded::new("EXTR");
        d.ops[0] = reg(rd);
        d.ops[1] = reg(rn);
        d.ops[2] = reg(rm);
        d.ops[3] = Operand::Imm(imms as i64);
        return d;
    }

    // ── Add/sub (shifted register) ───────────────────────────────
    match (w >> 24) & 0x7F {
        0x0B | 0x8B | 0x2B | 0xAB | 0x4B | 0xCB | 0x6B | 0xEB => {
            let op = (w >> 30) & 1;
            let s = (w >> 29) & 1;
            let width = if w >> 31 == 1 { 64 } else { 32 };
            let rd = (w & 31) as u8;
            let rn = ((w >> 5) & 31) as u8;
            let rm = ((w >> 16) & 31) as u8;
            let mnemonic = match (op, s, rd) {
                (0, 0, _) => "ADD",
                (1, 0, 31) => "NEG",
                (1, 0, _) => "SUB",
                (0, 1, 31) => "CMN",
                (0, 1, _) => "ADDS",
                (1, 1, 31) => "CMP",
                _ => {
                    if rn == 31 {
                        "NEGS"
                    } else {
                        "SUBS"
                    }
                }
            };
            let mut d = Decoded::new(mnemonic);
            d.ops[0] = Operand::Reg {
                id: rd,
                width,
                is_sp: rd == 31 && s == 0,
            };
            d.ops[1] = Operand::Reg {
                id: rn,
                width,
                is_sp: rn == 31,
            };
            d.ops[2] = Operand::Reg {
                id: rm,
                width,
                is_sp: false,
            };
            return d;
        }
        _ => {}
    }

    // ── Logical (shifted register) ───────────────────────────────
    if w & 0x1F20_0000 == 0x0A00_0000 {
        let opc = (w >> 29) & 3;
        let n = (w >> 21) & 1;
        let width = if w >> 31 == 1 { 64 } else { 32 };
        let rd = (w & 31) as u8;
        let rn = ((w >> 5) & 31) as u8;
        let rm = ((w >> 16) & 31) as u8;
        let mnemonic = match (opc, n) {
            (0, _) => "AND",
            (1, 0) => {
                if rn == 31 {
                    "MOV"
                } else {
                    "ORR"
                }
            }
            (1, 1) => {
                if rn == 31 {
                    "MVN"
                } else {
                    "ORN"
                }
            }
            (2, _) => "EOR",
            _ => {
                if rd == 31 {
                    "TST"
                } else {
                    "ANDS"
                }
            }
        };
        let mut d = Decoded::new(mnemonic);
        d.ops[0] = Operand::Reg {
            id: rd,
            width,
            is_sp: false,
        };
        d.ops[1] = Operand::Reg {
            id: rn,
            width,
            is_sp: false,
        };
        d.ops[2] = Operand::Reg {
            id: rm,
            width,
            is_sp: false,
        };
        return d;
    }

    // ── Multiply: MADD / MSUB / MUL / SMULL / UMULL / SMULH / UMULH
    if w & 0x1FE0_0000 == 0x1B00_0000 {
        let sf = w >> 31;
        let op54 = (w >> 29) & 7;
        let ra = ((w >> 10) & 31) as u8;
        let mnemonic = match op54 {
            0 => {
                if ra == 31 {
                    "MUL"
                } else {
                    "MADD"
                }
            }
            1 => "MSUB",
            2 | 3 => {
                if sf == 1 {
                    "SMULH"
                } else {
                    "SMULL"
                }
            }
            _ => {
                if sf == 1 {
                    "UMULH"
                } else {
                    "UMULL"
                }
            }
        };
        let width = if sf == 1 { 64 } else { 32 };
        let mut d = Decoded::new(mnemonic);
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[1] = Operand::Reg {
            id: ((w >> 5) & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[2] = Operand::Reg {
            id: ((w >> 16) & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[3] = Operand::Reg {
            id: ra,
            width,
            is_sp: false,
        };
        return d;
    }

    // ── Divide: SDIV / UDIV ──────────────────────────────────────
    if w & 0x7FE0_0C00 == 0x1AC0_0800 {
        return rr_alu("SDIV", w);
    }
    if w & 0x7FE0_0C00 == 0x1AC0_0000 {
        return rr_alu("UDIV", w);
    }

    // ── Conditional select: CSEL / CSINC / CSINV / CSNEG ─────────
    // Mask excludes sf/op (bits 31:30) and the op2 selector (bits 11:10).
    if w & 0x3FE0_0000 == 0x1A80_0000 {
        let key = (((w >> 30) & 1) << 2) | ((w >> 10) & 3);
        let mnemonic = match key {
            0 => "CSEL",
            1 => "CSINC",
            4 => "CSINV",
            5 => "CSNEG",
            _ => return Decoded::new("UNKNOWN"),
        };
        let width: u8 = if w >> 31 == 1 { 64 } else { 32 };
        let mut d = Decoded::new(mnemonic);
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[1] = Operand::Reg {
            id: ((w >> 5) & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[2] = Operand::Reg {
            id: ((w >> 16) & 31) as u8,
            width,
            is_sp: false,
        };
        d.cond = ((w >> 12) & 0xF) as u8;
        return d;
    }

    // ── Conditional compare: CCMP / CCMN ─────────────────────────
    if w & 0x3FE0_0C00 == 0x3A40_0400 {
        if (w >> 29) & 1 != 1 {
            return Decoded::new("UNKNOWN");
        }
        let width = if w >> 31 == 1 { 64 } else { 32 };
        let mut d = Decoded::new(if (w >> 30) & 1 == 0 { "CCMP" } else { "CCMN" });
        d.ops[0] = Operand::Reg {
            id: ((w >> 5) & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[1] = Operand::Reg {
            id: ((w >> 16) & 31) as u8,
            width,
            is_sp: false,
        };
        d.cond = ((w >> 12) & 0xF) as u8;
        return d;
    }

    // ── LDR (literal) / LDRSW (literal) ──────────────────────────
    if w & 0xBF00_0000 == 0x1800_0000 {
        let opc = (w >> 30) & 3;
        let (mnemonic, width) = match opc {
            0 => ("LDR", 32),
            1 => ("LDR", 64),
            2 => ("LDRSW", 64),
            _ => return Decoded::new("UNKNOWN"), // PRFM (literal)
        };
        let off = sx((w >> 5) & 0x7_FFFF, 19) << 2;
        let mut d = Decoded::new(mnemonic);
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[1] = Operand::Imm(addr.wrapping_add(off as u64) as i64);
        return d;
    }

    // ── Load/store (register offset) ─────────────────────────────
    if w & 0x3B20_0C00 == 0x3820_0800 {
        let named = ldst_name(w);
        let Ok((name, reg_width, _)) = named else {
            return Decoded::new("UNKNOWN");
        };
        let mut d = Decoded::new(name);
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width: reg_width,
            is_sp: false,
        };
        d.ops[1] = Operand::Mem {
            base: ((w >> 5) & 31) as u8,
            base_is_sp: ((w >> 5) & 31) == 31,
            disp: 0,
        };
        return d;
    }

    // ── Load/store immediate (unsigned / indexed / unscaled) ─────
    if w & 0x3A00_0000 == 0x3800_0000 {
        let named = ldst_name(w);
        let Ok((mut name, reg_width, scale)) = named else {
            return Decoded::new("UNKNOWN");
        };
        let disp = if (w >> 24) & 1 == 1 {
            // Unsigned offset: uimm12 scaled.
            (((w >> 10) & 0xFFF) << scale) as i64
        } else {
            match (w >> 10) & 3 {
                0 => {
                    // Unscaled: LDUR/STUR family.
                    name = match name {
                        "STR" => "STUR",
                        "LDR" => "LDUR",
                        _ => name,
                    };
                    sx((w >> 12) & 0x1FF, 9)
                }
                // 1 = post-index, 3 = pre-index, 2 = unprivileged
                // (plain form): all share the base mnemonic.
                _ => sx((w >> 12) & 0x1FF, 9),
            }
        };
        let mut d = Decoded::new(name);
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width: reg_width,
            is_sp: false,
        };
        d.ops[1] = Operand::Mem {
            base: ((w >> 5) & 31) as u8,
            base_is_sp: ((w >> 5) & 31) == 31,
            disp,
        };
        return d;
    }

    // ── Load/store pair: STP / LDP / LDPSW ───────────────────────
    if (w >> 27) & 7 == 5 && (w >> 26) & 1 == 0 && (w >> 25) & 1 == 0 {
        let opc = (w >> 30) & 3;
        let l = (w >> 22) & 1;
        let (name, pair64) = match (opc, l) {
            (0, 0) => ("STP", false),
            (0, 1) => ("LDP", false),
            (1, 1) => ("LDPSW", true),
            (2, 0) => ("STP", true),
            (2, 1) => ("LDP", true),
            _ => return Decoded::new("UNKNOWN"),
        };
        let disp = sx((w >> 15) & 0x7F, 7) << if pair64 { 3 } else { 2 };
        let width = if pair64 { 64 } else { 32 };
        let mut d = Decoded::new(name);
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[1] = Operand::Reg {
            id: ((w >> 10) & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[2] = Operand::Mem {
            base: ((w >> 5) & 31) as u8,
            base_is_sp: ((w >> 5) & 31) == 31,
            disp,
        };
        return d;
    }

    // ── Exclusive: LDAXR / STLXR / LDAR / STLR ───────────────────
    // Loads key on o2 (bit 23): LDAR vs LDAXR; stores degrade by
    // register fields (all map to Store downstream either way).
    if w & 0x3F00_0000 == 0x0800_0000 {
        let l = (w >> 22) & 1;
        let o2 = (w >> 23) & 1;
        let rs = (w >> 16) & 31;
        let rt2 = (w >> 10) & 31;
        let width = if w >> 30 == 3 { 64 } else { 32 };
        let name = if l == 1 {
            if o2 == 1 { "LDAR" } else { "LDAXR" }
        } else if rs == 31 && rt2 == 31 {
            "STLR"
        } else {
            "STLXR"
        };
        let mut d = Decoded::new(name);
        d.ops[0] = Operand::Reg {
            id: (w & 31) as u8,
            width,
            is_sp: false,
        };
        d.ops[1] = Operand::Mem {
            base: ((w >> 5) & 31) as u8,
            base_is_sp: ((w >> 5) & 31) == 31,
            disp: 0,
        };
        return d;
    }

    Decoded::new("UNKNOWN")
}

fn imm_only(mnemonic: &'static str, val: i64) -> Decoded {
    let mut d = Decoded::new(mnemonic);
    d.ops[0] = Operand::Imm(val);
    d
}

/// `[Rd, Rn, Rm]` ALU skeleton for SDIV/UDIV.
fn rr_alu(mnemonic: &'static str, w: u32) -> Decoded {
    let width = if w >> 31 == 1 { 64 } else { 32 };
    let mut d = Decoded::new(mnemonic);
    d.ops[0] = Operand::Reg {
        id: (w & 31) as u8,
        width,
        is_sp: false,
    };
    d.ops[1] = Operand::Reg {
        id: ((w >> 5) & 31) as u8,
        width,
        is_sp: false,
    };
    d.ops[2] = Operand::Reg {
        id: ((w >> 16) & 31) as u8,
        width,
        is_sp: false,
    };
    d
}

/// Shared mnemonic + widths for the LD/ST immediate/register groups.
/// Returns `(mnemonic, rt_width, scale_shift)`.
fn ldst_name(w: u32) -> Result<(&'static str, u8, u32), ()> {
    let v = (w >> 26) & 1;
    if v != 0 {
        return Err(()); // SIMD — out of scope.
    }
    let opc = (w >> 22) & 3;
    let size = w >> 30;
    match size {
        0 => match opc {
            0 => Ok(("STRB", 32, 0)),
            1 => Ok(("LDRB", 32, 0)),
            _ => Err(()),
        },
        1 => match opc {
            0 => Ok(("STRH", 32, 1)),
            1 => Ok(("LDRH", 32, 1)),
            _ => Err(()),
        },
        2 => match opc {
            0 => Ok(("STR", 32, 2)),
            1 => Ok(("LDR", 32, 2)),
            2 => Ok(("LDRSW", 64, 2)),
            _ => Err(()),
        },
        3 => match opc {
            0 => Ok(("STR", 64, 3)),
            1 => Ok(("LDR", 64, 3)),
            _ => Err(()),
        },
        _ => Err(()),
    }
}

/// Sign-extend the low `bits` of `v` to `i64`.
#[inline]
fn sx(v: u32, bits: u32) -> i64 {
    (((v << (32 - bits)) as i32) >> (32 - bits)) as i64
}

/// Decode an A64 logical-immediate bitmask (N:immr:imms) to a `u64`
/// pattern. Returns `None` for reserved encodings.
fn decode_bitmask(n: bool, immr: u32, imms: u32) -> Option<u64> {
    let not_imms = (!imms) & 0x3F;
    let combined = ((u32::from(n)) << 6) | not_imms; // 7 bits
    if combined == 0 {
        return None;
    }
    let len = combined.ilog2(); // 1..=6
    if len < 1 {
        return None;
    }
    let levels = (1u32 << len) - 1;
    let s = imms & levels;
    let r = immr & levels;
    let esize = 1u32 << len; // 2..=64
    let elem: u64 = if esize >= 64 {
        (if s == 63 {
            u64::MAX
        } else {
            (1u64 << (s + 1)) - 1
        })
        .rotate_right(r)
    } else {
        let mask = (1u64 << esize) - 1;
        let base = (1u64 << (s + 1)) - 1;
        let r = r % esize;
        if r == 0 {
            base & mask
        } else {
            ((base >> r) | (base << (esize - r))) & mask
        }
    };
    // Replicate the element across 64 bits.
    let mut out = 0u64;
    let mut b = 0;
    while b < 64 {
        out |= elem << b;
        b += esize;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(word: u32) -> &'static str {
        decode(word, 0x1000).mnemonic
    }

    #[test]
    fn golden_branches() {
        assert_eq!(m(0xD65F_03C0), "RET");
        assert_eq!(m(0xD503_201F), "NOP");
        assert_eq!(m(0x1400_0000), "B");
        assert_eq!(m(0x9400_0000), "BL");
        assert_eq!(m(0xD61F_0000), "BR");
        assert_eq!(m(0xD63F_0000), "BLR");
        assert_eq!(m(0x5400_0040), "B_cond");
        assert_eq!(m(0xB400_0040), "CBZ");
        assert_eq!(m(0xB500_0040), "CBNZ");
        assert_eq!(m(0x3600_0040), "TBZ");
        assert_eq!(m(0x3700_0040), "TBNZ");
        // Branch targets resolve against the address.
        let d = decode(0x1400_0002, 0x1000); // b #8
        assert_eq!(d.ops[0], Operand::Imm(0x1008));
        let d = decode(0x9400_0002, 0x1000); // bl #8
        assert_eq!(d.ops[0], Operand::Imm(0x1008));
        let d = decode(0x5400_0040, 0x1000); // b.eq #8
        assert_eq!(d.cond, 0);
        assert_eq!(d.ops[0], Operand::Imm(0x1008));
    }

    #[test]
    fn golden_data_processing() {
        assert_eq!(m(0x8B02_0020), "ADD"); // add x0, x1, x2
        assert_eq!(m(0x9100_03FD), "MOV"); // mov x29, sp (add #0)
        assert_eq!(m(0xD100_1443), "SUB"); // sub x3, x2, #5
        assert_eq!(m(0xF100_041F), "CMP"); // cmp x0, #1
        assert_eq!(m(0xD280_0140), "MOVZ"); // movz x0, #10
        assert_eq!(m(0xD280_0000), "MOVZ"); // movz x0, #0
        assert_eq!(m(0xB240_03E0), "MOV"); // orr x0, xzr, #1 -> mov
        assert_eq!(m(0xF200_1C1F), "TST"); // ands xzr, x0, #0xff -> tst
        assert_eq!(m(0x1AC1_0802), "SDIV"); // sdiv x2, x0, x1
        assert_eq!(m(0x1AC1_0002), "UDIV"); // udiv x2, x0, x1
        assert_eq!(m(0x1B01_7C20), "MUL"); // mul x0, x1, x1 (Ra=xzr)
        assert_eq!(m(0x1A81_0000), "CSEL"); // csel x0, x0, x1, eq
        assert_eq!(m(0x1A80_0420), "CSINC"); // csinc x0, x0, x0, eq
        assert_eq!(m(0x9000_0000), "ADRP"); // adrp x0, #0
        assert_eq!(m(0xD503_30BF), "DMB");
        assert_eq!(m(0xD503_309F), "DSB");
        assert_eq!(m(0xD503_30DF), "ISB");
        assert_eq!(m(0xD400_0001), "SVC");
        assert_eq!(m(0xD420_0000), "BRK");
        assert_eq!(m(0x9342_FC20), "ASR"); // asr x0, x1, #2
        assert_eq!(m(0xD37E_F420), "LSL"); // lsl x0, x1, #2
        assert_eq!(m(0xD342_FC20), "LSR"); // lsr x0, x1, #2
        assert_eq!(m(0x9340_7C20), "SXTW"); // sxtw x0, w1
        assert_eq!(m(0x13C1_1020), "ROR"); // ror x0, x1, #4
        assert_eq!(m(0xC85F_7C20), "LDAXR"); // ldaxr x0, [x1]
        assert_eq!(m(0xC8DF_7C20), "LDAR"); // ldar x0, [x1]
    }

    #[test]
    fn golden_loads_stores() {
        assert_eq!(m(0xF940_0020), "LDR"); // ldr x0, [x1]
        assert_eq!(m(0xF900_0020), "STR"); // str x0, [x1]
        assert_eq!(m(0xF840_0020), "LDUR"); // ldur x0, [x1]
        assert_eq!(m(0xF800_0020), "STUR"); // stur x0, [x1]
        assert_eq!(m(0xA9BF_7BFD), "STP"); // stp x29, x30, [sp, #-16]!
        assert_eq!(m(0xA940_7BFD), "LDP"); // ldp x29, x30, [sp] (offset)
        assert_eq!(m(0x3940_0020), "LDRB"); // ldrb w0, [x1]
        assert_eq!(m(0xF862_6820), "LDR"); // ldr x0, [x1, x2]
        assert_eq!(m(0x5800_0040), "LDR"); // ldr x0, [pc, #8] (literal)
        assert_eq!(m(0xF81F_0FE0), "STR"); // str x0, [sp, #-16]! (pre-index)
        // str x0, [x1, #8] -> disp 8
        let d = decode(0xF900_0420, 0);
        assert_eq!(d.mnemonic, "STR");
        assert_eq!(
            d.ops[1],
            Operand::Mem {
                base: 1,
                base_is_sp: false,
                disp: 8
            }
        );
        // stp pre-index disp -16
        let d = decode(0xA9BF_7BFD, 0);
        assert_eq!(
            d.ops[2],
            Operand::Mem {
                base: 31,
                base_is_sp: true,
                disp: -16
            }
        );
        // literal target resolves against pc
        let d = decode(0x5800_0040, 0x1000);
        assert_eq!(d.ops[1], Operand::Imm(0x1008));
        // pre-index disp -16
        let d = decode(0xF81F_0FE0, 0);
        assert_eq!(
            d.ops[1],
            Operand::Mem {
                base: 31,
                base_is_sp: true,
                disp: -16
            }
        );
    }

    #[test]
    fn golden_bitmask_values() {
        // and x0, x0, #0xff -> value 0xff
        let d = decode(0x9240_1C00, 0);
        assert_eq!(d.mnemonic, "AND");
        assert_eq!(d.ops[2], Operand::Imm(0xFF));
        // orr x0, xzr, #1 -> mov, value 1
        let d = decode(0xB240_03E0, 0);
        assert_eq!(d.mnemonic, "MOV");
        assert_eq!(
            d.ops[1],
            Operand::Reg {
                id: 31,
                width: 64,
                is_sp: false
            }
        );
        assert_eq!(d.ops[2], Operand::Imm(1));
        // ands xzr, x0, #0xff -> tst, value 0xff
        let d = decode(0xF200_1C1F, 0);
        assert_eq!(d.mnemonic, "TST");
        assert_eq!(d.ops[2], Operand::Imm(0xFF));
    }

    #[test]
    fn unknown_never_traps() {
        // UDF #0 and zero word still produce a placeholder.
        assert_eq!(m(0x0000_0000), "UNKNOWN");
        assert_eq!(m(0xD4A0_0000), "UNKNOWN");
        assert_eq!(decode_bytes(&[0xC0, 0x03], 0), None);
        assert_eq!(
            decode_bytes(&[0xC0, 0x03, 0x5F, 0xD6], 0)
                .unwrap()
                .0
                .mnemonic,
            "RET"
        );
    }

    #[test]
    fn add_operands_structured() {
        // add x0, x1, x2
        let d = decode(0x8B02_0020, 0);
        assert_eq!(
            d.ops[0],
            Operand::Reg {
                id: 0,
                width: 64,
                is_sp: false
            }
        );
        assert_eq!(
            d.ops[1],
            Operand::Reg {
                id: 1,
                width: 64,
                is_sp: false
            }
        );
        assert_eq!(
            d.ops[2],
            Operand::Reg {
                id: 2,
                width: 64,
                is_sp: false
            }
        );
        // sub x3, x2, #5
        let d = decode(0xD100_1443, 0);
        assert_eq!(d.ops[2], Operand::Imm(5));
    }
}
