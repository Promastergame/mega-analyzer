//! Hardware-assisted tracing via Intel Processor Trace.
//!
//! This crate provides the building blocks for Intel PT based tracing:
//!
//! - [`PtCapabilities::probe`] — detects whether the host CPU/OS exposes
//!   Intel PT (`/sys/bus/event_source/devices/intel_pt` on Linux) and why
//!   tracing is unavailable when it is not. No `unsafe` is required: probing
//!   is done through sysfs and `/proc`.
//! - [`PtDecoder`] — a pure-Rust streaming decoder for Intel PT packets,
//!   faithful to the Linux kernel reference
//!   (`tools/perf/util/intel-pt-decoder/intel-pt-pkt-decoder.c`, GPL-2.0,
//!   Adrian Hunter / Intel) and Intel SDM Vol. 3 Chapter 32. Dispatch rules:
//!   `0x00` = `PAD`, `0x02` = extended opcode (second byte selects `PSB`,
//!   `CBR`, `PIP`, `TMA`, ...), even bytes = short `TNT`, odd bytes with
//!   bit1 set = `CYC`, remaining odd bytes = `TIP`/`TIP.PGE`/`TIP.PGD`/
//!   `FUP`/`TSC`/`MTC`/`MODE` families. On top of the reference the decoder
//!   reconstructs full IPs with last-IP state, which the kernel leaves to
//!   its upper layer.
//! - [`PtSession`] — userspace session/buffer management (AUX ring buffer
//!   bookkeeping, packet counters). Actually programming the CPU still
//!   requires `perf_event_open(2)` with privileges on a Linux host;
//!   [`session_create`] validates the request against the probed
//!   capabilities and returns a precise error instead of a fake success.

#![allow(missing_docs)]
#![forbid(unsafe_code)]

use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap as FxHashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════════════
// CAPABILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of probing the host for Intel PT support.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct PtCapabilities {
    /// Whether hardware tracing can be started on this host.
    pub available: bool,
    /// Machine-readable reason code (`ok`, `non_linux`, `no_sysfs`,
    /// `perf_paranoid`, ...).
    pub reason: String,
    /// Human-readable explanation.
    pub detail: String,
    /// Value of `/proc/sys/kernel/perf_event_paranoid`, when readable.
    pub perf_paranoid: Option<i64>,
    /// CPU flags containing `intel_pt`-style tokens, when readable.
    pub cpu_flags_hint: Option<String>,
}

impl PtCapabilities {
    /// Probe the host for Intel PT support without requiring privileges.
    #[must_use]
    pub fn probe() -> Self {
        #[cfg(not(target_os = "linux"))]
        {
            return Self {
                available: false,
                reason: "non_linux".to_string(),
                detail: "Intel PT tracing requires Linux perf_event_open or a \
                         custom kernel driver. Standard Windows/macOS kernels \
                         do not expose the PT MSRs to userspace."
                    .to_string(),
                perf_paranoid: None,
                cpu_flags_hint: None,
            };
        }

        #[cfg(target_os = "linux")]
        {
            Self::probe_linux()
        }
    }

    #[cfg(target_os = "linux")]
    fn probe_linux() -> Self {
        // 1. sysfs PMU must exist.
        let pmu = std::path::Path::new("/sys/bus/event_source/devices/intel_pt");
        if !pmu.exists() {
            return Self {
                available: false,
                reason: "no_sysfs".to_string(),
                detail: "No intel_pt PMU at \
                         /sys/bus/event_source/devices/intel_pt: CPU or kernel \
                         does not expose Intel Processor Trace."
                    .to_string(),
                perf_paranoid: read_perf_paranoid(),
                cpu_flags_hint: cpu_flags_hint(),
            };
        }

        // 2. perf_event_paranoid gate.
        let paranoid = read_perf_paranoid();
        if paranoid.is_some_and(|v| v > 1) {
            return Self {
                available: false,
                reason: "perf_paranoid".to_string(),
                detail: format!(
                    "perf_event_paranoid is {} (>1); unprivileged perf tracing \
                     is restricted. Lower it or run with CAP_SYS_ADMIN.",
                    paranoid.unwrap_or(-1)
                ),
                perf_paranoid: paranoid,
                cpu_flags_hint: cpu_flags_hint(),
            };
        }

        Self {
            available: true,
            reason: "ok".to_string(),
            detail: "intel_pt PMU present and perf_event_paranoid permits \
                     tracing. Starting a session still requires privileges \
                     and a configured AUX buffer; see PtSession."
                .to_string(),
            perf_paranoid: paranoid,
            cpu_flags_hint: cpu_flags_hint(),
        }
    }
}

#[cfg(target_os = "linux")]
fn read_perf_paranoid() -> Option<i64> {
    std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn cpu_flags_hint() -> Option<String> {
    let info = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in info.lines() {
        if line.starts_with("flags") {
            if line.contains("intel_pt") {
                return Some("intel_pt".to_string());
            }
            return Some("no_intel_pt_flag".to_string());
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
// PACKETS (dispatch mirrors intel-pt-pkt-decoder.c)
// ═══════════════════════════════════════════════════════════════════════════════

/// Target-IP packet flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
pub enum TipKind {
    /// Indirect branch target.
    Tip,
    /// Packet generation disabled (async branch out of the traced context).
    TipPgd,
    /// Packet generation enabled (async entry into the traced context).
    TipPge,
    /// Flow update (async branch source address).
    Fup,
}

/// A decoded Intel PT packet.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub enum PtPacket {
    /// `0x00` padding.
    Pad,
    /// Short TNT: even byte (`!= 0x00, 0x02`). Outcomes oldest-first;
    /// `true` = branch taken.
    Tnt {
        /// One entry per conditional branch, oldest first.
        taken: Vec<bool>,
    },
    /// Long TNT: `02 A3` + 6 bytes. Outcomes oldest-first.
    LongTnt {
        /// One entry per conditional branch, oldest first.
        taken: Vec<bool>,
    },
    /// Target IP packet with last-IP reconstruction applied.
    Tip {
        /// Full IP after last-IP update (`last_ip` when no payload).
        ip: u64,
        /// Packet flavour.
        kind: TipKind,
        /// Raw IP payload bytes carried on the wire (0, 2, 4, 6 or 8).
        payload_len: usize,
    },
    /// Timestamp counter: `0x19` + 7 bytes LE.
    Tsc {
        /// Raw 56-bit TSC value.
        value: u64,
    },
    /// TSC/MTC alignment: `02 73` + CTC (u16) + FC (9 bit).
    Tma {
        /// Cycle-time counter.
        ctc: u16,
        /// Fast counter.
        fc: u16,
    },
    /// Mode.Exec: `0x99` + mode byte (CSD 16/32/64, IFLAG in raw).
    ModeExec {
        /// Core:bus... actually code-segment descriptor: 16, 32 or 64.
        csd: u8,
        /// Raw mode byte (bit 2 = IFLAG on newer SDM).
        raw: u8,
    },
    /// Mode.TSX: `0x99` + mode byte.
    ModeTsx {
        /// Raw TSX mode bits.
        flags: u8,
    },
    /// Mini timestamp counter: `0x59` + 1 byte.
    Mtc {
        /// 8-bit MTC value.
        value: u8,
    },
    /// Cycle count: odd byte with bit1 set, plus extension bytes.
    Cyc {
        /// Cycle count value.
        value: u64,
    },
    /// Core:bus ratio: `02 03` + u16 LE.
    Cbr {
        /// Core-to-bus ratio.
        ratio: u16,
    },
    /// Packet Stream Boundary: sixteen bytes `02 82` × 8. Resync point.
    Psb,
    /// `02 23` — end of PSB+ header block.
    PsbEnd,
    /// `02 83` — tracing stopped by hardware.
    TraceStop,
    /// `02 F3` — trace overflow; packets were dropped.
    Overflow,
    /// Paging info: `02 43` + 6 bytes (CR3 + NR flag in bit 63).
    Pip {
        /// CR3 value (bit 63 masked off into `nr`).
        cr3: u64,
        /// Non-root (VMX) flag.
        nr: bool,
    },
    /// VMCS: `02 C8` + 5 bytes.
    Vmcs {
        /// Raw 40-bit payload.
        payload: u64,
    },
    /// Maintenance: `02 C3 88` + 8 bytes.
    Mnt {
        /// Raw 64-bit payload.
        payload: u64,
    },
    /// PTWRITE: extended opcode with low 5 bits `10010`; 4- or 8-byte payload.
    Ptwrite {
        /// Written value.
        payload: u64,
        /// Whether packet carries the IP (`FUP` follows when true).
        ip: bool,
    },
    /// Execution stop: `02 62` (no IP) / `02 E2` (with IP).
    Exstop {
        /// Whether an IP payload follows.
        ip: bool,
    },
    /// Monitor wait: `02 C2` + 8 bytes.
    Mwait {
        /// Raw 64-bit payload (hints + extensions).
        payload: u64,
    },
    /// Power entry: `02 22` + 2 bytes.
    Pwre {
        /// Raw 16-bit payload.
        payload: u16,
    },
    /// Power exit: `02 A2` + 5 bytes.
    Pwrx {
        /// Raw 40-bit payload.
        payload: u64,
    },
    /// Block begin: `02 63` + 1 byte.
    Bbp {
        /// Whether subsequent blocks use 4-byte (`true`) or 8-byte BIP.
        is_4byte: bool,
        /// Block type.
        kind: u8,
    },
    /// Block end: `02 33` (no IP) / `02 B3` (with IP).
    Bep {
        /// Whether an IP payload follows.
        ip: bool,
    },
    /// Control-flow event: `02 13` + type/vector bytes.
    Cfe {
        /// Whether an IP payload follows.
        ip: bool,
        /// Event type.
        kind: u8,
        /// Event vector.
        vector: u8,
    },
    /// Event data: `02 53` + type + 8-byte payload.
    Evd {
        /// Event type.
        kind: u8,
        /// Event payload.
        payload: u64,
    },
    /// Unrecognised or truncated bytes, preserved losslessly.
    Bad {
        /// Raw bytes consumed for this entry.
        raw: Vec<u8>,
    },
}

const PSB_LEN: usize = 16;

/// Streaming Intel PT packet decoder with last-IP reconstruction.
#[derive(Debug, Default)]
pub struct PtDecoder {
    last_ip: u64,
    packets: u64,
    resyncs: u64,
}

impl PtDecoder {
    /// Create a fresh decoder (last-IP starts at zero).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of packets decoded so far.
    #[must_use]
    pub const fn packets_decoded(&self) -> u64 {
        self.packets
    }

    /// Number of `PSB` resynchronisations observed.
    #[must_use]
    pub const fn resyncs(&self) -> u64 {
        self.resyncs
    }

    /// Decode a complete AUX buffer, returning packets in order.
    /// Truncated tails are returned as [`PtPacket::Bad`] instead of being
    /// silently dropped.
    pub fn decode(&mut self, mut data: &[u8]) -> Vec<PtPacket> {
        let mut out = Vec::new();
        while !data.is_empty() {
            let (packet, consumed) = self.decode_one(data);
            out.push(packet);
            self.packets += 1;
            if consumed == 0 {
                break;
            }
            data = &data[consumed.min(data.len())..];
        }
        out
    }

    fn bad(data: &[u8], len: usize) -> (PtPacket, usize) {
        let n = len.min(data.len());
        (
            PtPacket::Bad {
                raw: data[..n].to_vec(),
            },
            n,
        )
    }

    fn need(data: &[u8], need: usize) -> bool {
        data.len() < need
    }

    fn decode_one(&mut self, data: &[u8]) -> (PtPacket, usize) {
        let b0 = data[0];

        // PAD.
        if b0 == 0x00 {
            return (PtPacket::Pad, 1);
        }
        // Extended opcode.
        if b0 == 0x02 {
            return self.decode_ext(data);
        }
        // Short TNT: even bytes.
        if b0 & 0x01 == 0 {
            return (decode_short_tnt(b0), 1);
        }
        // Odd bytes with bit1 set: CYC (possibly multi-byte).
        if b0 & 0x02 != 0 {
            return decode_cyc(data);
        }
        // Remaining odd bytes: TIP / TSC / MTC / MODE families.
        match b0 & 0x1F {
            0x0D => self.decode_tip(data, b0, TipKind::Tip),
            0x11 => self.decode_tip(data, b0, TipKind::TipPge),
            0x01 => self.decode_tip(data, b0, TipKind::TipPgd),
            0x1D => self.decode_tip(data, b0, TipKind::Fup),
            0x19 => match b0 {
                0x19 => {
                    if Self::need(data, 8) {
                        return Self::bad(data, data.len());
                    }
                    let mut v: u64 = 0;
                    for (i, b) in data[1..8].iter().enumerate() {
                        v |= u64::from(*b) << (8 * i);
                    }
                    (PtPacket::Tsc { value: v }, 8)
                }
                0x59 => {
                    if Self::need(data, 2) {
                        return Self::bad(data, data.len());
                    }
                    (PtPacket::Mtc { value: data[1] }, 2)
                }
                0x99 => {
                    if Self::need(data, 2) {
                        return Self::bad(data, data.len());
                    }
                    let mode = data[1];
                    match mode >> 5 {
                        0 => {
                            let csd = match mode & 3 {
                                0 => 16,
                                1 => 64,
                                2 => 32,
                                _ => return Self::bad(data, 2),
                            };
                            (PtPacket::ModeExec { csd, raw: mode }, 2)
                        }
                        1 => {
                            if mode & 3 == 3 {
                                return Self::bad(data, 2);
                            }
                            (PtPacket::ModeTsx { flags: mode & 3 }, 2)
                        }
                        _ => Self::bad(data, 2),
                    }
                }
                _ => Self::bad(data, 1),
            },
            _ => Self::bad(data, 1),
        }
    }

    fn decode_ext(&mut self, data: &[u8]) -> (PtPacket, usize) {
        if Self::need(data, 2) {
            return Self::bad(data, data.len());
        }
        let b1 = data[1];

        // PTWRITE emery: low 5 bits 10010.
        if b1 & 0x1F == 0x12 {
            let count = (b1 >> 5) & 0x03;
            let ip = b1 & 0x80 != 0;
            match count {
                0 => {
                    if Self::need(data, 6) {
                        return Self::bad(data, data.len());
                    }
                    return (
                        PtPacket::Ptwrite {
                            payload: u64::from(u32::from_le_bytes(
                                data[2..6].try_into().unwrap_or([0; 4]),
                            )),
                            ip,
                        },
                        6,
                    );
                }
                1 => {
                    if Self::need(data, 10) {
                        return Self::bad(data, data.len());
                    }
                    return (
                        PtPacket::Ptwrite {
                            payload: u64::from_le_bytes(data[2..10].try_into().unwrap_or([0; 8])),
                            ip,
                        },
                        10,
                    );
                }
                _ => return Self::bad(data, 2),
            }
        }

        match b1 {
            0xA3 => {
                // Long TNT: 8 bytes incl. header.
                if Self::need(data, 8) {
                    return Self::bad(data, data.len());
                }
                (decode_long_tnt(data), 8)
            }
            0x43 => {
                if Self::need(data, 8) {
                    return Self::bad(data, data.len());
                }
                let mut payload: u64 = 0;
                for (i, b) in data[2..8].iter().enumerate() {
                    payload |= u64::from(*b) << (8 * i);
                }
                (
                    PtPacket::Pip {
                        cr3: payload & !(1 << 63),
                        nr: payload & (1 << 63) != 0,
                    },
                    8,
                )
            }
            0x83 => (PtPacket::TraceStop, 2),
            0x03 => {
                if Self::need(data, 4) {
                    return Self::bad(data, data.len());
                }
                (
                    PtPacket::Cbr {
                        ratio: u16::from_le_bytes([data[2], data[3]]),
                    },
                    4,
                )
            }
            0xC8 => {
                if Self::need(data, 7) {
                    return Self::bad(data, data.len());
                }
                let mut payload: u64 = 0;
                for (i, b) in data[2..7].iter().enumerate() {
                    payload |= u64::from(*b) << (8 * i);
                }
                (PtPacket::Vmcs { payload }, 7)
            }
            0xF3 => (PtPacket::Overflow, 2),
            0x82 => {
                if Self::need(data, PSB_LEN) {
                    return Self::bad(data, data.len());
                }
                if !is_psb(&data[..PSB_LEN]) {
                    return Self::bad(data, 2);
                }
                self.resyncs += 1;
                (PtPacket::Psb, PSB_LEN)
            }
            0x23 => (PtPacket::PsbEnd, 2),
            0x73 => {
                if Self::need(data, 7) {
                    return Self::bad(data, data.len());
                }
                (
                    PtPacket::Tma {
                        ctc: u16::from_le_bytes([data[2], data[3]]),
                        fc: u16::from(data[5]) | (u16::from(data[6] & 0x01) << 8),
                    },
                    7,
                )
            }
            0xC3 => {
                if Self::need(data, 3) {
                    return Self::bad(data, data.len());
                }
                if data[2] != 0x88 {
                    return Self::bad(data, 3);
                }
                if Self::need(data, 11) {
                    return Self::bad(data, data.len());
                }
                (
                    PtPacket::Mnt {
                        payload: u64::from_le_bytes(data[3..11].try_into().unwrap_or([0; 8])),
                    },
                    11,
                )
            }
            0x62 => (PtPacket::Exstop { ip: false }, 2),
            0xE2 => (PtPacket::Exstop { ip: true }, 2),
            0xC2 => {
                if Self::need(data, 10) {
                    return Self::bad(data, data.len());
                }
                (
                    PtPacket::Mwait {
                        payload: u64::from_le_bytes(data[2..10].try_into().unwrap_or([0; 8])),
                    },
                    10,
                )
            }
            0x22 => {
                if Self::need(data, 4) {
                    return Self::bad(data, data.len());
                }
                (
                    PtPacket::Pwre {
                        payload: u16::from_le_bytes([data[2], data[3]]),
                    },
                    4,
                )
            }
            0xA2 => {
                if Self::need(data, 7) {
                    return Self::bad(data, data.len());
                }
                let mut payload: u64 = 0;
                for (i, b) in data[2..7].iter().enumerate() {
                    payload |= u64::from(*b) << (8 * i);
                }
                (PtPacket::Pwrx { payload }, 7)
            }
            0x63 => {
                if Self::need(data, 3) {
                    return Self::bad(data, data.len());
                }
                (
                    PtPacket::Bbp {
                        is_4byte: data[2] >> 7 != 0,
                        kind: data[2] & 0x1F,
                    },
                    3,
                )
            }
            0x33 => (PtPacket::Bep { ip: false }, 2),
            0xB3 => (PtPacket::Bep { ip: true }, 2),
            0x13 => {
                if Self::need(data, 4) {
                    return Self::bad(data, data.len());
                }
                (
                    PtPacket::Cfe {
                        ip: data[2] & 0x80 != 0,
                        kind: data[2] & 0x1F,
                        vector: data[3],
                    },
                    4,
                )
            }
            0x53 => {
                if Self::need(data, 11) {
                    return Self::bad(data, data.len());
                }
                (
                    PtPacket::Evd {
                        kind: data[2] & 0x3F,
                        payload: u64::from_le_bytes(data[3..11].try_into().unwrap_or([0; 8])),
                    },
                    11,
                )
            }
            _ => Self::bad(data, 2),
        }
    }

    fn decode_tip(&mut self, data: &[u8], b0: u8, kind: TipKind) -> (PtPacket, usize) {
        // IPBytes in bits 7:5; counts 5 and 7 are invalid (kernel get_ip).
        let payload_len = match b0 >> 5 {
            0 => 0,
            1 => 2,
            2 => 4,
            3 | 4 => 6,
            6 => 8,
            _ => return Self::bad(data, 1),
        };
        if Self::need(data, 1 + payload_len) {
            return Self::bad(data, data.len());
        }
        let mut part: u64 = 0;
        for (i, b) in data[1..1 + payload_len].iter().enumerate() {
            part |= u64::from(*b) << (8 * i);
        }
        // IP compression: payload replaces the low bytes of last-IP.
        let full_ip = if payload_len == 0 {
            self.last_ip
        } else if payload_len >= 8 {
            part
        } else {
            let mask = u64::MAX << (payload_len * 8);
            (self.last_ip & mask) | part
        };
        self.last_ip = full_ip;
        (
            PtPacket::Tip {
                ip: full_ip,
                kind,
                payload_len,
            },
            1 + payload_len,
        )
    }
}

/// Decode a short-TNT byte (even, not `0x00`/`0x02`).
///
/// Wire format: bit 0 is the even tag; the highest set bit is the stop
/// marker; the bits below it (up to 6) are branch outcomes, oldest first.
/// A byte with bit 7 set carries a full 6-outcome payload in bits 6:1.
fn decode_short_tnt(byte: u8) -> PtPacket {
    let msb = 7 - byte.leading_zeros() as usize; // highest set bit (byte != 0)
    let top = msb.saturating_sub(1); // stop marker excluded... see below
    // Outcomes are the bits strictly below the stop marker, down to bit 1.
    let count = top.min(6);
    let mut taken = Vec::with_capacity(count);
    for i in 0..count {
        let bit = msb - 1 - i;
        taken.push(byte & (1 << bit) != 0);
    }
    PtPacket::Tnt { taken }
}

/// Decode a long-TNT packet (`02 A3` + 6 bytes), mirroring
/// `intel_pt_get_long_tnt`: the 8 LE bytes (header included) are scanned
/// for the stop bit from the top; outcomes are the following bits.
fn decode_long_tnt(data: &[u8]) -> PtPacket {
    let mut payload = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
    let mut count: usize = 47;
    while count > 0 && payload & (1 << 63) == 0 {
        payload <<= 1;
        count -= 1;
    }
    payload <<= 1; // drop the stop bit
    let mut taken = Vec::with_capacity(count);
    for i in 0..count {
        taken.push(payload & (1 << (63 - i)) != 0);
    }
    PtPacket::LongTnt { taken }
}

/// Decode a CYC packet: odd first byte with bit1 set, value seeded from
/// bits 7:3, extended while bit0 of each following byte is set.
fn decode_cyc(data: &[u8]) -> (PtPacket, usize) {
    let mut value: u64 = u64::from(data[0] >> 3);
    let mut byte = data[0] >> 2;
    let mut offs = 1usize;
    let mut shift = 5u32;
    while byte & 0x01 != 0 {
        if offs > 9 || data.len() <= offs {
            return PtDecoder::bad(data, data.len());
        }
        byte = data[offs];
        offs += 1;
        value |= u64::from(byte >> 1) << shift;
        shift += 7;
    }
    (PtPacket::Cyc { value }, offs)
}

fn is_psb(block: &[u8]) -> bool {
    if block.len() < PSB_LEN {
        return false;
    }
    block[0] == 0x02 && block[1] == 0x82 && block.chunks_exact(2).all(|c| c == [0x02, 0x82])
}

/// Encode branch outcomes (oldest first, 1–6 entries) into one short-TNT
/// byte. Returns `None` for empty or over-long inputs. This is the exact
/// inverse of [`decode_short_tnt`].
#[must_use]
pub fn encode_short_tnt(taken: &[bool]) -> Option<u8> {
    if taken.is_empty() || taken.len() > 6 {
        return None;
    }
    let mut bits: u8 = 0;
    for t in taken {
        bits = (bits << 1) | u8::from(*t);
    }
    if taken.len() == 6 {
        Some(0x80 | (bits << 1))
    } else {
        let len = taken.len() as u32;
        Some((bits << 1) | (1 << (len + 1)))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SESSIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Tracing session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
pub enum SessionState {
    /// Configured but the CPU has not been programmed yet.
    Configured,
    /// Actively collecting into the AUX buffer.
    Running,
    /// Stopped; buffered packets are available for decode.
    Stopped,
}

/// A userspace Intel PT session: validated configuration plus an AUX
/// byte buffer. Hardware programming requires Linux + privileges; the
/// session API validates everything it can in userspace first.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct PtSession {
    /// Session id.
    pub id: u64,
    /// Target pid (`None` = whole-system, requires extra privilege).
    pub pid: Option<u32>,
    /// AUX buffer size in bytes (must be a power of two ≥ 4 KiB).
    pub aux_size: usize,
    /// Bytes currently staged in the AUX buffer.
    pub aux_used: usize,
    /// Current state.
    pub state: SessionState,
    /// Milliseconds since epoch when the session was created.
    pub created_ms: u64,
    /// Packets decoded from this session so far.
    pub packets_decoded: u64,
    /// PSB resyncs observed.
    pub resyncs: u64,
}

/// Errors when configuring or starting a session.
#[derive(Debug, Clone, ToJson, FromJson)]
pub enum SessionError {
    /// Host cannot do Intel PT (reason code + detail).
    Unavailable {
        /// Machine-readable reason (see [`PtCapabilities::reason`]).
        reason: String,
        /// Human-readable detail.
        detail: String,
    },
    /// Bad AUX configuration.
    BadAuxSize(usize),
    /// Unknown session id.
    UnknownSession(u64),
    /// Wrong state for the requested operation.
    BadState(u64, SessionState, SessionState),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { reason, detail } => {
                write!(f, "intel-pt unavailable ({reason}): {detail}")
            }
            Self::BadAuxSize(size) => {
                write!(f, "invalid aux_size {size}: must be a power of two >= 4096")
            }
            Self::UnknownSession(id) => write!(f, "unknown session {id}"),
            Self::BadState(id, got, expected) => {
                write!(f, "session {id} is {got:?}, expected {expected:?}")
            }
        }
    }
}

impl std::error::Error for SessionError {}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn validate_aux_size(aux_size: usize) -> Result<(), SessionError> {
    if aux_size < 4096 || !aux_size.is_power_of_two() {
        return Err(SessionError::BadAuxSize(aux_size));
    }
    Ok(())
}

static SESSIONS: std::sync::LazyLock<Mutex<FxHashMap<u64, (PtSession, Vec<u8>)>>> =
    std::sync::LazyLock::new(|| Mutex::new(FxHashMap::default()));
static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Create a session after validating AUX size and host capabilities.
/// Fails with [`SessionError::Unavailable`] on hosts without Intel PT
/// instead of pretending tracing works.
pub fn session_create(pid: Option<u32>, aux_size: usize) -> Result<PtSession, SessionError> {
    validate_aux_size(aux_size)?;
    let caps = PtCapabilities::probe();
    if !caps.available {
        return Err(SessionError::Unavailable {
            reason: caps.reason,
            detail: caps.detail,
        });
    }
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let session = PtSession {
        id,
        pid,
        aux_size,
        aux_used: 0,
        state: SessionState::Configured,
        created_ms: now_ms(),
        packets_decoded: 0,
        resyncs: 0,
    };
    SESSIONS
        .lock()
        .map_err(|_| SessionError::UnknownSession(id))?
        .insert(id, (session.clone(), vec![0u8; aux_size]));
    Ok(session)
}

/// Mark a configured session running (userspace bookkeeping; the caller is
/// responsible for the privileged `perf_event_open` ioctl sequence, whose
/// parameters can be derived from [`PtSession`]).
pub fn session_mark_running(id: u64) -> Result<PtSession, SessionError> {
    let mut lock = SESSIONS
        .lock()
        .map_err(|_| SessionError::UnknownSession(id))?;
    let (session, _) = lock.get_mut(&id).ok_or(SessionError::UnknownSession(id))?;
    if session.state != SessionState::Configured {
        return Err(SessionError::BadState(
            id,
            session.state,
            SessionState::Configured,
        ));
    }
    session.state = SessionState::Running;
    Ok(session.clone())
}

/// Ingest AUX bytes into a running session's buffer (wraps like a ring).
pub fn session_ingest(id: u64, bytes: &[u8]) -> Result<usize, SessionError> {
    let mut lock = SESSIONS
        .lock()
        .map_err(|_| SessionError::UnknownSession(id))?;
    let (session, buf) = lock.get_mut(&id).ok_or(SessionError::UnknownSession(id))?;
    if session.state != SessionState::Running {
        return Err(SessionError::BadState(
            id,
            session.state,
            SessionState::Running,
        ));
    }
    let mut written = 0;
    for b in bytes {
        buf[session.aux_used % session.aux_size] = *b;
        session.aux_used = session.aux_used.saturating_add(1);
        written += 1;
        if written >= session.aux_size {
            break;
        }
    }
    Ok(written)
}

/// Stop a session and decode the staged AUX bytes.
pub fn session_stop(id: u64) -> Result<(PtSession, Vec<PtPacket>), SessionError> {
    let mut lock = SESSIONS
        .lock()
        .map_err(|_| SessionError::UnknownSession(id))?;
    let (session, buf) = lock.remove(&id).ok_or(SessionError::UnknownSession(id))?;
    if session.state != SessionState::Running && session.state != SessionState::Configured {
        return Err(SessionError::BadState(
            id,
            session.state,
            SessionState::Running,
        ));
    }
    let staged = session.aux_used.min(session.aux_size);
    let bytes = buf[..staged].to_vec();
    let mut decoder = PtDecoder::new();
    let packets = decoder.decode(&bytes);
    let mut finished = session;
    finished.state = SessionState::Stopped;
    finished.packets_decoded = decoder.packets_decoded();
    finished.resyncs = decoder.resyncs();
    Ok((finished, packets))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Packet description helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Short text description of a decoded [`PtPacket`]: `(kind, detail)`.
/// Kept public for reuse by future ports and tests.
pub fn packet_kind(packet: &PtPacket) -> (&'static str, String) {
    match packet {
        PtPacket::Pad => ("pad", String::new()),
        PtPacket::Tnt { taken } => (
            "tnt",
            taken.iter().map(|t| if *t { 'T' } else { 'N' }).collect(),
        ),
        PtPacket::LongTnt { taken } => (
            "tnt_long",
            taken.iter().map(|t| if *t { 'T' } else { 'N' }).collect(),
        ),
        PtPacket::Tip {
            ip,
            kind,
            payload_len,
        } => (
            match kind {
                TipKind::Tip => "tip",
                TipKind::TipPgd => "tip_pgd",
                TipKind::TipPge => "tip_pge",
                TipKind::Fup => "fup",
            },
            format!("ip=0x{ip:016x} payload_len={payload_len}"),
        ),
        PtPacket::Tsc { value } => ("tsc", format!("0x{value:x}")),
        PtPacket::Tma { ctc, fc } => ("tma", format!("ctc=0x{ctc:x} fc=0x{fc:x}")),
        PtPacket::ModeExec { csd, raw } => ("mode_exec", format!("csd={csd} raw=0x{raw:02x}")),
        PtPacket::ModeTsx { flags } => ("mode_tsx", format!("0x{flags:02x}")),
        PtPacket::Mtc { value } => ("mtc", format!("0x{value:02x}")),
        PtPacket::Cyc { value } => ("cyc", format!("0x{value:x}")),
        PtPacket::Cbr { ratio } => ("cbr", format!("0x{ratio:x}")),
        PtPacket::Psb => ("psb", String::new()),
        PtPacket::PsbEnd => ("psbend", String::new()),
        PtPacket::TraceStop => ("tracestop", String::new()),
        PtPacket::Overflow => ("overflow", String::new()),
        PtPacket::Pip { cr3, nr } => ("pip", format!("cr3=0x{cr3:x} nr={nr}")),
        PtPacket::Vmcs { payload } => ("vmcs", format!("0x{payload:x}")),
        PtPacket::Mnt { payload } => ("mnt", format!("0x{payload:x}")),
        PtPacket::Ptwrite { payload, ip } => ("ptwrite", format!("0x{payload:x} ip={ip}")),
        PtPacket::Exstop { ip } => ("exstop", format!("ip={ip}")),
        PtPacket::Mwait { payload } => ("mwait", format!("0x{payload:x}")),
        PtPacket::Pwre { payload } => ("pwre", format!("0x{payload:x}")),
        PtPacket::Pwrx { payload } => ("pwrx", format!("0x{payload:x}")),
        PtPacket::Bbp { is_4byte, kind } => (
            "bbp",
            format!("size={} kind=0x{kind:02x}", if *is_4byte { 4 } else { 8 }),
        ),
        PtPacket::Bep { ip } => ("bep", format!("ip={ip}")),
        PtPacket::Cfe { ip, kind, vector } => (
            "cfe",
            format!("ip={ip} kind=0x{kind:02x} vector=0x{vector:02x}"),
        ),
        PtPacket::Evd { kind, payload } => {
            ("evd", format!("kind=0x{kind:02x} payload=0x{payload:x}"))
        }
        PtPacket::Bad { raw } => (
            "bad",
            raw.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(""),
        ),
    }
}

// Former NIF entry points (`pt_capabilities`, `pt_decode_packets`,
// `start_pt_trace`) were thin wrappers over `PtCapabilities::probe`,
// `PtDecoder::decode`, `packet_kind` and the session API above — call
// those directly instead. (Removed with the Rustler dependency.)

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS (vectors mirror the kernel pkt-decoder self-test)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_one(bytes: &[u8]) -> (Vec<PtPacket>, usize) {
        let mut d = PtDecoder::new();
        let packets = d.decode(bytes);
        let consumed: usize = packets.len(); // 1:1 here: each vector is 1 packet
        (packets, consumed)
    }

    #[test]
    fn pad_psb_psbend_tracestop_ovf() {
        let mut d = PtDecoder::new();
        let mut buf = vec![0x00];
        buf.extend([0x02, 0x82].iter().cycle().take(PSB_LEN).copied());
        buf.extend([0x02, 0x23, 0x02, 0x83, 0x02, 0xF3]);
        let packets = d.decode(&buf);
        assert_eq!(
            packets,
            vec![
                PtPacket::Pad,
                PtPacket::Psb,
                PtPacket::PsbEnd,
                PtPacket::TraceStop,
                PtPacket::Overflow,
            ]
        );
        assert_eq!(d.resyncs(), 1);
    }

    #[test]
    fn short_tnt_kernel_vectors() {
        // From the kernel self-test: {0x06} -> 1 TNT, {0x80} -> 6xN, {0xFE} -> 6xT.
        let (p, _) = decode_one(&[0x06]);
        assert_eq!(
            p,
            vec![PtPacket::Tnt { taken: vec![true] }],
            "0x06 is a single taken branch"
        );
        let (p, _) = decode_one(&[0x80]);
        assert_eq!(
            p,
            vec![PtPacket::Tnt {
                taken: vec![false; 6]
            }]
        );
        let (p, _) = decode_one(&[0xFE]);
        assert_eq!(
            p,
            vec![PtPacket::Tnt {
                taken: vec![true; 6]
            }]
        );
    }

    #[test]
    fn short_tnt_roundtrip() {
        let cases = [
            vec![false],
            vec![true],
            vec![true, false],
            vec![false, true, true],
            vec![true, false, true, false, true],
            vec![true, true, true, true, true, true],
            vec![false, false, false, false, false, false],
        ];
        for case in cases {
            let b = encode_short_tnt(&case).expect("encodable");
            assert_eq!(b & 0x01, 0, "short TNT is an even byte");
            let (p, _) = decode_one(&[b]);
            assert_eq!(p, vec![PtPacket::Tnt { taken: case }]);
        }
        assert_eq!(encode_short_tnt(&[]), None);
        assert_eq!(encode_short_tnt(&[true; 7]), None);
    }

    #[test]
    fn long_tnt_kernel_vector() {
        // {02 A3 02 ...} -> 1 TNT outcome, the low header bit pattern.
        let (p, _) = decode_one(&[0x02, 0xA3, 0x02, 0, 0, 0, 0, 0]);
        assert_eq!(p.len(), 1);
        match &p[0] {
            PtPacket::LongTnt { taken } => assert_eq!(taken.len(), 1),
            other => panic!("expected long TNT, got {other:?}"),
        }
    }

    #[test]
    fn tip_family_kernel_vectors() {
        // TIP with no IP.
        let (p, _) = decode_one(&[0x0D]);
        assert_eq!(
            p,
            vec![PtPacket::Tip {
                ip: 0,
                kind: TipKind::Tip,
                payload_len: 0
            }]
        );
        // TIP with 2/4/6/8 payload bytes.
        let (p, _) = decode_one(&[0x2D, 0x01, 0x02]);
        assert!(matches!(&p[0], PtPacket::Tip { ip: 0x0201, .. }));
        let (p, _) = decode_one(&[0x4D, 0x01, 0x02, 0x03, 0x04]);
        assert!(matches!(
            &p[0],
            PtPacket::Tip {
                ip: 0x0403_0201,
                ..
            }
        ));
        let (p, _) = decode_one(&[0x6D, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert!(matches!(
            &p[0],
            PtPacket::Tip {
                ip: 0x0605_0403_0201,
                ..
            }
        ));
        let (p, _) = decode_one(&[0xCD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert!(matches!(
            &p[0],
            PtPacket::Tip {
                ip: 0x0807_0605_0403_0201,
                ..
            }
        ));
        // PGE / PGD / FUP flavours.
        let (p, _) = decode_one(&[0x11]);
        assert!(matches!(
            &p[0],
            PtPacket::Tip {
                kind: TipKind::TipPge,
                ..
            }
        ));
        let (p, _) = decode_one(&[0x31, 0x01, 0x02]);
        assert!(matches!(
            &p[0],
            PtPacket::Tip {
                kind: TipKind::TipPge,
                ip: 0x0201,
                ..
            }
        ));
        let (p, _) = decode_one(&[0x01]);
        assert!(matches!(
            &p[0],
            PtPacket::Tip {
                kind: TipKind::TipPgd,
                ..
            }
        ));
        let (p, _) = decode_one(&[0x1D]);
        assert!(matches!(
            &p[0],
            PtPacket::Tip {
                kind: TipKind::Fup,
                ..
            }
        ));
        // Invalid IPBytes counts 5 and 7 are rejected, not misdecoded.
        let (p, _) = decode_one(&[0xAD]);
        assert!(matches!(&p[0], PtPacket::Bad { .. }));
    }

    #[test]
    fn tip_last_ip_reconstruction() {
        let mut d = PtDecoder::new();
        let full_ip: u64 = 0x7FFF_1234_5678;
        let mut buf = vec![0xCD]; // TIP, 8 payload bytes (count 6)
        buf.extend(full_ip.to_le_bytes());
        buf.extend([0x2D, 0x9A, 0xBC]); // TIP, low 2 bytes replaced
        let packets = d.decode(&buf);
        assert_eq!(packets.len(), 2);
        assert_eq!(
            packets[0],
            PtPacket::Tip {
                ip: full_ip,
                kind: TipKind::Tip,
                payload_len: 8
            }
        );
        let expected = (full_ip & 0xFFFF_FFFF_FFFF_0000) | 0xBC9A;
        assert_eq!(
            packets[1],
            PtPacket::Tip {
                ip: expected,
                kind: TipKind::Tip,
                payload_len: 2
            }
        );
    }

    #[test]
    fn timing_packets_kernel_vectors() {
        let (p, _) = decode_one(&[0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(
            p,
            vec![PtPacket::Tsc {
                value: 0x0706_0504_0302_01
            }]
        );
        let (p, _) = decode_one(&[0x59, 0x12]);
        assert_eq!(p, vec![PtPacket::Mtc { value: 0x12 }]);
        let (p, _) = decode_one(&[0x02, 0x73, 0x01, 0x02, 0x00, 0x00, 0x00]);
        assert_eq!(p, vec![PtPacket::Tma { ctc: 0x0201, fc: 0 }]);
        let (p, _) = decode_one(&[0x02, 0x03, 0x12, 0x00]);
        assert_eq!(p, vec![PtPacket::Cbr { ratio: 0x12 }]);
    }

    #[test]
    fn mode_packets_kernel_vectors() {
        let (p, _) = decode_one(&[0x99, 0x00]);
        assert_eq!(p, vec![PtPacket::ModeExec { csd: 16, raw: 0x00 }]);
        let (p, _) = decode_one(&[0x99, 0x01]);
        assert_eq!(p, vec![PtPacket::ModeExec { csd: 64, raw: 0x01 }]);
        let (p, _) = decode_one(&[0x99, 0x02]);
        assert_eq!(p, vec![PtPacket::ModeExec { csd: 32, raw: 0x02 }]);
        let (p, _) = decode_one(&[0x99, 0x20]);
        assert_eq!(p, vec![PtPacket::ModeTsx { flags: 0 }]);
    }

    #[test]
    fn cyc_kernel_vectors() {
        let (p, _) = decode_one(&[0x03]);
        assert_eq!(p, vec![PtPacket::Cyc { value: 0 }]);
        let (p, _) = decode_one(&[0x0B]);
        assert_eq!(p, vec![PtPacket::Cyc { value: 1 }]);
        let (p, _) = decode_one(&[0xFB]);
        assert_eq!(p, vec![PtPacket::Cyc { value: 0x1F }]);
        let (p, _) = decode_one(&[0x07, 0x02]);
        assert_eq!(p, vec![PtPacket::Cyc { value: 0x20 }]);
        let (p, _) = decode_one(&[0xFF, 0xFE]);
        assert_eq!(p, vec![PtPacket::Cyc { value: 0xFFF }]);
    }

    #[test]
    fn misc_ext_packets_kernel_vectors() {
        let (p, _) = decode_one(&[0x02, 0x43, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(
            p,
            vec![PtPacket::Pip {
                cr3: 0x0605_0403_0201,
                nr: false
            }]
        );
        let (p, _) = decode_one(&[0x02, 0xC8, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(
            p,
            vec![PtPacket::Vmcs {
                payload: 0x0504_0302_01
            }]
        );
        let (p, _) = decode_one(&[
            0x02, 0xC3, 0x88, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00,
        ]);
        assert_eq!(
            p,
            vec![PtPacket::Mnt {
                payload: 0x0007_0605_0403_0201
            }]
        );
        let (p, _) = decode_one(&[0x02, 0x12, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            p,
            vec![PtPacket::Ptwrite {
                payload: 0x0403_0201,
                ip: false
            }]
        );
        let (p, _) = decode_one(&[0x02, 0x62]);
        assert_eq!(p, vec![PtPacket::Exstop { ip: false }]);
        let (p, _) = decode_one(&[0x02, 0xE2]);
        assert_eq!(p, vec![PtPacket::Exstop { ip: true }]);
        let (p, _) = decode_one(&[0x02, 0xC2, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(
            p,
            vec![PtPacket::Mwait {
                payload: 0x0807_0605_0403_0201
            }]
        );
        let (p, _) = decode_one(&[0x02, 0x22, 0x01, 0x02]);
        assert_eq!(p, vec![PtPacket::Pwre { payload: 0x0201 }]);
        let (p, _) = decode_one(&[0x02, 0xA2, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(
            p,
            vec![PtPacket::Pwrx {
                payload: 0x0504_0302_01
            }]
        );
        let (p, _) = decode_one(&[0x02, 0x63, 0x9F]);
        assert_eq!(
            p,
            vec![PtPacket::Bbp {
                is_4byte: true,
                kind: 0x1F
            }]
        );
        let (p, _) = decode_one(&[0x02, 0x33]);
        assert_eq!(p, vec![PtPacket::Bep { ip: false }]);
        let (p, _) = decode_one(&[0x02, 0x13, 0x01, 0x03]);
        assert_eq!(
            p,
            vec![PtPacket::Cfe {
                ip: false,
                kind: 1,
                vector: 3
            }]
        );
        let (p, _) = decode_one(&[
            0x02, 0x53, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]);
        assert_eq!(
            p,
            vec![PtPacket::Evd {
                kind: 0x09,
                payload: 0x0807_0605_0403_0201
            }]
        );
    }

    #[test]
    fn truncated_tail_is_bad_not_lost() {
        let (p, _) = decode_one(&[0x02]);
        assert!(matches!(&p[0], PtPacket::Bad { .. }));
        let (p, _) = decode_one(&[0x19, 0x01]);
        assert!(matches!(&p[0], PtPacket::Bad { .. }));
    }

    #[test]
    fn bad_aux_size_rejected() {
        assert!(matches!(
            validate_aux_size(1000),
            Err(SessionError::BadAuxSize(_))
        ));
        assert!(matches!(
            validate_aux_size(4096 + 1),
            Err(SessionError::BadAuxSize(_))
        ));
        assert!(validate_aux_size(65536).is_ok());
    }

    #[test]
    fn capabilities_probe_returns_structured_answer() {
        let caps = PtCapabilities::probe();
        assert!(!caps.reason.is_empty());
        assert!(!caps.detail.is_empty());
        #[cfg(not(target_os = "linux"))]
        assert!(!caps.available);
    }
}
