//! Rust NIF bridge for the OmniSec interactive debugger.
//!
//! Exposes a stateless JSON API so the Elixir server can:
//! 1.  Start a debug session (`debug_session_start/1`)
//! 2.  Step / continue (`debug_step/1`, `debug_continue/1`)
//! 3.  Add / remove breakpoints (`debug_breakpoint/2`, `debug_remove_bp/2`)
//! 4.  Read registers / disassemble (`debug_registers/1`, `debug_disassemble/3`)
//! 5.  Destroy session (`debug_session_stop/1`)
//!
//! All functions are dirty-CPU scheduled because emulation can take
//! milliseconds. NIF plumbing (arg decoding/encoding, dirty-scheduler
//! flags, the `ErlNifEntry` table) is provided by the local
//! zero-dependency `nifshim` crate instead of `rustler` — see
//! `native/nifshim` and `src/entry.c`. Business logic below is
//! unchanged from the original.

use nifshim::{decode, nif_entry};
use omnisec_debugger::{
    DebuggerSession, SessionConfig, StopReason,
    BreakTarget, DisassemblyFlavor,
};
use omnisec_debugger::watchpoint::WatchType;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// ═══════════════════════════════════════════════════════════════════════════════
// SESSION STORE
// ═══════════════════════════════════════════════════════════════════════════════

fn sessions() -> &'static Mutex<HashMap<u64, DebuggerSession>> {
    static STORE: OnceLock<Mutex<HashMap<u64, DebuggerSession>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_sessions() -> Result<std::sync::MutexGuard<'static, HashMap<u64, DebuggerSession>>, String> {
    sessions().lock().map_err(|_| "session lock poisoned".to_string())
}

static NEXT_SESSION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_id() -> u64 {
    NEXT_SESSION_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

// ═══════════════════════════════════════════════════════════════════════════════
// REQUEST / RESPONSE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(omnisec_json::FromJson)]
struct StartRequest {
    file_path: String,
    #[json(default)]
    entry: Option<u64>,
    #[json(default)]
    flavor: String,
}

#[derive(omnisec_json::ToJson)]
struct StartResponse {
    session_id: u64,
    entry_point: u64,
    arch: String,
}

#[derive(omnisec_json::ToJson)]
struct StepResponse {
    rip: u64,
    instruction: Option<String>,
    stop_reason: String,
    stop_address: Option<u64>,
}

#[derive(omnisec_json::ToJson)]
struct RegistersResponse {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    flags: FlagsSnapshot,
}

#[derive(omnisec_json::ToJson)]
struct FlagsSnapshot {
    zf: bool,
    sf: bool,
    cf: bool,
    of: bool,
}

#[derive(omnisec_json::ToJson)]
struct DisassemblyLine {
    address: String,
    raw: String,
    text: String,
    is_pc: bool,
}

#[derive(omnisec_json::ToJson)]
struct DisassembleResponse {
    lines: Vec<DisassemblyLine>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// NIF FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Start a debugger session for a file.
fn debug_session_start_impl(json: String) -> Result<String, String> {
    let req: StartRequest = omnisec_json::from_json_str(&json)
        .map_err(|e| format!("invalid JSON: {e}"))?;

    let path = std::path::Path::new(&req.file_path);
    let mut config = SessionConfig::default();
    if let Some(e) = req.entry {
        config.entry_point = Some(e);
    }
    config.disassembly_flavor = match req.flavor.to_lowercase().as_str() {
        "att" => DisassemblyFlavor::Att,
        _ => DisassemblyFlavor::Intel,
    };

    let session = DebuggerSession::from_file(path, config)
        .map_err(|e| e.to_string())?;

    let entry = session.engine.state.get(omnisec_emu_x86::Register::RIP);
    let arch = format!("{}", session.config.arch);

    let id = next_id();
    lock_sessions()?.insert(id, session);

    let resp = StartResponse {
        session_id: id,
        entry_point: entry,
        arch,
    };
    Ok(omnisec_json::to_json_string(&resp))
}

/// Stop and destroy a session.
fn debug_session_stop_impl(session_id: u64) -> Result<(), String> {
    lock_sessions()?.remove(&session_id);
    Ok(())
}

fn do_step(session: &mut DebuggerSession) -> StepResponse {
    let result = session.step();
    let stop_str = format!("{:?}", result.stop_reason);
    let stop_addr = match result.stop_reason {
        StopReason::Breakpoint { address } | StopReason::TempBreakpoint { address } | StopReason::Watchpoint { address, .. } => Some(address),
        _ => None,
    };

    StepResponse {
        rip: result.state.get(omnisec_emu_x86::Register::RIP),
        instruction: result.instruction,
        stop_reason: stop_str,
        stop_address: stop_addr,
    }
}

/// Step one instruction.
fn debug_step_impl(session_id: u64) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let resp = do_step(session);
    Ok(omnisec_json::to_json_string(&resp))
}

/// Continue execution until stop.
fn debug_continue_impl(session_id: u64) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let mut resp = do_step(session);
    // Keep stepping until we hit a real stop (not MaxInstructions)
    while resp.stop_reason == "MaxInstructions" {
        resp = do_step(session);
    }
    Ok(omnisec_json::to_json_string(&resp))
}

/// Set a breakpoint.
fn debug_breakpoint_impl(session_id: u64, target: String) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let target = if target.starts_with("0x") || target.starts_with("0X") || target.chars().all(|c| c.is_ascii_digit()) {
        let addr = u64::from_str_radix(target.trim_start_matches("0x"), 16)
            .or_else(|_| target.parse())
            .map_err(|_| format!("invalid address: {target}"))?;
        BreakTarget::Address(addr)
    } else {
        BreakTarget::Symbol(target)
    };

    let addr = match &target {
        BreakTarget::Address(a) => *a,
        BreakTarget::Symbol(name) => session.resolve_symbol(name)
            .ok_or_else(|| format!("symbol not found: {name}"))?,
    };

    let val = match session.add_breakpoint(addr) {
        Ok(id) => omnisec_json::json!({
            "ok": true,
            "id": id,
            "address": addr,
        }),
        Err(e) => omnisec_json::json!({
            "ok": false,
            "error": e.to_string(),
        }),
    };
    Ok(omnisec_json::to_json_string(&val))
}

/// Remove a breakpoint by number.
fn debug_remove_bp_impl(session_id: u64, bp_id: u32) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let val = match session.remove_breakpoint(bp_id) {
        Ok(()) => omnisec_json::json!({
            "ok": true,
        }),
        Err(e) => omnisec_json::json!({
            "ok": false,
            "error": e.to_string(),
        }),
    };
    Ok(omnisec_json::to_json_string(&val))
}

/// Read all registers.
fn debug_registers_impl(session_id: u64) -> Result<String, String> {
    let sessions = lock_sessions()?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let s = &session.engine.state;
    let f = &s.flags;
    let resp = RegistersResponse {
        rax: s.get(omnisec_emu_x86::Register::RAX),
        rbx: s.get(omnisec_emu_x86::Register::RBX),
        rcx: s.get(omnisec_emu_x86::Register::RCX),
        rdx: s.get(omnisec_emu_x86::Register::RDX),
        rsi: s.get(omnisec_emu_x86::Register::RSI),
        rdi: s.get(omnisec_emu_x86::Register::RDI),
        rbp: s.get(omnisec_emu_x86::Register::RBP),
        rsp: s.get(omnisec_emu_x86::Register::RSP),
        r8:  s.get(omnisec_emu_x86::Register::R8),
        r9:  s.get(omnisec_emu_x86::Register::R9),
        r10: s.get(omnisec_emu_x86::Register::R10),
        r11: s.get(omnisec_emu_x86::Register::R11),
        r12: s.get(omnisec_emu_x86::Register::R12),
        r13: s.get(omnisec_emu_x86::Register::R13),
        r14: s.get(omnisec_emu_x86::Register::R14),
        r15: s.get(omnisec_emu_x86::Register::R15),
        rip: s.get(omnisec_emu_x86::Register::RIP),
        flags: FlagsSnapshot {
            zf: f.zf,
            sf: f.sf,
            cf: f.cf,
            of: f.of,
        },
    };
    Ok(omnisec_json::to_json_string(&resp))
}

/// Disassemble at address.
fn debug_disassemble_impl(session_id: u64, address: u64, count: usize) -> Result<String, String> {
    let sessions = lock_sessions()?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction as IcedInsn};

    let is_64bit = session.config.arch == omnisec_core::Arch::X86_64;
    let bitness = if is_64bit { 64 } else { 32 };

    let mut formatter: Box<dyn Formatter> = match session.config.disassembly_flavor {
        DisassemblyFlavor::Intel => Box::new(iced_x86::IntelFormatter::new()),
        DisassemblyFlavor::Att => Box::new(iced_x86::GasFormatter::new()),
    };

    let mut lines = Vec::new();
    let mut insn = IcedInsn::default();
    let mut addr = address;

    for _ in 0..count {
        let mem_bytes = session.engine.memory.read(addr, 15);
        let chunk = match mem_bytes {
            Ok(b) => b,
            Err(_) => break,
        };

        let mut decoder = Decoder::with_ip(bitness, &chunk, addr, DecoderOptions::NONE);
        decoder.decode_out(&mut insn);

        if insn.is_invalid() {
            lines.push(DisassemblyLine {
                address: format!("{addr:#018x}"),
                raw: format!("{:02x}", chunk[0]),
                text: format!(".byte 0x{:02x}", chunk[0]),
                is_pc: addr == session.engine.state.get(omnisec_emu_x86::Register::RIP),
            });
            addr += 1;
            continue;
        }

        let mut output = String::new();
        formatter.format(&insn, &mut output);

        let raw: Vec<u8> = chunk[..insn.len()].to_vec();
        let raw_str = raw.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");

        lines.push(DisassemblyLine {
            address: format!("{addr:#018x}"),
            raw: raw_str,
            text: output,
            is_pc: addr == session.engine.state.get(omnisec_emu_x86::Register::RIP),
        });
        addr += insn.len() as u64;
    }

    let resp = DisassembleResponse { lines };
    Ok(omnisec_json::to_json_string(&resp))
}

/// Read raw memory bytes.
fn debug_read_memory_impl(session_id: u64, address: u64, size: u64) -> Result<String, String> {
    let sessions = lock_sessions()?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let size = size.min(4096);
    let val = match session.engine.memory.read(address, size as usize) {
        Ok(bytes) => {
            let hex = bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            omnisec_json::json!({
                "ok": true,
                "address": address,
                "hex": hex,
                "size": bytes.len(),
            })
        }
        Err(e) => omnisec_json::json!({
            "ok": false,
            "error": e.to_string(),
        }),
    };
    Ok(omnisec_json::to_json_string(&val))
}

/// Set disassembly flavor (intel / att).
fn debug_set_flavor_impl(session_id: u64, flavor: String) -> Result<(), String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    session.config.disassembly_flavor = match flavor.to_lowercase().as_str() {
        "att" | "at&t" | "gas" => DisassemblyFlavor::Att,
        _ => DisassemblyFlavor::Intel,
    };
    Ok(())
}

/// List all breakpoints.
fn debug_list_bp_impl(session_id: u64) -> Result<String, String> {
    let sessions = lock_sessions()?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let entries: Vec<omnisec_json::JsonValue> = session.breakpoints.iter().map(|bp| {
        omnisec_json::json!({
            "id": bp.id.0,
            "address": bp.address,
            "enabled": bp.enabled,
            "hits": bp.hit_count,
        })
    }).collect();
    let val = omnisec_json::json!({
        "ok": true,
        "breakpoints": entries,
    });
    Ok(omnisec_json::to_json_string(&val))
}

/// Add a watchpoint.
fn debug_add_watch_impl(session_id: u64, address: u64, size: u64, kind: String) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let wt = match kind.to_lowercase().as_str() {
        "read" | "r" => WatchType::Read,
        "write" | "w" => WatchType::Write,
        _ => WatchType::Access,
    };
    let id = session.engine.watchpoints.add(address, size, wt);
    let val = omnisec_json::json!({
        "ok": true,
        "id": id,
        "address": address,
        "size": size,
        "kind": kind,
    });
    Ok(omnisec_json::to_json_string(&val))
}

/// Remove a watchpoint by id.
fn debug_remove_watch_impl(session_id: u64, watch_id: u32) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let val = match session.engine.watchpoints.remove(watch_id) {
        Some(_) => omnisec_json::json!({
            "ok": true
        }),
        None => omnisec_json::json!({
            "ok": false,
            "error": format!("no watchpoint #{watch_id}"),
        }),
    };
    Ok(omnisec_json::to_json_string(&val))
}

/// List all watchpoints.
fn debug_list_watch_impl(session_id: u64) -> Result<String, String> {
    let sessions = lock_sessions()?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let entries: Vec<omnisec_json::JsonValue> = session.engine.watchpoints.iter().map(|wp| {
        let kind_str = match wp.kind {
            WatchType::Read => "read",
            WatchType::Write => "write",
            WatchType::Access => "access",
        };
        omnisec_json::json!({
            "id": wp.id,
            "address": wp.address,
            "size": wp.size,
            "kind": kind_str,
            "hits": wp.hit_count,
        })
    }).collect();
    let val = omnisec_json::json!({
        "ok": true,
        "watchpoints": entries,
    });
    Ok(omnisec_json::to_json_string(&val))
}

/// Write raw bytes to memory (for patching).
fn debug_write_memory_impl(session_id: u64, address: u64, hex_str: String) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let hex_clean = hex_str.replace(" ", "").replace("\n", "");
    let mut data = Vec::with_capacity(hex_clean.len() / 2);
    for i in (0..hex_clean.len()).step_by(2) {
        if i + 2 > hex_clean.len() { break; }
        if let Ok(byte) = u8::from_str_radix(&hex_clean[i..i+2], 16) {
            data.push(byte);
        } else {
            let val = omnisec_json::json!({
                "ok": false,
                "error": format!("invalid hex at offset {i}"),
            });
            return Ok(omnisec_json::to_json_string(&val));
        }
    }

    let val = match session.engine.memory.write_raw(address, &data) {
        Ok(()) => omnisec_json::json!({
            "ok": true,
            "written": data.len(),
        }),
        Err(e) => omnisec_json::json!({
            "ok": false,
            "error": e.to_string(),
        }),
    };
    Ok(omnisec_json::to_json_string(&val))
}

/// Enable or disable time-travel tracing.
fn debug_trace_enable_impl(session_id: u64, enabled: bool) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    if enabled {
        session.engine.enable_tracing();
    } else {
        session.engine.disable_tracing();
    }
    let val = omnisec_json::json!({
        "ok": true
    });
    Ok(omnisec_json::to_json_string(&val))
}

/// Step back one instruction.
fn debug_reverse_step_impl(session_id: u64) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let val = match session.engine.reverse_step() {
        Some(result) => {
            let stop_addr = match result.stop_reason {
                StopReason::Breakpoint { address } | StopReason::TempBreakpoint { address } | StopReason::Watchpoint { address, .. } => Some(address),
                _ => None,
            };
            omnisec_json::json!({
                "rip": result.state.get(omnisec_emu_x86::Register::RIP),
                "instruction": result.instruction,
                "stop_reason": format!("{:?}", result.stop_reason),
                "stop_address": stop_addr,
            })
        }
        None => omnisec_json::json!({
            "ok": false,
            "error": "no trace available",
        }),
    };
    Ok(omnisec_json::to_json_string(&val))
}

/// Rewind until previous breakpoint or trace start.
fn debug_reverse_continue_impl(session_id: u64) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let val = match session.engine.reverse_continue() {
        Some(result) => {
            let stop_addr = match result.stop_reason {
                StopReason::Breakpoint { address } | StopReason::TempBreakpoint { address } | StopReason::Watchpoint { address, .. } => Some(address),
                _ => None,
            };
            omnisec_json::json!({
                "rip": result.state.get(omnisec_emu_x86::Register::RIP),
                "instruction": result.instruction,
                "stop_reason": format!("{:?}", result.stop_reason),
                "stop_address": stop_addr,
            })
        }
        None => omnisec_json::json!({
            "ok": false,
            "error": "no trace available",
        }),
    };
    Ok(omnisec_json::to_json_string(&val))
}

/// Scan memory for a byte pattern (hex with ?? wildcards).
fn debug_scan_memory_impl(session_id: u64, pattern: String) -> Result<String, String> {
    let sessions = lock_sessions()?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    // Parse pattern like "48 8B ?? 24" into bytes + mask
    let parts: Vec<&str> = pattern.split_whitespace().collect();
    let mut needle = Vec::with_capacity(parts.len());
    let mut mask = Vec::with_capacity(parts.len());
    for p in parts {
        if p == "??" || p == "?" {
            needle.push(0);
            mask.push(false);
        } else {
            let b = u8::from_str_radix(p, 16)
                .map_err(|_| format!("invalid hex in pattern: {p}"))?;
            needle.push(b);
            mask.push(true);
        }
    }
    if needle.is_empty() {
        let val = omnisec_json::json!({
            "ok": false,
            "error": "empty pattern",
        });
        return Ok(omnisec_json::to_json_string(&val));
    }

    let mut hits = Vec::new();
    for region in session.engine.memory.regions() {
        if region.size == 0 { continue; }
        if let Ok(data) = session.engine.memory.read(region.base, region.size as usize) {
            'outer: for i in 0..data.len().saturating_sub(needle.len() - 1) {
                for j in 0..needle.len() {
                    if mask[j] && data[i + j] != needle[j] {
                        continue 'outer;
                    }
                }
                hits.push(region.base + i as u64);
            }
        }
    }

    let hits_val: Vec<omnisec_json::JsonValue> = hits.iter().map(|&addr| {
        omnisec_json::json!({
            "address": addr
        })
    }).collect();

    let val = omnisec_json::json!({
        "ok": true,
        "hits": hits_val,
        "count": hits.len(),
    });
    Ok(omnisec_json::to_json_string(&val))
}

/// Set a single register value.
fn debug_set_register_impl(session_id: u64, reg: String, value: u64) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let register = match reg.to_lowercase().as_str() {
        "rax" => omnisec_emu_x86::Register::RAX,
        "rbx" => omnisec_emu_x86::Register::RBX,
        "rcx" => omnisec_emu_x86::Register::RCX,
        "rdx" => omnisec_emu_x86::Register::RDX,
        "rsi" => omnisec_emu_x86::Register::RSI,
        "rdi" => omnisec_emu_x86::Register::RDI,
        "rbp" => omnisec_emu_x86::Register::RBP,
        "rsp" => omnisec_emu_x86::Register::RSP,
        "r8"  => omnisec_emu_x86::Register::R8,
        "r9"  => omnisec_emu_x86::Register::R9,
        "r10" => omnisec_emu_x86::Register::R10,
        "r11" => omnisec_emu_x86::Register::R11,
        "r12" => omnisec_emu_x86::Register::R12,
        "r13" => omnisec_emu_x86::Register::R13,
        "r14" => omnisec_emu_x86::Register::R14,
        "r15" => omnisec_emu_x86::Register::R15,
        "rip" => omnisec_emu_x86::Register::RIP,
        _ => {
            let val = omnisec_json::json!({
                "ok": false,
                "error": format!("unknown register: {reg}"),
            });
            return Ok(omnisec_json::to_json_string(&val));
        }
    };

    session.engine.state.set(register, value);
    let val = omnisec_json::json!({
        "ok": true
    });
    Ok(omnisec_json::to_json_string(&val))
}

/// Set a CPU flag value (ZF, SF, CF, OF) for branch forcing.
fn debug_set_flag_impl(session_id: u64, flag: String, value: bool) -> Result<String, String> {
    let mut sessions = lock_sessions()?;
    let session = sessions.get_mut(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    match flag.to_lowercase().as_str() {
        "zf" => session.engine.state.flags.zf = value,
        "sf" => session.engine.state.flags.sf = value,
        "cf" => session.engine.state.flags.cf = value,
        "of" => session.engine.state.flags.of = value,
        _ => {
            let val = omnisec_json::json!({
                "ok": false,
                "error": format!("unknown flag: {flag}"),
            });
            return Ok(omnisec_json::to_json_string(&val));
        }
    }

    let val = omnisec_json::json!({
        "ok": true
    });
    Ok(omnisec_json::to_json_string(&val))
}

/// Get trace execution log.
fn debug_trace_log_impl(session_id: u64, start: usize, count: usize) -> Result<String, String> {
    let sessions = lock_sessions()?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let db = &session.engine.trace_db;
    let end = start + count;
    Ok(db.export_json_slice(start, end))
}

/// Get trace statistics.
fn debug_trace_stats_impl(session_id: u64) -> Result<String, String> {
    let sessions = lock_sessions()?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    let stats = session.engine.trace_db.stats();
    let val = omnisec_json::json!({
        "total": stats.total,
        "max_risk": stats.max_risk,
        "avg_risk": stats.avg_risk,
        "max_entropy": stats.max_entropy,
        "total_patterns": stats.total_patterns,
        "checkpoint_count": stats.checkpoint_count,
    });
    Ok(omnisec_json::to_json_string(&val))
}

/// Generate a Control Flow Graph (CFG) starting at address.
fn debug_cfg_impl(session_id: u64, address: u64, count: usize) -> Result<String, String> {
    let sessions = lock_sessions()?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| "invalid session_id".to_string())?;

    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction as IcedInsn, FlowControl};

    let is_64bit = session.config.arch == omnisec_core::Arch::X86_64;
    let bitness = if is_64bit { 64 } else { 32 };

    let mut formatter: Box<dyn Formatter> = match session.config.disassembly_flavor {
        DisassemblyFlavor::Intel => Box::new(iced_x86::IntelFormatter::new()),
        DisassemblyFlavor::Att => Box::new(iced_x86::GasFormatter::new()),
    };

    // 1. Decode instructions
    let mut instructions = Vec::with_capacity(count);
    let mut addr = address;
    let mut insn = IcedInsn::default();

    for _ in 0..count {
        let mem_bytes = session.engine.memory.read(addr, 15);
        let chunk = match mem_bytes {
            Ok(b) => b,
            Err(_) => break,
        };

        let mut decoder = Decoder::with_ip(bitness, &chunk, addr, DecoderOptions::NONE);
        decoder.decode_out(&mut insn);

        if insn.is_invalid() {
            instructions.push((addr, insn.len() as u64, ".byte invalid".to_string(), FlowControl::Next, None));
            addr += 1;
            continue;
        }

        let mut text = String::new();
        formatter.format(&insn, &mut text);

        let flow = insn.flow_control();
        
        // Resolve target if branch
        let target = match flow {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Call => {
                use iced_x86::OpKind;
                if insn.op_count() > 0 {
                    match insn.op_kind(0) {
                        OpKind::NearBranch16 => Some(u64::from(insn.near_branch16())),
                        OpKind::NearBranch32 => Some(u64::from(insn.near_branch32())),
                        OpKind::NearBranch64 => Some(insn.near_branch64()),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        instructions.push((addr, insn.len() as u64, text, flow, target));
        addr += insn.len() as u64;
    }

    if instructions.is_empty() {
        let val = omnisec_json::json!({
            "ok": true,
            "nodes": [],
            "edges": [],
        });
        return Ok(omnisec_json::to_json_string(&val));
    }

    // 2. Identify basic block leaders (start addresses)
    let mut leaders = std::collections::BTreeSet::new();
    leaders.insert(instructions[0].0); // First instruction is always a leader

    for i in 0..instructions.len() {
        let (_addr, _, _, flow, target) = &instructions[i];
        
        // Target of a branch is a leader
        if let Some(t) = target {
            leaders.insert(*t);
        }

        // Instruction after a branch or call or ret is a leader
        match flow {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Call | FlowControl::Return | FlowControl::Interrupt => {
                if i + 1 < instructions.len() {
                    leaders.insert(instructions[i + 1].0);
                }
            }
            _ => {}
        }
    }

    // 3. Build basic blocks
    struct BasicBlock {
        id: usize,
        start_addr: u64,
        end_addr: u64,
        instructions: Vec<(u64, String)>,
        flow: FlowControl,
        target: Option<u64>,
    }

    let mut blocks = Vec::new();
    let mut current_block: Option<BasicBlock> = None;
    let mut block_id_counter = 0;

    for (addr, len, text, flow, target) in instructions {
        if leaders.contains(&addr) {
            if let Some(bb) = current_block.take() {
                blocks.push(bb);
            }
            block_id_counter += 1;
            current_block = Some(BasicBlock {
                id: block_id_counter,
                start_addr: addr,
                end_addr: addr + len,
                instructions: vec![(addr, text)],
                flow,
                target,
            });
        } else if let Some(ref mut bb) = current_block {
            bb.end_addr = addr + len;
            bb.instructions.push((addr, text));
            bb.flow = flow;
            bb.target = target;
        }
    }
    if let Some(bb) = current_block {
        blocks.push(bb);
    }

    // 4. Generate edges
    let mut edges = Vec::new();
    for i in 0..blocks.len() {
        let bb = &blocks[i];
        
        match bb.flow {
            FlowControl::UnconditionalBranch => {
                if let Some(t) = bb.target {
                    if let Some(target_bb) = blocks.iter().find(|b| b.start_addr == t) {
                        edges.push(omnisec_json::json!({
                            "source": bb.id,
                            "target": target_bb.id,
                            "type": "jump",
                        }));
                    }
                }
            }
            FlowControl::ConditionalBranch => {
                // Branch taken edge
                if let Some(t) = bb.target {
                    if let Some(target_bb) = blocks.iter().find(|b| b.start_addr == t) {
                        edges.push(omnisec_json::json!({
                            "source": bb.id,
                            "target": target_bb.id,
                            "type": "conditional_taken",
                        }));
                    }
                }
                // Fallthrough edge
                if i + 1 < blocks.len() {
                    let next_bb = &blocks[i + 1];
                    edges.push(omnisec_json::json!({
                        "source": bb.id,
                        "target": next_bb.id,
                        "type": "conditional_fallthrough",
                    }));
                }
            }
            FlowControl::Call => {
                // Branch taken edge (call target)
                if let Some(t) = bb.target {
                    if let Some(target_bb) = blocks.iter().find(|b| b.start_addr == t) {
                        edges.push(omnisec_json::json!({
                            "source": bb.id,
                            "target": target_bb.id,
                            "type": "call",
                        }));
                    }
                }
                // Fallthrough edge (return path)
                if i + 1 < blocks.len() {
                    let next_bb = &blocks[i + 1];
                    edges.push(omnisec_json::json!({
                        "source": bb.id,
                        "target": next_bb.id,
                        "type": "fallthrough",
                    }));
                }
            }
            FlowControl::Return => {
                // Return terminates current path
            }
            _ => {
                // Regular instructions fall through to the next sequential block
                if i + 1 < blocks.len() {
                    let next_bb = &blocks[i + 1];
                    edges.push(omnisec_json::json!({
                        "source": bb.id,
                        "target": next_bb.id,
                        "type": "fallthrough",
                    }));
                }
            }
        }
    }

    // 5. Serialize
    let nodes_val: Vec<_> = blocks.iter().map(|b| {
        let insns_val: Vec<_> = b.instructions.iter().map(|(a, t)| {
            omnisec_json::json!({
                "address": format!("{a:#018x}"),
                "text": t,
            })
        }).collect();

        omnisec_json::json!({
            "id": b.id,
            "start_address": format!("{:#018x}", b.start_addr),
            "end_address": format!("{:#018x}", b.end_addr),
            "instructions": insns_val,
        })
    }).collect();

    let val = omnisec_json::json!({
        "ok": true,
        "nodes": nodes_val,
        "edges": edges,
    });

    Ok(omnisec_json::to_json_string(&val))
}

// ═══════════════════════════════════════════════════════════════════════════════
// NIF ENTRY POINTS (raw ABI, exported as `raw_*`, wired up in entry.c)
// ═══════════════════════════════════════════════════════════════════════════════

// Export `nif_init` directly from Rust so rustc's cdylib linker driver
// includes `nif_init` in the dynamic export table (.dynsym on Linux / export table on PE/Mach-O).
// It delegates to `c_nif_init` generated by `ERL_NIF_INIT` in `entry.c`.
#[cfg(windows)]
unsafe extern "C" {
    fn c_nif_init(callbacks: *mut core::ffi::c_void) -> *const core::ffi::c_void;
}
#[cfg(not(windows))]
unsafe extern "C" {
    fn c_nif_init() -> *const core::ffi::c_void;
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nif_init(callbacks: *mut core::ffi::c_void) -> *const core::ffi::c_void {
    unsafe { c_nif_init(callbacks) }
}

#[cfg(not(windows))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nif_init() -> *const core::ffi::c_void {
    unsafe { c_nif_init() }
}

nif_entry!(raw_debug_session_start, 1, |env, args| {
    let json = decode!(env, nifshim::get_string(env, args[0]));
    match debug_session_start_impl(json) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_session_stop, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match debug_session_stop_impl(session_id) {
        Ok(()) => nifshim::make_ok(env),
        Err(e) => nifshim::make_str(env, &e),
    }
});

nif_entry!(raw_debug_step, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match debug_step_impl(session_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_continue, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match debug_continue_impl(session_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_breakpoint, 2, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let target = decode!(env, nifshim::get_string(env, args[1]));
    match debug_breakpoint_impl(session_id, target) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_remove_bp, 2, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let bp_id = decode!(env, nifshim::get_u32(env, args[1]));
    match debug_remove_bp_impl(session_id, bp_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_registers, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match debug_registers_impl(session_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_disassemble, 3, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let address = decode!(env, nifshim::get_u64(env, args[1]));
    let count = decode!(env, nifshim::get_usize(env, args[2]));
    match debug_disassemble_impl(session_id, address, count) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_read_memory, 3, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let address = decode!(env, nifshim::get_u64(env, args[1]));
    let size = decode!(env, nifshim::get_u64(env, args[2]));
    match debug_read_memory_impl(session_id, address, size) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_set_flavor, 2, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let flavor = decode!(env, nifshim::get_string(env, args[1]));
    match debug_set_flavor_impl(session_id, flavor) {
        Ok(()) => nifshim::make_ok(env),
        Err(e) => nifshim::make_str(env, &e),
    }
});

nif_entry!(raw_debug_list_bp, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match debug_list_bp_impl(session_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_add_watch, 4, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let address = decode!(env, nifshim::get_u64(env, args[1]));
    let size = decode!(env, nifshim::get_u64(env, args[2]));
    let kind = decode!(env, nifshim::get_string(env, args[3]));
    match debug_add_watch_impl(session_id, address, size, kind) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_remove_watch, 2, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let watch_id = decode!(env, nifshim::get_u32(env, args[1]));
    match debug_remove_watch_impl(session_id, watch_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_list_watch, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match debug_list_watch_impl(session_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_write_memory, 3, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let address = decode!(env, nifshim::get_u64(env, args[1]));
    let hex_str = decode!(env, nifshim::get_string(env, args[2]));
    match debug_write_memory_impl(session_id, address, hex_str) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_trace_enable, 2, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let enabled = decode!(env, nifshim::get_bool(env, args[1]));
    match debug_trace_enable_impl(session_id, enabled) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_reverse_step, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match debug_reverse_step_impl(session_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_reverse_continue, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match debug_reverse_continue_impl(session_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_scan_memory, 2, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let pattern = decode!(env, nifshim::get_string(env, args[1]));
    match debug_scan_memory_impl(session_id, pattern) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_set_register, 3, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let reg = decode!(env, nifshim::get_string(env, args[1]));
    let value = decode!(env, nifshim::get_u64(env, args[2]));
    match debug_set_register_impl(session_id, reg, value) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_set_flag, 3, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let flag = decode!(env, nifshim::get_string(env, args[1]));
    let value = decode!(env, nifshim::get_bool(env, args[2]));
    match debug_set_flag_impl(session_id, flag, value) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_trace_log, 3, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let start = decode!(env, nifshim::get_usize(env, args[1]));
    let count = decode!(env, nifshim::get_usize(env, args[2]));
    match debug_trace_log_impl(session_id, start, count) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_trace_stats, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match debug_trace_stats_impl(session_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_debug_cfg, 3, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    let address = decode!(env, nifshim::get_u64(env, args[1]));
    let count = decode!(env, nifshim::get_usize(env, args[2]));
    match debug_cfg_impl(session_id, address, count) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});
