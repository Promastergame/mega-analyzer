//! C FFI bridge for omnisec-debugger — meant to be consumed via Go CGO.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Mutex, OnceLock};

use omnisec_debugger::{DebuggerSession, SessionConfig, StopReason};
use omnisec_emu_x86::Register;

// ═══════════════════════════════════════════════════════════════════════════════
// SESSION STORE
// ═══════════════════════════════════════════════════════════════════════════════

fn sessions() -> &'static Mutex<HashMap<u64, DebuggerSession>> {
    static STORE: OnceLock<Mutex<HashMap<u64, DebuggerSession>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

fn ok_json(s: String) -> String {
    format!("{{\"ok\":true,\"result\":{}}}", s)
}
fn err_json(e: String) -> String {
    format!("{{\"ok\":false,\"error\":\"{}\"}}", e.replace('"', "\\\""))
}

fn step_response_json(r: &omnisec_debugger::engine::StepResult) -> String {
    let rip = r.state.get(Register::RIP);
    let insn = r.instruction.as_deref().unwrap_or("<unknown>");
    let reason = format!("{:?}", r.stop_reason);
    let stop_addr = match r.stop_reason {
        StopReason::Breakpoint { address }
        | StopReason::TempBreakpoint { address }
        | StopReason::Watchpoint { address, .. } => format!("{}", address),
        _ => "null".to_string(),
    };
    ok_json(format!(
        "{{\"rip\":{},\"instruction\":\"{}\",\"stop_reason\":\"{}\",\"stop_address\":{}}}",
        rip,
        insn.replace('"', "\\\""),
        reason,
        stop_addr
    ))
}

fn with_session<F>(sid: u64, f: F) -> String
where
    F: FnOnce(&mut DebuggerSession) -> String,
{
    let Ok(mut m) = sessions().lock() else {
        return err_json("session store poisoned".to_string());
    };
    match m.get_mut(&sid) {
        Some(s) => f(s),
        None => err_json("invalid session_id".to_string()),
    }
}

fn into_raw(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => match CString::new("{\"ok\":false,\"error\":\"nul\"}") {
            Ok(c) => c.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// C API
// ═══════════════════════════════════════════════════════════════════════════════

/// Start a debugger session.
/// `file_path` must be valid UTF-8. `entry` may be 0 to use binary default.
/// Returns session_id (0 on error).
///
/// # Safety
/// `file_path` must be either NULL or a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_debugger_start(file_path: *const c_char, entry: u64) -> u64 {
    let path = unsafe {
        if file_path.is_null() {
            return 0;
        }
        CStr::from_ptr(file_path).to_string_lossy().to_string()
    };

    let mut config = SessionConfig::default();
    if entry != 0 {
        config.entry_point = Some(entry);
    }

    match DebuggerSession::from_file(std::path::Path::new(&path), config) {
        Ok(session) => {
            let id = next_id();
            match sessions().lock() {
                Ok(mut m) => {
                    m.insert(id, session);
                    id
                }
                Err(_) => 0,
            }
        }
        Err(e) => {
            eprintln!("debugger_start error: {}", e);
            0
        }
    }
}

/// Stop and destroy a session.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_stop(session_id: u64) {
    if let Ok(mut m) = sessions().lock() {
        m.remove(&session_id);
    }
}

/// Step one instruction. Returns JSON string — caller must free with `omnisec_debugger_free`.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_step(session_id: u64) -> *mut c_char {
    let json = with_session(session_id, |s| {
        let r = s.step();
        step_response_json(&r)
    });
    into_raw(json)
}

/// Continue until stop. Returns JSON — caller must free.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_continue(session_id: u64) -> *mut c_char {
    let json = with_session(session_id, |s| {
        let r = s.continue_run();
        step_response_json(&r)
    });
    into_raw(json)
}

/// Step over (next) — step one instruction, skip calls.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_next(session_id: u64) -> *mut c_char {
    let json = with_session(session_id, |s| {
        let r = s.next();
        step_response_json(&r)
    });
    into_raw(json)
}

/// Read registers. Returns JSON — caller must free.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_registers(session_id: u64) -> *mut c_char {
    let json = with_session(session_id, |s| {
        let st = &s.engine.state;
        let f = &st.flags;
        ok_json(format!(
            "{{\"rax\":{},\"rbx\":{},\"rcx\":{},\"rdx\":{},\"rsi\":{},\"rdi\":{},\"rbp\":{},\"rsp\":{},\"r8\":{},\"r9\":{},\"r10\":{},\"r11\":{},\"r12\":{},\"r13\":{},\"r14\":{},\"r15\":{},\"rip\":{},\"flags\":{{\"zf\":{},\"sf\":{},\"cf\":{},\"of\":{}}}}}",
            st.get(Register::RAX),
            st.get(Register::RBX),
            st.get(Register::RCX),
            st.get(Register::RDX),
            st.get(Register::RSI),
            st.get(Register::RDI),
            st.get(Register::RBP),
            st.get(Register::RSP),
            st.get(Register::R8),
            st.get(Register::R9),
            st.get(Register::R10),
            st.get(Register::R11),
            st.get(Register::R12),
            st.get(Register::R13),
            st.get(Register::R14),
            st.get(Register::R15),
            st.get(Register::RIP),
            f.zf,
            f.sf,
            f.cf,
            f.of,
        ))
    });
    into_raw(json)
}

/// Set a breakpoint. `target` = hex address or symbol name.
/// Returns JSON — caller must free.
///
/// # Safety
/// `target` must be either NULL or a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_debugger_breakpoint(
    session_id: u64,
    target: *const c_char,
) -> *mut c_char {
    let t = unsafe {
        if target.is_null() {
            return into_raw(err_json("null target".to_string()));
        }
        CStr::from_ptr(target).to_string_lossy().to_string()
    };
    let json = with_session(session_id, |s| {
        // Simple heuristic: starts with 0x or all digits = address
        let is_addr = t.starts_with("0x") || t.chars().all(|c| c.is_ascii_digit());
        let addr = if is_addr {
            u64::from_str_radix(t.trim_start_matches("0x"), 16)
                .or_else(|_| t.parse())
                .unwrap_or(0)
        } else {
            match s.resolve_symbol(&t) {
                Some(a) => a,
                None => return err_json(format!("symbol not found: {}", t)),
            }
        };
        match s.add_breakpoint(addr) {
            Ok(id) => ok_json(format!("{{\"id\":{},\"address\":{}}}", id, addr)),
            Err(e) => err_json(e.to_string()),
        }
    });
    into_raw(json)
}

/// Remove breakpoint by id. Returns JSON.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_remove_bp(session_id: u64, bp_id: u32) -> *mut c_char {
    let json = with_session(session_id, |s| match s.remove_breakpoint(bp_id) {
        Ok(_) => ok_json("{}".to_string()),
        Err(e) => err_json(e.to_string()),
    });
    into_raw(json)
}

/// Disassemble at address. Returns JSON — caller must free.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_disassemble(
    session_id: u64,
    address: u64,
    count: usize,
) -> *mut c_char {
    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction as IcedInsn};
    let json = with_session(session_id, |s| {
        let is_64 = s.config.arch == omnisec_core::Arch::X86_64;
        let bitness = if is_64 { 64 } else { 32 };
        let mut fmt: Box<dyn Formatter> = match s.config.disassembly_flavor {
            omnisec_debugger::DisassemblyFlavor::Intel => Box::new(iced_x86::IntelFormatter::new()),
            omnisec_debugger::DisassemblyFlavor::Att => Box::new(iced_x86::GasFormatter::new()),
        };
        let mut lines = Vec::new();
        let mut insn = IcedInsn::default();
        let mut addr = address;
        for _ in 0..count {
            let chunk = match s.engine.memory.read(addr, 15) {
                Ok(b) => b,
                Err(_) => break,
            };
            let mut dec = Decoder::with_ip(bitness, &chunk, addr, DecoderOptions::NONE);
            dec.decode_out(&mut insn);
            if insn.is_invalid() {
                lines.push(format!(
                    "{{\"address\":\"{:#018x}\",\"raw\":\"{:02x}\",\"text\":\".byte 0x{:02x}\",\"is_pc\":false}}",
                    addr, chunk[0], chunk[0]
                ));
                addr += 1;
                continue;
            }
            let mut out = String::new();
            fmt.format(&insn, &mut out);
            let raw_str: String = chunk[..insn.len()]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            let is_pc = addr == s.engine.state.get(Register::RIP);
            lines.push(format!(
                "{{\"address\":\"{:#018x}\",\"raw\":\"{}\",\"text\":\"{}\",\"is_pc\":{}}}",
                addr,
                raw_str,
                out.replace('"', "\\\""),
                is_pc
            ));
            addr += insn.len() as u64;
        }
        ok_json(format!("{{\"lines\":[{}]}}", lines.join(",")))
    });
    into_raw(json)
}

/// Read memory bytes. Returns JSON — caller must free.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_read_memory(
    session_id: u64,
    address: u64,
    size: u64,
) -> *mut c_char {
    let sz = size.min(4096) as usize;
    let json = with_session(session_id, |s| match s.engine.memory.read(address, sz) {
        Ok(bytes) => {
            let hex = bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            ok_json(format!(
                "{{\"address\":{},\"hex\":\"{}\",\"size\":{}}}",
                address,
                hex,
                bytes.len()
            ))
        }
        Err(e) => err_json(e.to_string()),
    });
    into_raw(json)
}

/// Write raw hex bytes to memory. Returns JSON — caller must free.
///
/// # Safety
/// `hex_str` must be either NULL or a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_debugger_write_memory(
    session_id: u64,
    address: u64,
    hex_str: *const c_char,
) -> *mut c_char {
    let hex = unsafe {
        if hex_str.is_null() {
            return into_raw(err_json("null hex".to_string()));
        }
        CStr::from_ptr(hex_str).to_string_lossy().to_string()
    };
    let hex_clean = hex.replace(" ", "").replace("\n", "");
    let mut data = Vec::with_capacity(hex_clean.len() / 2);
    for i in (0..hex_clean.len()).step_by(2) {
        if i + 2 > hex_clean.len() {
            break;
        }
        if let Ok(b) = u8::from_str_radix(&hex_clean[i..i + 2], 16) {
            data.push(b);
        } else {
            return into_raw(err_json("invalid hex".to_string()));
        }
    }
    let json = with_session(session_id, |s| {
        match s.engine.memory.write_raw(address, &data) {
            Ok(_) => ok_json(format!("{{\"written\":{}}}", data.len())),
            Err(e) => err_json(e.to_string()),
        }
    });
    into_raw(json)
}

/// Set a register value. Returns JSON — caller must free.
///
/// # Safety
/// `reg_name` must be either NULL or a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_debugger_set_register(
    session_id: u64,
    reg_name: *const c_char,
    value: u64,
) -> *mut c_char {
    let reg = unsafe {
        if reg_name.is_null() {
            return into_raw(err_json("null reg".to_string()));
        }
        CStr::from_ptr(reg_name).to_string_lossy().to_string()
    };
    let json = with_session(session_id, |s| {
        let r = match reg.to_lowercase().as_str() {
            "rax" => Register::RAX,
            "rbx" => Register::RBX,
            "rcx" => Register::RCX,
            "rdx" => Register::RDX,
            "rsi" => Register::RSI,
            "rdi" => Register::RDI,
            "rbp" => Register::RBP,
            "rsp" => Register::RSP,
            "r8" => Register::R8,
            "r9" => Register::R9,
            "r10" => Register::R10,
            "r11" => Register::R11,
            "r12" => Register::R12,
            "r13" => Register::R13,
            "r14" => Register::R14,
            "r15" => Register::R15,
            "rip" => Register::RIP,
            _ => return err_json(format!("unknown register: {}", reg)),
        };
        s.engine.state.set(r, value);
        ok_json("{}".to_string())
    });
    into_raw(json)
}

/// Set disassembly flavor. `flavor` = "intel" | "att".
///
/// # Safety
/// `flavor` must be either NULL or a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_debugger_set_flavor(session_id: u64, flavor: *const c_char) {
    let f = unsafe {
        if flavor.is_null() {
            return;
        }
        CStr::from_ptr(flavor).to_string_lossy().to_string()
    };
    let Ok(mut m) = sessions().lock() else {
        return;
    };
    if let Some(s) = m.get_mut(&session_id) {
        s.config.disassembly_flavor = match f.to_lowercase().as_str() {
            "att" | "at&t" | "gas" => omnisec_debugger::DisassemblyFlavor::Att,
            _ => omnisec_debugger::DisassemblyFlavor::Intel,
        };
    }
}

/// Enable or disable time-travel tracing.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_trace_enable(session_id: u64, enabled: bool) {
    let Ok(mut m) = sessions().lock() else {
        return;
    };
    if let Some(s) = m.get_mut(&session_id) {
        if enabled {
            s.engine.enable_tracing();
        } else {
            s.engine.disable_tracing();
        }
    }
}

/// Reverse-step one instruction (requires trace enabled).
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_reverse_step(session_id: u64) -> *mut c_char {
    let json = with_session(session_id, |s| match s.engine.reverse_step() {
        Some(r) => step_response_json(&r),
        None => err_json("no trace available".to_string()),
    });
    into_raw(json)
}

/// Reverse-continue until previous breakpoint or trace start.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_debugger_reverse_continue(session_id: u64) -> *mut c_char {
    let json = with_session(session_id, |s| match s.engine.reverse_continue() {
        Some(r) => step_response_json(&r),
        None => err_json("no trace available".to_string()),
    });
    into_raw(json)
}

/// Scan memory for a byte pattern (hex with ?? wildcards).
/// Returns JSON with hits array — caller must free.
///
/// # Safety
/// `pattern` must be either NULL or a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_debugger_scan_memory(
    session_id: u64,
    pattern: *const c_char,
) -> *mut c_char {
    let pat = unsafe {
        if pattern.is_null() {
            return into_raw(err_json("null pattern".to_string()));
        }
        CStr::from_ptr(pattern).to_string_lossy().to_string()
    };
    let json = with_session(session_id, |s| {
        let parts: Vec<&str> = pat.split_whitespace().collect();
        let mut needle = Vec::with_capacity(parts.len());
        let mut mask = Vec::with_capacity(parts.len());
        for p in parts {
            if p == "??" || p == "?" {
                needle.push(0);
                mask.push(false);
            } else if let Ok(b) = u8::from_str_radix(p, 16) {
                needle.push(b);
                mask.push(true);
            } else {
                return err_json(format!("invalid hex in pattern: {p}"));
            }
        }
        if needle.is_empty() {
            return err_json("empty pattern".to_string());
        }
        let mut hits = Vec::new();
        for region in s.engine.memory.regions() {
            if region.size == 0 {
                continue;
            }
            if let Ok(data) = s.engine.memory.read(region.base, region.size as usize) {
                'outer: for i in 0..data.len().saturating_sub(needle.len() - 1) {
                    for j in 0..needle.len() {
                        if mask[j] && data[i + j] != needle[j] {
                            continue 'outer;
                        }
                    }
                    hits.push(format!("{{\"address\":{}}}", region.base + i as u64));
                    if hits.len() >= 1000 {
                        break;
                    }
                }
            }
            if hits.len() >= 1000 {
                break;
            }
        }
        ok_json(format!(
            "{{\"hits\":[{}],\"count\":{}}}",
            hits.join(","),
            hits.len()
        ))
    });
    into_raw(json)
}

#[derive(Debug)]
enum FfiCommand {
    Step,
    Continue,
    Next,
    Registers,
    Disassemble { address: u64, count: usize },
    ReadMemory { address: u64, size: usize },
    WriteMemory { address: u64, hex_data: String },
    SetRegister { register: String, value: u64 },
    Breakpoint { target: String },
    RemoveBreakpoint { id: u32 },
    TraceEnable { enabled: bool },
    ReverseStep,
    ReverseContinue,
    ScanMemory { pattern: String },
    SetFlavor { flavor: String },
}

impl omnisec_json::FromJson for FfiCommand {
    fn from_json(v: &omnisec_json::JsonValue) -> Result<Self, omnisec_json::JsonError> {
        use omnisec_json::{FromJson, JsonError, JsonValue};
        let err = || JsonError("invalid debugger command".into());
        let obj = match v {
            JsonValue::Object(o) => o,
            _ => return Err(err()),
        };
        let get = |k: &str| obj.iter().find(|(key, _)| key == k).map(|(_, v)| v);
        let cmd = get("command").and_then(|v| v.as_str()).ok_or_else(err)?;
        macro_rules! req_u64 {
            ($name:literal) => {
                get($name).ok_or_else(err)?.as_u64().ok_or_else(err)?
            };
        }
        macro_rules! req_str {
            ($name:literal) => {
                get($name)
                    .ok_or_else(err)?
                    .as_str()
                    .ok_or_else(err)?
                    .to_string()
            };
        }
        Ok(match cmd {
            "step" => Self::Step,
            "continue" => Self::Continue,
            "next" => Self::Next,
            "registers" => Self::Registers,
            "disassemble" => Self::Disassemble {
                address: req_u64!("address"),
                count: req_u64!("count") as usize,
            },
            "read_memory" => Self::ReadMemory {
                address: req_u64!("address"),
                size: req_u64!("size") as usize,
            },
            "write_memory" => Self::WriteMemory {
                address: req_u64!("address"),
                hex_data: req_str!("hex_data"),
            },
            "set_register" => Self::SetRegister {
                register: req_str!("register"),
                value: req_u64!("value"),
            },
            "breakpoint" => Self::Breakpoint {
                target: req_str!("target"),
            },
            "remove_breakpoint" => Self::RemoveBreakpoint {
                id: req_u64!("id") as u32,
            },
            "trace_enable" => Self::TraceEnable {
                enabled: get("enabled").ok_or_else(err)?.as_bool().ok_or_else(err)?,
            },
            "reverse_step" => Self::ReverseStep,
            "reverse_continue" => Self::ReverseContinue,
            "scan_memory" => Self::ScanMemory {
                pattern: req_str!("pattern"),
            },
            "set_flavor" => Self::SetFlavor {
                flavor: req_str!("flavor"),
            },
            _ => return Err(err()),
        })
    }
}

/// Unified entry-point for JSON debugger commands.
///
/// # Safety
/// `json_command` must be either NULL or a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_debugger_command(
    session_id: u64,
    json_command: *const c_char,
) -> *mut c_char {
    let cmd_str = unsafe {
        if json_command.is_null() {
            return into_raw(err_json("null command string".to_string()));
        }
        CStr::from_ptr(json_command).to_string_lossy().into_owned()
    };

    let cmd: FfiCommand = match omnisec_json::from_json_str(&cmd_str) {
        Ok(c) => c,
        Err(e) => return into_raw(err_json(format!("JSON parse error: {}", e))),
    };

    let result_json = with_session(session_id, |s| match cmd {
        FfiCommand::Step => {
            let r = s.step();
            step_response_json(&r)
        }
        FfiCommand::Continue => {
            let r = s.continue_run();
            step_response_json(&r)
        }
        FfiCommand::Next => {
            let r = s.next();
            step_response_json(&r)
        }
        FfiCommand::Registers => {
            let st = &s.engine.state;
            let f = &st.flags;
            ok_json(format!(
                "{{\"rax\":{},\"rbx\":{},\"rcx\":{},\"rdx\":{},\"rsi\":{},\"rdi\":{},\"rbp\":{},\"rsp\":{},\"r8\":{},\"r9\":{},\"r10\":{},\"r11\":{},\"r12\":{},\"r13\":{},\"r14\":{},\"r15\":{},\"rip\":{},\"flags\":{{\"zf\":{},\"sf\":{},\"cf\":{},\"of\":{}}}}}",
                st.get(Register::RAX),
                st.get(Register::RBX),
                st.get(Register::RCX),
                st.get(Register::RDX),
                st.get(Register::RSI),
                st.get(Register::RDI),
                st.get(Register::RBP),
                st.get(Register::RSP),
                st.get(Register::R8),
                st.get(Register::R9),
                st.get(Register::R10),
                st.get(Register::R11),
                st.get(Register::R12),
                st.get(Register::R13),
                st.get(Register::R14),
                st.get(Register::R15),
                st.get(Register::RIP),
                f.zf,
                f.sf,
                f.cf,
                f.of,
            ))
        }
        FfiCommand::Disassemble { address, count } => {
            use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction as IcedInsn};
            let is_64 = s.config.arch == omnisec_core::Arch::X86_64;
            let bitness = if is_64 { 64 } else { 32 };
            let mut fmt: Box<dyn Formatter> = match s.config.disassembly_flavor {
                omnisec_debugger::DisassemblyFlavor::Intel => {
                    Box::new(iced_x86::IntelFormatter::new())
                }
                omnisec_debugger::DisassemblyFlavor::Att => Box::new(iced_x86::GasFormatter::new()),
            };
            let mut lines = Vec::new();
            let mut insn = IcedInsn::default();
            let mut addr = address;
            for _ in 0..count {
                let chunk = match s.engine.memory.read(addr, 15) {
                    Ok(b) => b,
                    Err(_) => break,
                };
                let mut dec = Decoder::with_ip(bitness, &chunk, addr, DecoderOptions::NONE);
                dec.decode_out(&mut insn);
                if insn.is_invalid() {
                    lines.push(format!(
                            "{{\"address\":\"{:#018x}\",\"raw\":\"{:02x}\",\"text\":\".byte 0x{:02x}\",\"is_pc\":false}}",
                            addr, chunk[0], chunk[0]
                        ));
                    addr += 1;
                    continue;
                }
                let mut out = String::new();
                fmt.format(&insn, &mut out);
                let raw_str: String = chunk[..insn.len()]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                let is_pc = addr == s.engine.state.get(Register::RIP);
                lines.push(format!(
                    "{{\"address\":\"{:#018x}\",\"raw\":\"{}\",\"text\":\"{}\",\"is_pc\":{}}}",
                    addr,
                    raw_str,
                    out.replace('"', "\\\""),
                    is_pc
                ));
                addr += insn.len() as u64;
            }
            ok_json(format!("{{\"lines\":[{}]}}", lines.join(",")))
        }
        FfiCommand::ReadMemory { address, size } => {
            let sz = size.min(4096);
            match s.engine.memory.read(address, sz) {
                Ok(bytes) => {
                    let hex = bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    ok_json(format!(
                        "{{\"address\":{},\"hex\":\"{}\",\"size\":{}}}",
                        address,
                        hex,
                        bytes.len()
                    ))
                }
                Err(e) => err_json(e.to_string()),
            }
        }
        FfiCommand::WriteMemory { address, hex_data } => {
            let hex_clean = hex_data.replace(" ", "").replace("\n", "");
            let mut data = Vec::with_capacity(hex_clean.len() / 2);
            for i in (0..hex_clean.len()).step_by(2) {
                if i + 2 > hex_clean.len() {
                    break;
                }
                if let Ok(b) = u8::from_str_radix(&hex_clean[i..i + 2], 16) {
                    data.push(b);
                } else {
                    return err_json("invalid hex".to_string());
                }
            }
            match s.engine.memory.write_raw(address, &data) {
                Ok(_) => ok_json(format!("{{\"written\":{}}}", data.len())),
                Err(e) => err_json(e.to_string()),
            }
        }
        FfiCommand::SetRegister { register, value } => {
            let r = match register.to_lowercase().as_str() {
                "rax" => Register::RAX,
                "rbx" => Register::RBX,
                "rcx" => Register::RCX,
                "rdx" => Register::RDX,
                "rsi" => Register::RSI,
                "rdi" => Register::RDI,
                "rbp" => Register::RBP,
                "rsp" => Register::RSP,
                "r8" => Register::R8,
                "r9" => Register::R9,
                "r10" => Register::R10,
                "r11" => Register::R11,
                "r12" => Register::R12,
                "r13" => Register::R13,
                "r14" => Register::R14,
                "r15" => Register::R15,
                "rip" => Register::RIP,
                _ => return err_json(format!("unknown register: {}", register)),
            };
            s.engine.state.set(r, value);
            ok_json("{}".to_string())
        }
        FfiCommand::Breakpoint { target } => {
            let is_addr = target.starts_with("0x") || target.chars().all(|c| c.is_ascii_digit());
            let addr = if is_addr {
                u64::from_str_radix(target.trim_start_matches("0x"), 16)
                    .or_else(|_| target.parse())
                    .unwrap_or(0)
            } else {
                match s.resolve_symbol(&target) {
                    Some(a) => a,
                    None => return err_json(format!("symbol not found: {}", target)),
                }
            };
            match s.add_breakpoint(addr) {
                Ok(id) => ok_json(format!("{{\"id\":{},\"address\":{}}}", id, addr)),
                Err(e) => err_json(e.to_string()),
            }
        }
        FfiCommand::RemoveBreakpoint { id } => match s.remove_breakpoint(id) {
            Ok(_) => ok_json("{}".to_string()),
            Err(e) => err_json(e.to_string()),
        },
        FfiCommand::TraceEnable { enabled } => {
            if enabled {
                s.engine.enable_tracing();
            } else {
                s.engine.disable_tracing();
            }
            ok_json("{}".to_string())
        }
        FfiCommand::ReverseStep => match s.engine.reverse_step() {
            Some(r) => step_response_json(&r),
            None => err_json("no trace available".to_string()),
        },
        FfiCommand::ReverseContinue => match s.engine.reverse_continue() {
            Some(r) => step_response_json(&r),
            None => err_json("no trace available".to_string()),
        },
        FfiCommand::ScanMemory { pattern } => {
            let parts: Vec<&str> = pattern.split_whitespace().collect();
            let mut needle = Vec::with_capacity(parts.len());
            let mut mask = Vec::with_capacity(parts.len());
            for p in parts {
                if p == "??" || p == "?" {
                    needle.push(0);
                    mask.push(false);
                } else if let Ok(b) = u8::from_str_radix(p, 16) {
                    needle.push(b);
                    mask.push(true);
                } else {
                    return err_json(format!("invalid hex in pattern: {p}"));
                }
            }
            if needle.is_empty() {
                return err_json("empty pattern".to_string());
            }
            let mut hits = Vec::new();
            for region in s.engine.memory.regions() {
                if region.size == 0 {
                    continue;
                }
                if let Ok(data) = s.engine.memory.read(region.base, region.size as usize) {
                    'outer: for i in 0..data.len().saturating_sub(needle.len() - 1) {
                        for j in 0..needle.len() {
                            if mask[j] && data[i + j] != needle[j] {
                                continue 'outer;
                            }
                        }
                        hits.push(format!("{{\"address\":{}}}", region.base + i as u64));
                        if hits.len() >= 1000 {
                            break;
                        }
                    }
                }
                if hits.len() >= 1000 {
                    break;
                }
            }
            ok_json(format!(
                "{{\"hits\":[{}],\"count\":{}}}",
                hits.join(","),
                hits.len()
            ))
        }
        FfiCommand::SetFlavor { flavor } => {
            s.config.disassembly_flavor = match flavor.to_lowercase().as_str() {
                "att" | "at&t" | "gas" => omnisec_debugger::DisassemblyFlavor::Att,
                _ => omnisec_debugger::DisassemblyFlavor::Intel,
            };
            ok_json("{}".to_string())
        }
    });

    into_raw(result_json)
}

/// Free a string previously returned by this library.
///
/// # Safety
/// `ptr` must be either NULL or a pointer previously returned by another function in this library.
/// Calling this function twice on the same pointer is undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_debugger_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}
