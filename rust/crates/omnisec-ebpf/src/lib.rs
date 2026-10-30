//! eBPF system-call tracer and kernel instrumentation.
//!
//! Backend selection is explicit and honest:
//!
//! - Linux: [`Backend::Procfs`] collects real telemetry from `/proc`
//!   (process status, current syscall, open file descriptors, TCP flows).
//!   No kernel hooks, but every event is a genuine observation.
//! - Non-Linux hosts: [`Backend::Simulator`] stages nothing by itself.
//!   Deterministic fixtures for integration tests live behind the explicit
//!   [`dev_fixture_events`] helper (and `#[cfg(test)]`), never in the
//!   production start path.
//!
//! [`Backend::Aya`] (kernel tracing via the `aya` crate) was retired in
//! the zero-dep pass: it required Linux + a compiled BPF object +
//! root/CAP_BPF simultaneously, and `probe()` now always selects
//! `Procfs` on Linux. The enum variant and the `aya_usable`/`aya_reason`
//! report fields are kept for serialized-API compatibility.
//!
//! [`EbpfCapabilities::probe`] reports which path will be taken and why.

#![allow(missing_docs)]
#![forbid(unsafe_code)]

use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap as FxHashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════════════
// EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// System call event intercepted in kernel space (or observed via `/proc`).
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct SyscallEvent {
    /// Timestamp in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Thread ID (PID inside kernel).
    pub pid: u32,
    /// Process ID (TGID inside kernel).
    pub tgid: u32,
    /// Command/Process name.
    pub comm: String,
    /// Syscall identifier name (e.g., "openat", "execve", "connect").
    pub syscall_name: String,
    /// Formatted arguments.
    pub args: Vec<String>,
    /// Return value (for sys_exit events).
    pub return_value: Option<i64>,
    /// Event source: `"procfs"`, `"simulator"` (`"aya:ringbuf"` retired).
    #[json(default = "default_source")]
    pub source: String,
    /// `true` for synthetic development fixtures (see [`dev_fixture_events`]).
    #[json(default)]
    pub simulated: bool,
    /// Monotonic sequence number within the session.
    #[json(default)]
    pub seq: u64,
}

fn default_source() -> String {
    "unknown".to_string()
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CAPABILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/// Which collection backend the host supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
pub enum Backend {
    /// Retired: kernel eBPF via `aya` (removed in the zero-dep pass).
    /// Kept for serialized-API compatibility; never selected by `probe()`.
    Aya,
    /// Real `/proc` telemetry (Linux, no BPF object required).
    Procfs,
    /// Empty staging session (non-Linux development hosts).
    Simulator,
}

/// Host capability report for the tracer.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct EbpfCapabilities {
    /// Backend that [`start_session`] will select.
    pub backend: Backend,
    /// Whether kernel tracing (aya) is usable right now.
    pub aya_usable: bool,
    /// Why aya is (un)usable.
    pub aya_reason: String,
    /// Path of the BPF object when one was found.
    pub bpf_program: Option<String>,
    /// Whether `/proc` observation is available.
    pub procfs_available: bool,
}

impl EbpfCapabilities {
    #[must_use]
    pub fn probe() -> Self {
        #[cfg(not(target_os = "linux"))]
        {
            return Self {
                backend: Backend::Simulator,
                aya_usable: false,
                aya_reason: "non-Linux kernel: eBPF is Linux-only".to_string(),
                bpf_program: None,
                procfs_available: false,
            };
        }

        #[cfg(target_os = "linux")]
        {
            Self::probe_linux()
        }
    }

    #[cfg(target_os = "linux")]
    fn probe_linux() -> Self {
        let procfs = std::path::Path::new("/proc/self/status").exists();
        let program = find_bpf_program();
        // Zero-dep build: the aya backend was retired, so kernel tracing is
        // never usable; Linux hosts always fall back to real /proc telemetry.
        // `bpf_program` is still reported for operator visibility.
        Self {
            backend: Backend::Procfs,
            aya_usable: false,
            aya_reason: "aya backend removed in zero-dep build; procfs fallback in use".to_string(),
            bpf_program: program,
            procfs_available: procfs,
        }
    }
}

#[cfg(target_os = "linux")]
fn find_bpf_program() -> Option<String> {
    if let Ok(p) = std::env::var("OMNISEC_EBPF_PROG") {
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    for candidate in [
        "/etc/omnisec/ebpf_prog.o",
        "/usr/lib/omnisec/ebpf_prog.o",
        "priv/native/ebpf_prog.o",
    ] {
        if std::path::Path::new(candidate).exists() {
            return Some(candidate.to_string());
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
// SESSIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Active tracing session.
pub struct EbpfTraceSession {
    /// Target PID being traced (None = system-wide tracing).
    pub target_pid: Option<u32>,
    /// Backend selected at start time.
    pub backend: Backend,
    /// Accumulated trace events buffer.
    pub events: Vec<SyscallEvent>,
    /// Next sequence number.
    pub next_seq: u64,
    /// Milliseconds since epoch at creation.
    pub created_ms: u64,
}

static SESSIONS: std::sync::LazyLock<Mutex<FxHashMap<u64, EbpfTraceSession>>> =
    std::sync::LazyLock::new(|| Mutex::new(FxHashMap::default()));

static NEXT_SESSION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Initialize a tracing session for a target process.
///
/// Selects the backend from [`EbpfCapabilities::probe`]: real `/proc`
/// telemetry on Linux, an empty staging session on non-Linux hosts.
/// Never injects fake events into the production path.
pub fn start_session(pid: Option<u32>) -> Result<u64, String> {
    let id = NEXT_SESSION_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let caps = EbpfCapabilities::probe();

    #[allow(unused_mut)]
    let mut session = EbpfTraceSession {
        target_pid: pid,
        backend: caps.backend,
        events: Vec::new(),
        next_seq: 0,
        created_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    };

    match caps.backend {
        Backend::Aya => {
            // Retired variant: `probe()` never selects it; the arm stays
            // for enum exhaustiveness (and old serialized payloads).
            return Err("aya backend removed in zero-dep build".to_string());
        }
        Backend::Procfs => {
            #[cfg(target_os = "linux")]
            procfs_backend::snapshot(&mut session)?;
        }
        Backend::Simulator => {
            // Intentionally empty: use dev_fixture_events() in tests.
        }
    }

    SESSIONS
        .lock()
        .map_err(|_| "mutex poisoned".to_string())?
        .insert(id, session);
    Ok(id)
}

/// Stop a tracing session and return its captured events.
pub fn stop_session(session_id: u64) -> Result<Vec<SyscallEvent>, String> {
    let mut lock = SESSIONS.lock().map_err(|_| "mutex poisoned")?;
    let session = lock.remove(&session_id).ok_or("invalid ebpf session id")?;
    Ok(session.events)
}

/// Poll new events from an active session.
///
/// On Linux procfs sessions this re-samples `/proc` so long-lived
/// sessions observe fresh state; simulator sessions drain staged events.
pub fn poll_events(session_id: u64) -> Result<Vec<SyscallEvent>, String> {
    // Refresh first (procfs), then drain — split borrows to keep it simple.
    #[cfg(target_os = "linux")]
    {
        let backend = {
            let lock = SESSIONS.lock().map_err(|_| "mutex poisoned")?;
            lock.get(&session_id)
                .map(|s| s.backend)
                .ok_or("invalid ebpf session id")?
        };
        if backend == Backend::Procfs {
            let mut lock = SESSIONS.lock().map_err(|_| "mutex poisoned")?;
            if let Some(session) = lock.get_mut(&session_id) {
                let _ = procfs_backend::snapshot(session);
            }
        }
    }
    let mut lock = SESSIONS.lock().map_err(|_| "mutex poisoned")?;
    let session = lock.get_mut(&session_id).ok_or("invalid ebpf session id")?;
    Ok(std::mem::take(&mut session.events))
}

/// Report the backend a session is using.
pub fn session_backend(session_id: u64) -> Result<Backend, String> {
    let lock = SESSIONS.lock().map_err(|_| "mutex poisoned")?;
    lock.get(&session_id)
        .map(|s| s.backend)
        .ok_or_else(|| "invalid ebpf session id".to_string())
}

/// Deterministic synthetic events for integration tests of the upper
/// layers (Elixir/Go). Explicitly marked `simulated: true` and never
/// used by [`start_session`].
#[must_use]
pub fn dev_fixture_events(pid: Option<u32>) -> Vec<SyscallEvent> {
    let target = pid.unwrap_or(9999);
    let base = now_ns();
    vec![
        SyscallEvent {
            timestamp_ns: base,
            pid: target,
            tgid: target,
            comm: "suspicious_bin".to_string(),
            syscall_name: "execve".to_string(),
            args: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "cat /etc/passwd".to_string(),
            ],
            return_value: Some(0),
            source: "simulator".to_string(),
            simulated: true,
            seq: 0,
        },
        SyscallEvent {
            timestamp_ns: base + 5_000_000,
            pid: target,
            tgid: target,
            comm: "sh".to_string(),
            syscall_name: "openat".to_string(),
            args: vec!["/etc/passwd".to_string(), "O_RDONLY".to_string()],
            return_value: Some(3),
            source: "simulator".to_string(),
            simulated: true,
            seq: 1,
        },
        SyscallEvent {
            timestamp_ns: base + 10_000_000,
            pid: target,
            tgid: target,
            comm: "sh".to_string(),
            syscall_name: "connect".to_string(),
            args: vec![
                "family=AF_INET".to_string(),
                "addr=192.168.1.100".to_string(),
                "port=4444".to_string(),
            ],
            return_value: Some(0),
            source: "simulator".to_string(),
            simulated: true,
            seq: 2,
        },
    ]
}

// ═══════════════════════════════════════════════════════════════════════════════
// LINUX PROCFS FALLBACK (real observations, no kernel hooks)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
mod procfs_backend {
    use super::*;

    pub fn snapshot(session: &mut EbpfTraceSession) -> Result<(), String> {
        let pid = session.target_pid.unwrap_or_else(std::process::id);
        let base = session.target_pid.map_or(true, |t| t == pid);
        let _ = base;

        push_status(session, pid);
        push_current_syscall(session, pid);
        push_listen_sockets(session, pid);
        Ok(())
    }

    fn emit(session: &mut EbpfTraceSession, comm: String, name: String, args: Vec<String>) {
        let seq = session.next_seq;
        session.next_seq += 1;
        let pid = session.target_pid.unwrap_or_else(std::process::id);
        session.events.push(SyscallEvent {
            timestamp_ns: now_ns(),
            pid,
            tgid: pid,
            comm,
            syscall_name: name,
            args,
            return_value: None,
            source: "procfs".to_string(),
            simulated: false,
            seq,
        });
    }

    fn comm_of(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| format!("pid:{pid}"))
    }

    fn push_status(session: &mut EbpfTraceSession, pid: u32) {
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            emit(
                session,
                comm_of(pid),
                "process_missing".to_string(),
                vec![format!("pid={pid}")],
            );
            return;
        };
        let mut state = String::from("?");
        let mut vm_rss = String::from("?");
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("State:") {
                state = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("VmRSS:") {
                vm_rss = v.trim().to_string();
            }
        }
        emit(
            session,
            comm_of(pid),
            "proc_status".to_string(),
            vec![format!("state={state}"), format!("rss={vm_rss}")],
        );
    }

    fn push_current_syscall(session: &mut EbpfTraceSession, pid: u32) {
        // /proc/<pid>/syscall: nr arg0 arg1 ... (blocked-task snapshot).
        let Ok(body) = std::fs::read_to_string(format!("/proc/{pid}/syscall")) else {
            return;
        };
        let fields: Vec<&str> = body.split_whitespace().collect();
        if fields.is_empty() {
            return;
        }
        emit(
            session,
            comm_of(pid),
            "current_syscall".to_string(),
            vec![format!("nr={}", fields[0])]
                .into_iter()
                .chain(fields[1..].iter().map(|a| (*a).to_string()))
                .collect(),
        );
    }

    fn push_listen_sockets(session: &mut EbpfTraceSession, pid: u32) {
        // Real flow telemetry: TCP sockets owned by the target via /proc/net/tcp.
        let inodes = task_inodes(pid);
        if inodes.is_empty() {
            return;
        }
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(body) = std::fs::read_to_string(table) else {
                continue;
            };
            for line in body.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 10 {
                    continue;
                }
                if inodes.iter().any(|ino| cols[9].contains(ino)) {
                    emit(
                        session,
                        comm_of(pid),
                        "tcp_socket".to_string(),
                        vec![
                            format!("local={}", cols[1]),
                            format!("remote={}", cols[2]),
                            format!("state={}", cols[3]),
                        ],
                    );
                }
            }
        }
    }

    fn task_inodes(pid: u32) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            return out;
        };
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                let s = link.to_string_lossy().into_owned();
                if s.starts_with("socket:[") {
                    out.push(s);
                }
            }
        }
        out
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_probe_is_structured() {
        let caps = EbpfCapabilities::probe();
        match caps.backend {
            Backend::Aya => assert!(caps.aya_usable),
            Backend::Procfs | Backend::Simulator => {}
        }
        assert!(!caps.aya_reason.is_empty());
    }

    #[test]
    fn session_lifecycle_roundtrip() {
        let id = start_session(None).expect("session starts on any host");
        let events = poll_events(id).expect("poll works");
        assert!(
            events.iter().all(|e| !e.simulated),
            "production path must not inject simulated events"
        );
        let drained = stop_session(id).expect("stop works");
        assert!(stop_session(id).is_err(), "double stop is an error");
        let _ = drained;
    }

    #[test]
    fn procfs_snapshot_observes_self() {
        #[cfg(target_os = "linux")]
        {
            let id = start_session(Some(std::process::id())).expect("self session");
            let events = stop_session(id).expect("stop");
            assert!(
                events.iter().any(|e| e.source == "procfs"),
                "procfs backend must produce real observations, got {events:?}"
            );
        }
    }

    #[test]
    fn dev_fixture_is_explicitly_simulated() {
        let events = dev_fixture_events(Some(4242));
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|e| e.simulated));
        assert!(events.iter().all(|e| e.source == "simulator"));
        assert_eq!(events[0].pid, 4242);
    }

    #[test]
    fn events_serialize_with_new_fields() {
        let events = dev_fixture_events(None);
        let json = omnisec_json::to_json_string(&events[0]);
        assert!(json.contains("simulated"));
        assert!(json.contains("source"));
        // Back-compat: old payloads without the new fields still parse.
        let legacy = r#"{"timestamp_ns":1,"pid":2,"tgid":2,"comm":"c",
            "syscall_name":"openat","args":[],"return_value":null}"#;
        let parsed: SyscallEvent = omnisec_json::from_json_str(legacy).expect("legacy parses");
        assert!(!parsed.simulated);
        assert_eq!(parsed.source, "unknown");
    }
}
