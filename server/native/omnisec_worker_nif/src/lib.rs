//! Rust NIF worker for OmniSec Elixir server.
//!
//! This crate provides Erlang NIF functions that bridge the BEAM VM
//! to the omnisec analysis engines. All heavy analysis runs
//! on dirty CPU schedulers to avoid blocking normal BEAM schedulers.
//!
//! NIF plumbing (arg decoding/encoding, dirty-scheduler flags, the
//! `ErlNifEntry` table) is provided by the local zero-dependency
//! `nifshim` crate instead of `rustler` — see `native/nifshim` and
//! `src/entry.c`. Business logic below is unchanged from the original.

use nifshim::{decode, nif_entry};
use omnisec_ml_inference::{FeatureHasher, HotspotRanker, PatternMatcher};
use omnisec_ml_inference::pattern_matcher::VulnPattern;
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════════
// IMPLEMENTATION (pure Rust, no NIF types) — logic identical to the original
// ═══════════════════════════════════════════════════════════════════════════════

fn analyze_apk_impl(bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty() {
        return Err("empty input".to_string());
    }

    let is_dex = bytes.len() >= 8 && &bytes[0..4] == b"dex\n";
    let is_apk = bytes.len() >= 4 && &bytes[0..4] == b"PK\x03\x04";

    if !is_dex && !is_apk {
        return Err("unsupported format: expected DEX (dex\\n) or APK (PK\\x03\\x04)".to_string());
    }

    let dex_bytes: &[u8] = if is_dex {
        bytes
    } else {
        match find_dex_in_apk(bytes) {
            Some(dex) => dex,
            None => {
                let result = omnisec_json::json!({
                    "status": "error",
                    "engine": "omnisec-loader-dex",
                    "error": "no stored (uncompressed) classes.dex found in APK",
                });
                return Ok(omnisec_json::to_json_string(&result));
            }
        }
    };

    match omnisec_loader_dex::parser::DexParser::parse(dex_bytes) {
        Ok(parsed) => {
            let result = omnisec_json::json!({
                "status": "ok",
                "engine": "omnisec-loader-dex",
                "version": parsed.version,
                "class_count": parsed.classes.len(),
                "method_count": parsed.classes.iter()
                    .map(|c| c.direct_methods.len() + c.virtual_methods.len())
                    .sum::<usize>(),
                "string_count": parsed.strings.len(),
                "warnings": parsed.warnings,
                "parse_time_ms": parsed.metrics.parse_duration.as_millis() as u64,
            });
            Ok(omnisec_json::to_json_string(&result))
        }
        Err(e) => {
            let result = omnisec_json::json!({
                "status": "error",
                "engine": "omnisec-loader-dex",
                "error": e.to_string(),
            });
            Ok(omnisec_json::to_json_string(&result))
        }
    }
}

fn analyze_binary_impl(bytes: &[u8]) -> Result<String, String> {
    use omnisec_loader_elf::ElfLoader;
    use omnisec_loader::traits::Loader;

    if bytes.is_empty() {
        return Err("empty input".to_string());
    }

    let is_elf = bytes.len() >= 4 && &bytes[0..4] == b"\x7fELF";
    if !is_elf {
        let result = omnisec_json::json!({
            "status": "unsupported",
            "engine": "omnisec-scan-native",
            "error": "only ELF binaries are supported in this build",
            "size": bytes.len(),
        });
        return Ok(omnisec_json::to_json_string(&result));
    }

    let loader = ElfLoader::new();
    match loader.load(bytes) {
        Ok(loaded) => match omnisec_scan_native::scan(&loaded, bytes) {
            Ok(report) => {
                let result = omnisec_json::json!({
                    "status": "ok",
                    "engine": "omnisec-scan-native",
                    "size": bytes.len(),
                    "verdict": format!("{:?}", report.verdict),
                    "score": report.score,
                    "hardening": {
                        "nx": report.hardening.nx,
                        "pie": report.hardening.pie,
                        "stack_canary": report.hardening.stack_canary,
                        "relro": format!("{:?}", report.hardening.relro),
                        "stripped": report.hardening.stripped,
                    },
                    "finding_count": report.findings.len(),
                    "findings": report.findings.iter().take(50).map(|f| omnisec_json::json!({
                        "category": format!("{:?}", f.category),
                        "severity": format!("{:?}", f.severity),
                        "title": f.title,
                        "description": f.description,
                    })).collect::<Vec<_>>(),
                });
                Ok(omnisec_json::to_json_string(&result))
            }
            Err(e) => {
                let result = omnisec_json::json!({
                    "status": "error",
                    "engine": "omnisec-scan-native",
                    "error": e.to_string(),
                });
                Ok(omnisec_json::to_json_string(&result))
            }
        },
        Err(e) => {
            let result = omnisec_json::json!({
                "status": "error",
                "engine": "omnisec-loader-elf",
                "error": e.to_string(),
            });
            Ok(omnisec_json::to_json_string(&result))
        }
    }
}

/// Locate the raw bytes of `classes.dex` inside a minimal ZIP/APK buffer.
///
/// Only STORED entries (compression method 0) are returned: feeding the
/// compressed bytes of a deflated entry to `DexParser::parse` was a
/// guaranteed parse failure for every real-world APK, where `classes.dex`
/// is almost always deflated. Returns `None` for missing, deflated, or
/// data-descriptor entries so the caller reports a clear error instead.
fn find_dex_in_apk(apk: &[u8]) -> Option<&[u8]> {
    const LOCAL_HDR: &[u8] = b"PK\x03\x04";
    const DEX_NAME: &[u8] = b"classes.dex";

    let mut offset = 0usize;
    while offset + 30 < apk.len() {
        if &apk[offset..offset + 4] != LOCAL_HDR {
            offset += 1;
            continue;
        }
        let fname_len = u16::from_le_bytes([apk[offset + 26], apk[offset + 27]]) as usize;
        let extra_len = u16::from_le_bytes([apk[offset + 28], apk[offset + 29]]) as usize;
        let method = u16::from_le_bytes([apk[offset + 8], apk[offset + 9]]);
        let flags = u16::from_le_bytes([apk[offset + 6], apk[offset + 7]]);
        let fname_start = offset + 30;
        let fname_end = fname_start.checked_add(fname_len)?;
        if fname_end > apk.len() {
            break;
        }
        if &apk[fname_start..fname_end] == DEX_NAME {
            let data_start = fname_end.checked_add(extra_len)?;
            let comp_size = u32::from_le_bytes([
                apk[offset + 18],
                apk[offset + 19],
                apk[offset + 20],
                apk[offset + 21],
            ]) as usize;
            let data_end = data_start.checked_add(comp_size)?;
            if method == 0 && flags & 0x0008 == 0 && data_end <= apk.len() {
                return Some(&apk[data_start..data_end]);
            }
        }
        let comp_size = u32::from_le_bytes([
            apk[offset + 18],
            apk[offset + 19],
            apk[offset + 20],
            apk[offset + 21],
        ]) as usize;
        offset = offset
            .checked_add(30)?
            .checked_add(fname_len)?
            .checked_add(extra_len)?
            .checked_add(comp_size)?;
    }
    None
}

fn scan_patterns_impl(data: &[u8], patterns_json: &str) -> Result<String, String> {
    let patterns: Vec<VulnPattern> = omnisec_json::from_json_str(patterns_json)
        .map_err(|e| format!("invalid patterns JSON: {e}"))?;

    let matcher = PatternMatcher::new(patterns);
    let results = matcher.scan(data);

    Ok(omnisec_json::to_json_string(&results))
}

fn rank_hotspots_impl(request_json: &str) -> Result<String, String> {
    #[derive(omnisec_json::FromJson)]
    struct RankRequest {
        anchors: Vec<AnchorDef>,
        candidates: Vec<CandidateDef>,
        threshold: f64,
    }
    #[derive(omnisec_json::FromJson)]
    struct AnchorDef {
        name: String,
        vector: Vec<u64>,
        weight: f64,
    }
    #[derive(omnisec_json::FromJson)]
    struct CandidateDef {
        id: String,
        vector: Vec<u64>,
    }

    let req: RankRequest =
        omnisec_json::from_json_str(request_json).map_err(|e| format!("invalid request JSON: {e}"))?;

    let mut ranker = HotspotRanker::new(req.threshold);
    for a in req.anchors {
        ranker.add_anchor(a.name, a.vector, a.weight);
    }

    let candidates: Vec<(String, Vec<u64>)> =
        req.candidates.into_iter().map(|c| (c.id, c.vector)).collect();

    let result = ranker.rank(&candidates);
    Ok(omnisec_json::to_json_string(&result))
}

fn hash_features_impl(features_json: &str, seed: u64) -> Result<String, String> {
    let features: HashMap<String, u32> =
        omnisec_json::from_json_str(features_json).map_err(|e| format!("invalid features JSON: {e}"))?;

    let mut hasher = FeatureHasher::new(seed);
    let vector = hasher.hash_features(&features);

    Ok(omnisec_json::to_json_string(&vector))
}

fn predict_variable_name_impl(
    context_json: &str,
    database_json: &str,
    threshold: f64,
) -> Result<String, String> {
    let context: omnisec_hdc::VariableContext =
        omnisec_json::from_json_str(context_json).map_err(|e| format!("invalid context JSON: {e}"))?;
    let namer = omnisec_hdc::HdcNamer::from_json(database_json)
        .map_err(|e| format!("invalid database JSON: {e}"))?;
    let predictions = namer.predict_variable(&context, threshold);
    Ok(omnisec_json::to_json_string(&predictions))
}

fn predict_function_name_impl(
    context_json: &str,
    database_json: &str,
    threshold: f64,
) -> Result<String, String> {
    let context: omnisec_hdc::FunctionContext =
        omnisec_json::from_json_str(context_json).map_err(|e| format!("invalid context JSON: {e}"))?;
    let namer = omnisec_hdc::HdcNamer::from_json(database_json)
        .map_err(|e| format!("invalid database JSON: {e}"))?;
    let predictions = namer.predict_function(&context, threshold);
    Ok(omnisec_json::to_json_string(&predictions))
}

fn train_variable_name_impl(
    context_json: &str,
    database_json: &str,
    clean_name: String,
) -> Result<String, String> {
    let context: omnisec_hdc::VariableContext =
        omnisec_json::from_json_str(context_json).map_err(|e| format!("invalid context JSON: {e}"))?;
    let mut namer = omnisec_hdc::HdcNamer::from_json(database_json)
        .map_err(|e| format!("invalid database JSON: {e}"))?;
    namer.train_variable(&context, clean_name);
    Ok(namer.to_json())
}

fn train_function_name_impl(
    context_json: &str,
    database_json: &str,
    clean_name: String,
) -> Result<String, String> {
    let context: omnisec_hdc::FunctionContext =
        omnisec_json::from_json_str(context_json).map_err(|e| format!("invalid context JSON: {e}"))?;
    let mut namer = omnisec_hdc::HdcNamer::from_json(database_json)
        .map_err(|e| format!("invalid database JSON: {e}"))?;
    namer.train_function(&context, clean_name);
    Ok(namer.to_json())
}

fn ebpf_start_trace_impl(pid: Option<u32>) -> Result<u64, String> {
    omnisec_ebpf::start_session(pid).map_err(|e| e.to_string())
}

fn ebpf_poll_events_impl(session_id: u64) -> Result<String, String> {
    let events = omnisec_ebpf::poll_events(session_id).map_err(|e| e.to_string())?;
    Ok(omnisec_json::to_json_string(&events))
}

fn ebpf_stop_trace_impl(session_id: u64) -> Result<String, String> {
    let events = omnisec_ebpf::stop_session(session_id).map_err(|e| e.to_string())?;
    Ok(omnisec_json::to_json_string(&events))
}

fn scan_yara_impl(_rules_str: &str, _data: &[u8]) -> Result<String, String> {
    // Zero-dep build: `boreal` (YARA engine) removed. The NIF entry point is
    // kept so Elixir callers don't crash; they get a structured `unavailable`
    // status instead of matches.
    let result = omnisec_json::json!({
        "status": "unavailable",
        "matches": [],
        "reason": "yara engine removed for zero-dep build (boreal dependency eliminated)"
    });

    Ok(omnisec_json::to_json_string(&result))
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

nif_entry!(raw_analyze_apk, 1, |env, args| {
    let data = decode!(env, nifshim::get_binary(env, args[0]));
    match analyze_apk_impl(&data) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_analyze_binary, 1, |env, args| {
    let data = decode!(env, nifshim::get_binary(env, args[0]));
    match analyze_binary_impl(&data) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_scan_patterns, 2, |env, args| {
    let data = decode!(env, nifshim::get_binary(env, args[0]));
    let patterns_json = decode!(env, nifshim::get_string(env, args[1]));
    match scan_patterns_impl(&data, &patterns_json) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_rank_hotspots, 1, |env, args| {
    let request_json = decode!(env, nifshim::get_string(env, args[0]));
    match rank_hotspots_impl(&request_json) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_hash_features, 2, |env, args| {
    let features_json = decode!(env, nifshim::get_string(env, args[0]));
    let seed = decode!(env, nifshim::get_u64(env, args[1]));
    match hash_features_impl(&features_json, seed) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_health_check, 0, |env, _args| { nifshim::make_ok(env) });

nif_entry!(raw_scan_yara, 2, |env, args| {
    let rules_str = decode!(env, nifshim::get_string(env, args[0]));
    let data = decode!(env, nifshim::get_binary(env, args[1]));
    match scan_yara_impl(&rules_str, &data) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_predict_variable_name, 3, |env, args| {
    let context_json = decode!(env, nifshim::get_string(env, args[0]));
    let database_json = decode!(env, nifshim::get_string(env, args[1]));
    let threshold = decode!(env, nifshim::get_f64(env, args[2]));
    match predict_variable_name_impl(&context_json, &database_json, threshold) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_predict_function_name, 3, |env, args| {
    let context_json = decode!(env, nifshim::get_string(env, args[0]));
    let database_json = decode!(env, nifshim::get_string(env, args[1]));
    let threshold = decode!(env, nifshim::get_f64(env, args[2]));
    match predict_function_name_impl(&context_json, &database_json, threshold) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_train_variable_name, 3, |env, args| {
    let context_json = decode!(env, nifshim::get_string(env, args[0]));
    let database_json = decode!(env, nifshim::get_string(env, args[1]));
    let clean_name = decode!(env, nifshim::get_string(env, args[2]));
    match train_variable_name_impl(&context_json, &database_json, clean_name) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_train_function_name, 3, |env, args| {
    let context_json = decode!(env, nifshim::get_string(env, args[0]));
    let database_json = decode!(env, nifshim::get_string(env, args[1]));
    let clean_name = decode!(env, nifshim::get_string(env, args[2]));
    match train_function_name_impl(&context_json, &database_json, clean_name) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_ebpf_start_trace, 1, |env, args| {
    let pid = decode!(env, nifshim::get_option_u32(env, args[0]));
    match ebpf_start_trace_impl(pid) {
        Ok(v) => nifshim::make_u64(env, v),
        Err(e) => nifshim::make_str(env, &e),
    }
});

nif_entry!(raw_ebpf_poll_events, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match ebpf_poll_events_impl(session_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});

nif_entry!(raw_ebpf_stop_trace, 1, |env, args| {
    let session_id = decode!(env, nifshim::get_u64(env, args[0]));
    match ebpf_stop_trace_impl(session_id) {
        Ok(s) | Err(s) => nifshim::make_str(env, &s),
    }
});
