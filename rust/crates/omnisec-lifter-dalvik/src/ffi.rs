//! C-ABI FFI bridge for calling from Go via cgo.
//!
//! This module necessarily uses `unsafe` — it is the boundary between
//! Rust's safe world and Go's raw pointers.

#![allow(unsafe_code)]

use std::slice;

use omnisec_cfg::{BlockKind, build_cfg};
use omnisec_deobfuscator::{DeobfuscationPipeline, PipelineConfig};

use crate::lifter::DalvikLifter;

/// Result struct returned across the FFI boundary.
#[repr(C)]
pub struct ByteSlice {
    /// Pointer to the JSON result buffer.
    pub ptr: *mut u8,
    /// Length of the buffer in bytes.
    pub len: u64,
}

/// Deobfuscate a method's MIR instructions.
///
/// # Safety
/// `mir_buf` must point to a valid buffer of at least `mir_len` bytes.
/// `out` must point to a valid, writable `ByteSlice` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_deobfuscate_v3(
    mir_buf: *const u8,
    mir_len: u64,
    mode: u8,
    out: *mut ByteSlice,
) {
    if out.is_null() {
        return;
    }
    // A panic on crafted input must degrade to the empty result, never
    // unwind across the C-ABI boundary.
    if omnisec_core::ffi_guard::catch_panic(
        || deobfuscate_v3_impl(mir_buf, mir_len, mode, out),
        || unsafe { *out = empty_result_inner() },
    )
    .is_none()
    {
        return;
    }
}

unsafe fn deobfuscate_v3_impl(mir_buf: *const u8, mir_len: u64, mode: u8, out: *mut ByteSlice) {
    if mir_buf.is_null() || mir_len == 0 {
        unsafe { *out = empty_result_inner() };
        return;
    }

    let buf = unsafe { slice::from_raw_parts(mir_buf, mir_len as usize) };

    // Step 1: Lift MIR → OmniIR
    let instructions = DalvikLifter::lift_method(buf);
    if instructions.is_empty() {
        unsafe { *out = empty_result_inner() };
        return;
    }

    // Step 2: Build CFG
    let entry_addr = instructions.first().map_or(0, |i| i.address);
    let mut cfg = if let Ok(cfg) = build_cfg(&instructions, entry_addr) {
        cfg
    } else {
        // [DEBUG CLEANUP]
        unsafe { *out = empty_result_inner() };
        return;
    };

    // Step 3: Run deobfuscation pipeline
    let config = match mode {
        0 => PipelineConfig::fast(),
        2 => PipelineConfig::aggressive(),
        _ => PipelineConfig::default(),
    };
    let pipeline = DeobfuscationPipeline::new(config);
    let result = pipeline.run(&mut cfg);

    // Step 4: Serialize result to JSON
    let json = omnisec_json::json!({
        "debug_mir_len": mir_len,
        "debug_insn_count": instructions.len(),
        "converged": result.converged,
        "iterations": result.stats.iterations,
        "instructions_before": result.stats.instructions_before,
        "instructions_after": result.stats.instructions_after,
        "blocks_before": result.stats.blocks_before,
        "blocks_after": result.stats.blocks_after,
        "constants_resolved": result.stats.total_constants_resolved,
        "opaque_predicates_removed": result.stats.total_opaque_predicates_removed,
        "patterns_applied": result.stats.total_patterns_applied,
        "strings_decrypted": result.stats.total_strings_decrypted,
        "mba_simplified": result.stats.total_mba_simplified,
        "reduction_percent": result.stats.reduction_percent(),
        "duration_ms": result.stats.total_duration.as_millis(),
    });

    let json_bytes = omnisec_json::to_string(&json).into_bytes();
    let len = json_bytes.len() as u64;
    let boxed = json_bytes.into_boxed_slice();
    let ptr = Box::into_raw(boxed).cast::<u8>();

    unsafe {
        (*out).ptr = ptr;
        (*out).len = len;
    }
}

/// Free a result previously returned by `omnisec_deobfuscate_method`.
///
/// # Safety
/// `result.ptr` must be a pointer previously returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_free_result(result: ByteSlice) {
    if !result.ptr.is_null() {
        let slice = unsafe { slice::from_raw_parts_mut(result.ptr, result.len as usize) };
        drop(unsafe { Box::from_raw(std::ptr::from_mut::<[u8]>(slice)) });
    }
}

fn empty_result_inner() -> ByteSlice {
    let json = b"{}".to_vec();
    let len = json.len() as u64;
    let boxed = json.into_boxed_slice();
    let ptr = Box::into_raw(boxed).cast::<u8>();
    ByteSlice { ptr, len }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CFG construction (offload Go's BuildCFG onto Rust)
//
// Plan v11.0 — Task #3 (Rust FFI Bridge): the Go `BuildCFG` walks every MIR
// instruction twice and allocates a `*BasicBlock` per leader; on a 50k-method
// APK that's hundreds of millions of pointer-laden allocations and the GC
// dominates the profile. By pushing it through the same FFI boundary already
// used by `omnisec_deobfuscate_v3`, we get monomorphic, arena-style block
// storage and no Go heap traffic.
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a CFG from a packed MIR buffer and return the structure as JSON.
///
/// The buffer must use the same 40-byte packed layout as
/// `omnisec_deobfuscate_v3` (see `lifter::lift_one`). Output JSON has the
/// shape:
/// ```json
/// {
///   "block_count": <usize>,
///   "edge_count": <usize>,
///   "entry": <u32>,
///   "blocks": [
///     {
///       "id": <u32>,
///       "start_address": <u64>,
///       "end_address": <u64>,
///       "kind": "entry" | "exit" | "unresolved_exit" | "normal",
///       "instruction_count": <usize>,
///       "successors": [<u32>, ...],
///       "predecessors": [<u32>, ...]
///     }, ...
///   ],
///   "reverse_postorder": [<u32>, ...],
///   "reachable": [<u32>, ...]
/// }
/// ```
///
/// `{}` is returned on any failure (empty input, invalid layout, bad CFG).
///
/// # Safety
/// `mir_buf` must point to a valid buffer of at least `mir_len` bytes.
/// `out` must point to a valid, writable `ByteSlice` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_build_cfg(mir_buf: *const u8, mir_len: u64, out: *mut ByteSlice) {
    if out.is_null() {
        return;
    }
    // A panic on crafted input must degrade to the empty result, never
    // unwind across the C-ABI boundary.
    if omnisec_core::ffi_guard::catch_panic(
        || build_cfg_impl(mir_buf, mir_len, out),
        || unsafe { *out = empty_result_inner() },
    )
    .is_none()
    {
        return;
    }
}

unsafe fn build_cfg_impl(mir_buf: *const u8, mir_len: u64, out: *mut ByteSlice) {
    if mir_buf.is_null() || mir_len == 0 {
        unsafe { *out = empty_result_inner() };
        return;
    }

    let buf = unsafe { slice::from_raw_parts(mir_buf, mir_len as usize) };

    let instructions = DalvikLifter::lift_method(buf);
    if instructions.is_empty() {
        unsafe { *out = empty_result_inner() };
        return;
    }

    let entry_addr = instructions.first().map_or(0, |i| i.address);
    let cfg = if let Ok(cfg) = build_cfg(&instructions, entry_addr) {
        cfg
    } else {
        unsafe { *out = empty_result_inner() };
        return;
    };

    let blocks: Vec<_> = cfg
        .iter()
        .map(|(id, b)| {
            let kind_str = match b.kind {
                BlockKind::Entry => "entry",
                BlockKind::Exit => "exit",
                BlockKind::UnresolvedExit => "unresolved_exit",
                BlockKind::Normal => "normal",
            };
            omnisec_json::json!({
                "id": id,
                "start_address": b.start_address,
                "end_address": b.end_address,
                "kind": kind_str,
                "instruction_count": b.len(),
                "successors": cfg.successors(id),
                "predecessors": cfg.predecessors(id),
            })
        })
        .collect();

    let rpo = cfg.reverse_postorder();
    let reachable: Vec<u32> = {
        let mut v: Vec<u32> = cfg.reachable_from_entry().into_iter().collect();
        v.sort_unstable();
        v
    };

    let json = omnisec_json::json!({
        "block_count": cfg.block_count(),
        "edge_count": cfg.edge_count(),
        "entry": cfg.entry(),
        "blocks": blocks,
        "reverse_postorder": rpo,
        "reachable": reachable,
    });

    let json_bytes = omnisec_json::to_string(&json).into_bytes();
    let len = json_bytes.len() as u64;
    let boxed = json_bytes.into_boxed_slice();
    let ptr = Box::into_raw(boxed).cast::<u8>();

    unsafe {
        (*out).ptr = ptr;
        (*out).len = len;
    }
}

/// Free a result returned by `omnisec_build_cfg`.
///
/// # Safety
/// `result.ptr` must be a pointer previously returned by this library
/// from `omnisec_build_cfg` (or any other function in this crate that
/// returns a `ByteSlice` — they share the same allocator path).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_free_cfg_result(result: ByteSlice) {
    if !result.ptr.is_null() {
        let slice = unsafe { slice::from_raw_parts_mut(result.ptr, result.len as usize) };
        drop(unsafe { Box::from_raw(std::ptr::from_mut::<[u8]>(slice)) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_const(buf: &mut [u8], offset: u32, dst: i16, imm: i64) {
        // kind = 4 (CONST/MOVE-imm in lifter table), data layout matches
        // `lift_one`.
        buf[0] = 4;
        buf[4..8].copy_from_slice(&offset.to_le_bytes());
        buf[8..10].copy_from_slice(&dst.to_le_bytes());
        buf[16..24].copy_from_slice(&imm.to_le_bytes());
    }

    fn write_return(buf: &mut [u8], offset: u32) {
        // kind = 22 → OpCode::Return (terminator)
        buf[0] = 22;
        buf[4..8].copy_from_slice(&offset.to_le_bytes());
    }

    #[test]
    fn build_cfg_round_trip_emits_valid_json() {
        // Two instructions: const + return. Single straight-line block.
        let mut buf = [0u8; 80];
        write_const(&mut buf[..40], 0x1000, 0, 42);
        write_return(&mut buf[40..], 0x1002);

        let mut out = ByteSlice {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        unsafe {
            omnisec_build_cfg(buf.as_ptr(), buf.len() as u64, &raw mut out);
        }

        assert!(!out.ptr.is_null());
        assert!(out.len > 0);

        let json_bytes = unsafe { slice::from_raw_parts(out.ptr, out.len as usize) };
        let value: omnisec_json::JsonValue = omnisec_json::from_json_slice(json_bytes).unwrap();
        assert_eq!(value["block_count"].as_u64().unwrap(), 1);
        assert!(value["blocks"].is_array());

        unsafe { omnisec_free_cfg_result(out) };
    }

    #[test]
    fn build_cfg_handles_empty_input() {
        let mut out = ByteSlice {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        unsafe {
            omnisec_build_cfg(std::ptr::null(), 0, &raw mut out);
        }
        assert!(!out.ptr.is_null());
        let bytes = unsafe { slice::from_raw_parts(out.ptr, out.len as usize) };
        assert_eq!(bytes, b"{}");
        unsafe { omnisec_free_cfg_result(out) };
    }

    #[test]
    fn build_cfg_handles_null_out() {
        // Must not crash when caller passes a null `out` pointer.
        unsafe {
            omnisec_build_cfg(std::ptr::null(), 0, std::ptr::null_mut());
        }
    }
}
