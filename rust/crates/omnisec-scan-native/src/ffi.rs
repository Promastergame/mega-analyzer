//! C-ABI FFI bridge for calling from Go via cgo.
//!
//! This module necessarily uses `unsafe` — it is the boundary between
//! Rust's safe world and Go's raw pointers.

#![allow(unsafe_code)]

use crate::{AetriumScanConfig, scan, scan_with_aetrium};
use omnisec_core::{Format, detect_format};
use omnisec_hdc::{AnchorStore, HyperVector};
use omnisec_loader::prelude::*;
use omnisec_loader_elf::ElfLoader;
use omnisec_loader_pe::PeLoader;
use std::slice;

/// Result struct returned across the FFI boundary.
#[repr(C)]
pub struct ByteSlice {
    /// Pointer to the JSON result buffer.
    pub ptr: *mut u8,
    /// Length of the buffer in bytes.
    pub len: u64,
}

/// Hand ownership of `bytes` to the caller through `out`. The caller must
/// release it with `omnisec_free_native_result`. Centralising this removes
/// the five near-identical `Box::into_raw` blocks that were copy-pasted
/// across every success path (each an opportunity to leak or double-free).
///
/// # Safety
/// `out` must be a valid, writable pointer to a `ByteSlice`.
unsafe fn write_result(out: *mut ByteSlice, bytes: Vec<u8>) {
    let len = bytes.len() as u64;
    let ptr = Box::into_raw(bytes.into_boxed_slice()).cast::<u8>();
    unsafe {
        (*out).ptr = ptr;
        (*out).len = len;
    }
}

/// Run the native scanner on a raw ELF or PE buffer.
///
/// # Safety
/// `elf_buf` must point to a valid buffer of at least `elf_len` bytes.
/// `out` must point to a valid, writable `ByteSlice` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_scan_native(
    elf_buf: *const u8,
    elf_len: u64,
    out: *mut ByteSlice,
) {
    if out.is_null() {
        return;
    }
    // A panic on crafted input must degrade to the empty result, never
    // unwind across the C-ABI boundary.
    if omnisec_core::ffi_guard::catch_panic(
        || scan_native_impl(elf_buf, elf_len, out),
        || unsafe { *out = empty_result_inner() },
    )
    .is_none()
    {
        return;
    }
}

unsafe fn scan_native_impl(elf_buf: *const u8, elf_len: u64, out: *mut ByteSlice) {
    if elf_buf.is_null() || elf_len == 0 {
        unsafe { *out = empty_result_inner() };
        return;
    }

    let bytes = unsafe { slice::from_raw_parts(elf_buf, elf_len as usize) };

    // Refuse pathologically large inputs up front so a crafted length can
    // never drive the scanner into multi-minute / multi-GB territory
    // across the FFI boundary.
    if bytes.len() > crate::limits::MAX_INPUT_SIZE {
        unsafe { *out = empty_result_inner() };
        return;
    }

    // Step 1: Detect format and dispatch to the right loader. Previously the
    // FFI only handled ELF — PE / `.dll` / `.exe` inputs went silently empty.
    let bin = if let Ok(b) = load_native_bytes(bytes) {
        b
    } else {
        unsafe { *out = empty_result_inner() };
        return;
    };

    // Step 2: Scan
    let report = if let Ok(r) = scan(&bin, bytes) {
        r
    } else {
        unsafe { *out = empty_result_inner() };
        return;
    };

    // Step 3: Serialize to JSON
    let json_bytes = omnisec_json::to_json_vec(&report);

    unsafe { write_result(out, json_bytes) };
}

/// Run the native scanner with ML-Aetrium and ML-Apli-Ex support.
///
/// # Safety
/// `elf_buf` and `anchor_buf` must be valid for their respective lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_scan_native_ext(
    elf_buf: *const u8,
    elf_len: u64,
    anchor_buf: *const u8,
    anchor_len: u64,
    enable_weaponization: u8,
    out: *mut ByteSlice,
) {
    if out.is_null() {
        return;
    }
    if omnisec_core::ffi_guard::catch_panic(
        || {
            scan_native_ext_impl(
                elf_buf,
                elf_len,
                anchor_buf,
                anchor_len,
                enable_weaponization,
                out,
            )
        },
        || unsafe { *out = empty_result_inner() },
    )
    .is_none()
    {
        return;
    }
}

unsafe fn scan_native_ext_impl(
    elf_buf: *const u8,
    elf_len: u64,
    anchor_buf: *const u8,
    anchor_len: u64,
    enable_weaponization: u8,
    out: *mut ByteSlice,
) {
    if elf_buf.is_null() || elf_len == 0 {
        unsafe { *out = empty_result_inner() };
        return;
    }

    let bytes = unsafe { slice::from_raw_parts(elf_buf, elf_len as usize) };

    // Refuse pathologically large inputs up front so a crafted length can
    // never drive the scanner into multi-minute / multi-GB territory
    // across the FFI boundary.
    if bytes.len() > crate::limits::MAX_INPUT_SIZE {
        unsafe { *out = empty_result_inner() };
        return;
    }

    // Step 1: Load via format-aware dispatch (ELF or PE).
    let bin = if let Ok(b) = load_native_bytes(bytes) {
        b
    } else {
        unsafe { *out = empty_result_inner() };
        return;
    };

    // Step 2: Load Anchors (if provided)
    let mut anchor_store = None;
    if !anchor_buf.is_null() && anchor_len > 0 {
        let a_bytes = unsafe { slice::from_raw_parts(anchor_buf, anchor_len as usize) };
        if let Ok(store) = omnisec_json::from_json_slice::<AnchorStore>(a_bytes) {
            anchor_store = Some(store);
        }
    }

    // Step 3: Scan
    let report_res = if let Some(ref store) = anchor_store {
        let mut config = AetriumScanConfig::new(store);
        config.enable_weaponization = enable_weaponization != 0;
        scan_with_aetrium(&bin, bytes, &config)
    } else {
        scan(&bin, bytes)
    };

    let report = if let Ok(r) = report_res {
        r
    } else {
        unsafe { *out = empty_result_inner() };
        return;
    };

    // Step 4: Serialize
    let json_bytes = omnisec_json::to_json_vec(&report);

    unsafe { write_result(out, json_bytes) };
}

/// Free a result previously returned by `omnisec_scan_native`.
///
/// # Safety
/// `result.ptr` must be a pointer previously returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_free_native_result(result: ByteSlice) {
    if !result.ptr.is_null() {
        let slice = unsafe { slice::from_raw_parts_mut(result.ptr, result.len as usize) };
        drop(unsafe { Box::from_raw(std::ptr::from_mut::<[u8]>(slice)) });
    }
}

/// Reinforce one anchor in a serialised store with a hypervector built
/// from a feature vector, and return the updated store as JSON.
///
/// This is the Rust half of the active-learning loop: when Go confirms a
/// finding, it ships the matched anchor name + the feature vector that
/// produced it. We:
///
///   1. Deserialise the existing anchor store.
///   2. Hash the feature vector into a deterministic sparse HV.
///   3. Call `AnchorStore::reinforce(name, hv)` so the anchor's running
///      counts incorporate the confirmed example.
///   4. Re-serialise the store and hand the new bytes back.
///
/// Returning the full updated store keeps the Go side authoritative for
/// persistence (it owns the JSON file path); this function is stateless
/// across calls. On any failure the output is `{}`.
///
/// # Safety
/// `anchor_buf`/`anchor_len`, `feature_buf`/`feature_len`, and `name_buf`/
/// `name_len` must all describe valid readable buffers. `out` must be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_reinforce_anchor(
    anchor_buf: *const u8,
    anchor_len: u64,
    name_buf: *const u8,
    name_len: u64,
    feature_buf: *const f64,
    feature_len: u64,
    out: *mut ByteSlice,
) {
    if out.is_null() {
        return;
    }
    if omnisec_core::ffi_guard::catch_panic(
        || {
            reinforce_anchor_impl(
                anchor_buf,
                anchor_len,
                name_buf,
                name_len,
                feature_buf,
                feature_len,
                out,
            )
        },
        || unsafe { *out = empty_result_inner() },
    )
    .is_none()
    {
        return;
    }
}

unsafe fn reinforce_anchor_impl(
    anchor_buf: *const u8,
    anchor_len: u64,
    name_buf: *const u8,
    name_len: u64,
    feature_buf: *const f64,
    feature_len: u64,
    out: *mut ByteSlice,
) {
    if anchor_buf.is_null() || name_buf.is_null() || feature_buf.is_null() {
        unsafe { *out = empty_result_inner() };
        return;
    }

    let anchor_bytes = unsafe { slice::from_raw_parts(anchor_buf, anchor_len as usize) };
    let name_bytes = unsafe { slice::from_raw_parts(name_buf, name_len as usize) };
    let features = unsafe { slice::from_raw_parts(feature_buf, feature_len as usize) };

    let Ok(name) = std::str::from_utf8(name_bytes) else {
        unsafe { *out = empty_result_inner() };
        return;
    };

    let mut store = if let Ok(s) = omnisec_json::from_json_slice::<AnchorStore>(anchor_bytes) {
        s
    } else {
        unsafe { *out = empty_result_inner() };
        return;
    };

    let hv = features_to_hv(features);
    if !store.reinforce(name, &hv) {
        // Anchor name not in store — keep the input intact rather than
        // silently mutating, but the caller can detect the no-op by the
        // returned signature being unchanged.
        let json = omnisec_json::to_json_vec(&store);
        unsafe { write_result(out, json) };
        return;
    }

    let json = omnisec_json::to_json_vec(&store);
    unsafe { write_result(out, json) };
}

/// Map a feature vector into the HDC sparse hypervector space.
///
/// The mapping is deliberately simple and deterministic:
///
/// * Each feature contributes a "salt" derived from its index.
/// * The salt is mixed with a quantised version of the feature value
///   (so values cluster but extreme outliers shift the seed) to produce
///   a per-feature seed.
/// * The HVs of all non-zero features are XOR-bound together — this is
///   the canonical VSA way to combine a heterogeneous record into a
///   single HV without privileging any one slot.
///
/// This is *not* the full topology-aware encoder used in `omnisec-hdc`'s
/// SubgraphEncoder — it is the cheaper, schema-free encoder appropriate
/// for the active-learning path where the Go side has only flat features
/// and no guarantee about graph structure.
fn features_to_hv(features: &[f64]) -> HyperVector {
    if features.is_empty() {
        return HyperVector::zero();
    }
    let mut acc = HyperVector::zero();
    for (i, &v) in features.iter().enumerate() {
        if v == 0.0 || !v.is_finite() {
            continue;
        }
        // Quantise to 1e-3 to keep similar values in the same HV bucket.
        let q = (v * 1000.0).round() as i64;
        let mix = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ (q as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        acc = acc.bind(HyperVector::sparse(mix));
    }
    acc
}

fn empty_result_inner() -> ByteSlice {
    let json = b"{}".to_vec();
    let len = json.len() as u64;
    let boxed = json.into_boxed_slice();
    let ptr = Box::into_raw(boxed).cast::<u8>();
    ByteSlice { ptr, len }
}

/// Format-aware loader dispatch for the FFI surface.
///
/// Detects the binary format from the leading magic bytes and routes the
/// input to the matching loader implementation. Mirrors the dispatch in
/// `omnisec-loader::registry`, but kept inline here so the FFI doesn't
/// need to instantiate the full registry just to load one buffer.
fn load_native_bytes(bytes: &[u8]) -> omnisec_core::Result<LoadedBinary> {
    match detect_format(bytes) {
        Format::Pe => PeLoader::new().load(bytes),
        Format::Elf => ElfLoader::new().load(bytes),
        // Unknown / Mach-O / DEX / etc — try ELF first, then PE; this
        // mirrors the original behaviour for ambiguous inputs and keeps
        // the existing test suite green.
        _ => ElfLoader::new()
            .load(bytes)
            .or_else(|_| PeLoader::new().load(bytes)),
    }
}
