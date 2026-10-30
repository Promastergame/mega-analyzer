//! FFI exports — C-ABI functions callable from Go via cgo.
//!
//! All functions follow the OmniSec FFI convention:
//! - Input: raw byte pointer + length
//! - Output: `ByteSlice` (ptr + len) containing JSON
//! - Caller must free with `omnisec_free_ml_result`

use crate::pattern_matcher::VulnPattern;
use crate::{FeatureHasher, HotspotRanker, PatternMatcher};
use std::collections::HashMap as FxHashMap;
use std::slice;

/// FFI result type shared across all OmniSec Rust libraries.
#[repr(C)]
pub struct ByteSlice {
    ptr: *mut u8,
    len: u64,
}

/// Helper: serialize to JSON and return as FFI ByteSlice.
fn json_result<T: omnisec_json::ToJson + ?Sized>(value: &T) -> ByteSlice {
    let bytes = omnisec_json::to_json_vec(value);
    let len = bytes.len() as u64;
    let boxed = bytes.into_boxed_slice();
    let ptr = Box::into_raw(boxed).cast::<u8>();
    ByteSlice { ptr, len }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN MATCHER FFI
// ═══════════════════════════════════════════════════════════════════════════════

/// Load patterns from JSON and scan a data buffer.
///
/// # Safety
/// `patterns_json` must point to valid JSON bytes of length `patterns_len`.
/// `data_ptr` must point to valid bytes of length `data_len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_ml_pattern_scan(
    patterns_json: *const u8,
    patterns_len: u64,
    data_ptr: *const u8,
    data_len: u64,
    out: *mut ByteSlice,
) {
    // A panic on crafted input must degrade to the null result, never
    // unwind across the C-ABI boundary.
    let result = omnisec_core::ffi_guard::catch_panic(
        || -> Option<ByteSlice> {
            if patterns_json.is_null() || data_ptr.is_null() || out.is_null() {
                return None;
            }

            let patterns_bytes =
                unsafe { slice::from_raw_parts(patterns_json, patterns_len as usize) };
            let data = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) };

            let patterns: Vec<VulnPattern> = omnisec_json::from_json_slice(patterns_bytes).ok()?;
            let matcher = PatternMatcher::new(patterns);
            let results = matcher.scan(data);

            Some(json_result(&results))
        },
        || {},
    );

    if let Some(Some(res)) = result {
        unsafe { *out = res };
    } else if !out.is_null() {
        unsafe {
            *out = ByteSlice {
                ptr: std::ptr::null_mut(),
                len: 0,
            }
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE HASHER FFI
// ═══════════════════════════════════════════════════════════════════════════════

/// Hash a JSON feature map into an HDC hypervector.
///
/// Input JSON: `{"permission:SMS": 1, "api:DexClassLoader": 3}`
/// Output JSON: `[u64, u64, ...]` (128 words = 8192-bit vector)
///
/// # Safety
/// `features_json` must point to valid JSON bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_ml_hash_features(
    features_json: *const u8,
    features_len: u64,
    seed: u64,
    out: *mut ByteSlice,
) {
    // A panic on crafted input must degrade to the null result, never
    // unwind across the C-ABI boundary.
    let result = omnisec_core::ffi_guard::catch_panic(
        || -> Option<ByteSlice> {
            if features_json.is_null() || out.is_null() {
                return None;
            }

            let bytes = unsafe { slice::from_raw_parts(features_json, features_len as usize) };
            let features: FxHashMap<String, u32> = omnisec_json::from_json_slice(bytes).ok()?;

            let mut hasher = FeatureHasher::new(seed);
            let vector = hasher.hash_features(&features);

            Some(json_result(&vector))
        },
        || {},
    );

    if let Some(Some(res)) = result {
        unsafe { *out = res };
    } else if !out.is_null() {
        unsafe {
            *out = ByteSlice {
                ptr: std::ptr::null_mut(),
                len: 0,
            }
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOTSPOT RANKER FFI
// ═══════════════════════════════════════════════════════════════════════════════

/// Rank candidates against anchors.
///
/// Input: JSON with `{ "anchors": [...], "candidates": [...], "threshold": 0.3 }`
/// Output: JSON `RankingResult`
///
/// # Safety
/// `request_json` must point to valid JSON bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_ml_rank_hotspots(
    request_json: *const u8,
    request_len: u64,
    out: *mut ByteSlice,
) {
    use omnisec_json::FromJson;

    #[derive(FromJson)]
    struct RankRequest {
        anchors: Vec<AnchorDef>,
        candidates: Vec<CandidateDef>,
        threshold: f64,
    }

    #[derive(FromJson)]
    struct AnchorDef {
        name: String,
        vector: Vec<u64>,
        weight: f64,
    }

    #[derive(FromJson)]
    struct CandidateDef {
        id: String,
        vector: Vec<u64>,
    }

    // A panic on crafted input must degrade to the null result, never
    // unwind across the C-ABI boundary.
    let result = omnisec_core::ffi_guard::catch_panic(
        || -> Option<ByteSlice> {
            if request_json.is_null() || out.is_null() {
                return None;
            }

            let bytes = unsafe { slice::from_raw_parts(request_json, request_len as usize) };

            let req: RankRequest = omnisec_json::from_json_slice(bytes).ok()?;

            let mut ranker = HotspotRanker::new(req.threshold);
            for a in req.anchors {
                ranker.add_anchor(a.name, a.vector, a.weight);
            }

            let candidates: Vec<(String, Vec<u64>)> = req
                .candidates
                .into_iter()
                .map(|c| (c.id, c.vector))
                .collect();

            let result = ranker.rank(&candidates);
            Some(json_result(&result))
        },
        || {},
    );

    if let Some(Some(res)) = result {
        unsafe { *out = res };
    } else if !out.is_null() {
        unsafe {
            *out = ByteSlice {
                ptr: std::ptr::null_mut(),
                len: 0,
            }
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MEMORY MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

/// Free a result returned by any `omnisec_ml_*` function.
///
/// # Safety
/// `result` must have been returned by an `omnisec_ml_*` function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_free_ml_result(result: ByteSlice) {
    if !result.ptr.is_null() && result.len > 0 {
        let _ = unsafe {
            Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                result.ptr,
                result.len as usize,
            ))
        };
    }
}
