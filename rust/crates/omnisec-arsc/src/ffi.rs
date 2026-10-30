//! C ABI surface used by the Go side via cgo.
//!
//! Calls return JSON payloads through a heap-allocated buffer that
//! must be freed with `arsc_free_buffer`. This indirection avoids the
//! Go GC having to track Rust-owned memory and makes integration with
//! existing Go tooling straightforward — Go already speaks JSON for
//! every other crate boundary in this workspace.

#![allow(unsafe_code)]

use std::ffi::c_char;
use std::os::raw::c_int;
use std::ptr;
use std::slice;

use crate::{ArscError, parse_arsc};

/// Reusable result wrapper.
///
/// `ptr` is non-null when the call succeeds. `len` is the byte length
/// of the JSON payload. On failure both fields are zero and
/// `error_code` is populated.
#[repr(C)]
pub struct ArscResult {
    pub ptr: *mut c_char,
    pub len: usize,
    pub error_code: c_int,
}

impl ArscResult {
    fn err(code: c_int) -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            error_code: code,
        }
    }
}

/// Parses a `resources.arsc` blob and returns the decoded table as
/// JSON.
///
/// # Safety
///
/// `data` must point to at least `len` valid bytes. The returned
/// buffer must be freed via `arsc_free_buffer`. Calling with a null
/// `data` pointer is a usage error and returns an error result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arsc_parse(data: *const u8, len: usize) -> ArscResult {
    if data.is_null() || len == 0 {
        return ArscResult::err(1);
    }
    // A panic on crafted input must degrade to the error result, never
    // unwind across the C-ABI boundary.
    let guarded = omnisec_core::ffi_guard::catch_panic(|| arsc_parse_impl(data, len), || {});
    match guarded {
        Some(result) => result,
        None => ArscResult::err(99),
    }
}

unsafe fn arsc_parse_impl(data: *const u8, len: usize) -> ArscResult {
    // SAFETY: caller contract guarantees `len` valid bytes at `data`.
    let bytes = unsafe { slice::from_raw_parts(data, len) };
    match parse_arsc(bytes) {
        Ok(table) => {
            let json = omnisec_json::to_json_vec(&table);
            let len = json.len();
            let boxed = json.into_boxed_slice();
            let ptr = Box::into_raw(boxed).cast::<c_char>();
            ArscResult {
                ptr,
                len,
                error_code: 0,
            }
        }
        Err(ArscError::BadMagic(_, _)) => ArscResult::err(3),
        Err(ArscError::TooSmall(_)) => ArscResult::err(4),
        Err(ArscError::ChunkOverrun { .. }) => ArscResult::err(5),
        Err(_) => ArscResult::err(99),
    }
}

/// Frees a buffer returned by `arsc_parse`.
///
/// # Safety
///
/// `ptr` must come from a successful `arsc_parse` call and `len` must
/// match the value returned in `ArscResult.len`. Double-free is
/// undefined behaviour; the Go side wraps each call in
/// `runtime.SetFinalizer` to keep this contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arsc_free_buffer(ptr: *mut c_char, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: `ptr` was produced by `Box::into_raw` from a `Box<[u8]>`
    // of exactly `len` bytes and the caller pinky-promises not to
    // double-free.
    unsafe {
        let slice = slice::from_raw_parts_mut(ptr.cast::<u8>(), len);
        drop(Box::from_raw(slice));
    }
}
