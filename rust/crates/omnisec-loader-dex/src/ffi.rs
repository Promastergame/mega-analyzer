//! C-ABI FFI bridge for calling the DEX parser from Go via CGO.
//!
//! Exposes `omnisec_parse_dex` and `omnisec_free_dex_result`.

#![allow(unsafe_code)]

use std::slice;

use crate::parser::DexParser;

/// Result struct returned across the FFI boundary.
#[repr(C)]
pub struct ByteSlice {
    /// Pointer to the JSON result buffer.
    pub ptr: *mut u8,
    /// Length of the buffer in bytes.
    pub len: u64,
}

/// Parse a DEX file and return JSON result.
///
/// # Safety
/// `dex_buf` must point to a valid buffer of at least `dex_len` bytes.
/// `out` must point to a valid, writable `ByteSlice` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_parse_dex(dex_buf: *const u8, dex_len: u64, out: *mut ByteSlice) {
    if out.is_null() {
        return;
    }
    // A panic on crafted DEX input must degrade to the error result, never
    // unwind across the C-ABI boundary.
    if omnisec_core::ffi_guard::catch_panic(
        || unsafe { parse_dex_impl(dex_buf, dex_len, out) },
        || unsafe { write_byte_slice(out, br#"{"error": "parser panicked"}"#.as_slice()) },
    )
    .is_none()
    {
        return;
    }
}

/// Serialise `bytes` into `out` the same way the success path does.
///
/// # Safety
/// `out` must point to a valid, writable `ByteSlice` structure.
unsafe fn write_byte_slice(out: *mut ByteSlice, bytes: &[u8]) {
    let len = bytes.len() as u64;
    let boxed = bytes.to_vec().into_boxed_slice();
    let ptr = Box::into_raw(boxed).cast::<u8>();
    unsafe {
        (*out).ptr = ptr;
        (*out).len = len;
    }
}

unsafe fn parse_dex_impl(dex_buf: *const u8, dex_len: u64, out: *mut ByteSlice) {
    if dex_buf.is_null() {
        return;
    }

    let data = unsafe { slice::from_raw_parts(dex_buf, dex_len as usize) };

    let result = match DexParser::parse(data) {
        Ok(parsed) => omnisec_json::to_json_vec(&parsed),
        Err(e) => {
            let err = format!("{{\"error\": \"{e}\"}}");
            err.into_bytes()
        }
    };

    let len = result.len() as u64;
    let boxed = result.into_boxed_slice();
    let ptr = Box::into_raw(boxed).cast::<u8>();

    unsafe {
        (*out).ptr = ptr;
        (*out).len = len;
    }
}

/// Free a result previously returned by `omnisec_parse_dex`.
///
/// # Safety
/// `result.ptr` must be a pointer previously returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_free_dex_result(result: ByteSlice) {
    if !result.ptr.is_null() {
        let slice = unsafe { slice::from_raw_parts_mut(result.ptr, result.len as usize) };
        drop(unsafe { Box::from_raw(std::ptr::from_mut::<[u8]>(slice)) });
    }
}
