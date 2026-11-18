//! Browser ABI: the same trained model and inference implementation as native.
//! Buffers live in this module's memory; no filesystem or WASI is required.
#![allow(unsafe_code)]
use crate::weights::WeightStore;
use std::alloc::{Layout, alloc, dealloc};
use std::ffi::c_void;
use std::ptr;

#[unsafe(no_mangle)]
pub extern "C" fn gnn_wasm_alloc(length: usize) -> *mut u8 {
    if length == 0 || length > 64 * 1024 * 1024 {
        return ptr::null_mut();
    }
    match Layout::from_size_align(length, 16) {
        Ok(layout) => unsafe { alloc(layout) },
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnn_wasm_free(pointer: *mut u8, length: usize) {
    if !pointer.is_null() && length > 0 {
        if let Ok(layout) = Layout::from_size_align(length, 16) {
            unsafe {
                dealloc(pointer, layout);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnn_model_load_bytes(pointer: *const u8, length: usize) -> *mut c_void {
    if pointer.is_null() || length == 0 || length > 16 * 1024 * 1024 {
        return ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return ptr::null_mut();
    };
    let Ok(store) = omnisec_json::from_json_str::<WeightStore>(text) else {
        return ptr::null_mut();
    };
    if store.validate().is_err() {
        return ptr::null_mut();
    }
    let Ok(model) = store.to_model() else {
        return ptr::null_mut();
    };
    if model.config.num_classes != crate::taxonomy::NUM_CLASSES {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(model)).cast::<c_void>()
}
