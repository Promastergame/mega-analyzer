//! C-ABI FFI bridge for calling the virtualization detector from Go via CGO.

#![allow(unsafe_code)]

use std::slice;

use crate::detector::{MirOp, VirtBlock, VirtInsn, VirtualizationDetector};

/// FFI result type.
#[repr(C)]
pub struct ByteSlice {
    /// Pointer to JSON result buffer.
    pub ptr: *mut u8,
    /// Length of the buffer.
    pub len: u64,
}

/// MIR instruction from Go.
#[repr(C)]
pub struct FfiVirtInsn {
    /// Opcode.
    pub kind: u8,
    /// Padding.
    pub _pad: [u8; 3],
    /// Destination register.
    pub dst: i16,
    /// Source register 1.
    pub src1: i16,
    /// Source register 2.
    pub src2: i16,
    /// Padding.
    pub _pad2: [u8; 2],
    /// Immediate value.
    pub imm: i64,
    /// Reference index.
    pub ref_idx: u32,
    /// Padding.
    pub _pad3: [u8; 4],
}

/// Block from Go.
#[repr(C)]
pub struct FfiVirtBlock {
    /// Block ID.
    pub id: u32,
    /// Instruction count.
    pub insn_count: u32,
    /// Instructions pointer.
    pub insns: *const FfiVirtInsn,
    /// Successor count.
    pub succ_count: u32,
    /// Successors pointer.
    pub succs: *const u32,
}

/// Run virtualization detection.
///
/// # Safety
/// All pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_detect_virtualization(
    blocks_ptr: *const FfiVirtBlock,
    blocks_count: u32,
    confidence_threshold: u8,
    out: *mut ByteSlice,
) {
    if out.is_null() {
        return;
    }
    // A panic on crafted input must degrade to the empty result, never
    // unwind across the C-ABI boundary.
    if omnisec_core::ffi_guard::catch_panic(
        || detect_virtualization_impl(blocks_ptr, blocks_count, confidence_threshold, out),
        || unsafe {
            let err: &[u8] = br#"{"error": "virtualization detection panicked"}"#;
            let len = err.len() as u64;
            let boxed = err.to_vec().into_boxed_slice();
            (*out).ptr = Box::into_raw(boxed).cast::<u8>();
            (*out).len = len;
        },
    )
    .is_none()
    {
        return;
    }
}

unsafe fn detect_virtualization_impl(
    blocks_ptr: *const FfiVirtBlock,
    blocks_count: u32,
    confidence_threshold: u8,
    out: *mut ByteSlice,
) {
    if blocks_ptr.is_null() {
        return;
    }

    let ffi_blocks = unsafe { slice::from_raw_parts(blocks_ptr, blocks_count as usize) };

    let blocks: Vec<VirtBlock> = ffi_blocks
        .iter()
        .map(|fb| {
            let insns = if fb.insns.is_null() || fb.insn_count == 0 {
                Vec::new()
            } else {
                let ffi_insns = unsafe { slice::from_raw_parts(fb.insns, fb.insn_count as usize) };
                ffi_insns
                    .iter()
                    .map(|fi| VirtInsn {
                        kind: MirOp::from(fi.kind),
                        dst: fi.dst,
                        src1: fi.src1,
                        src2: fi.src2,
                        imm: fi.imm,
                        ref_idx: fi.ref_idx,
                    })
                    .collect()
            };

            let succs = if fb.succs.is_null() || fb.succ_count == 0 {
                Vec::new()
            } else {
                let ffi_succs = unsafe { slice::from_raw_parts(fb.succs, fb.succ_count as usize) };
                ffi_succs.iter().map(|&s| s as usize).collect()
            };

            VirtBlock {
                id: fb.id as usize,
                insns,
                succs,
            }
        })
        .collect();

    let mut detector = VirtualizationDetector::new(blocks);
    if confidence_threshold > 0 {
        detector.set_confidence_threshold(confidence_threshold);
    }
    let result = detector.detect();

    let json_bytes = omnisec_json::to_json_vec(&result);

    let len = json_bytes.len() as u64;
    let boxed = json_bytes.into_boxed_slice();
    let ptr = Box::into_raw(boxed).cast::<u8>();

    unsafe {
        (*out).ptr = ptr;
        (*out).len = len;
    }
}

/// Free a result from `omnisec_detect_virtualization`.
///
/// # Safety
/// Pointer must have been returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_free_virt_result(result: ByteSlice) {
    if !result.ptr.is_null() {
        let slice = unsafe { slice::from_raw_parts_mut(result.ptr, result.len as usize) };
        drop(unsafe { Box::from_raw(std::ptr::from_mut::<[u8]>(slice)) });
    }
}
