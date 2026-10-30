//! C-ABI FFI bridge for calling the symbolic executor from Go via CGO.

#![allow(unsafe_code)]

use std::slice;

use crate::executor::{MirInsn, MirOp, SymBlock, SymbolicExecutor};

/// FFI result type.
#[repr(C)]
pub struct ByteSlice {
    /// Pointer to JSON result buffer.
    pub ptr: *mut u8,
    /// Length of the buffer.
    pub len: u64,
}

/// MIR instruction as received from Go (C-compatible layout).
#[repr(C)]
pub struct FfiMirInsn {
    /// Opcode kind.
    pub kind: u8,
    /// Condition code.
    pub cond: u8,
    /// Padding.
    pub _pad: [u8; 2],
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

/// Block descriptor from Go.
#[repr(C)]
pub struct FfiBlock {
    /// Block ID.
    pub id: u32,
    /// Number of instructions.
    pub insn_count: u32,
    /// Pointer to instructions array.
    pub insns: *const FfiMirInsn,
    /// Number of successors.
    pub succ_count: u32,
    /// Pointer to successor IDs array.
    pub succs: *const u32,
}

/// Run symbolic execution on a set of blocks.
///
/// # Safety
/// All pointers must be valid for the specified lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_symbolic_execute(
    blocks_ptr: *const FfiBlock,
    blocks_count: u32,
    entry_id: u32,
    reg_count: u32,
    max_depth: u32,
    max_paths: u32,
    out: *mut ByteSlice,
) {
    if out.is_null() {
        return;
    }
    // A panic on crafted input must degrade to the empty result, never
    // unwind across the C-ABI boundary.
    if omnisec_core::ffi_guard::catch_panic(
        || {
            symbolic_execute_impl(
                blocks_ptr,
                blocks_count,
                entry_id,
                reg_count,
                max_depth,
                max_paths,
                out,
            )
        },
        || unsafe {
            let err: &[u8] = br#"{"error": "symbolic execution panicked"}"#;
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

unsafe fn symbolic_execute_impl(
    blocks_ptr: *const FfiBlock,
    blocks_count: u32,
    entry_id: u32,
    reg_count: u32,
    max_depth: u32,
    max_paths: u32,
    out: *mut ByteSlice,
) {
    if blocks_ptr.is_null() {
        return;
    }

    let ffi_blocks = unsafe { slice::from_raw_parts(blocks_ptr, blocks_count as usize) };

    let blocks: Vec<SymBlock> = ffi_blocks
        .iter()
        .map(|fb| {
            let insns = if fb.insns.is_null() || fb.insn_count == 0 {
                Vec::new()
            } else {
                let ffi_insns = unsafe { slice::from_raw_parts(fb.insns, fb.insn_count as usize) };
                ffi_insns
                    .iter()
                    .map(|fi| MirInsn {
                        kind: MirOp::from(fi.kind),
                        cond: fi.cond,
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

            SymBlock {
                id: fb.id as usize,
                insns,
                succs,
            }
        })
        .collect();

    let mut executor = SymbolicExecutor::new(blocks, entry_id as usize, reg_count as usize);
    if max_depth > 0 {
        executor.set_max_depth(max_depth as usize);
    }
    if max_paths > 0 {
        executor.set_max_paths(max_paths as usize);
    }

    let result = executor.execute();

    let json_bytes = omnisec_json::to_json_vec(&result);

    let len = json_bytes.len() as u64;
    let boxed = json_bytes.into_boxed_slice();
    let ptr = Box::into_raw(boxed).cast::<u8>();

    unsafe {
        (*out).ptr = ptr;
        (*out).len = len;
    }
}

/// Free a result from `omnisec_symbolic_execute`.
///
/// # Safety
/// Pointer must have been returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_free_symbolic_result(result: ByteSlice) {
    if !result.ptr.is_null() {
        let slice = unsafe { slice::from_raw_parts_mut(result.ptr, result.len as usize) };
        drop(unsafe { Box::from_raw(std::ptr::from_mut::<[u8]>(slice)) });
    }
}
