//! C-ABI exports for Go integration via cgo / FFI.
//!
//! Provides `gnn_model_load`, `gnn_model_free`, `gnn_model_infer`, and
//! `gnn_free_result` — the four functions declared in `include/omnisec_ml_gnn.h`.
#![allow(unsafe_code)]

use std::ffi::{CStr, c_char, c_void};
use std::ptr;

use crate::graph_tensor::{EdgeType, GraphTensor};
use crate::model::GnnModel;
use crate::weights::WeightStore;

/// FFI graph tensor matching `ffi_graph_tensor_t` in the C header.
#[repr(C)]
pub struct FfiGraphTensor {
    /// CSR row pointers (u64 from Go side).
    pub row_ptrs: *const u64,
    /// Length of `row_ptrs` array.
    pub row_ptrs_len: u64,
    /// CSR column indices (u64 from Go side).
    pub col_indices: *const u64,
    /// Length of `col_indices` array.
    pub col_indices_len: u64,
    /// Edge types aligned with `col_indices`.
    pub edge_types: *const u32,
    /// Length of `edge_types` array.
    pub edge_types_len: u64,
    /// Flat node feature matrix (num_nodes × feature_dim, row-major).
    pub node_features: *const f32,
    /// Number of nodes.
    pub num_nodes: u64,
    /// Feature dimension per node.
    pub feature_dim: u64,
}

/// Load a GNN model from a weight file.
///
/// Both on-disk formats are accepted and told apart by extension: `.gnnbuf`
/// is the compact binary encoding, anything else is parsed as JSON. Only JSON
/// used to be attempted, so passing the `.gnnbuf` file this crate itself
/// writes — and which ships in the repository — failed the load and silently
/// skipped the whole GNN stage.
///
/// If `path` is `"__dummy__"`, creates a Xavier-initialized dummy model.
/// Returns a heap-allocated `GnnModel` pointer, or null on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnn_model_load(path: *const c_char) -> *mut c_void {
    if path.is_null() {
        return ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let model = if path_str == "__dummy__" {
        match WeightStore::dummy(crate::model::ModelConfig::default()).to_model() {
            Ok(model) => model,
            Err(_) => return ptr::null_mut(),
        }
    } else {
        let is_gnnbuf = std::path::Path::new(path_str)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("gnnbuf"));
        let store = if is_gnnbuf {
            match WeightStore::load_gnnbuf(path_str) {
                Ok(s) => s,
                Err(_) => return ptr::null_mut(),
            }
        } else {
            match WeightStore::load_json(path_str) {
                Ok(s) => s,
                Err(_) => return ptr::null_mut(),
            }
        };
        match store.to_model() {
            Ok(model) => model,
            Err(_) => return ptr::null_mut(),
        }
    };

    // The public C/Go ABI maps indices to the fixed eight VulnClass values.
    // Reject otherwise-valid research models here instead of letting callers
    // mislabel a different class schema at inference time.
    if model.config.num_classes != 8 {
        return ptr::null_mut();
    }

    Box::into_raw(Box::new(model)).cast::<c_void>()
}

/// Free a previously loaded model.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnn_model_free(model: *mut c_void) {
    if !model.is_null() {
        unsafe {
            drop(Box::from_raw(model.cast::<GnnModel>()));
        }
    }
}

/// Run inference on a single graph tensor.
///
/// Writes the number of output classes into `*out_classes` and returns
/// a heap-allocated `f32` array of class probabilities. The caller must
/// free the result with [`gnn_free_result`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnn_model_infer(
    model: *mut c_void,
    graph: *const FfiGraphTensor,
    out_classes: *mut u64,
) -> *mut f32 {
    // A panic on a crafted tensor must degrade to the null result, never
    // unwind across the C-ABI boundary.
    match omnisec_core::ffi_guard::catch_panic(
        // SAFETY: `model`, `graph` and `out_classes` are validated inside
        // `gnn_model_infer_impl` before any dereference.
        || unsafe { gnn_model_infer_impl(model, graph, out_classes) },
        || {},
    ) {
        Some(result) => result,
        None => ptr::null_mut(),
    }
}

unsafe fn gnn_model_infer_impl(
    model: *mut c_void,
    graph: *const FfiGraphTensor,
    out_classes: *mut u64,
) -> *mut f32 {
    if model.is_null() || graph.is_null() || out_classes.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        *out_classes = 0;
    }

    let model = unsafe { &*(model as *const GnnModel) };
    let ffi = unsafe { &*graph };

    let (Ok(num_nodes), Ok(feature_dim), Ok(row_ptrs_len), Ok(col_indices_len), Ok(edge_types_len)) = (
        usize::try_from(ffi.num_nodes),
        usize::try_from(ffi.feature_dim),
        usize::try_from(ffi.row_ptrs_len),
        usize::try_from(ffi.col_indices_len),
        usize::try_from(ffi.edge_types_len),
    ) else {
        return ptr::null_mut();
    };

    if num_nodes == 0 || feature_dim == 0 || row_ptrs_len != num_nodes + 1 {
        return ptr::null_mut();
    }
    if ffi.row_ptrs.is_null() || ffi.node_features.is_null() {
        return ptr::null_mut();
    }
    if col_indices_len > 0 && ffi.col_indices.is_null() {
        return ptr::null_mut();
    }
    if edge_types_len > 0 && ffi.edge_types.is_null() {
        return ptr::null_mut();
    }
    let Some(feature_count) = num_nodes.checked_mul(feature_dim) else {
        return ptr::null_mut();
    };

    let row_ptrs_u64 = unsafe { std::slice::from_raw_parts(ffi.row_ptrs, row_ptrs_len) };
    let col_indices_u64 = if col_indices_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(ffi.col_indices, col_indices_len) }
    };
    let edge_types_u32 = if edge_types_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(ffi.edge_types, edge_types_len) }
    };
    let features_raw = unsafe { std::slice::from_raw_parts(ffi.node_features, feature_count) };
    let Some(expected_feature_dim) = model.config.layers.first().map(|layer| layer.features_in)
    else {
        return ptr::null_mut();
    };
    let Some(graph_tensor) = prepare_graph_tensor(
        row_ptrs_u64,
        col_indices_u64,
        edge_types_u32,
        features_raw,
        num_nodes,
        feature_dim,
        expected_feature_dim,
    ) else {
        return ptr::null_mut();
    };

    // Attention scores never cross the FFI boundary (only class
    // probabilities do), so skip computing them entirely.
    let Ok(prediction) = model.predict_no_attention(&graph_tensor) else {
        return ptr::null_mut();
    };

    let probs = prediction.class_probs;
    let len = probs.len();
    let probability_sum: f32 = probs.iter().sum();
    if len != 8
        || probs
            .iter()
            .any(|probability| !probability.is_finite() || !(0.0..=1.0).contains(probability))
        || !probability_sum.is_finite()
        || (probability_sum - 1.0).abs() > 1e-3
    {
        return ptr::null_mut();
    }
    let out = alloc_f32_array(len);
    if out.is_null() {
        unsafe {
            *out_classes = 0;
        }
        return ptr::null_mut();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(probs.as_ptr(), out, len);
    }

    unsafe {
        *out_classes = len as u64;
    }
    out
}

/// Zero-dependency replacement for `libc::malloc` / `libc::free`.
///
/// Layout: `[u64 len][f32 data...]`, 8-byte aligned. The length prefix lets
/// `free_f32_array` rebuild the `Layout` without the caller passing the size
/// (mirrors malloc/free semantics over `std::alloc`, std-only).
fn alloc_f32_array(len: usize) -> *mut f32 {
    use std::alloc::{Layout, alloc};
    if len == 0 {
        return ptr::null_mut();
    }
    let Some(byte_len) = len.checked_mul(std::mem::size_of::<f32>()) else {
        return ptr::null_mut();
    };
    let Some(total) = byte_len.checked_add(std::mem::size_of::<u64>()) else {
        return ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, std::mem::align_of::<u64>()) else {
        return ptr::null_mut();
    };
    // SAFETY: layout is non-zero; pointer checked for null below.
    let raw = unsafe { alloc(layout) };
    if raw.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (raw as *mut u64).write(len as u64);
        raw.add(std::mem::size_of::<u64>()) as *mut f32
    }
}

/// Frees a pointer from [`alloc_f32_array`]. No-op on null.
unsafe fn free_f32_array(ptr: *mut f32) {
    use std::alloc::{Layout, dealloc};
    if ptr.is_null() {
        return;
    }
    // SAFETY: `ptr` came from `alloc_f32_array`, so the 8 bytes before it
    // hold the length and the whole allocation uses the layout below.
    unsafe {
        let raw = (ptr as *mut u8).sub(std::mem::size_of::<u64>());
        let len = (raw as *const u64).read() as usize;
        let byte_len = len.wrapping_mul(std::mem::size_of::<f32>());
        let total = byte_len.wrapping_add(std::mem::size_of::<u64>());
        if let Ok(layout) = Layout::from_size_align(total, std::mem::align_of::<u64>()) {
            dealloc(raw, layout);
        }
    }
}

fn decode_edge_type(value: u32) -> Option<EdgeType> {
    match value {
        0 => Some(EdgeType::ControlFlow),
        1 => Some(EdgeType::DataDependency),
        2 => Some(EdgeType::Call),
        3 => Some(EdgeType::Return),
        4 => Some(EdgeType::SelfLoop),
        _ => None,
    }
}

fn edge_type_order(edge_type: EdgeType) -> u8 {
    match edge_type {
        EdgeType::ControlFlow => 0,
        EdgeType::DataDependency => 1,
        EdgeType::Call => 2,
        EdgeType::Return => 3,
        EdgeType::SelfLoop => 4,
    }
}

/// Validate the foreign CSR tensor and rebuild it row-by-row. Rebuilding is
/// required when adding missing self-loops: appending them globally and only
/// shifting row pointers assigns each new edge to the wrong CSR row.
#[allow(clippy::too_many_arguments)]
fn prepare_graph_tensor(
    row_ptrs: &[u64],
    col_indices: &[u64],
    edge_type_values: &[u32],
    features: &[f32],
    num_nodes: usize,
    feature_dim: usize,
    expected_feature_dim: usize,
) -> Option<GraphTensor> {
    if num_nodes == 0
        || num_nodes > u32::MAX as usize
        || feature_dim == 0
        || feature_dim != expected_feature_dim
        || row_ptrs.len() != num_nodes.checked_add(1)?
        || row_ptrs.first().copied()? != 0
        || usize::try_from(row_ptrs.last().copied()?).ok()? != col_indices.len()
        || (!edge_type_values.is_empty() && edge_type_values.len() != col_indices.len())
        || features.len() != num_nodes.checked_mul(feature_dim)?
        || features.iter().any(|value| !value.is_finite())
    {
        return None;
    }
    if row_ptrs.windows(2).any(|window| window[0] > window[1]) {
        return None;
    }

    // Single pass with one reusable scratch row: avoids allocating a Vec per
    // node (the previous version built a Vec<Vec<..>> and then flattened it).
    let capacity = col_indices.len().checked_add(num_nodes)?; // worst-case self-loops
    if capacity > u32::MAX as usize {
        return None;
    }
    let mut row_ptr = Vec::with_capacity(num_nodes + 1);
    let mut col_idx = Vec::with_capacity(capacity);
    let mut edge_types = Vec::with_capacity(capacity);
    row_ptr.push(0);
    let mut scratch: Vec<(u32, EdgeType)> = Vec::new();
    for node in 0..num_nodes {
        let start = usize::try_from(row_ptrs[node]).ok()?;
        let end = usize::try_from(row_ptrs[node + 1]).ok()?;
        if end > col_indices.len() {
            return None;
        }
        scratch.clear();
        for edge_index in start..end {
            let column = u32::try_from(col_indices[edge_index]).ok()?;
            if column as usize >= num_nodes {
                return None;
            }
            let edge_type = if edge_type_values.is_empty() {
                EdgeType::ControlFlow
            } else {
                decode_edge_type(edge_type_values[edge_index])?
            };
            scratch.push((column, edge_type));
        }
        let node_column = node as u32;
        // Match `Csr::build_into`: any (i, i) edge counts as the self entry,
        // regardless of its type — otherwise inference would double-count.
        if !scratch.iter().any(|&(column, _)| column == node_column) {
            scratch.push((node_column, EdgeType::SelfLoop));
        }
        scratch.sort_by_key(|&(column, edge_type)| (column, edge_type_order(edge_type)));
        for &(column, edge_type) in &scratch {
            col_idx.push(column);
            edge_types.push(edge_type);
        }
        row_ptr.push(u32::try_from(col_idx.len()).ok()?);
    }

    Some(GraphTensor {
        num_nodes,
        row_ptr,
        col_idx,
        edge_types,
        node_features: features.to_vec(),
        feature_dims: feature_dim,
    })
}

/// Free a result array returned by [`gnn_model_infer`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnn_free_result(result: *mut f32) {
    if !result.is_null() {
        unsafe {
            free_f32_array(result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_self_loops_are_inserted_in_their_own_rows() {
        let graph = prepare_graph_tensor(&[0, 1, 2], &[1, 0], &[0, 0], &[0.0; 4], 2, 2, 2)
            .expect("valid graph");

        assert_eq!(graph.row_ptr, vec![0, 2, 4]);
        assert_eq!(graph.col_idx, vec![0, 1, 0, 1]);
        assert_eq!(
            graph.edge_types,
            vec![
                EdgeType::SelfLoop,
                EdgeType::ControlFlow,
                EdgeType::ControlFlow,
                EdgeType::SelfLoop,
            ]
        );
        // Edge weights are NOT stored on the tensor: the propagation matrix
        // is recomputed by `build_normalized_csr` at inference time.
        assert_eq!(graph.num_edges(), 4);
    }

    #[test]
    fn malformed_foreign_graphs_are_rejected() {
        let features = [0.0; 4];
        assert!(prepare_graph_tensor(&[0, 2, 1], &[0], &[], &features, 2, 2, 2).is_none());
        assert!(prepare_graph_tensor(&[0, 1, 1], &[2], &[], &features, 2, 2, 2).is_none());
        assert!(prepare_graph_tensor(&[0, 1, 1], &[0], &[99], &features, 2, 2, 2).is_none());
        assert!(prepare_graph_tensor(&[0, 1, 1], &[0], &[], &features, 2, 2, 3).is_none());
    }
}
