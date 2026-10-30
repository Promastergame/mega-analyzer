//! Sparse Matrix-Vector Multiply (SpMV) — SIMD-accelerated kernels for GNN inference.
//!
//! GNN message-passing requires multiplying sparse adjacency matrices by dense
//! feature vectors. This module provides POPCNT/SIMD-optimized SpMV for the
//! Mega-Analyzer ML pipeline.
//!
//! Sparse format: CSR (Compressed Sparse Row) — standard for graph adjacency.
//!
//! Phase 1: CPU SIMD (AVX2/POPCNT). Phase 2: AVX-512 for server CPUs.

const std = @import("std");

fn checkedMul(a: usize, b: usize) ?usize {
    return std.math.mul(usize, a, b) catch null;
}

fn validateCsr(row_ptr: []const u32, col_idx: []const u32, rows: usize, nnz: usize, cols: usize) bool {
    if (row_ptr.len != rows + 1) return false;
    if (row_ptr[0] != 0) return false;

    var previous: usize = 0;
    for (row_ptr) |raw| {
        const current: usize = @as(usize, raw);
        if (current < previous or current > nnz) return false;
        previous = current;
    }
    if (previous != nnz) return false;

    for (col_idx) |col| {
        if (@as(usize, col) >= cols) return false;
    }
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CSR SPARSE MATRIX-VECTOR MULTIPLY
// ═══════════════════════════════════════════════════════════════════════════════

/// Sparse Matrix-Vector multiply in CSR format.
///
/// Computes y = A * x, where A is sparse (CSR) and x is dense.
///
/// CSR layout:
///   - `values`:    non-zero entries (length = nnz)
///   - `col_idx`:   column index for each non-zero (length = nnz)
///   - `row_ptr`:   start offset of each row in values/col_idx (length = rows + 1)
///   - `x`:         dense input vector (length = cols)
///   - `y`:         dense output vector (length = rows), OVERWRITTEN
pub fn spmv_f32(
    values: []const f32,
    col_idx: []const u32,
    row_ptr: []const u32,
    x: []const f32,
    y: []f32,
) void {
    const rows = y.len;
    for (0..rows) |i| {
        const start = row_ptr[i];
        const end = row_ptr[i + 1];
        var sum: f32 = 0.0;

        // Inner loop — hottest path, candidates for SIMD widening in Phase 2
        for (start..end) |idx| {
            const col = col_idx[idx];
            sum += values[idx] * x[col];
        }
        y[i] = sum;
    }
}

/// ReLU activation in-place: y[i] = max(0, y[i])
pub fn relu_f32(y: []f32) void {
    const zero: FVec = @splat(0.0);
    var i: usize = 0;
    while (i + LANES <= y.len) : (i += LANES) {
        const v: FVec = y[i..][0..LANES].*;
        y[i..][0..LANES].* = @max(v, zero);
    }
    while (i < y.len) : (i += 1) {
        if (y[i] < 0.0) y[i] = 0.0;
    }
}

/// Element-wise addition: y[i] += bias[i]
pub fn add_bias_f32(y: []f32, bias: []const f32) void {
    std.debug.assert(y.len == bias.len);
    var i: usize = 0;
    while (i + LANES <= y.len) : (i += LANES) {
        const a: FVec = y[i..][0..LANES].*;
        const b: FVec = bias[i..][0..LANES].*;
        y[i..][0..LANES].* = a + b;
    }
    while (i < y.len) : (i += 1) y[i] += bias[i];
}

/// L2-normalize a vector in-place: y[i] /= ||y||_2
pub fn l2_normalize_f32(y: []f32) void {
    var norm_sq: f32 = 0.0;
    for (y) |val| {
        norm_sq += val * val;
    }
    if (norm_sq < 1e-12) return;
    const inv_norm = 1.0 / @sqrt(norm_sq);
    for (y) |*val| {
        val.* *= inv_norm;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GNN MESSAGE PASSING LAYER
// ═══════════════════════════════════════════════════════════════════════════════

// ═══ SIMD helpers ═════════════════════════════════════════════════════════════════
//
// The module header has always advertised SIMD, but every kernel below was a
// scalar loop. The vector width is picked by the compiler for the target CPU
// (8 f32 with AVX2 on x86-64); the tail is handled scalar.

const LANES: usize = std.simd.suggestVectorLength(f32) orelse 4;
const FVec = @Vector(LANES, f32);

/// dst += a * src  (both slices have equal length)
inline fn axpy(dst: []f32, src: []const f32, a: f32) void {
    std.debug.assert(dst.len == src.len);
    const va: FVec = @splat(a);
    var i: usize = 0;
    while (i + LANES <= dst.len) : (i += LANES) {
        const s: FVec = src[i..][0..LANES].*;
        const d: FVec = dst[i..][0..LANES].*;
        dst[i..][0..LANES].* = d + va * s;
    }
    while (i < dst.len) : (i += 1) dst[i] += a * src[i];
}

/// Fused layer pass: the H·W projection is computed ONCE into `proj`
/// (nodes × features_out), followed by a single sweep over the CSR.
///
/// The per-column path recomputed that projection for every output feature,
/// i.e. it re-read the whole of `h_in` `features_out` times. At
/// features_out = 64 that is 64× the memory traffic for the same FLOP count,
/// which is what actually hurts once a graph stops fitting in L2.
fn gnnFused(
    adj_values: []const f32,
    adj_col_idx: []const u32,
    adj_row_ptr: []const u32,
    h_in: []const f32,
    features_in: usize,
    weights: []const f32,
    features_out: usize,
    bias: []const f32,
    h_out: []f32,
    proj: []f32,
) void {
    const nodes = adj_row_ptr.len - 1;
    @memset(proj, 0.0);

    // Step 1: proj = H · W, dense and row-major.
    for (0..nodes) |n| {
        const row = proj[n * features_out ..][0..features_out];
        const hrow = h_in[n * features_in ..][0..features_in];
        for (0..features_in) |f| {
            const a = hrow[f];
            // CFG node features are heavily one-hot, so skipping zeros pays
            // for the branch several times over.
            if (a == 0.0) continue;
            axpy(row, weights[f * features_out ..][0..features_out], a);
        }
    }

    // Step 2: aggregate over edges, then bias + ReLU.
    for (0..nodes) |i| {
        const out = h_out[i * features_out ..][0..features_out];
        @memset(out, 0.0);
        const start = adj_row_ptr[i];
        const end = adj_row_ptr[i + 1];
        for (start..end) |idx| {
            const col: usize = @as(usize, adj_col_idx[idx]);
            axpy(out, proj[col * features_out ..][0..features_out], adj_values[idx]);
        }
        for (0..features_out) |f| {
            const v = out[f] + bias[f];
            out[f] = if (v > 0.0) v else 0.0;
        }
    }
}

/// One layer of GNN message passing:
///   1. SpMV: aggregate neighbor features via adjacency (A * H)
///   2. Linear transform: multiply by weight matrix W
///   3. Bias + ReLU activation
///
/// This combines the hot-path operations into a single fused call.
pub fn gnn_message_pass(
    // Adjacency (CSR)
    adj_values: []const f32,
    adj_col_idx: []const u32,
    adj_row_ptr: []const u32,
    // Node features (dense, row-major: nodes × features_in)
    h_in: []const f32,
    features_in: usize,
    // Weight matrix (dense, row-major: features_in × features_out)
    weights: []const f32,
    features_out: usize,
    // Bias (length = features_out)
    bias: []const f32,
    // Output (dense, row-major: nodes × features_out)
    h_out: []f32,
    // Scratch buffer. At least `nodes`; pass `nodes * features_out` to
    // unlock the fused single-projection path.
    scratch: []f32,
) void {
    const nodes = adj_row_ptr.len - 1;
    if (nodes == 0 or features_in == 0 or features_out == 0) return;

    // Fast path: when the caller hands over scratch for the whole projection
    // matrix, compute H · W once. Otherwise fall through to the original
    // per-column path, so the existing omnisec_gnn_layer ABI is untouched.
    if (scratch.len >= nodes * features_out) {
        gnnFused(
            adj_values,
            adj_col_idx,
            adj_row_ptr,
            h_in,
            features_in,
            weights,
            features_out,
            bias,
            h_out,
            scratch[0 .. nodes * features_out],
        );
        return;
    }

    // For each output feature dimension
    for (0..features_out) |f_out| {
        // Step 1: Compute the f_out-th column of (H_in * W) for all nodes
        // by first extracting column weights, then SpMV
        for (0..nodes) |n| {
            var sum: f32 = 0.0;
            for (0..features_in) |f_in| {
                sum += h_in[n * features_in + f_in] * weights[f_in * features_out + f_out];
            }
            scratch[n] = sum;
        }

        // Step 2: Aggregate via adjacency: y = A * scratch
        // Temporary output column
        for (0..nodes) |i| {
            const start = adj_row_ptr[i];
            const end = adj_row_ptr[i + 1];
            var agg: f32 = 0.0;
            for (start..end) |idx| {
                const col = adj_col_idx[idx];
                agg += adj_values[idx] * scratch[col];
            }
            // Step 3: Bias + ReLU
            const val = agg + bias[f_out];
            h_out[i * features_out + f_out] = if (val > 0.0) val else 0.0;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// C ABI EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

/// C ABI: Sparse Matrix-Vector multiply (CSR format, f32).
pub export fn omnisec_spmv_f32(
    values: [*]const f32,
    col_idx: [*]const u32,
    row_ptr: [*]const u32,
    x_ptr: [*]const f32,
    y_ptr: [*]f32,
    rows: u32,
    nnz: u32,
    cols: u32,
) bool {
    if (rows == 0) return true;
    if (@intFromPtr(row_ptr) == 0 or @intFromPtr(y_ptr) == 0) return false;

    const rows_usize: usize = @as(usize, rows);
    const nnz_usize: usize = @as(usize, nnz);
    const cols_usize: usize = @as(usize, cols);
    const rptr_len = std.math.add(usize, rows_usize, 1) catch return false;
    const rptr_slice = row_ptr[0..rptr_len];
    const y_slice = y_ptr[0..rows_usize];

    if (nnz_usize == 0) {
        const empty_cols = [_]u32{};
        if (!validateCsr(rptr_slice, &empty_cols, rows_usize, 0, cols_usize)) return false;
        @memset(y_slice, 0.0);
        return true;
    }

    if (@intFromPtr(values) == 0 or @intFromPtr(col_idx) == 0 or @intFromPtr(x_ptr) == 0) return false;
    const vals_slice = values[0..nnz_usize];
    const cols_slice = col_idx[0..nnz_usize];
    const x_slice = x_ptr[0..cols_usize];
    if (!validateCsr(rptr_slice, cols_slice, rows_usize, nnz_usize, cols_usize)) return false;

    spmv_f32(vals_slice, cols_slice, rptr_slice, x_slice, y_slice);
    return true;
}

/// C ABI: GNN message passing layer.
pub export fn omnisec_gnn_layer(
    adj_values: [*]const f32,
    adj_col_idx: [*]const u32,
    adj_row_ptr: [*]const u32,
    h_in: [*]const f32,
    features_in: u32,
    weights: [*]const f32,
    features_out: u32,
    bias_ptr: [*]const f32,
    h_out: [*]f32,
    scratch: [*]f32,
    nodes: u32,
    nnz: u32,
) bool {
    if (nodes == 0 or features_in == 0 or features_out == 0) return true;
    if (@intFromPtr(adj_row_ptr) == 0) return false;
    if (@intFromPtr(h_in) == 0) return false;
    if (@intFromPtr(weights) == 0) return false;
    if (@intFromPtr(bias_ptr) == 0) return false;
    if (@intFromPtr(h_out) == 0) return false;
    if (@intFromPtr(scratch) == 0) return false;

    const nodes_usize: usize = @as(usize, nodes);
    const fin: usize = @as(usize, features_in);
    const fout: usize = @as(usize, features_out);
    const nnz_usize: usize = @as(usize, nnz);
    const row_len = std.math.add(usize, nodes_usize, 1) catch return false;
    const h_in_len = checkedMul(nodes_usize, fin) orelse return false;
    const weight_len = checkedMul(fin, fout) orelse return false;
    const h_out_len = checkedMul(nodes_usize, fout) orelse return false;

    const rptr_slice = adj_row_ptr[0..row_len];
    const empty_values = [_]f32{};
    const empty_cols = [_]u32{};
    const vals_slice = if (nnz_usize == 0) empty_values[0..] else blk: {
        if (@intFromPtr(adj_values) == 0) return false;
        break :blk adj_values[0..nnz_usize];
    };
    const cols_slice = if (nnz_usize == 0) empty_cols[0..] else blk: {
        if (@intFromPtr(adj_col_idx) == 0) return false;
        break :blk adj_col_idx[0..nnz_usize];
    };
    if (!validateCsr(rptr_slice, cols_slice, nodes_usize, nnz_usize, nodes_usize)) return false;

    gnn_message_pass(
        vals_slice,
        cols_slice,
        rptr_slice,
        h_in[0..h_in_len],
        fin,
        weights[0..weight_len],
        fout,
        bias_ptr[0..fout],
        h_out[0..h_out_len],
        scratch[0..nodes_usize],
    );
    return true;
}

/// C ABI: GNN message passing with the fused projection.
///
/// Identical to `omnisec_gnn_layer` apart from an explicit scratch length.
/// With `scratch_len >= nodes * features_out` the fused path runs; with less
/// the result is bit-for-bit what the older export produces, so a caller can
/// migrate to this entry point unconditionally.
///
/// Recommended scratch size: `nodes * features_out` f32 elements.
pub export fn omnisec_gnn_layer2(
    adj_values: [*]const f32,
    adj_col_idx: [*]const u32,
    adj_row_ptr: [*]const u32,
    h_in: [*]const f32,
    features_in: u32,
    weights: [*]const f32,
    features_out: u32,
    bias_ptr: [*]const f32,
    h_out: [*]f32,
    scratch: [*]f32,
    scratch_len: u32,
    nodes: u32,
    nnz: u32,
) bool {
    if (nodes == 0 or features_in == 0 or features_out == 0) return true;
    if (@intFromPtr(adj_row_ptr) == 0) return false;
    if (@intFromPtr(h_in) == 0) return false;
    if (@intFromPtr(weights) == 0) return false;
    if (@intFromPtr(bias_ptr) == 0) return false;
    if (@intFromPtr(h_out) == 0) return false;
    if (@intFromPtr(scratch) == 0) return false;

    const nodes_usize: usize = @as(usize, nodes);
    const fin: usize = @as(usize, features_in);
    const fout: usize = @as(usize, features_out);
    const nnz_usize: usize = @as(usize, nnz);
    const scratch_usize: usize = @as(usize, scratch_len);
    // The per-column fallback still needs one slot per node.
    if (scratch_usize < nodes_usize) return false;
    const row_len = std.math.add(usize, nodes_usize, 1) catch return false;
    const h_in_len = checkedMul(nodes_usize, fin) orelse return false;
    const weight_len = checkedMul(fin, fout) orelse return false;
    const h_out_len = checkedMul(nodes_usize, fout) orelse return false;

    const rptr_slice = adj_row_ptr[0..row_len];
    const empty_values = [_]f32{};
    const empty_cols = [_]u32{};
    const vals_slice = if (nnz_usize == 0) empty_values[0..] else blk: {
        if (@intFromPtr(adj_values) == 0) return false;
        break :blk adj_values[0..nnz_usize];
    };
    const cols_slice = if (nnz_usize == 0) empty_cols[0..] else blk: {
        if (@intFromPtr(adj_col_idx) == 0) return false;
        break :blk adj_col_idx[0..nnz_usize];
    };
    if (!validateCsr(rptr_slice, cols_slice, nodes_usize, nnz_usize, nodes_usize)) return false;

    gnn_message_pass(
        vals_slice,
        cols_slice,
        rptr_slice,
        h_in[0..h_in_len],
        fin,
        weights[0..weight_len],
        fout,
        bias_ptr[0..fout],
        h_out[0..h_out_len],
        scratch[0..scratch_usize],
    );
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "spmv identity matrix" {
    // 3×3 identity matrix in CSR
    const values = [_]f32{ 1.0, 1.0, 1.0 };
    const col_idx = [_]u32{ 0, 1, 2 };
    const row_ptr = [_]u32{ 0, 1, 2, 3 };
    const x = [_]f32{ 10.0, 20.0, 30.0 };
    var y = [_]f32{ 0.0, 0.0, 0.0 };

    spmv_f32(&values, &col_idx, &row_ptr, &x, &y);

    try std.testing.expectApproxEqAbs(@as(f32, 10.0), y[0], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 20.0), y[1], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 30.0), y[2], 1e-6);
}

test "spmv triangle adjacency" {
    // Triangle: 0→1, 1→2, 2→0 (plus self-loops)
    // Row 0: [1, 1, 0]  Row 1: [0, 1, 1]  Row 2: [1, 0, 1]
    const values = [_]f32{ 1.0, 1.0, 1.0, 1.0, 1.0, 1.0 };
    const col_idx = [_]u32{ 0, 1, 1, 2, 0, 2 };
    const row_ptr = [_]u32{ 0, 2, 4, 6 };
    const x = [_]f32{ 1.0, 2.0, 3.0 };
    var y = [_]f32{ 0.0, 0.0, 0.0 };

    spmv_f32(&values, &col_idx, &row_ptr, &x, &y);

    try std.testing.expectApproxEqAbs(@as(f32, 3.0), y[0], 1e-6); // 1+2
    try std.testing.expectApproxEqAbs(@as(f32, 5.0), y[1], 1e-6); // 2+3
    try std.testing.expectApproxEqAbs(@as(f32, 4.0), y[2], 1e-6); // 1+3
}

test "relu zeroes negatives" {
    var data = [_]f32{ -3.0, 0.0, 2.5, -1.0, 7.0 };
    relu_f32(&data);
    try std.testing.expectApproxEqAbs(@as(f32, 0.0), data[0], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.0), data[1], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 2.5), data[2], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.0), data[3], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 7.0), data[4], 1e-6);
}

test "l2 normalize" {
    var data = [_]f32{ 3.0, 4.0 }; // norm = 5
    l2_normalize_f32(&data);
    try std.testing.expectApproxEqAbs(@as(f32, 0.6), data[0], 1e-5);
    try std.testing.expectApproxEqAbs(@as(f32, 0.8), data[1], 1e-5);
}

test "C ABI spmv wrapper" {
    const values = [_]f32{ 2.0, 3.0 };
    const col_idx = [_]u32{ 0, 1 };
    const row_ptr = [_]u32{ 0, 1, 2 };
    const x = [_]f32{ 5.0, 7.0 };
    var y = [_]f32{ 0.0, 0.0 };

    try std.testing.expect(omnisec_spmv_f32(&values, &col_idx, &row_ptr, &x, &y, 2, 2, 2));
    try std.testing.expectApproxEqAbs(@as(f32, 10.0), y[0], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 21.0), y[1], 1e-6);
}

test "C ABI spmv rejects malformed CSR" {
    const values = [_]f32{1.0};
    const col_idx = [_]u32{99};
    const row_ptr = [_]u32{ 0, 1 };
    const x = [_]f32{5.0};
    var y = [_]f32{0.0};

    try std.testing.expect(!omnisec_spmv_f32(&values, &col_idx, &row_ptr, &x, &y, 1, 1, 1));
}

test "fused layer matches the per-column reference" {
    // 0 -> {0,1}, 1 -> {1,2}, 2 -> {2,0}; 4 input features, 6 output.
    const adj_values = [_]f32{ 1.0, 0.5, 1.0, 0.25, 1.0, 0.75 };
    const adj_col_idx = [_]u32{ 0, 1, 1, 2, 2, 0 };
    const adj_row_ptr = [_]u32{ 0, 2, 4, 6 };
    const fin: usize = 4;
    const fout: usize = 6;
    const nodes: usize = 3;

    var h_in: [nodes * fin]f32 = undefined;
    for (&h_in, 0..) |*v, i| v.* = @as(f32, @floatFromInt(i % 7)) - 3.0;
    var weights: [fin * fout]f32 = undefined;
    for (&weights, 0..) |*v, i| v.* = 0.1 * (@as(f32, @floatFromInt(i % 5)) - 2.0);
    const bias = [_]f32{ 0.1, -0.2, 0.3, -0.4, 0.5, -0.6 };

    var out_ref = std.mem.zeroes([nodes * fout]f32);
    var out_fast = std.mem.zeroes([nodes * fout]f32);
    var scratch_small = std.mem.zeroes([nodes]f32);
    var scratch_big = std.mem.zeroes([nodes * fout]f32);

    // Small scratch -> legacy per-column path.
    gnn_message_pass(&adj_values, &adj_col_idx, &adj_row_ptr, &h_in, fin, &weights, fout, &bias, &out_ref, &scratch_small);
    // Full scratch -> fused path.
    gnn_message_pass(&adj_values, &adj_col_idx, &adj_row_ptr, &h_in, fin, &weights, fout, &bias, &out_fast, &scratch_big);

    for (out_ref, out_fast) |a, b| {
        try std.testing.expectApproxEqAbs(a, b, 1e-5);
    }
}

test "C ABI omnisec_gnn_layer2 agrees with omnisec_gnn_layer" {
    const adj_values = [_]f32{ 1.0, 1.0, 1.0 };
    const adj_col_idx = [_]u32{ 0, 1, 2 };
    const adj_row_ptr = [_]u32{ 0, 1, 2, 3 };
    const fin: u32 = 3;
    const fout: u32 = 5;
    const nodes: u32 = 3;

    const h_in = [_]f32{ 1.0, 0.0, -2.0, 0.5, 3.0, 0.0, -1.0, 0.0, 4.0 };
    var weights: [15]f32 = undefined;
    for (&weights, 0..) |*v, i| v.* = 0.25 * (@as(f32, @floatFromInt(i % 4)) - 1.0);
    const bias = [_]f32{ 0.0, 0.1, -0.1, 0.2, -0.2 };

    var out_a = std.mem.zeroes([15]f32);
    var out_b = std.mem.zeroes([15]f32);
    var scratch_a = std.mem.zeroes([3]f32);
    var scratch_b = std.mem.zeroes([15]f32);

    try std.testing.expect(omnisec_gnn_layer(&adj_values, &adj_col_idx, &adj_row_ptr, &h_in, fin, &weights, fout, &bias, &out_a, &scratch_a, nodes, 3));
    try std.testing.expect(omnisec_gnn_layer2(&adj_values, &adj_col_idx, &adj_row_ptr, &h_in, fin, &weights, fout, &bias, &out_b, &scratch_b, 15, nodes, 3));

    for (out_a, out_b) |a, b| {
        try std.testing.expectApproxEqAbs(a, b, 1e-5);
    }
}

test "omnisec_gnn_layer2 rejects an undersized scratch buffer" {
    const adj_values = [_]f32{1.0};
    const adj_col_idx = [_]u32{0};
    const adj_row_ptr = [_]u32{ 0, 1 };
    const h_in = [_]f32{1.0};
    const weights = [_]f32{1.0};
    const bias = [_]f32{0.0};
    var out = [_]f32{0.0};
    var scratch = [_]f32{0.0};

    try std.testing.expect(!omnisec_gnn_layer2(&adj_values, &adj_col_idx, &adj_row_ptr, &h_in, 1, &weights, 1, &bias, &out, &scratch, 0, 1, 1));
}

test "axpy tail is handled past the vector width" {
    // Length deliberately not a multiple of any plausible LANES value.
    var dst = [_]f32{ 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0 };
    const src = [_]f32{ 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0 };
    axpy(&dst, &src, 2.0);
    for (dst, 0..) |v, i| {
        const want = @as(f32, @floatFromInt(i + 1)) + 2.0;
        try std.testing.expectApproxEqAbs(want, v, 1e-6);
    }
}
