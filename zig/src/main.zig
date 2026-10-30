//! OmniSec ML Runtime — Bit-Tensor Engine for HDC/GNN inference.
//!
//! This is the Zig runtime for the OmniSec ML pipeline. It provides:
//! - XNOR-GEMM (binarized matrix multiply via POPCNT)
//! - Forward-Forward layer training (no backprop)
//! - CPU SIMD optimized paths (AVX2/POPCNT, with @Vector fallback)
//!
//! Phase 1: CPU-only SIMD. Phase 2: OpenCL for GTX 650.

const std = @import("std");

pub const OMNISEC_ML_RUNTIME_ABI_VERSION: u32 = 1;
pub const spmv = @import("spmv");
pub const batch_inference = @import("batch_inference");
pub const hdc_train = @import("hdc_train");

comptime {
    // Force imported modules to be analyzed so their `pub export` C ABI symbols
    // are retained in the final runtime artifact.
    _ = spmv.omnisec_spmv_f32;
    _ = spmv.omnisec_gnn_layer;
    _ = spmv.omnisec_gnn_layer2;
    _ = batch_inference.omnisec_batched_hamming;
    _ = batch_inference.omnisec_batched_scan;
    _ = batch_inference.omnisec_batched_scan_topk;
    _ = batch_inference.omnisec_masked_hamming;
    _ = hdc_train.omnisec_bundle_majority;
    _ = hdc_train.omnisec_bundle_accumulate;
    _ = hdc_train.omnisec_bundle_finalize;
    _ = hdc_train.omnisec_bind_xor;
}

pub export fn omnisec_ml_runtime_abi_version() u32 {
    return OMNISEC_ML_RUNTIME_ABI_VERSION;
}

fn checkedMul(a: usize, b: usize) ?usize {
    return std.math.mul(usize, a, b) catch null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIMD CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

/// Lane count for u64 vectors. 8×u64 = 512 bits, which lines up with AVX-512
/// when the CPU has it and gracefully falls back to scalar/SSE on older silicon
/// (LLVM legalizes the wide vector for us). Keeping a single vector width
/// simplifies the kernels — the compiler picks the best instruction sequence.
pub const U64_LANES: usize = 8;
pub const U64Vec = @Vector(U64_LANES, u64);

/// Hamming distance between two binary vectors stored as u64 slices.
///
/// Hot path for HDC inference. The body is unrolled across `U64_LANES` u64s
/// at a time using `@Vector` + `@popCount`, which lowers to VPOPCNTQ on
/// AVX-512-VPOPCNTDQ-capable CPUs and to a tight scalar loop everywhere else.
pub fn hamming_distance(a: []const u64, b: []const u64) usize {
    std.debug.assert(a.len == b.len);

    var dist: usize = 0;
    var i: usize = 0;

    // Vector body: U64_LANES words at a time.
    while (i + U64_LANES <= a.len) : (i += U64_LANES) {
        const va: U64Vec = a[i..][0..U64_LANES].*;
        const vb: U64Vec = b[i..][0..U64_LANES].*;
        const xor = va ^ vb;
        const pc: U64Vec = @popCount(xor);
        dist += @reduce(.Add, pc);
    }

    // Tail.
    while (i < a.len) : (i += 1) {
        dist += @popCount(a[i] ^ b[i]);
    }

    return dist;
}

/// C ABI wrapper for hamming distance over packed u64 words.
///
/// Returns `usize::max` on null input to make FFI misuse fail closed.
pub export fn omnisec_hamming_distance(a: [*]const u64, b: [*]const u64, words: usize) usize {
    if (words == 0) return 0;
    if (@intFromPtr(a) == 0 or @intFromPtr(b) == 0) return std.math.maxInt(usize);

    const a_slice = a[0..words];
    const b_slice = b[0..words];
    return hamming_distance(a_slice, b_slice);
}

/// XNOR-GEMM: Binarized matrix multiply.
///
/// For binary matrices A (M×K packed in u64) and B (K×N packed in u64),
/// computes C[i][j] = popcount(NOT(A_row[i] XOR B_col[j])).
///
/// This replaces floating-point MatMul with pure bitwise ops. Inner loop
/// is vectorized across `U64_LANES` u64 lanes per iteration; the tail is
/// handled scalar.
pub fn xnor_gemm(
    a: []const u64,
    b: []const u64,
    c: []u32,
    m: usize,
    n: usize,
    k_words: usize,
) void {
    for (0..m) |i| {
        const a_row = a[i * k_words .. (i + 1) * k_words];
        for (0..n) |j| {
            const b_col = b[j * k_words .. (j + 1) * k_words];

            var sum: u32 = 0;
            var k: usize = 0;

            while (k + U64_LANES <= k_words) : (k += U64_LANES) {
                const va: U64Vec = a_row[k..][0..U64_LANES].*;
                const vb: U64Vec = b_col[k..][0..U64_LANES].*;
                const xnor = ~(va ^ vb);
                const pc: U64Vec = @popCount(xnor);
                sum += @as(u32, @intCast(@reduce(.Add, pc)));
            }
            while (k < k_words) : (k += 1) {
                sum += @popCount(~(a_row[k] ^ b_col[k]));
            }

            c[i * n + j] = sum;
        }
    }
}

/// C ABI wrapper for XNOR-GEMM over packed u64 rows/columns.
///
/// Returns `false` on null inputs and `true` once `c` has been filled.
pub export fn omnisec_xnor_gemm(
    a: [*]const u64,
    b: [*]const u64,
    c: [*]u32,
    m: usize,
    n: usize,
    k_words: usize,
) bool {
    if (m == 0 or n == 0 or k_words == 0) return true;
    if (@intFromPtr(a) == 0 or @intFromPtr(b) == 0 or @intFromPtr(c) == 0) return false;

    const a_len = checkedMul(m, k_words) orelse return false;
    const b_len = checkedMul(n, k_words) orelse return false;
    const c_len = checkedMul(m, n) orelse return false;

    const a_slice = a[0..a_len];
    const b_slice = b[0..b_len];
    const c_slice = c[0..c_len];
    xnor_gemm(a_slice, b_slice, c_slice, m, n, k_words);
    return true;
}

/// Sign function for binarization: writes a 1-bit per element when
/// `values[i] > threshold`, packed LSB-first into `output` (u64 per 64 bits).
///
/// `output` must be pre-zeroed by the caller (we only OR in 1-bits).
pub fn sign_threshold(values: []const u32, threshold: u32, output: []u64) void {
    var bit_idx: usize = 0;
    for (values) |val| {
        const word = bit_idx / 64;
        const bit: u6 = @intCast(bit_idx % 64);
        if (val > threshold) {
            output[word] |= @as(u64, 1) << bit;
        }
        bit_idx += 1;
    }
}

/// C ABI wrapper for sign_threshold. `output` must hold at least
/// `ceil(values_len / 64)` u64s. The wrapper clears required output words.
pub export fn omnisec_sign_threshold(
    values: [*]const u32,
    values_len: usize,
    threshold: u32,
    output: [*]u64,
    output_words: usize,
) bool {
    if (values_len == 0) return true;
    if (@intFromPtr(values) == 0 or @intFromPtr(output) == 0) return false;
    const rounded = std.math.add(usize, values_len, 63) catch return false;
    const required_words = rounded / 64;
    if (output_words < required_words) return false;

    const out_slice = output[0..required_words];
    @memset(out_slice, 0);
    sign_threshold(values[0..values_len], threshold, out_slice);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "runtime ABI version is stable" {
    try std.testing.expectEqual(@as(u32, OMNISEC_ML_RUNTIME_ABI_VERSION), omnisec_ml_runtime_abi_version());
}

test "hamming distance of identical vectors is zero" {
    const a = [_]u64{ 0xDEADBEEF, 0xCAFEBABE };
    const b = [_]u64{ 0xDEADBEEF, 0xCAFEBABE };
    try std.testing.expectEqual(@as(usize, 0), hamming_distance(&a, &b));
}

test "hamming distance of opposite vectors is max" {
    const a = [_]u64{ 0x0000000000000000, 0x0000000000000000 };
    const b = [_]u64{ 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF };
    try std.testing.expectEqual(@as(usize, 128), hamming_distance(&a, &b));
}

test "hamming distance covers vector body and scalar tail" {
    // 10 words = one full vector body (8) plus a 2-word tail.
    var a: [10]u64 = undefined;
    var b: [10]u64 = undefined;
    var expected: usize = 0;
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rnd = prng.random();
    for (0..10) |i| {
        a[i] = rnd.int(u64);
        b[i] = rnd.int(u64);
        expected += @popCount(a[i] ^ b[i]);
    }

    try std.testing.expectEqual(expected, hamming_distance(&a, &b));
}

test "xnor gemm basic" {
    // 1×1 matrix, K=1 word (64 bits)
    const a = [_]u64{0xFF00FF00FF00FF00};
    const b = [_]u64{0xFF00FF00FF00FF00};
    var c = [_]u32{0};

    xnor_gemm(&a, &b, &c, 1, 1, 1);

    // XNOR of identical = all 1s, popcount = 64
    try std.testing.expectEqual(@as(u32, 64), c[0]);
}

test "xnor gemm k_words crosses simd boundary" {
    // K = 9 words → 1 vector body (8) + 1 scalar tail.
    const k_words: usize = 9;
    var a: [k_words]u64 = undefined;
    var b: [k_words]u64 = undefined;
    var c = [_]u32{0};

    var expected: u32 = 0;
    for (0..k_words) |i| {
        a[i] = @as(u64, i) * 0x1111_1111_1111_1111;
        b[i] = @as(u64, i ^ 0xA) * 0x1111_1111_1111_1111;
        expected += @popCount(~(a[i] ^ b[i]));
    }

    xnor_gemm(&a, &b, &c, 1, 1, k_words);
    try std.testing.expectEqual(expected, c[0]);
}

test "C ABI hamming wrapper" {
    const a = [_]u64{ 0xFFFF0000FFFF0000, 0x0 };
    const b = [_]u64{ 0x0000FFFF0000FFFF, 0x0 };

    try std.testing.expectEqual(@as(usize, 64), omnisec_hamming_distance(&a, &b, a.len));
}

test "C ABI xnor gemm wrapper" {
    const a = [_]u64{0xFFFFFFFFFFFFFFFF};
    const b = [_]u64{0xFFFFFFFFFFFFFFFF};
    var c = [_]u32{0};

    try std.testing.expect(omnisec_xnor_gemm(&a, &b, &c, 1, 1, 1));
    try std.testing.expectEqual(@as(u32, 64), c[0]);
}

test "sign threshold packs bits LSB-first" {
    // values: 5, 0, 9, 1, 12 — threshold 3 → bits set for indices 0, 2, 4
    const values = [_]u32{ 5, 0, 9, 1, 12 };
    var packed_out = [_]u64{0};
    sign_threshold(&values, 3, &packed_out);

    // Expected: bit 0 (5>3), bit 2 (9>3), bit 4 (12>3) → 0b10101 = 0x15
    try std.testing.expectEqual(@as(u64, 0x15), packed_out[0]);
}

test "C ABI sign threshold clears stale output bits" {
    const values = [_]u32{ 0, 0, 10 };
    var packed_out = [_]u64{std.math.maxInt(u64)};
    try std.testing.expect(omnisec_sign_threshold(&values, values.len, 3, &packed_out, packed_out.len));
    try std.testing.expectEqual(@as(u64, 0b100), packed_out[0]);
}

test "C ABI sign threshold validates output capacity" {
    const values = [_]u32{ 1, 2, 3 };
    var packed_out = [_]u64{0};
    try std.testing.expect(omnisec_sign_threshold(&values, values.len, 1, &packed_out, packed_out.len));
    // Only values[1] = 2 > 1 and values[2] = 3 > 1 → bits 1 and 2.
    try std.testing.expectEqual(@as(u64, 0b110), packed_out[0]);

    // Too-small output buffer → false.
    var empty: [0]u64 = .{};
    const empty_ptr: [*]u64 = @ptrCast(&empty);
    try std.testing.expect(!omnisec_sign_threshold(&values, values.len, 1, empty_ptr, 0));
}
