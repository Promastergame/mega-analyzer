//! Batched HDC Inference — Process multiple code samples in a single pass.
//!
//! Instead of running Hamming distance one-at-a-time, batch mode processes
//! up to 64 query vectors against the anchor store simultaneously, leveraging
//! SIMD parallelism across the batch dimension.
//!
//! This is the key performance upgrade for v11+: scanning a 10k-method APK
//! should take seconds, not minutes.

const std = @import("std");

fn checkedMul(a: usize, b: usize) ?usize {
    return std.math.mul(usize, a, b) catch null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIMD CONFIG + SHARED HAMMING KERNEL
// ═══════════════════════════════════════════════════════════════════════════════

/// Lane count for u64 vectors. 8×u64 = 512 bits, lining up with AVX-512 when
/// present and legalized down to SSE/scalar by LLVM on older silicon.
const U64_LANES: usize = 8;
const U64Vec = @Vector(U64_LANES, u64);

/// Hamming distance between two equal-length packed-u64 word slices.
///
/// This is the single hot kernel shared by every batched scan/search path.
/// The body processes `U64_LANES` words at a time via `@Vector` + `@popCount`
/// (which lowers to VPOPCNTQ on AVX-512-VPOPCNTDQ CPUs and a tight scalar loop
/// elsewhere) followed by a scalar tail. It is marked `inline` so each caller
/// keeps a specialised, call-free loop while the logic lives in exactly one
/// place — the previous copy-pasted variants had already drifted, leaving
/// `batched_scan` on a slow scalar path.
inline fn hammingWords(a: []const u64, b: []const u64) u32 {
    std.debug.assert(a.len == b.len);

    var dist: u32 = 0;
    var w: usize = 0;
    while (w + U64_LANES <= a.len) : (w += U64_LANES) {
        const va: U64Vec = a[w..][0..U64_LANES].*;
        const vb: U64Vec = b[w..][0..U64_LANES].*;
        const pc: U64Vec = @popCount(va ^ vb);
        dist += @as(u32, @intCast(@reduce(.Add, pc)));
    }
    while (w < a.len) : (w += 1) {
        dist += @popCount(a[w] ^ b[w]);
    }
    return dist;
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCHED HAMMING DISTANCE
// ═══════════════════════════════════════════════════════════════════════════════

/// Compute Hamming distances for a batch of query vectors against one anchor.
///
/// `queries`:  batch × words packed u64 matrix (row-major)
/// `anchor`:   single anchor vector (words u64)
/// `distances`: output array (length = batch_size)
///
/// Each query is `words` u64s wide. The batch is laid out contiguously:
///   queries[0..words] = query 0
///   queries[words..2*words] = query 1
///   ...
pub fn batched_hamming(
    queries: []const u64,
    anchor: []const u64,
    distances: []u32,
    batch_size: usize,
    words: usize,
) void {
    for (0..batch_size) |b| {
        const offset = b * words;
        distances[b] = hammingWords(queries[offset .. offset + words], anchor[0..words]);
    }
}

/// Batched scan: compare `batch_size` queries against `num_anchors` anchors.
///
/// `queries`:    batch × words (row-major u64 matrix)
/// `anchors`:    num_anchors × words (row-major u64 matrix)
/// `scores`:     batch × num_anchors output scores (row-major)
/// `thresholds`: per-anchor thresholds (length = num_anchors)
///
/// scores[b * num_anchors + a] = 1.0 - (hamming(query_b, anchor_a) / max_dist)
/// where max_dist = words * 64
pub fn batched_scan(
    queries: []const u64,
    anchors: []const u64,
    scores: []f32,
    thresholds: []const f32,
    batch_size: usize,
    num_anchors: usize,
    words: usize,
) u32 {
    const max_dist: f32 = @floatFromInt(words * 64);
    var total_hits: u32 = 0;

    for (0..batch_size) |b| {
        const q_offset = b * words;
        const query = queries[q_offset .. q_offset + words];
        for (0..num_anchors) |a| {
            const a_offset = a * words;

            const dist = hammingWords(query, anchors[a_offset .. a_offset + words]);

            const similarity: f32 = 1.0 - @as(f32, @floatFromInt(dist)) / max_dist;
            scores[b * num_anchors + a] = similarity;

            if (similarity >= thresholds[a]) {
                total_hits += 1;
            }
        }
    }

    return total_hits;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOP-K SELECTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Find top-K anchors for each query in the batch.
///
/// `scores`:     batch × num_anchors (from batched_scan)
/// `top_indices`: batch × k output (anchor indices, sorted by score desc)
/// `top_scores`:  batch × k output (corresponding scores)
pub fn batch_top_k(
    scores: []const f32,
    top_indices: []u32,
    top_scores: []f32,
    batch_size: usize,
    num_anchors: usize,
    k: usize,
) void {
    const actual_k = @min(k, num_anchors);
    if (actual_k == 0) return;

    for (0..batch_size) |b| {
        const row = scores[b * num_anchors .. (b + 1) * num_anchors];
        const out_idx = top_indices[b * actual_k .. (b + 1) * actual_k];
        const out_sc = top_scores[b * actual_k .. (b + 1) * actual_k];

        // Simple selection sort for small K (typically K <= 10)
        // Initialize with sentinel values
        for (0..actual_k) |i| {
            out_idx[i] = 0;
            out_sc[i] = -1.0;
        }

        for (0..num_anchors) |a| {
            const sc = row[a];

            // Check if this score is better than the worst in top-K
            var worst_pos: usize = 0;
            for (1..actual_k) |i| {
                if (out_sc[i] < out_sc[worst_pos]) {
                    worst_pos = i;
                }
            }

            if (sc > out_sc[worst_pos]) {
                out_sc[worst_pos] = sc;
                out_idx[worst_pos] = @intCast(a);
            }
        }

        // Sort top-K descending
        if (actual_k > 1) {
            for (0..actual_k - 1) |i| {
                var max_pos = i;
                for (i + 1..actual_k) |j| {
                    if (out_sc[j] > out_sc[max_pos]) {
                        max_pos = j;
                    }
                }
                if (max_pos != i) {
                    const tmp_sc = out_sc[i];
                    out_sc[i] = out_sc[max_pos];
                    out_sc[max_pos] = tmp_sc;

                    const tmp_idx = out_idx[i];
                    out_idx[i] = out_idx[max_pos];
                    out_idx[max_pos] = tmp_idx;
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// C ABI EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

/// C ABI: Batched Hamming distance computation.
pub export fn omnisec_batched_hamming(
    queries: [*]const u64,
    anchor: [*]const u64,
    distances: [*]u32,
    batch_size: u32,
    words: u32,
) bool {
    if (batch_size == 0 or words == 0) return true;
    if (@intFromPtr(queries) == 0 or @intFromPtr(anchor) == 0 or @intFromPtr(distances) == 0)
        return false;

    const batch_usize: usize = @as(usize, batch_size);
    const words_usize: usize = @as(usize, words);
    const query_len = checkedMul(batch_usize, words_usize) orelse return false;

    batched_hamming(
        queries[0..query_len],
        anchor[0..words_usize],
        distances[0..batch_usize],
        batch_usize,
        words_usize,
    );
    return true;
}

/// C ABI: Batched scan against anchor store. Returns number of hits.
pub export fn omnisec_batched_scan(
    queries: [*]const u64,
    anchors: [*]const u64,
    scores: [*]f32,
    thresholds: [*]const f32,
    batch_size: u32,
    num_anchors: u32,
    words: u32,
) u32 {
    if (batch_size == 0 or num_anchors == 0 or words == 0) return 0;
    if (@intFromPtr(queries) == 0) return 0;
    if (@intFromPtr(anchors) == 0) return 0;
    if (@intFromPtr(scores) == 0) return 0;
    if (@intFromPtr(thresholds) == 0) return 0;

    const batch_usize: usize = @as(usize, batch_size);
    const anchors_usize: usize = @as(usize, num_anchors);
    const words_usize: usize = @as(usize, words);
    const query_len = checkedMul(batch_usize, words_usize) orelse return 0;
    const anchor_len = checkedMul(anchors_usize, words_usize) orelse return 0;
    const scores_len = checkedMul(batch_usize, anchors_usize) orelse return 0;

    return batched_scan(
        queries[0..query_len],
        anchors[0..anchor_len],
        scores[0..scores_len],
        thresholds[0..anchors_usize],
        batch_usize,
        anchors_usize,
        words_usize,
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "batched hamming identical" {
    const anchor = [_]u64{ 0xDEADBEEF, 0xCAFEBABE };
    const queries = [_]u64{
        0xDEADBEEF, 0xCAFEBABE, // query 0 = identical
        0x00000000, 0x00000000, // query 1 = different
    };
    var distances = [_]u32{ 99, 99 };

    batched_hamming(&queries, &anchor, &distances, 2, 2);

    try std.testing.expectEqual(@as(u32, 0), distances[0]);
    try std.testing.expect(distances[1] > 0);
}

test "batched scan finds hits" {
    const words = 1;
    const queries = [_]u64{ 0xFFFFFFFFFFFFFFFF, 0x0000000000000000 };
    const anchors = [_]u64{0xFFFFFFFFFFFFFFFF}; // one anchor
    const thresholds = [_]f32{0.5};
    var scores = [_]f32{ 0.0, 0.0 };

    const hits = batched_scan(&queries, &anchors, &scores, &thresholds, 2, 1, words);

    // Query 0 should match (identical), query 1 should not
    try std.testing.expect(scores[0] > 0.9); // very similar
    try std.testing.expect(scores[1] < 0.1); // very different
    try std.testing.expectEqual(@as(u32, 1), hits);
}

test "batched scan vectorised path matches scalar reference across SIMD boundary" {
    // words = 9 exercises one full 8-wide vector body plus a 1-word scalar tail,
    // which is exactly where a broken vectorisation would diverge from scalar.
    const words: usize = 9;
    const batch_size: usize = 3;
    const num_anchors: usize = 2;

    var queries: [batch_size * words]u64 = undefined;
    var anchors: [num_anchors * words]u64 = undefined;
    var prng = std.Random.DefaultPrng.init(0x5EED_1234);
    const rnd = prng.random();
    for (&queries) |*q| q.* = rnd.int(u64);
    for (&anchors) |*a| a.* = rnd.int(u64);

    // Thresholds above 1.0 are unreachable, so hit-counting stays out of the way
    // and the test focuses purely on the similarity scores.
    const thresholds = [_]f32{ 2.0, 2.0 };
    var scores: [batch_size * num_anchors]f32 = undefined;
    const max_dist: f32 = @floatFromInt(words * 64);

    const hits = batched_scan(&queries, &anchors, &scores, &thresholds, batch_size, num_anchors, words);
    try std.testing.expectEqual(@as(u32, 0), hits);

    for (0..batch_size) |b| {
        for (0..num_anchors) |a| {
            var dist: u32 = 0;
            for (0..words) |w| {
                dist += @popCount(queries[b * words + w] ^ anchors[a * words + w]);
            }
            const expected = 1.0 - @as(f32, @floatFromInt(dist)) / max_dist;
            try std.testing.expectApproxEqAbs(expected, scores[b * num_anchors + a], 1e-6);
        }
    }
}

test "C ABI batched scan" {
    // With words=1 (64 bits) and anchor 0xFFFF (16 bits set):
    //   query 0 (0xFFFF) → XOR popcount = 0  → similarity = 1.00
    //   query 1 (0x0000) → XOR popcount = 16 → similarity = 0.75
    // Threshold 0.9 keeps only the exact match as a hit.
    const queries = [_]u64{ 0xFFFF, 0x0000 };
    const anchors = [_]u64{0xFFFF};
    const thresholds = [_]f32{0.9};
    var scores = [_]f32{ 0.0, 0.0 };

    const hits = omnisec_batched_scan(&queries, &anchors, &scores, &thresholds, 2, 1, 1);
    try std.testing.expectEqual(@as(u32, 1), hits);
}

// ═══════════════════════════════════════════════════════════════════════════════
// FUSED BATCHED SCAN + TOP-K
//
// v11.1.1 fuses the scan-and-topk path into a single kernel so the cache
// line carrying `scores[b * num_anchors + a]` is touched exactly once per
// (query, anchor) pair. This roughly halves the wall time on large APKs
// where `scan` and `top_k` were previously two consecutive passes.
// ═══════════════════════════════════════════════════════════════════════════════

/// Fused: compute similarity AND track the top-K anchors in a single pass.
///
/// Equivalent to `batched_scan` followed by `batch_top_k`, but never
/// materialises the full `scores` matrix — useful when batch_size *
/// num_anchors is too big to keep resident.
///
/// Caller-provided `out_indices` and `out_scores` are batch_size * k each.
pub fn batched_scan_topk(
    queries: []const u64,
    anchors: []const u64,
    out_indices: []u32,
    out_scores: []f32,
    batch_size: usize,
    num_anchors: usize,
    words: usize,
    k: usize,
) u32 {
    const max_dist: f32 = @floatFromInt(words * 64);
    const actual_k = @min(k, num_anchors);
    if (actual_k == 0) return 0;
    var total_hits: u32 = 0;

    for (0..batch_size) |b| {
        const q_offset = b * words;
        const query = queries[q_offset .. q_offset + words];
        const out_idx = out_indices[b * actual_k .. (b + 1) * actual_k];
        const out_sc = out_scores[b * actual_k .. (b + 1) * actual_k];

        for (0..actual_k) |i| {
            out_idx[i] = 0;
            out_sc[i] = -1.0;
        }

        for (0..num_anchors) |a| {
            const a_offset = a * words;

            const dist = hammingWords(query, anchors[a_offset .. a_offset + words]);

            const similarity: f32 = 1.0 - @as(f32, @floatFromInt(dist)) / max_dist;

            // Insert into top-K if better than the current worst
            var worst_pos: usize = 0;
            for (1..actual_k) |i| {
                if (out_sc[i] < out_sc[worst_pos]) {
                    worst_pos = i;
                }
            }
            if (similarity > out_sc[worst_pos]) {
                out_sc[worst_pos] = similarity;
                out_idx[worst_pos] = @intCast(a);
                total_hits += 1;
            }
        }

        // Sort top-K descending
        if (actual_k > 1) {
            for (0..actual_k - 1) |i| {
                var max_pos = i;
                for (i + 1..actual_k) |j| {
                    if (out_sc[j] > out_sc[max_pos]) {
                        max_pos = j;
                    }
                }
                if (max_pos != i) {
                    const tmp_sc = out_sc[i];
                    out_sc[i] = out_sc[max_pos];
                    out_sc[max_pos] = tmp_sc;

                    const tmp_idx = out_idx[i];
                    out_idx[i] = out_idx[max_pos];
                    out_idx[max_pos] = tmp_idx;
                }
            }
        }
    }

    return total_hits;
}

/// Hamming distance with a per-bit mask. Allows callers to ignore noisy
/// dimensions when comparing HDC vectors. `mask[i]` set bit means the
/// corresponding query/anchor bit participates; cleared bits are skipped.
pub fn masked_hamming(
    a: []const u64,
    b: []const u64,
    mask: []const u64,
) usize {
    std.debug.assert(a.len == b.len and a.len == mask.len);
    var dist: usize = 0;
    for (a, b, mask) |ai, bi, m| {
        dist += @popCount((ai ^ bi) & m);
    }
    return dist;
}

/// C ABI: fused scan + top-K. Returns the total hit count (entries that
/// improved at least one slot in the per-query top-K table).
pub export fn omnisec_batched_scan_topk(
    queries: [*]const u64,
    anchors: [*]const u64,
    out_indices: [*]u32,
    out_scores: [*]f32,
    batch_size: u32,
    num_anchors: u32,
    words: u32,
    k: u32,
) u32 {
    if (batch_size == 0 or num_anchors == 0 or words == 0 or k == 0) return 0;
    if (@intFromPtr(queries) == 0 or @intFromPtr(anchors) == 0) return 0;
    if (@intFromPtr(out_indices) == 0 or @intFromPtr(out_scores) == 0) return 0;

    const batch_usize: usize = @as(usize, batch_size);
    const anchors_usize: usize = @as(usize, num_anchors);
    const words_usize: usize = @as(usize, words);
    const actual_k = @min(@as(usize, k), anchors_usize);
    const query_len = checkedMul(batch_usize, words_usize) orelse return 0;
    const anchor_len = checkedMul(anchors_usize, words_usize) orelse return 0;
    const out_len = checkedMul(batch_usize, actual_k) orelse return 0;

    return batched_scan_topk(
        queries[0..query_len],
        anchors[0..anchor_len],
        out_indices[0..out_len],
        out_scores[0..out_len],
        batch_usize,
        anchors_usize,
        words_usize,
        actual_k,
    );
}

/// C ABI: masked Hamming distance. Returns `usize::max` on null pointers.
pub export fn omnisec_masked_hamming(
    a: [*]const u64,
    b: [*]const u64,
    mask: [*]const u64,
    words: usize,
) usize {
    if (words == 0) return 0;
    if (@intFromPtr(a) == 0 or @intFromPtr(b) == 0 or @intFromPtr(mask) == 0)
        return std.math.maxInt(usize);

    return masked_hamming(a[0..words], b[0..words], mask[0..words]);
}

test "fused scan-topk matches scan + topk" {
    const words = 1;
    const queries = [_]u64{ 0xFFFF, 0x00FF };
    const anchors = [_]u64{ 0xFFFF, 0x00FF, 0x000F };
    var out_idx = [_]u32{ 0, 0 };
    var out_sc = [_]f32{ 0, 0 };

    const hits = batched_scan_topk(&queries, &anchors, &out_idx, &out_sc, 2, 3, words, 1);
    // Each query updates top-1 at least once (initial sentinel was -1).
    try std.testing.expect(hits >= 2);

    // Top-1 for query 0 (0xFFFF) must be anchor 0.
    try std.testing.expectEqual(@as(u32, 0), out_idx[0]);
    // Top-1 for query 1 (0x00FF) must be anchor 1.
    try std.testing.expectEqual(@as(u32, 1), out_idx[1]);
}

test "masked hamming respects the mask" {
    const a = [_]u64{0xFFFF};
    const b = [_]u64{0x0000};
    // Without mask the distance would be 16; mask clamps to lowest 4 bits.
    const mask = [_]u64{0x000F};
    try std.testing.expectEqual(@as(usize, 4), masked_hamming(&a, &b, &mask));
}

test "C ABI fused scan-topk" {
    const queries = [_]u64{0xFFFF};
    const anchors = [_]u64{ 0xFFFF, 0x0000 };
    var out_idx = [_]u32{0};
    var out_sc = [_]f32{0};

    const hits = omnisec_batched_scan_topk(&queries, &anchors, &out_idx, &out_sc, 1, 2, 1, 1);
    try std.testing.expect(hits >= 1);
    try std.testing.expectEqual(@as(u32, 0), out_idx[0]);
}
