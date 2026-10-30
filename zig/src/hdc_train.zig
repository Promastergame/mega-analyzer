//! HDC Training & Encoding — build class prototypes on-device.
//!
//! The rest of the runtime is inference-only: given anchors it scans queries
//! (Hamming / batched scan / top-K). This module supplies the missing other
//! half of a hyperdimensional-computing pipeline — the *encoding and training*
//! primitives that manufacture those anchors in the first place:
//!
//!   - `bundle_majority`  : one-shot majority-vote superposition of N samples
//!   - `bundle_accumulate` / `bundle_finalize` : streaming/online training that
//!     never needs all samples resident at once (ideal for a 10k-method APK
//!     fed in chunks)
//!   - `bind_xor`         : role-filler binding (element-wise XOR)
//!
//! Bit layout matches the rest of the engine: hypervectors are packed LSB-first
//! into u64 words, `words` u64s per vector.

const std = @import("std");

fn checkedMul(a: usize, b: usize) ?usize {
    return std.math.mul(usize, a, b) catch null;
}

// ══════════════════════════════════════════════════════════════════════════════════
// MAJORITY-VOTE BUNDLING (SUPERPOSITION)
// ══════════════════════════════════════════════════════════════════════════════════

/// Element-wise binary majority vote across `num_samples` packed hypervectors.
///
/// `samples`: num_samples × words packed-u64 matrix (row-major).
/// `out`:     words u64s; a bit is set when a strict majority of samples set it
///            (`2 * set_count > num_samples`). Ties on an even sample count
///            resolve to 0, which is deterministic and bias-free.
///
/// Runs word-by-word with a 64-wide stack counter, so it needs no allocator and
/// no scratch buffer.
pub fn bundle_majority(samples: []const u64, num_samples: usize, words: usize, out: []u64) void {
    std.debug.assert(out.len == words);
    if (num_samples == 0) {
        @memset(out, 0);
        return;
    }
    for (0..words) |w| {
        var counts = std.mem.zeroes([64]u32);
        for (0..num_samples) |s| {
            const word = samples[s * words + w];
            for (0..64) |bit| {
                counts[bit] += @as(u32, @intCast((word >> @intCast(bit)) & 1));
            }
        }
        var packed_word: u64 = 0;
        for (0..64) |bit| {
            if (2 * @as(usize, counts[bit]) > num_samples) {
                packed_word |= @as(u64, 1) << @intCast(bit);
            }
        }
        out[w] = packed_word;
    }
}

/// Accumulate per-bit set-counts for a batch of samples into `counts`.
///
/// `counts`: words × 64 u32 running totals (row-major: `counts[w * 64 + bit]`).
/// The caller zeroes it once, then calls this across as many batches as needed;
/// `bundle_finalize` turns the running totals into a packed prototype. This is
/// the streaming/online path: samples never all need to be resident.
pub fn bundle_accumulate(samples: []const u64, num_samples: usize, words: usize, counts: []u32) void {
    std.debug.assert(counts.len == words * 64);
    for (0..num_samples) |s| {
        for (0..words) |w| {
            const word = samples[s * words + w];
            const base = w * 64;
            for (0..64) |bit| {
                counts[base + bit] += @as(u32, @intCast((word >> @intCast(bit)) & 1));
            }
        }
    }
}

/// Threshold running counts into a packed majority prototype.
///
/// `total` is the number of samples accumulated so far. Uses the same strict
/// majority rule as `bundle_majority` (`2 * count > total`).
pub fn bundle_finalize(counts: []const u32, total: usize, words: usize, out: []u64) void {
    std.debug.assert(counts.len == words * 64 and out.len == words);
    for (0..words) |w| {
        const base = w * 64;
        var packed_word: u64 = 0;
        for (0..64) |bit| {
            if (2 * @as(usize, counts[base + bit]) > total) {
                packed_word |= @as(u64, 1) << @intCast(bit);
            }
        }
        out[w] = packed_word;
    }
}

// ══════════════════════════════════════════════════════════════════════════════════
// BINDING
// ══════════════════════════════════════════════════════════════════════════════════

/// Role-filler binding: `out[i] = a[i] ^ b[i]`. XOR is its own inverse, so
/// binding twice with the same key vector recovers the original hypervector.
pub fn bind_xor(a: []const u64, b: []const u64, out: []u64) void {
    std.debug.assert(a.len == b.len and a.len == out.len);
    for (a, b, out) |ai, bi, *oi| {
        oi.* = ai ^ bi;
    }
}

// ══════════════════════════════════════════════════════════════════════════════════
// C ABI EXPORTS
// ══════════════════════════════════════════════════════════════════════════════════

/// C ABI: one-shot majority-vote bundling. `out` must hold `words` u64s.
pub export fn omnisec_bundle_majority(
    samples: [*]const u64,
    out: [*]u64,
    num_samples: usize,
    words: usize,
) bool {
    if (words == 0) return true;
    if (@intFromPtr(out) == 0) return false;
    const out_slice = out[0..words];
    if (num_samples == 0) {
        @memset(out_slice, 0);
        return true;
    }
    if (@intFromPtr(samples) == 0) return false;
    const total_words = checkedMul(num_samples, words) orelse return false;
    bundle_majority(samples[0..total_words], num_samples, words, out_slice);
    return true;
}

/// C ABI: accumulate a batch of samples into a running per-bit counts buffer.
/// `counts_len` must be at least `words * 64`.
pub export fn omnisec_bundle_accumulate(
    samples: [*]const u64,
    counts: [*]u32,
    num_samples: usize,
    words: usize,
    counts_len: usize,
) bool {
    if (words == 0 or num_samples == 0) return true;
    if (@intFromPtr(samples) == 0 or @intFromPtr(counts) == 0) return false;
    const need = checkedMul(words, 64) orelse return false;
    if (counts_len < need) return false;
    const total_words = checkedMul(num_samples, words) orelse return false;
    bundle_accumulate(samples[0..total_words], num_samples, words, counts[0..need]);
    return true;
}

/// C ABI: threshold a running counts buffer into a packed prototype.
/// `counts_len` must be at least `words * 64`; `out` must hold `words` u64s.
pub export fn omnisec_bundle_finalize(
    counts: [*]const u32,
    out: [*]u64,
    total: usize,
    words: usize,
    counts_len: usize,
) bool {
    if (words == 0) return true;
    if (@intFromPtr(counts) == 0 or @intFromPtr(out) == 0) return false;
    const need = checkedMul(words, 64) orelse return false;
    if (counts_len < need) return false;
    bundle_finalize(counts[0..need], total, words, out[0..words]);
    return true;
}

/// C ABI: role-filler binding (element-wise XOR).
pub export fn omnisec_bind_xor(
    a: [*]const u64,
    b: [*]const u64,
    out: [*]u64,
    words: usize,
) bool {
    if (words == 0) return true;
    if (@intFromPtr(a) == 0 or @intFromPtr(b) == 0 or @intFromPtr(out) == 0) return false;
    bind_xor(a[0..words], b[0..words], out[0..words]);
    return true;
}

// ══════════════════════════════════════════════════════════════════════════════════
// TESTS
// ══════════════════════════════════════════════════════════════════════════════════

test "bundle_majority elects per-bit majority" {
    // 3 samples, 1 word. bit0 set in 3/3, bit2 set in 2/3 -> both win.
    const samples = [_]u64{
        0b0101, // bit0, bit2
        0b0001, // bit0
        0b0101, // bit0, bit2
    };
    var out = [_]u64{0};
    bundle_majority(&samples, 3, 1, &out);
    try std.testing.expectEqual(@as(u64, 0b0101), out[0]);
}

test "bundle_majority ties resolve to zero on even counts" {
    // 2 samples: bit0 in both (2/2 -> set), bit1 in exactly one (tie -> clear).
    const samples = [_]u64{ 0b11, 0b01 };
    var out = [_]u64{0};
    bundle_majority(&samples, 2, 1, &out);
    try std.testing.expectEqual(@as(u64, 0b01), out[0]);
}

test "bundle_majority zero samples yields zero vector" {
    var out = [_]u64{ 0xFFFF, 0xFFFF };
    bundle_majority(&.{}, 0, 2, &out);
    try std.testing.expectEqual(@as(u64, 0), out[0]);
    try std.testing.expectEqual(@as(u64, 0), out[1]);
}

test "streaming accumulate+finalize equals one-shot majority" {
    const words: usize = 2;
    const n: usize = 5;
    var samples: [n * words]u64 = undefined;
    var prng = std.Random.DefaultPrng.init(0xA11CE);
    const rnd = prng.random();
    for (&samples) |*s| s.* = rnd.int(u64);

    var one_shot = [_]u64{ 0, 0 };
    bundle_majority(&samples, n, words, &one_shot);

    // Feed the same samples in two chunks (2 then 3) through the streaming path.
    var counts = std.mem.zeroes([words * 64]u32);
    bundle_accumulate(samples[0 .. 2 * words], 2, words, &counts);
    bundle_accumulate(samples[2 * words .. n * words], 3, words, &counts);
    var streamed = [_]u64{ 0, 0 };
    bundle_finalize(&counts, n, words, &streamed);

    try std.testing.expectEqualSlices(u64, &one_shot, &streamed);
}

test "bind_xor is its own inverse" {
    const a = [_]u64{ 0xDEADBEEF, 0x1234 };
    const key = [_]u64{ 0xFACEFEED, 0xABCD };
    var bound = [_]u64{ 0, 0 };
    bind_xor(&a, &key, &bound);
    var unbound = [_]u64{ 0, 0 };
    bind_xor(&bound, &key, &unbound);
    try std.testing.expectEqualSlices(u64, &a, &unbound);
}

test "C ABI bundle majority" {
    // bit0: 2/3, bit1: 1/3, bit2: 3/3 -> 0b101.
    const samples = [_]u64{ 0b111, 0b101, 0b100 };
    var out = [_]u64{0};
    try std.testing.expect(omnisec_bundle_majority(&samples, &out, 3, 1));
    try std.testing.expectEqual(@as(u64, 0b101), out[0]);
}

test "C ABI bundle accumulate then finalize" {
    const samples = [_]u64{ 0b11, 0b01, 0b01 }; // words=1, n=3
    var counts = std.mem.zeroes([64]u32);
    try std.testing.expect(omnisec_bundle_accumulate(&samples, &counts, 3, 1, counts.len));
    var out = [_]u64{0};
    try std.testing.expect(omnisec_bundle_finalize(&counts, &out, 3, 1, counts.len));
    // bit0: 3/3 -> set; bit1: 1/3 -> clear -> 0b01.
    try std.testing.expectEqual(@as(u64, 0b01), out[0]);
}

test "C ABI bundle finalize validates capacity" {
    var counts = std.mem.zeroes([64]u32); // enough for words=1, not words=2
    var out = [_]u64{0};
    try std.testing.expect(omnisec_bundle_finalize(&counts, &out, 0, 1, counts.len));
    try std.testing.expect(!omnisec_bundle_finalize(&counts, &out, 0, 2, counts.len));
}

test "C ABI bind xor" {
    const a = [_]u64{0xFF00};
    const b = [_]u64{0x0FF0};
    var out = [_]u64{0};
    try std.testing.expect(omnisec_bind_xor(&a, &b, &out, 1));
    try std.testing.expectEqual(@as(u64, 0xF0F0), out[0]);
}
