//! Centralised resource limits.
//!
//! The scanner ingests *untrusted* binaries (that is the whole point), so
//! every unbounded loop or allocation is a denial-of-service vector. A
//! crafted input can otherwise force gigabytes of string allocation or a
//! multi-minute entropy sweep. These caps keep a single scan bounded in
//! both time and memory regardless of how hostile the input is.

/// Hard ceiling on the input we will look at at all. Anything larger is
/// almost certainly not a shippable `.so`/`.dll` and is refused up front.
pub const MAX_INPUT_SIZE: usize = 512 * 1024 * 1024;

/// Ceiling on the number of bytes any *whole-file* linear probe (embedded
/// ELF magic, entropy blobs, numeric candidates, ASCII strings) will walk.
/// We scan a prefix rather than the entire multi-hundred-MB file; the
/// interesting stubs/headers/payloads live near the front and back, and a
/// prefix keeps offsets valid.
pub const MAX_CONTENT_SCAN_BYTES: usize = 128 * 1024 * 1024;

/// Ceiling on how many distinct ASCII strings we will materialise. Without
/// this a `.rodata`-heavy binary can spike memory into the gigabytes
/// before any per-category cap kicks in.
pub const MAX_EXTRACTED_STRINGS: usize = 200_000;
