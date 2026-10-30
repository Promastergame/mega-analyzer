//! DWARF debug symbol resolver (zero-dependency stub).
//!
//! Previously backed by `gimli`; the third-party DWARF stack was eliminated
//! in the dependency-removal pass. The public API is intentionally preserved
//! (`new` / `resolve` with identical signatures) so a future in-house DWARF
//! reader (DIE trees, line programs) can fill this struct back in without
//! touching callers.
//!
//! Current behavior: construction always succeeds but holds no data, and
//! [`DwarfSymbolicator::resolve`] always returns `None`. Callers already
//! treat `None` as "no debug info" (frames get `symbol: None`), and the
//! debugger keeps resolving symbols through the loader's `.symtab` —
//! which covers stripped-vs-unstripped detection and import-based probes.
//! Net effect today: zero, since no call site currently constructs the
//! symbolicator with real data.

use omnisec_loader::LoadedBinary;

/// Resolves target memory addresses to DWARF function/line info.
///
/// Zero-dependency stub: holds no data, [`DwarfSymbolicator::resolve`]
/// always returns `None`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DwarfSymbolicator {
    /// Reserved for a future in-house DWARF reader; always zero.
    _reserved: u8,
}

impl DwarfSymbolicator {
    /// Load DWARF sections from binary metadata and raw file bytes.
    ///
    /// Currently a no-op returning an empty resolver (DWARF parsing was
    /// removed with the `gimli` dependency). The signature is kept so
    /// callers and a future in-house reader stay compatible.
    #[must_use]
    pub fn new(_binary: &LoadedBinary, _file_bytes: &[u8]) -> Self {
        Self { _reserved: 0 }
    }

    /// Resolve an address to a function name (symbol) and source line location.
    /// Returns: `Some((function_name, file_path, line_number))`
    ///
    /// Currently always returns `None` (see module docs).
    #[must_use]
    pub fn resolve(&self, _addr: u64) -> Option<(String, String, u32)> {
        None
    }
}
