//! The [`Loader`] trait — what every per-format parser implements.

use omnisec_core::{Format, Result};

use crate::LoadedBinary;

/// A parser for one binary container format.
///
/// Implementations should be cheap to construct (typically zero-sized) and
/// stateless. All work happens in [`Loader::load`].
///
/// # Contract
///
/// - [`Loader::format`] returns the *single* [`Format`] this loader handles.
///   Multi-format loaders should be split into one impl per format.
/// - [`Loader::can_load`] must be a fast pre-check (magic / a few bytes).
///   It MAY return false negatives but MUST NOT return false positives if
///   the loader will subsequently panic on `load`.
/// - [`Loader::load`] must populate the mandatory fields of [`LoadedBinary`].
///   Optional fields (symbols, imports, exports) should be populated when
///   present in the input.
pub trait Loader: Send + Sync {
    /// Stable, human-readable identifier (e.g. `"pe"`, `"elf"`).
    fn name(&self) -> &'static str;

    /// The format this loader claims.
    fn format(&self) -> Format;

    /// Fast pre-check: can this loader handle these bytes?
    /// Default impl runs [`omnisec_core::detect_format`] and compares.
    fn can_load(&self, bytes: &[u8]) -> bool {
        omnisec_core::detect_format(bytes) == self.format()
    }

    /// Parse `bytes` into a [`LoadedBinary`].
    fn load(&self, bytes: &[u8]) -> Result<LoadedBinary>;
}
