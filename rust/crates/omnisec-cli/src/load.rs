//! Filesystem -> bytes -> [`LoaderRegistry`] dispatch.

use std::path::Path;

use omnisec_core::Format;
use omnisec_loader::{LoadedBinary, LoaderRegistry};
use omnisec_loader_elf::ElfLoader;
use omnisec_loader_pe::PeLoader;

use crate::error::{Error, Result, ResultExt};

/// Build a registry pre-populated with every loader OmniSec ships in Phase 1.
#[must_use]
pub fn default_registry() -> LoaderRegistry {
    let mut r = LoaderRegistry::new();
    r.register(PeLoader::new());
    r.register(ElfLoader::new());
    r
}

/// Read the file at `path`, dispatch through the default registry (or the
/// forced format), and return the resulting [`LoadedBinary`].
///
/// We deliberately use plain `std::fs::read` rather than `mmap`: the
/// workspace forbids `unsafe_code` and CLI-scale inputs (≤ a few hundred
/// MB) load fast enough either way. If we ever need streaming for huge
/// firmware images we'll wall off the `unsafe` in a tiny dedicated crate.
pub fn open_and_dispatch(path: &Path, force: Option<Format>) -> Result<LoadedBinary> {
    let bytes = std::fs::read(path).context(format!("reading '{}'", path.display()))?;
    if bytes.is_empty() {
        return Err(Error::msg(format!("'{}' is empty", path.display())));
    }

    let registry = default_registry();
    let bin = match force {
        Some(fmt) => registry
            .load_with(fmt, &bytes)
            .context(format!("forced format {fmt} on '{}'", path.display()))?,
        None => registry
            .dispatch(&bytes)
            .context(format!("dispatching '{}'", path.display()))?,
    };
    Ok(bin)
}
