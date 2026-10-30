//! Universal loader layer.
//!
//! Every binary container (PE, ELF, Mach-O, DEX, JVM, .NET, WASM, ...) is
//! parsed by an implementation of [`Loader`]. A [`LoaderRegistry`] dispatches
//! input bytes to the right [`Loader`] using magic-byte detection from
//! [`omnisec_core::detect_format`].
//!
//! The output of every loader is the same — a [`LoadedBinary`] — so the rest
//! of the OmniSec pipeline (CFG, vulndisc, exploit, ...) doesn't care what
//! the source format was.
//!
//! ## Adding a new loader
//!
//! 1. Create a new crate `omnisec-loader-FOO`.
//! 2. Implement [`Loader`] for your parser type.
//! 3. Register an instance in [`LoaderRegistry::with_defaults`] (or call
//!    [`LoaderRegistry::register`] at runtime).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod binary;
pub mod registry;
pub mod traits;

pub use binary::{Export, Import, LoadedBinary, Section, SectionFlags, Symbol, SymbolKind};
pub use registry::LoaderRegistry;
pub use traits::Loader;

/// Re-export commonly used items from `omnisec-core` so loaders only need one
/// `use` line.
pub mod prelude {
    pub use omnisec_core::{Arch, Bitness, Endian, Error, Format, Result, detect_format};

    pub use crate::{
        Export, Import, LoadedBinary, Loader, LoaderRegistry, Section, SectionFlags, Symbol,
        SymbolKind,
    };
}
