//! [`LoaderRegistry`] — the central dispatch point.

use std::sync::Arc;

use omnisec_core::{Error, Format, Result, detect_format};

use crate::{LoadedBinary, Loader};

/// Registry of [`Loader`] implementations.
///
/// `dispatch(bytes)` picks a loader using magic-byte detection and runs it.
/// `load_with(format, bytes)` forces a specific format (useful when magic
/// detection is ambiguous, e.g. `.NET` PE vs plain PE).
///
/// Loaders are stored as `Arc<dyn Loader>` so the registry is cheaply
/// cloneable and thread-safe.
#[derive(Clone, Default)]
pub struct LoaderRegistry {
    loaders: Vec<Arc<dyn Loader>>,
}

impl LoaderRegistry {
    /// Empty registry. Call [`Self::register`] to add loaders.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a loader. Last-registered wins on ties (later loaders are
    /// tried first), so prefer registering more-specific loaders later.
    pub fn register<L: Loader + 'static>(&mut self, loader: L) -> &mut Self {
        self.loaders.push(Arc::new(loader));
        self
    }

    /// Number of registered loaders.
    #[must_use]
    pub fn len(&self) -> usize {
        self.loaders.len()
    }

    /// `true` if no loaders are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.loaders.is_empty()
    }

    /// All registered loaders, in registration order.
    #[must_use]
    pub fn loaders(&self) -> &[Arc<dyn Loader>] {
        &self.loaders
    }

    /// Find a loader for the given format. Last-registered wins.
    #[must_use]
    pub fn find(&self, format: Format) -> Option<&dyn Loader> {
        self.loaders
            .iter()
            .rev()
            .find(|l| l.format() == format)
            .map(std::convert::AsRef::as_ref)
    }

    /// Detect the format of `bytes` and run the matching loader.
    ///
    /// Returns [`Error::UnknownFormat`] if magic detection fails or no
    /// loader is registered for the detected format.
    pub fn dispatch(&self, bytes: &[u8]) -> Result<LoadedBinary> {
        let detected = detect_format(bytes);
        if detected == Format::Unknown {
            return Err(Error::unknown_format(
                "magic-byte detection did not match any known format",
            ));
        }

        self.load_with(detected, bytes)
    }

    /// Run the loader for `format` directly, bypassing magic detection.
    pub fn load_with(&self, format: Format, bytes: &[u8]) -> Result<LoadedBinary> {
        let loader = self
            .find(format)
            .ok_or_else(|| Error::unsupported(format!("no loader registered for {format}")))?;
        loader.load(bytes)
    }
}

impl std::fmt::Debug for LoaderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&'static str> = self.loaders.iter().map(|l| l.name()).collect();
        f.debug_struct("LoaderRegistry")
            .field("loaders", &names)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use omnisec_core::{Arch, Endian};

    use super::*;
    use crate::LoadedBinary;

    /// Mock loader that succeeds for one fixed format.
    struct MockLoader {
        fmt: Format,
    }

    impl Loader for MockLoader {
        fn name(&self) -> &'static str {
            "mock"
        }

        fn format(&self) -> Format {
            self.fmt
        }

        fn load(&self, bytes: &[u8]) -> Result<LoadedBinary> {
            Ok(LoadedBinary::new(
                self.fmt,
                Arch::X86_64,
                Endian::Little,
                bytes.len(),
            ))
        }
    }

    #[test]
    fn empty_registry_rejects_dispatch() {
        let r = LoaderRegistry::new();
        let bytes = [0x7F, b'E', b'L', b'F', 0, 0, 0, 0];
        let err = r.dispatch(&bytes).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));
    }

    #[test]
    fn dispatch_routes_by_magic() {
        let mut r = LoaderRegistry::new();
        r.register(MockLoader { fmt: Format::Elf });
        r.register(MockLoader { fmt: Format::Pe });

        let elf = [0x7F, b'E', b'L', b'F', 0, 0, 0, 0];
        let bin = r.dispatch(&elf).unwrap();
        assert_eq!(bin.format, Format::Elf);
        assert_eq!(bin.raw_size, 8);

        let pe = b"MZ\x90\x00";
        let bin = r.dispatch(pe).unwrap();
        assert_eq!(bin.format, Format::Pe);
    }

    #[test]
    fn dispatch_rejects_unknown() {
        let mut r = LoaderRegistry::new();
        r.register(MockLoader { fmt: Format::Elf });
        let err = r.dispatch(&[0; 4]).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat { .. }));
    }

    #[test]
    fn last_registered_loader_wins_on_collision() {
        let mut r = LoaderRegistry::new();
        r.register(MockLoader { fmt: Format::Elf });
        r.register(MockLoader { fmt: Format::Elf });
        assert_eq!(r.len(), 2);

        let elf = [0x7F, b'E', b'L', b'F', 0, 0, 0, 0];
        let _bin = r.dispatch(&elf).unwrap(); // doesn't matter which one wins; both succeed
    }
}
