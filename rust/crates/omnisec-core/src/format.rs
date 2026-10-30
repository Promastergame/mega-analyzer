//! Binary container formats supported by OmniSec.

use omnisec_json::{FromJson, ToJson};

/// A binary container format.
///
/// This is the top-level taxonomy of "what kind of file is this?". It is
/// intentionally coarse: the [`Arch`](crate::Arch) enum carries instruction-set
/// information, and each loader crate decides how to parse the inside.
///
/// `Unknown` is *not* a parse error — it simply means magic-byte detection
/// could not classify the input. Callers may still try every loader by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum Format {
    /// Portable Executable (Windows EXE / DLL / SYS / OCX).
    Pe,
    /// Executable and Linkable Format (Linux/BSD ELF, Android shared libs, .o).
    Elf,
    /// Apple Mach-O (macOS / iOS / dylib / framework).
    MachO,
    /// Android Dalvik Executable.
    Dex,
    /// JVM ClassFile (single `.class`).
    JvmClass,
    /// JVM archive (`.jar` / `.war` / `.ear`) — a ZIP of class files plus metadata.
    JvmArchive,
    /// .NET PE assembly (CLR/CIL/MSIL).
    DotNet,
    /// WebAssembly module.
    Wasm,
    /// Android APK (a ZIP container holding DEX, resources, manifest).
    Apk,
    /// ISO 9660 / UDF disk image.
    Iso,
    /// Generic ZIP archive (we may dive in for nested binaries).
    Zip,
    /// Raw firmware blob — we'll fall back to entropy / string scanning.
    Firmware,
    /// Detection inconclusive.
    Unknown,
}

impl Format {
    /// Human-readable short name (used by CLI output and reports).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pe => "PE",
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
            Self::Dex => "DEX",
            Self::JvmClass => "JVM Class",
            Self::JvmArchive => "JVM Archive",
            Self::DotNet => ".NET",
            Self::Wasm => "WASM",
            Self::Apk => "APK",
            Self::Iso => "ISO",
            Self::Zip => "ZIP",
            Self::Firmware => "Firmware",
            Self::Unknown => "Unknown",
        }
    }

    /// `true` if this is some flavour of native machine code (PE/ELF/Mach-O).
    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, Self::Pe | Self::Elf | Self::MachO)
    }

    /// `true` if this is a managed-bytecode container (DEX/JVM-class/.NET/WASM).
    ///
    /// `JvmArchive` (`.jar`) is *not* counted here — it's a `.zip` envelope.
    /// Once the JVM-archive loader unpacks it, individual `.class` entries
    /// fall under `JvmClass`.
    #[must_use]
    pub const fn is_bytecode(self) -> bool {
        matches!(self, Self::Dex | Self::JvmClass | Self::DotNet | Self::Wasm)
    }

    /// `true` if this is a higher-level archive that may *contain* binaries
    /// (APK / JAR / ISO / ZIP). Loaders for these are expected to recurse.
    #[must_use]
    pub const fn is_archive(self) -> bool {
        matches!(self, Self::Apk | Self::JvmArchive | Self::Iso | Self::Zip)
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_is_consistent() {
        assert!(Format::Pe.is_native());
        assert!(Format::Elf.is_native());
        assert!(Format::MachO.is_native());

        assert!(Format::Dex.is_bytecode());
        assert!(Format::JvmClass.is_bytecode());
        assert!(Format::DotNet.is_bytecode());
        assert!(Format::Wasm.is_bytecode());

        assert!(Format::Apk.is_archive());
        assert!(Format::JvmArchive.is_archive());
        assert!(Format::Iso.is_archive());

        // No format should be more than one of {native, bytecode, archive}.
        for f in [
            Format::Pe,
            Format::Elf,
            Format::MachO,
            Format::Dex,
            Format::JvmClass,
            Format::JvmArchive,
            Format::DotNet,
            Format::Wasm,
            Format::Apk,
            Format::Iso,
            Format::Zip,
            Format::Firmware,
            Format::Unknown,
        ] {
            let count =
                u8::from(f.is_native()) + u8::from(f.is_bytecode()) + u8::from(f.is_archive());
            assert!(count <= 1, "format {f:?} is in more than one category");
        }
    }

    #[test]
    fn name_is_non_empty_for_every_variant() {
        for f in [
            Format::Pe,
            Format::Elf,
            Format::MachO,
            Format::Dex,
            Format::JvmClass,
            Format::JvmArchive,
            Format::DotNet,
            Format::Wasm,
            Format::Apk,
            Format::Iso,
            Format::Zip,
            Format::Firmware,
            Format::Unknown,
        ] {
            assert!(!f.name().is_empty());
        }
    }
}
