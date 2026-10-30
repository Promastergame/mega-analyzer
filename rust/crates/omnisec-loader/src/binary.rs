//! [`LoadedBinary`] — the format-agnostic view of a parsed input.
//!
//! Loaders translate their format-specific structures into this shared shape.
//! Downstream analyses (CFG, type recovery, vulndisc, exploit) only depend on
//! `LoadedBinary` and never on the original parser.

use omnisec_core::{Arch, Bitness, Endian, Format};
use omnisec_json::{FromJson, ToJson};

/// Universal "I parsed your binary" output.
///
/// Fields are populated on a best-effort basis: a stripped ELF won't have
/// `symbols`; a Mach-O without imports will have an empty `imports`; etc.
/// Loaders MUST populate `format`, `arch`, `endian` and `raw_size`.
/// Everything else is optional / may be empty.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct LoadedBinary {
    /// The container format we parsed.
    pub format: Format,

    /// The dominant ISA / VM target.
    pub arch: Arch,

    /// Pointer width, when the format implies one.
    pub bitness: Option<Bitness>,

    /// Endianness of the target.
    pub endian: Endian,

    /// Entry-point virtual address, if the format defines one.
    pub entry_point: Option<u64>,

    /// Preferred image base, if the format defines one (PE `ImageBase`,
    /// ELF lowest p_vaddr, ...).
    pub base_address: Option<u64>,

    /// Code & data sections / segments.
    pub sections: Vec<Section>,

    /// Defined symbols (functions, objects, ...).
    pub symbols: Vec<Symbol>,

    /// Imports / undefined externs (PE imports, ELF .dynsym externs, ...).
    pub imports: Vec<Import>,

    /// Exports (PE export table, ELF dynamic exports, ...).
    pub exports: Vec<Export>,

    /// Raw size of the original input in bytes.
    pub raw_size: usize,

    /// Free-form, format-specific notes — surfaced in CLI / reports without
    /// having to extend `LoadedBinary`. Use sparingly.
    #[json(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl LoadedBinary {
    /// Build a near-empty `LoadedBinary` with mandatory fields filled in.
    /// Loaders are expected to push into the vector fields after construction.
    #[must_use]
    pub fn new(format: Format, arch: Arch, endian: Endian, raw_size: usize) -> Self {
        Self {
            format,
            arch,
            bitness: arch.bitness(),
            endian,
            entry_point: None,
            base_address: None,
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            raw_size,
            notes: Vec::new(),
        }
    }

    /// Number of code-bearing (executable) sections.
    #[must_use]
    pub fn code_section_count(&self) -> usize {
        self.sections
            .iter()
            .filter(|s| s.flags.contains(SectionFlags::EXECUTE))
            .count()
    }

    /// Total executable bytes across all `EXECUTE` sections.
    #[must_use]
    pub fn code_bytes(&self) -> u64 {
        self.sections
            .iter()
            .filter(|s| s.flags.contains(SectionFlags::EXECUTE))
            .map(|s| s.virtual_size)
            .sum()
    }
}

/// Permission/usage flags for a [`Section`]. Mapped from format-native
/// flags by each loader (PE characteristics, ELF p_flags, Mach-O initprot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, ToJson, FromJson)]
pub struct SectionFlags(u32);

impl SectionFlags {
    /// Mapped readable.
    pub const READ: Self = Self(0b0000_0001);
    /// Mapped writable.
    pub const WRITE: Self = Self(0b0000_0010);
    /// Mapped executable.
    pub const EXECUTE: Self = Self(0b0000_0100);
    /// Contains initialized data on disk.
    pub const INITIALIZED: Self = Self(0b0000_1000);
    /// Contains uninitialized (zero-fill) data — BSS-style.
    pub const BSS: Self = Self(0b0001_0000);
    /// Linker-generated discardable section (.debug, .pdata, ...).
    pub const DISCARDABLE: Self = Self(0b0010_0000);

    /// No flags set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Raw bit value.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Build from raw bits (unknown bits are preserved).
    #[must_use]
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits)
    }

    /// `true` if no bits are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// `true` if all bits of `other` are set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// `true` if any bit of `other` is set.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Set the given bits.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Clear the given bits.
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}

impl std::ops::BitOr for SectionFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for SectionFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A code or data section / segment of a [`LoadedBinary`].
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Section {
    /// Section / segment name as it appears in the file (".text", "TEXT", ...).
    pub name: String,
    /// Virtual address where this section is mapped at runtime.
    pub virtual_address: u64,
    /// Virtual size (in-memory). May exceed `file_size` for BSS-like sections.
    pub virtual_size: u64,
    /// File offset of section bytes.
    pub file_offset: u64,
    /// On-disk size of the section.
    pub file_size: u64,
    /// Permission / usage flags.
    pub flags: SectionFlags,
}

impl Section {
    /// `true` if this is a BSS-like section (uninitialised zero-fill).
    #[must_use]
    pub fn is_bss(&self) -> bool {
        self.flags.contains(SectionFlags::BSS)
            || (self.virtual_size > self.file_size
                && !self.flags.contains(SectionFlags::INITIALIZED))
    }
}

/// What a [`Symbol`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum SymbolKind {
    /// A function (code).
    Function,
    /// A data object (variable, table, ...).
    Object,
    /// A section symbol (synthetic).
    Section,
    /// A file symbol (debug info).
    File,
    /// Anything else (or "we don't know").
    Other,
}

/// A defined symbol.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Symbol {
    /// Name (mangled — demangling is a downstream concern).
    pub name: String,
    /// Virtual address.
    pub address: u64,
    /// Size in bytes (0 if unknown).
    pub size: u64,
    /// Kind of symbol.
    pub kind: SymbolKind,
    /// `true` if this is exported / globally visible.
    pub is_global: bool,
}

/// An imported symbol — undefined inside this binary, expected from a library.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Import {
    /// Library / module the symbol comes from
    /// (e.g. "kernel32.dll", "libc.so.6", "/usr/lib/libSystem.B.dylib").
    pub library: String,
    /// Imported symbol name.
    pub name: String,
    /// PLT/IAT slot address, if known.
    pub address: Option<u64>,
    /// Ordinal-only imports keep `name` empty and store the ordinal here
    /// (PE import-by-ordinal).
    pub ordinal: Option<u32>,
    /// `true` if the symbol is imported as data, not code.
    pub is_data: bool,
}

/// An exported symbol — visible to dynamic linkers.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Export {
    /// Exported symbol name.
    pub name: String,
    /// Virtual address of the export.
    pub address: u64,
    /// Ordinal, if the format uses ordinals.
    pub ordinal: Option<u32>,
    /// `true` if this is a forwarder export to another DLL/symbol.
    pub is_forwarder: bool,
    /// Forwarded target ("KERNEL32.LoadLibraryW") if `is_forwarder`.
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub forward_target: Option<String>,
}

/// Tiny helper alias used internally by some loaders for stack-allocated
/// per-symbol metadata. Public for crate consumers that want to mirror the
/// shape.
pub type SmallSymbols = Vec<Symbol>;

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_core::{Endian, Format};

    #[test]
    fn new_loaded_binary_has_zero_sections() {
        let b = LoadedBinary::new(Format::Pe, Arch::X86_64, Endian::Little, 1024);
        assert_eq!(b.format, Format::Pe);
        assert_eq!(b.arch, Arch::X86_64);
        assert_eq!(b.bitness, Some(Bitness::Bits64));
        assert_eq!(b.endian, Endian::Little);
        assert_eq!(b.raw_size, 1024);
        assert!(b.sections.is_empty());
        assert_eq!(b.code_section_count(), 0);
        assert_eq!(b.code_bytes(), 0);
    }

    #[test]
    fn code_metrics_count_only_executable_sections() {
        let mut b = LoadedBinary::new(Format::Elf, Arch::X86_64, Endian::Little, 4096);
        b.sections.push(Section {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x500,
            file_offset: 0x200,
            file_size: 0x500,
            flags: SectionFlags::READ | SectionFlags::EXECUTE,
        });
        b.sections.push(Section {
            name: ".data".into(),
            virtual_address: 0x2000,
            virtual_size: 0x100,
            file_offset: 0x700,
            file_size: 0x100,
            flags: SectionFlags::READ | SectionFlags::WRITE,
        });
        b.sections.push(Section {
            name: ".bss".into(),
            virtual_address: 0x3000,
            virtual_size: 0x400,
            file_offset: 0,
            file_size: 0,
            flags: SectionFlags::READ | SectionFlags::WRITE | SectionFlags::BSS,
        });

        assert_eq!(b.code_section_count(), 1);
        assert_eq!(b.code_bytes(), 0x500);
        assert!(b.sections[2].is_bss());
        assert!(!b.sections[0].is_bss());
    }
}
