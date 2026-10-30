//! PE (Portable Executable) loader.
//!
//! Uses the in-house [`peparse`] module (zero third-party dependencies)
//! and projects its result into the universal [`LoadedBinary`] shape.
//! Tested against tiny synthetic PEs assembled in the unit tests below —
//! no external fixtures required.
//!
//! ## Detected vs not-yet-supported
//!
//! - ✅ Architectures: `x86`, `x86_64`, `ARM`, `ARM64`, `Thumb` → mapped to
//!   the closest [`Arch`].
//! - ✅ Sections (with R/W/X flags + INITIALIZED / BSS / DISCARDABLE).
//! - ✅ Imports by name and by ordinal.
//! - ✅ Exports including forwarders.
//! - ✅ `.NET` detection (via CLR data directory) — surfaced in `notes`.
//! - ⏳ COFF symbol table, resources, TLS callbacks, debug directory,
//!   exception data — Phase 2.
//!
//! Parity contract: `pkg/internal/peinspect/pe_parity_test.go` pins the shared
//! corpus (PE32/PE32+/ARM64/plain/hardened/corrupt). Rust arch mapping must
//! stay aligned: 0x14C→x86, 0x8664→x86_64, 0xAA64→ARM64.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod peparse;

use omnisec_loader::prelude::*;
use peparse::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_DISCARDABLE,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PeFile,
};

// COFF `Machine` field values, per the Microsoft PE spec (stable numeric
// values that never change).
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01C0;
const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01C2;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01C4;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

/// Loader for the `Pe` format.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeLoader;

impl PeLoader {
    /// Construct a new `PeLoader`. Stateless / zero-cost.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Loader for PeLoader {
    fn name(&self) -> &'static str {
        "pe"
    }

    fn format(&self) -> Format {
        Format::Pe
    }

    fn load(&self, bytes: &[u8]) -> Result<LoadedBinary> {
        let pe = peparse::parse_pe(bytes)
            .map_err(|e| Error::parse(Format::Pe, format!("peparse: {e}")))?;

        let arch = arch_from_machine(pe.header.coff_header.machine);
        let endian = Endian::Little; // PE is always little-endian on disk.

        let mut bin = LoadedBinary::new(Format::Pe, arch, endian, bytes.len());
        // The parser exposes the image base as `u64` and entry / RVAs as
        // `u32`. We widen and fold in the image base so downstream
        // consumers always see absolute virtual addresses, never RVAs.
        let image_base: u64 = pe.image_base;
        let va = |rva: u32| {
            image_base
                .checked_add(u64::from(rva))
                .ok_or_else(|| Error::parse(Format::Pe, "virtual address overflow"))
        };
        bin.entry_point = if pe.entry == 0 {
            None
        } else {
            Some(va(pe.entry)?)
        };
        bin.base_address = Some(image_base);

        // Sections.
        bin.sections.reserve(pe.sections.len());
        for s in &pe.sections {
            let raw_name = s.name().unwrap_or("");
            bin.sections.push(Section {
                name: raw_name.to_string(),
                virtual_address: va(s.virtual_address)?,
                virtual_size: u64::from(s.virtual_size),
                file_offset: u64::from(s.pointer_to_raw_data),
                file_size: u64::from(s.size_of_raw_data),
                flags: pe_section_flags(s.characteristics),
            });
        }

        // Imports.
        bin.imports.reserve(pe.imports.len());
        for imp in &pe.imports {
            bin.imports.push(Import {
                library: imp.dll.to_string(),
                name: imp.name.to_string(),
                address: Some(va(imp.rva)?),
                ordinal: imp.ordinal.map(u32::from),
                is_data: false,
            });
        }

        // Exports.
        bin.exports.reserve(pe.exports.len());
        for exp in &pe.exports {
            let name = exp.name.as_deref().unwrap_or("").to_string();
            let (is_forwarder, forward_target) = match &exp.reexport {
                Some(re) => (true, Some(format!("{}.{}", re.lib, re.name))),
                None => (false, None),
            };
            bin.exports.push(Export {
                name,
                address: va(exp.rva)?,
                ordinal: exp.ordinal,
                is_forwarder,
                forward_target,
            });
        }

        if has_clr_directory(&pe) {
            bin.notes.push(".NET CLR header present".into());
        }

        Ok(bin)
    }
}

/// Map a COFF `Machine` value to our [`Arch`].
///
/// Note: `IMAGE_FILE_MACHINE_IA64` (Itanium) and any unknown value both fall
/// through to `Arch::Unknown` — Itanium support is intentionally not
/// planned for OmniSec.
fn arch_from_machine(machine: u16) -> Arch {
    match machine {
        IMAGE_FILE_MACHINE_I386 => Arch::X86,
        IMAGE_FILE_MACHINE_AMD64 => Arch::X86_64,
        IMAGE_FILE_MACHINE_ARM | IMAGE_FILE_MACHINE_THUMB | IMAGE_FILE_MACHINE_ARMNT => Arch::Arm,
        IMAGE_FILE_MACHINE_ARM64 => Arch::Arm64,
        _ => Arch::Unknown,
    }
}

/// Translate PE section `Characteristics` into our [`SectionFlags`].
fn pe_section_flags(ch: u32) -> SectionFlags {
    let mut f = SectionFlags::empty();
    if ch & IMAGE_SCN_MEM_READ != 0 {
        f |= SectionFlags::READ;
    }
    if ch & IMAGE_SCN_MEM_WRITE != 0 {
        f |= SectionFlags::WRITE;
    }
    if ch & IMAGE_SCN_MEM_EXECUTE != 0 {
        f |= SectionFlags::EXECUTE;
    }
    if ch & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
        f |= SectionFlags::INITIALIZED;
    }
    if ch & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
        f |= SectionFlags::BSS;
    }
    if ch & IMAGE_SCN_MEM_DISCARDABLE != 0 {
        f |= SectionFlags::DISCARDABLE;
    }
    f
}

/// `true` if the PE has a non-empty CLR (.NET) data directory.
fn has_clr_directory(pe: &PeFile) -> bool {
    let Some(oh) = &pe.header.optional_header else {
        return false;
    };
    matches!(
        oh.data_directories.get_clr_runtime_header(),
        Some(d) if d.size > 0,
    )
}

#[cfg(test)]
mod tests {
    use omnisec_core::detect_format;

    use super::*;

    /// Build a minimal valid 64-bit PE for testing.
    fn build_min_pe64() -> Vec<u8> {
        const PE_OFFSET: usize = 0x80;
        let mut buf = vec![0u8; 0x600];

        // DOS stub: just "MZ" and e_lfanew at 0x3C.
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());

        // PE signature.
        buf[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        // COFF header (20 bytes after "PE\0\0").
        let coff = PE_OFFSET + 4;
        buf[coff..coff + 2].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        buf[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
        buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // Characteristics

        // Optional header (PE32+).
        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // Magic = PE32+
        buf[opt + 2] = 14;
        buf[opt + 4..opt + 8].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfCode
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        buf[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        buf[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // ImageBase
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        buf[opt + 40..opt + 42].copy_from_slice(&6u16.to_le_bytes());
        buf[opt + 48..opt + 50].copy_from_slice(&6u16.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        buf[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem = Console
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        // Section header (40 bytes), placed right after the optional header.
        let sec = opt + 0xF0;
        buf[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        buf[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        buf[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        buf[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        buf[sec + 36..sec + 40].copy_from_slice(
            &(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA)
                .to_le_bytes(),
        );

        buf
    }

    #[test]
    fn loader_metadata() {
        let l = PeLoader::new();
        assert_eq!(l.name(), "pe");
        assert_eq!(l.format(), Format::Pe);
    }

    #[test]
    fn detect_format_recognises_synthetic_pe() {
        let pe = build_min_pe64();
        assert_eq!(detect_format(&pe), Format::Pe);
    }

    #[test]
    fn loads_min_pe64() {
        let pe = build_min_pe64();
        let bin = PeLoader::new().load(&pe).expect("min PE should parse");
        assert_eq!(bin.format, Format::Pe);
        assert_eq!(bin.arch, Arch::X86_64);
        assert_eq!(bin.endian, Endian::Little);
        assert_eq!(bin.bitness, Some(Bitness::Bits64));
        assert_eq!(bin.entry_point, Some(0x0001_4000_1000));
        assert_eq!(bin.base_address, Some(0x0000_0001_4000_0000));
        assert_eq!(bin.sections.len(), 1);
        assert_eq!(bin.sections[0].name, ".text");
        assert!(bin.sections[0].flags.contains(SectionFlags::EXECUTE));
        assert!(bin.sections[0].flags.contains(SectionFlags::READ));
        assert!(!bin.sections[0].flags.contains(SectionFlags::WRITE));
        assert_eq!(bin.code_section_count(), 1);
    }

    #[test]
    fn rejects_non_pe() {
        let l = PeLoader::new();
        let elf = [0x7F, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(!l.can_load(&elf));
        let err = l.load(&elf).unwrap_err();
        assert!(matches!(
            err,
            Error::Parse {
                format: Format::Pe,
                ..
            }
        ));
    }

    #[test]
    fn arch_mapping_covers_known_machines() {
        assert_eq!(arch_from_machine(IMAGE_FILE_MACHINE_I386), Arch::X86);
        assert_eq!(arch_from_machine(IMAGE_FILE_MACHINE_AMD64), Arch::X86_64);
        assert_eq!(arch_from_machine(IMAGE_FILE_MACHINE_ARM), Arch::Arm);
        assert_eq!(arch_from_machine(IMAGE_FILE_MACHINE_ARM64), Arch::Arm64);
        assert_eq!(arch_from_machine(IMAGE_FILE_MACHINE_THUMB), Arch::Arm);
        assert_eq!(arch_from_machine(0xFFFF), Arch::Unknown);
    }

    #[test]
    fn pe_flags_round_trip_through_helper() {
        let f = pe_section_flags(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
        assert!(f.contains(SectionFlags::EXECUTE));
        assert!(f.contains(SectionFlags::READ));
        assert!(!f.contains(SectionFlags::WRITE));

        let f2 = pe_section_flags(IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_UNINITIALIZED_DATA);
        assert!(f2.contains(SectionFlags::WRITE));
        assert!(f2.contains(SectionFlags::BSS));
        assert!(!f2.contains(SectionFlags::EXECUTE));
    }

    /// Build a PE64 with one named import (`kernel32.dll!ExitProcess`), one
    /// ordinal import (`#5`) and one export (`TestFunc`).
    ///
    /// Layout (RVAs): `.text` = 0x1000, `.idata` = 0x2000 (file 0x600),
    /// `.edata` = 0x3000 (file 0x800).
    fn build_imp_exp_pe64() -> Vec<u8> {
        const PE_OFFSET: usize = 0x80;
        let mut buf = vec![0u8; 0x1000];

        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());
        buf[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        let coff = PE_OFFSET + 4;
        buf[coff..coff + 2].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&3u16.to_le_bytes()); // sections
        buf[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        buf[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x5000u32.to_le_bytes()); // SizeOfImage
        buf[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // console
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        // Data directories: [0] export, [1] import.
        buf[opt + 112..opt + 116].copy_from_slice(&0x3000u32.to_le_bytes());
        buf[opt + 116..opt + 120].copy_from_slice(&40u32.to_le_bytes());
        buf[opt + 120..opt + 124].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[opt + 124..opt + 128].copy_from_slice(&40u32.to_le_bytes());

        // Section headers.
        let mut sec =
            |idx: usize, name: &[u8; 8], vsize: u32, vaddr: u32, raw: u32, ptr: u32, ch: u32| {
                let b = opt + 0xF0 + idx * 40;
                buf[b..b + 8].copy_from_slice(name);
                buf[b + 8..b + 12].copy_from_slice(&vsize.to_le_bytes());
                buf[b + 12..b + 16].copy_from_slice(&vaddr.to_le_bytes());
                buf[b + 16..b + 20].copy_from_slice(&raw.to_le_bytes());
                buf[b + 20..b + 24].copy_from_slice(&ptr.to_le_bytes());
                buf[b + 36..b + 40].copy_from_slice(&ch.to_le_bytes());
            };
        sec(
            0,
            b".text\0\0\0",
            0x200,
            0x1000,
            0x200,
            0x400,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA,
        );
        sec(
            1,
            b".idata\0\0",
            0x100,
            0x2000,
            0x100,
            0x600,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA,
        );
        sec(
            2,
            b".edata\0\0",
            0x80,
            0x3000,
            0x80,
            0x800,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
        );

        // ── .idata (file 0x600, RVA 0x2000) ──
        let id = 0x600usize;
        // Descriptor[0] and the all-zero terminator occupy 0x2000..0x2028.
        // Keep ILT/IAT outside both descriptors.
        buf[id..id + 4].copy_from_slice(&0x2060u32.to_le_bytes());
        buf[id + 12..id + 16].copy_from_slice(&0x2040u32.to_le_bytes());
        buf[id + 16..id + 20].copy_from_slice(&0x20a0u32.to_le_bytes());
        // ILT: Hint/Name RVA, ordinal #5, end.
        buf[id + 0x60..id + 0x68].copy_from_slice(&0x2030u64.to_le_bytes());
        buf[id + 0x68..id + 0x70].copy_from_slice(&0x8000_0000_0000_0005u64.to_le_bytes());
        // Hint/Name at +0x30 (RVA 0x2030): hint + "ExitProcess".
        buf[id + 0x32..id + 0x32 + 11].copy_from_slice(b"ExitProcess");
        // DLL name at +0x40 (RVA 0x2040).
        buf[id + 0x40..id + 0x40 + 12].copy_from_slice(b"kernel32.dll");

        // ── .edata (file 0x800, RVA 0x3000) ──
        let ed = 0x800usize;
        buf[ed + 12..ed + 16].copy_from_slice(&0x3040u32.to_le_bytes()); // Name -> "test.dll"
        buf[ed + 16..ed + 20].copy_from_slice(&1u32.to_le_bytes()); // Base
        buf[ed + 20..ed + 24].copy_from_slice(&1u32.to_le_bytes()); // NumberOfFunctions
        buf[ed + 24..ed + 28].copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames
        buf[ed + 28..ed + 32].copy_from_slice(&0x3050u32.to_le_bytes()); // AddressOfFunctions
        buf[ed + 32..ed + 36].copy_from_slice(&0x3054u32.to_le_bytes()); // AddressOfNames
        buf[ed + 36..ed + 40].copy_from_slice(&0x3058u32.to_le_bytes()); // AddressOfNameOrdinals
        buf[ed + 0x50..ed + 0x54].copy_from_slice(&0x1000u32.to_le_bytes()); // func[0] -> .text
        buf[ed + 0x54..ed + 0x58].copy_from_slice(&0x3060u32.to_le_bytes()); // name[0]
        buf[ed + 0x40..ed + 0x40 + 8].copy_from_slice(b"test.dll");
        buf[ed + 0x60..ed + 0x60 + 8].copy_from_slice(b"TestFunc");

        buf
    }

    #[test]
    fn loads_imports_and_exports() {
        let pe = build_imp_exp_pe64();
        let bin = PeLoader::new()
            .load(&pe)
            .expect("import/export PE should parse");

        assert_eq!(bin.imports.len(), 2);
        assert_eq!(bin.imports[0].library, "kernel32.dll");
        assert_eq!(bin.imports[0].name, "ExitProcess");
        assert_eq!(bin.imports[0].ordinal, None);
        assert_eq!(bin.imports[0].address, Some(0x0000_0001_4000_20a0));
        assert_eq!(bin.imports[1].name, "");
        assert_eq!(bin.imports[1].ordinal, Some(5));

        assert_eq!(bin.exports.len(), 1);
        assert_eq!(bin.exports[0].name, "TestFunc");
        assert_eq!(bin.exports[0].address, 0x0000_0001_4000_1000);
        assert!(!bin.exports[0].is_forwarder);
    }
}
