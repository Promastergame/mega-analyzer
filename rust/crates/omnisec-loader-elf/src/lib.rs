//! ELF (Executable and Linkable Format) loader.
//!
//! Uses the in-house [`elfparse`] module (zero third-party dependencies)
//! and projects its result into the universal [`LoadedBinary`] shape.
//! Unit-tested against synthetic ELF64 buffers built inline — no external
//! fixtures required.
//!
//! ## Detected vs not-yet-supported
//!
//! - ✅ Architectures: `x86`, `x86_64`, `arm`, `arm64`, `mips`, `mips64`,
//!   `riscv32`, `riscv64`, `ppc`, `ppc64`, `sparc`.
//! - ✅ Endianness (little/big from `e_ident[EI_DATA]`).
//! - ✅ Sections (R/W/X/INITIALIZED/BSS) from `sh_flags`/`sh_type`.
//! - ✅ Static `.symtab` symbols *and* dynamic `.dynsym` symbols.
//! - ✅ Imports = undefined dynamic symbols (`SHN_UNDEF`).
//! - ✅ Exports = global defined dynamic symbols.
//! - ⏳ DT_NEEDED library list (currently lumped under `notes`).
//! - ⏳ DWARF / Build-ID / NT_GNU_BUILD_ID — Phase 2.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod elfparse;

use elfparse::{
    EM_386, EM_AARCH64, EM_ARM, EM_MIPS, EM_PPC, EM_PPC64, EM_RISCV, EM_SPARC, EM_SPARC32PLUS,
    EM_SPARCV9, EM_X86_64, ElfFile, PT_LOAD, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS,
    STB_GLOBAL, STB_WEAK, STT_FILE, STT_FUNC, STT_OBJECT, STT_SECTION,
};
use omnisec_loader::prelude::*;

/// Loader for the `Elf` format.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfLoader;

impl ElfLoader {
    /// Construct a new `ElfLoader`. Stateless / zero-cost.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Loader for ElfLoader {
    fn name(&self) -> &'static str {
        "elf"
    }

    fn format(&self) -> Format {
        Format::Elf
    }

    fn load(&self, bytes: &[u8]) -> Result<LoadedBinary> {
        let elf = elfparse::parse_elf(bytes)
            .map_err(|e| Error::parse(Format::Elf, format!("elfparse: {e}")))?;

        let arch = arch_from_elf(&elf);
        let endian = if elf.little_endian {
            Endian::Little
        } else {
            Endian::Big
        };

        let mut bin = LoadedBinary::new(Format::Elf, arch, endian, bytes.len());
        bin.entry_point = Some(elf.entry);
        bin.base_address = lowest_loadable_vaddr(&elf);

        // Sections.
        bin.sections.reserve(elf.section_headers.len());
        for sh in &elf.section_headers {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name as usize)
                .unwrap_or("")
                .to_string();
            // Skip the null section.
            if sh.sh_type == 0 && name.is_empty() {
                continue;
            }
            let mut flags = SectionFlags::empty();
            if sh.sh_flags & u64::from(SHF_ALLOC) != 0 {
                flags |= SectionFlags::READ;
            }
            if sh.sh_flags & u64::from(SHF_WRITE) != 0 {
                flags |= SectionFlags::WRITE;
            }
            if sh.sh_flags & u64::from(SHF_EXECINSTR) != 0 {
                flags |= SectionFlags::EXECUTE;
            }
            if sh.sh_type == SHT_NOBITS {
                flags |= SectionFlags::BSS;
            } else if !name.is_empty() && flags.intersects(SectionFlags::READ) {
                flags |= SectionFlags::INITIALIZED;
            }
            // Convention: linker-generated debug / unwind / pdata sections.
            if name.starts_with(".debug") || name == ".comment" {
                flags |= SectionFlags::DISCARDABLE;
            }

            bin.sections.push(Section {
                name,
                virtual_address: sh.sh_addr,
                virtual_size: sh.sh_size,
                file_offset: sh.sh_offset,
                file_size: if sh.sh_type == SHT_NOBITS {
                    0
                } else {
                    sh.sh_size
                },
                flags,
            });
        }

        // Symbols (static .symtab).
        for sym in &elf.syms {
            let name = elf
                .strtab
                .get_at(sym.st_name as usize)
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let kind = match sym.st_type() {
                STT_FUNC => SymbolKind::Function,
                STT_OBJECT => SymbolKind::Object,
                STT_SECTION => SymbolKind::Section,
                STT_FILE => SymbolKind::File,
                _ => SymbolKind::Other,
            };
            let bind = sym.st_bind();
            bin.symbols.push(Symbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
                kind,
                is_global: bind == STB_GLOBAL || bind == STB_WEAK,
            });
        }

        // Dynamic symbols → imports & exports.
        for sym in &elf.dynsyms {
            let name = elf
                .dynstrtab
                .get_at(sym.st_name as usize)
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            if sym.st_shndx == 0 {
                // SHN_UNDEF == imported (resolved at load-time by ld.so).
                bin.imports.push(Import {
                    library: dt_needed_for(&elf).unwrap_or_else(|| "<unknown>".into()),
                    name,
                    address: None,
                    ordinal: None,
                    is_data: matches!(sym.st_type(), STT_OBJECT),
                });
            } else if matches!(sym.st_bind(), STB_GLOBAL | STB_WEAK) {
                bin.exports.push(Export {
                    name,
                    address: sym.st_value,
                    ordinal: None,
                    is_forwarder: false,
                    forward_target: None,
                });
            }
        }

        // Surface DT_NEEDED list as notes for now.
        if !elf.libraries.is_empty() {
            bin.notes
                .push(format!("DT_NEEDED: {}", elf.libraries.join(", ")));
        }

        Ok(bin)
    }
}

/// Map ELF e_machine + ELF class to our [`Arch`].
fn arch_from_elf(elf: &ElfFile) -> Arch {
    let machine = elf.header.e_machine;
    let is_64 = elf.is_64;
    match machine {
        EM_386 => Arch::X86,
        EM_X86_64 => Arch::X86_64,
        EM_ARM => Arch::Arm,
        EM_AARCH64 => Arch::Arm64,
        EM_MIPS => {
            if is_64 {
                Arch::Mips64
            } else {
                Arch::Mips
            }
        }
        EM_RISCV => {
            if is_64 {
                Arch::RiscV64
            } else {
                Arch::RiscV32
            }
        }
        EM_PPC => Arch::Ppc,
        EM_PPC64 => Arch::Ppc64,
        EM_SPARC | EM_SPARC32PLUS | EM_SPARCV9 => Arch::Sparc,
        _ => Arch::Unknown,
    }
}

/// Lowest virtual address among LOAD program headers — a reasonable proxy
/// for "image base" in ET_EXEC / ET_DYN binaries.
fn lowest_loadable_vaddr(elf: &ElfFile) -> Option<u64> {
    elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| ph.p_vaddr)
        .min()
}

/// Pick the *first* DT_NEEDED entry, if any. For now we attribute all
/// imports to it; a future pass should use DT_SYMBOLIC / hash tables to
/// match each symbol to its concrete library.
fn dt_needed_for(elf: &ElfFile) -> Option<String> {
    elf.libraries.first().map(|s| (*s).to_string())
}

#[cfg(test)]
mod tests {
    use omnisec_core::detect_format;

    use super::*;

    /// Build a minimal valid 64-bit little-endian ELF executable for tests.
    /// One PT_LOAD, one .text section, no symbols. Ready to feed `elfparse`.
    fn build_min_elf64() -> Vec<u8> {
        // Layout:
        //   [0x000] ELF header (64 bytes)
        //   [0x040] Program header table (1 entry × 56 bytes)
        //   [0x078] Section header string table (".\0.shstrtab\0.text\0")
        //   [0x100] .text payload (0x10 bytes of NOP-equivalents)
        //   [0x110] Section header table (3 × 64 bytes)
        let mut buf = vec![0u8; 0x300];

        // ── ELF identification ──────────────────────────────────────────
        buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        buf[4] = 2; // EI_CLASS = ELFCLASS64
        buf[5] = 1; // EI_DATA = ELFDATA2LSB
        buf[6] = 1; // EI_VERSION
        // ── ELF header (64-bit little-endian) ───────────────────────────
        buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        buf[24..32].copy_from_slice(&0x4000_1000u64.to_le_bytes()); // e_entry
        buf[32..40].copy_from_slice(&0x40u64.to_le_bytes()); // e_phoff
        buf[40..48].copy_from_slice(&0x110u64.to_le_bytes()); // e_shoff
        buf[48..52].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        buf[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum (null + .shstrtab + .text)
        buf[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx -> 1

        // ── Program header (PT_LOAD) ────────────────────────────────────
        let ph = 0x40usize;
        buf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        buf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R+X
        buf[ph + 8..ph + 16].copy_from_slice(&0x100u64.to_le_bytes()); // p_offset
        buf[ph + 16..ph + 24].copy_from_slice(&0x4000_1000u64.to_le_bytes()); // p_vaddr
        buf[ph + 24..ph + 32].copy_from_slice(&0x4000_1000u64.to_le_bytes()); // p_paddr
        buf[ph + 32..ph + 40].copy_from_slice(&0x10u64.to_le_bytes()); // p_filesz
        buf[ph + 40..ph + 48].copy_from_slice(&0x10u64.to_le_bytes()); // p_memsz
        buf[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

        // ── .shstrtab ──────────────────────────────────────────────────
        // Layout: \0 .shstrtab \0 .text \0
        let shstrtab_off = 0x78usize;
        let shstrtab = b"\0.shstrtab\0.text\0";
        buf[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(shstrtab);

        // ── .text payload (just zeros for now) ─────────────────────────
        let text_off = 0x100usize;
        for b in &mut buf[text_off..text_off + 0x10] {
            *b = 0x90; // x86 NOP
        }

        // ── Section headers ─────────────────────────────────────────────
        let sh = 0x110usize;
        // [0] null section — left at zeros.
        // [1] .shstrtab
        let sh1 = sh + 64;
        buf[sh1..sh1 + 4].copy_from_slice(&1u32.to_le_bytes()); // sh_name -> ".shstrtab" at offset 1
        buf[sh1 + 4..sh1 + 8].copy_from_slice(&3u32.to_le_bytes()); // sh_type = SHT_STRTAB
        buf[sh1 + 24..sh1 + 32].copy_from_slice(&(shstrtab_off as u64).to_le_bytes()); // sh_offset
        buf[sh1 + 32..sh1 + 40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes()); // sh_size
        // [2] .text
        let sh2 = sh + 128;
        buf[sh2..sh2 + 4].copy_from_slice(&11u32.to_le_bytes()); // sh_name -> ".text" at offset 11
        buf[sh2 + 4..sh2 + 8].copy_from_slice(&1u32.to_le_bytes()); // sh_type = SHT_PROGBITS
        buf[sh2 + 8..sh2 + 16]
            .copy_from_slice(&(u64::from(SHF_ALLOC) | u64::from(SHF_EXECINSTR)).to_le_bytes());
        buf[sh2 + 16..sh2 + 24].copy_from_slice(&0x4000_1000u64.to_le_bytes()); // sh_addr
        buf[sh2 + 24..sh2 + 32].copy_from_slice(&(text_off as u64).to_le_bytes()); // sh_offset
        buf[sh2 + 32..sh2 + 40].copy_from_slice(&0x10u64.to_le_bytes()); // sh_size

        buf
    }

    #[test]
    fn loader_metadata() {
        let l = ElfLoader::new();
        assert_eq!(l.name(), "elf");
        assert_eq!(l.format(), Format::Elf);
    }

    #[test]
    fn detect_recognises_synthetic_elf() {
        let elf = build_min_elf64();
        assert_eq!(detect_format(&elf), Format::Elf);
    }

    #[test]
    fn loads_min_elf64() {
        let elf = build_min_elf64();
        let bin = ElfLoader::new().load(&elf).expect("min ELF should parse");
        assert_eq!(bin.format, Format::Elf);
        assert_eq!(bin.arch, Arch::X86_64);
        assert_eq!(bin.endian, Endian::Little);
        assert_eq!(bin.bitness, Some(Bitness::Bits64));
        assert_eq!(bin.entry_point, Some(0x4000_1000));
        assert_eq!(bin.base_address, Some(0x4000_1000));

        // Expect the .text section to be present, executable, and properly sized.
        let text = bin
            .sections
            .iter()
            .find(|s| s.name == ".text")
            .expect(".text section");
        assert_eq!(text.virtual_address, 0x4000_1000);
        assert_eq!(text.virtual_size, 0x10);
        assert!(text.flags.contains(SectionFlags::EXECUTE));
        assert!(text.flags.contains(SectionFlags::READ));
    }

    #[test]
    fn rejects_non_elf() {
        let l = ElfLoader::new();
        let pe = b"MZ\x90\x00";
        assert!(!l.can_load(pe));
        let err = l.load(pe).unwrap_err();
        assert!(matches!(
            err,
            Error::Parse {
                format: Format::Elf,
                ..
            }
        ));
    }

    /// Build an ELF64 LE executable with a dynamic section: one `DT_NEEDED`
    /// (`libc.so.6`), one undefined `.dynsym` entry (`printf` → import) and
    /// one defined global (`myfunc` → export).
    fn build_dyn_elf64() -> Vec<u8> {
        // Layout:
        //   [0x000] ELF header (64 B)
        //   [0x040] Program header (1 × 56 B, PT_LOAD R+X)
        //   [0x078] .shstrtab ("\0.shstrtab\0.text\0.dynstr\0.dynsym\0.dynamic\0")
        //   [0x100] .text (16 NOPs)
        //   [0x120] .dynstr ("\0libc.so.6\0printf\0myfunc\0")
        //   [0x140] .dynsym (3 × 24 B: null, printf UNDEF, myfunc defined)
        //   [0x190] .dynamic (DT_NEEDED, DT_NULL)
        //   [0x200] Section headers (6 × 64 B)
        let mut buf = vec![0u8; 0x400];

        buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1; // EI_VERSION
        buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..32].copy_from_slice(&0x4000_1000u64.to_le_bytes()); // e_entry
        buf[32..40].copy_from_slice(&0x40u64.to_le_bytes()); // e_phoff
        buf[40..48].copy_from_slice(&0x200u64.to_le_bytes()); // e_shoff
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        buf[58..60].copy_from_slice(&64u16.to_le_bytes());
        buf[60..62].copy_from_slice(&6u16.to_le_bytes()); // e_shnum
        buf[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx

        // PT_LOAD R+X covering .text.
        let ph = 0x40usize;
        buf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
        buf[ph + 8..ph + 16].copy_from_slice(&0x100u64.to_le_bytes());
        buf[ph + 16..ph + 24].copy_from_slice(&0x4000_1000u64.to_le_bytes());
        buf[ph + 24..ph + 32].copy_from_slice(&0x4000_1000u64.to_le_bytes());
        buf[ph + 32..ph + 40].copy_from_slice(&0x10u64.to_le_bytes());
        buf[ph + 40..ph + 48].copy_from_slice(&0x10u64.to_le_bytes());
        buf[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());

        // .shstrtab: \0 .shstrtab \0 .text \0 .dynstr \0 .dynsym \0 .dynamic \0
        let shstr = b"\0.shstrtab\0.text\0.dynstr\0.dynsym\0.dynamic\0";
        buf[0x78..0x78 + shstr.len()].copy_from_slice(shstr);

        // .text payload.
        for b in &mut buf[0x100..0x110] {
            *b = 0x90;
        }

        // .dynstr at 0x120: \0 libc.so.6 \0 printf \0 myfunc \0
        // offsets: libc.so.6 = 1, printf = 11, myfunc = 18.
        let dynstr = b"\0libc.so.6\0printf\0myfunc\0";
        buf[0x120..0x120 + dynstr.len()].copy_from_slice(dynstr);

        // .dynsym at 0x140: null, printf (UNDEF global func), myfunc (defined).
        // [1] printf: name=11, info=0x12 (GLOBAL|FUNC), shndx=0.
        let s1 = 0x140 + 24;
        buf[s1..s1 + 4].copy_from_slice(&11u32.to_le_bytes());
        buf[s1 + 4] = 0x12;
        // [2] myfunc: name=18, info=0x12, shndx=1, value=0x40001000.
        let s2 = 0x140 + 48;
        buf[s2..s2 + 4].copy_from_slice(&18u32.to_le_bytes());
        buf[s2 + 4] = 0x12;
        buf[s2 + 6..s2 + 8].copy_from_slice(&1u16.to_le_bytes());
        buf[s2 + 8..s2 + 16].copy_from_slice(&0x4000_1000u64.to_le_bytes());

        // .dynamic at 0x190: DT_NEEDED(1) -> 1, DT_NULL.
        buf[0x190..0x198].copy_from_slice(&1i64.to_le_bytes());
        buf[0x198..0x1A0].copy_from_slice(&1u64.to_le_bytes());
        // Second entry stays zeroed = DT_NULL.

        // Section headers at 0x200.
        let sh = 0x200usize;
        let mut hdr = |idx: usize,
                       name: u32,
                       stype: u32,
                       flags: u64,
                       off: u64,
                       size: u64,
                       link: u32,
                       info: u32,
                       entsize: u64| {
            let b = sh + idx * 64;
            buf[b..b + 4].copy_from_slice(&name.to_le_bytes());
            buf[b + 4..b + 8].copy_from_slice(&stype.to_le_bytes());
            buf[b + 8..b + 16].copy_from_slice(&flags.to_le_bytes());
            buf[b + 24..b + 32].copy_from_slice(&off.to_le_bytes());
            buf[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
            buf[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
            buf[b + 44..b + 48].copy_from_slice(&info.to_le_bytes());
            buf[b + 56..b + 64].copy_from_slice(&entsize.to_le_bytes());
        };
        hdr(1, 1, 3, 0, 0x78, shstr.len() as u64, 0, 0, 0); // .shstrtab
        hdr(
            2,
            11,
            1,
            u64::from(SHF_ALLOC) | u64::from(SHF_EXECINSTR),
            0x100,
            0x10,
            0,
            0,
            0,
        ); // .text
        hdr(
            3,
            17,
            3,
            u64::from(SHF_ALLOC),
            0x120,
            dynstr.len() as u64,
            0,
            0,
            0,
        ); // .dynstr
        hdr(4, 25, 11, u64::from(SHF_ALLOC), 0x140, 72, 3, 1, 24); // .dynsym
        hdr(
            5,
            33,
            6,
            u64::from(SHF_ALLOC) | u64::from(SHF_WRITE),
            0x190,
            32,
            3,
            0,
            16,
        ); // .dynamic

        buf
    }

    #[test]
    fn loads_dynamic_symbols() {
        let elf = build_dyn_elf64();
        let bin = ElfLoader::new()
            .load(&elf)
            .expect("dynamic ELF should parse");

        assert_eq!(bin.imports.len(), 1);
        assert_eq!(bin.imports[0].name, "printf");
        assert_eq!(bin.imports[0].library, "libc.so.6");
        assert!(!bin.imports[0].is_data);

        assert_eq!(bin.exports.len(), 1);
        assert_eq!(bin.exports[0].name, "myfunc");
        assert_eq!(bin.exports[0].address, 0x4000_1000);

        assert!(bin.notes.iter().any(|n| n.contains("libc.so.6")));
    }
}
