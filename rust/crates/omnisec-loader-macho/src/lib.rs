//! OmniSec Mach-O / FAT loader
//!
//! Parses Mach-O 64-bit binaries and FAT universal binaries,
//! extracting segments, symbols and dylib dependencies.

#![allow(missing_docs)] // early-phase crate; docs will be added once API stabilises

use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum MachOError {
    InvalidMagic(u32),
    TruncatedHeader,
    TruncatedLoadCommand(usize),
    StringTableOob,
    FatArchOutOfBounds(usize),
}

impl std::fmt::Display for MachOError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic(magic) => write!(
                f,
                "invalid magic: expected Mach-O 64 (0xfeedfacf), FAT (0xcafebabe) or Mach-O 32 (0xfeedface), got 0x{magic:08x}"
            ),
            Self::TruncatedHeader => write!(f, "truncated header"),
            Self::TruncatedLoadCommand(offset) => {
                write!(f, "truncated load command at offset {offset}")
            }
            Self::StringTableOob => write!(f, "string table out of bounds"),
            Self::FatArchOutOfBounds(index) => {
                write!(f, "FAT architecture index {index} out of bounds")
            }
        }
    }
}

impl std::error::Error for MachOError {}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed Mach-O / FAT file.
#[derive(Debug, Clone, PartialEq)]
pub struct MachOFile {
    pub architectures: Vec<Arch>,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    pub dylibs: Vec<Dylib>,
    pub entry_point: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Arch {
    pub cpu_type: CpuType,
    pub cpu_subtype: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuType {
    /// 32-bit Intel (`CPU_TYPE_X86`).
    X86,
    /// 64-bit Intel (`CPU_TYPE_X86_64`).
    X86_64,
    /// 32-bit ARM (`CPU_TYPE_ARM`, classic iOS).
    Arm,
    /// 64-bit ARM (`CPU_TYPE_ARM64`).
    Arm64,
    /// 64-bit ARM with pointer authentication (`CPU_TYPE_ARM64_32`/`ARM64E`).
    Arm64e,
    /// Unrecognised `cputype` (raw value preserved).
    Unknown(u32),
}

impl From<u32> for CpuType {
    fn from(v: u32) -> Self {
        match v {
            0x0000_0007 => CpuType::X86,
            0x0100_0007 => CpuType::X86_64,
            0x0000_000C => CpuType::Arm,
            0x0200_000C => CpuType::Arm64e,
            0x0100_000C => CpuType::Arm64,
            _ => CpuType::Unknown(v),
        }
    }
}

impl fmt::Display for CpuType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CpuType::X86 => write!(f, "x86"),
            CpuType::X86_64 => write!(f, "x86_64"),
            CpuType::Arm => write!(f, "arm"),
            CpuType::Arm64 => write!(f, "arm64"),
            CpuType::Arm64e => write!(f, "arm64e"),
            CpuType::Unknown(v) => write!(f, "unknown(0x{v:08x})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Symbol {
    pub name: String,
    pub addr: u64,
    pub section: u16,
    pub sym_type: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Dylib {
    pub name: String,
    pub current_version: u32,
    pub compatibility_version: u32,
}

impl MachOFile {
    pub fn parse(data: &[u8]) -> Result<Self, MachOError> {
        if data.len() < 4 {
            return Err(MachOError::TruncatedHeader);
        }
        let magic = u32::from_le_bytes(data[..4].try_into().unwrap());
        match magic {
            0xfeed_facf => parse_macho64(data),
            0xfeed_face => parse_macho32(data),
            0xcafe_babe => parse_fat(data),
            other => Err(MachOError::InvalidMagic(other)),
        }
    }

    /// Returns true if the binary links against the given dylib name (substring match).
    pub fn links_dylib(&self, name: &str) -> bool {
        self.dylibs.iter().any(|d| d.name.contains(name))
    }

    /// Returns the first segment whose name matches `name`.
    pub fn segment_by_name(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.name == name)
    }
}

use omnisec_core::{
    Arch as LoaderArch, Endian, Error as LoaderError, Format, Result as LoaderResult,
};
use omnisec_loader::{
    Export, Import, LoadedBinary, Loader, Section, SectionFlags, Symbol as LoaderSymbol, SymbolKind,
};

/// Loader for the `MachO` format.
#[derive(Debug, Clone, Copy, Default)]
pub struct MachOLoader;

impl MachOLoader {
    /// Construct a new `MachOLoader`. Stateless / zero-cost.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Loader for MachOLoader {
    fn name(&self) -> &'static str {
        "macho"
    }

    fn format(&self) -> Format {
        Format::MachO
    }

    fn load(&self, bytes: &[u8]) -> LoaderResult<LoadedBinary> {
        let macho = MachOFile::parse(bytes)
            .map_err(|e| LoaderError::parse(Format::MachO, format!("macho parse error: {e}")))?;

        // Map cpu_type / architecture
        let arch = if let Some(first_arch) = macho.architectures.first() {
            match first_arch.cpu_type {
                CpuType::X86 => LoaderArch::X86,
                CpuType::X86_64 => LoaderArch::X86_64,
                CpuType::Arm => LoaderArch::Arm,
                CpuType::Arm64 | CpuType::Arm64e => LoaderArch::Arm64,
                _ => LoaderArch::Unknown,
            }
        } else {
            LoaderArch::Unknown
        };

        // For modern macOS, little-endian is dominant.
        let endian = Endian::Little;

        let mut bin = LoadedBinary::new(Format::MachO, arch, endian, bytes.len());
        bin.entry_point = macho.entry_point;

        // Find the base address (typically lowest vmaddr of segments)
        bin.base_address = macho.segments.iter().map(|s| s.vmaddr).min();

        // Sections
        bin.sections.reserve(macho.segments.len());
        for seg in &macho.segments {
            let mut flags = SectionFlags::empty();
            // initprot / maxprot contain VM_PROT_* flags
            // In macOS/Mach-O initprot: 1 = read, 2 = write, 4 = execute
            if seg.initprot & 1 != 0 {
                flags |= SectionFlags::READ;
            }
            if seg.initprot & 2 != 0 {
                flags |= SectionFlags::WRITE;
            }
            if seg.initprot & 4 != 0 {
                flags |= SectionFlags::EXECUTE;
            }

            // Map BSS vs Initialized: BSS if filesize is 0 and vmsize > 0
            if seg.filesize == 0 && seg.vmsize > 0 {
                flags |= SectionFlags::BSS;
            } else if flags.intersects(SectionFlags::READ) {
                flags |= SectionFlags::INITIALIZED;
            }

            bin.sections.push(Section {
                name: seg.name.clone(),
                virtual_address: seg.vmaddr,
                virtual_size: seg.vmsize,
                file_offset: seg.fileoff,
                file_size: seg.filesize,
                flags,
            });
        }

        // Symbols, Imports, Exports
        for sym in &macho.symbols {
            let is_stab = (sym.sym_type & 0xe0) != 0;
            if is_stab {
                continue; // skip debug symbols
            }

            let is_external = (sym.sym_type & 0x01) != 0;
            let n_type = sym.sym_type & 0x0e;

            if n_type == 0x0 {
                // N_UNDF
                let library = macho
                    .dylibs
                    .first()
                    .map_or_else(|| "<unknown>".into(), |d| d.name.clone());
                bin.imports.push(Import {
                    library,
                    name: sym.name.clone(),
                    address: None,
                    ordinal: None,
                    is_data: false,
                });
            } else {
                let kind = if sym.name.starts_with("__") || sym.name.contains("func") {
                    SymbolKind::Function
                } else {
                    SymbolKind::Object
                };

                bin.symbols.push(LoaderSymbol {
                    name: sym.name.clone(),
                    address: sym.addr,
                    size: 0,
                    kind,
                    is_global: is_external,
                });

                if is_external {
                    bin.exports.push(Export {
                        name: sym.name.clone(),
                        address: sym.addr,
                        ordinal: None,
                        is_forwarder: false,
                        forward_target: None,
                    });
                }
            }
        }

        if !macho.dylibs.is_empty() {
            let libs: Vec<String> = macho.dylibs.iter().map(|d| d.name.clone()).collect();
            bin.notes.push(format!("DYLIBS: {}", libs.join(", ")));
        }

        Ok(bin)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MACH-O 64 PARSER
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_macho64(data: &[u8]) -> Result<MachOFile, MachOError> {
    if data.len() < 32 {
        return Err(MachOError::TruncatedHeader);
    }

    // let magic = u32_from_le(data, 0); // already checked
    let cputype = u32_from_le(data, 4);
    let cpusubtype = u32_from_le(data, 8);
    // let filetype = u32_from_le(data, 12);
    let ncmds = u32_from_le(data, 16) as usize;
    let sizeofcmds = u32_from_le(data, 20) as usize;
    // let flags = u32_from_le(data, 24);

    let mut file = MachOFile {
        architectures: vec![Arch {
            cpu_type: CpuType::from(cputype),
            cpu_subtype: cpusubtype,
        }],
        segments: Vec::new(),
        symbols: Vec::new(),
        dylibs: Vec::new(),
        entry_point: None,
    };

    let mut offset = 32usize;
    let end = 32 + sizeofcmds;
    if end > data.len() {
        return Err(MachOError::TruncatedHeader);
    }

    for _ in 0..ncmds {
        if offset + 8 > data.len() {
            return Err(MachOError::TruncatedLoadCommand(offset));
        }
        let cmd = u32_from_le(data, offset);
        let size = u32_from_le(data, offset + 4) as usize;
        // A load command header is 8 bytes (`cmd` + `cmdsize`), so `cmdsize`
        // must be at least 8. Rejecting smaller values also guarantees the
        // `offset += size` at the end of the loop makes progress — a crafted
        // `cmdsize` of 0 would otherwise spin here up to `ncmds` (~4 billion)
        // times without advancing, a cheap denial-of-service.
        if size < 8 || offset + size > data.len() {
            return Err(MachOError::TruncatedLoadCommand(offset));
        }

        match cmd {
            LC_SEGMENT_64 => parse_segment_64(data, offset, size, &mut file)?,
            LC_SYMTAB => parse_symtab(data, offset, &mut file)?,
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => {
                parse_dylib(data, offset, size, &mut file)?;
            }
            LC_MAIN | LC_UNIXTHREAD
                // Entry point hints — LC_MAIN has entryoff at offset 32+8
                if size >= 16 => {
                    file.entry_point = Some(u64_from_le(data, offset + 8));
                }
            _ => {}
        }

        offset += size;
    }

    Ok(file)
}

fn parse_macho32(data: &[u8]) -> Result<MachOFile, MachOError> {
    // 32-bit mach_header is 28 bytes (no `reserved` field).
    if data.len() < 28 {
        return Err(MachOError::TruncatedHeader);
    }
    let cputype = u32_from_le(data, 4);
    let cpusubtype = u32_from_le(data, 8);
    let ncmds = u32_from_le(data, 16) as usize;
    let sizeofcmds = u32_from_le(data, 20) as usize;

    let mut file = MachOFile {
        architectures: vec![Arch {
            cpu_type: CpuType::from(cputype),
            cpu_subtype: cpusubtype,
        }],
        segments: Vec::new(),
        symbols: Vec::new(),
        dylibs: Vec::new(),
        entry_point: None,
    };

    let mut offset = 28usize;
    let end = 28 + sizeofcmds;
    if end > data.len() {
        return Err(MachOError::TruncatedHeader);
    }

    for _ in 0..ncmds {
        if offset + 8 > data.len() {
            return Err(MachOError::TruncatedLoadCommand(offset));
        }
        let cmd = u32_from_le(data, offset);
        let size = u32_from_le(data, offset + 4) as usize;
        if size < 8 || offset + size > data.len() {
            return Err(MachOError::TruncatedLoadCommand(offset));
        }

        match cmd {
            LC_SEGMENT => parse_segment_32(data, offset, size, &mut file)?,
            LC_SYMTAB => parse_symtab_32(data, offset, &mut file)?,
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => {
                parse_dylib(data, offset, size, &mut file)?;
            }
            LC_THREAD | LC_UNIXTHREAD if size >= 16 => {
                // Best-effort entry from the thread state: x86 (flavor 1)
                // carries eip at word 10, ARM (flavor 1) carries pc at
                // word 15 of the state payload.
                if let Some(entry) = thread_entry_32(data, offset, size, cputype) {
                    file.entry_point = Some(entry);
                }
            }
            _ => {}
        }

        offset += size;
    }

    Ok(file)
}

/// Best-effort entry point from a 32-bit `LC_THREAD`/`LC_UNIXTHREAD`
/// command: `flavor` + `count` header followed by the thread state words.
fn thread_entry_32(data: &[u8], off: usize, size: usize, cputype: u32) -> Option<u64> {
    // Layout: cmd(4) size(4) flavor(4) count(4) state[count * 4].
    if size < 16 || off + 16 > data.len() {
        return None;
    }
    let flavor = u32_from_le(data, off + 8);
    let count = u32_from_le(data, off + 12) as usize;
    let state_off = off + 16;
    let state_end = state_off + count * 4;
    if state_end > data.len() || state_end > off + size {
        return None;
    }
    let word = |idx: usize| -> Option<u64> {
        if idx < count {
            Some(u64::from(u32_from_le(data, state_off + idx * 4)))
        } else {
            None
        }
    };
    match (cputype, flavor) {
        // x86_THREAD_STATE32: eip is word 10.
        (7, 1) => word(10),
        // ARM_THREAD_STATE32: pc (r15) is word 15.
        (12, 1) => word(15),
        _ => None,
    }
}

fn parse_segment_32(
    data: &[u8],
    off: usize,
    size: usize,
    file: &mut MachOFile,
) -> Result<(), MachOError> {
    // LC_SEGMENT body is 48 bytes after the 8-byte header.
    if size < 56 {
        return Ok(());
    }
    let segname = cstr_to_string(&data[off + 8..off + 24]);
    let vmaddr = u64::from(u32_from_le(data, off + 24));
    let vmsize = u64::from(u32_from_le(data, off + 28));
    let fileoff = u64::from(u32_from_le(data, off + 32));
    let filesize = u64::from(u32_from_le(data, off + 36));
    let maxprot = u32_from_le(data, off + 40);
    let initprot = u32_from_le(data, off + 44);

    file.segments.push(Segment {
        name: segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot,
        initprot,
    });
    Ok(())
}

fn parse_symtab_32(data: &[u8], off: usize, file: &mut MachOFile) -> Result<(), MachOError> {
    // LC_SYMTAB: cmd(4)+size(4) + symoff(4)+nsyms(4)+stroff(4)+strsize(4)
    if off + 24 > data.len() {
        return Ok(());
    }
    let symoff = u32_from_le(data, off + 8) as usize;
    let nsyms = u32_from_le(data, off + 12) as usize;
    let stroff = u32_from_le(data, off + 16) as usize;
    let strsize = u32_from_le(data, off + 20) as usize;

    if stroff + strsize > data.len() || symoff + nsyms * 12 > data.len() {
        return Ok(()); // best-effort
    }

    let strtab = &data[stroff..stroff + strsize];

    for i in 0..nsyms {
        let s_off = symoff + i * 12; // nlist (32-bit) is 12 bytes
        if s_off + 12 > data.len() {
            break;
        }
        let str_idx = u32_from_le(data, s_off) as usize;
        let sym_type = data[s_off + 4];
        let sect = data[s_off + 5];
        // let desc = u16_from_le(data, s_off + 6);
        let value = u64::from(u32_from_le(data, s_off + 8));

        let name = read_strtab(strtab, str_idx).unwrap_or_default();
        if !name.is_empty() {
            file.symbols.push(Symbol {
                name,
                addr: value,
                section: u16::from(sect),
                sym_type,
            });
        }
    }
    Ok(())
}

fn parse_segment_64(
    data: &[u8],
    off: usize,
    size: usize,
    file: &mut MachOFile,
) -> Result<(), MachOError> {
    if size < 72 {
        return Ok(());
    }
    let segname = cstr_to_string(&data[off + 8..off + 24]);
    let vmaddr = u64_from_le(data, off + 24);
    let vmsize = u64_from_le(data, off + 32);
    let fileoff = u64_from_le(data, off + 40);
    let filesize = u64_from_le(data, off + 48);
    let maxprot = u32_from_le(data, off + 56);
    let initprot = u32_from_le(data, off + 60);

    file.segments.push(Segment {
        name: segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot,
        initprot,
    });
    Ok(())
}

fn parse_symtab(data: &[u8], off: usize, file: &mut MachOFile) -> Result<(), MachOError> {
    // LC_SYMTAB: cmd(4)+size(4) + symoff(4)+nsyms(4)+stroff(4)+strsize(4)
    if off + 24 > data.len() {
        return Ok(());
    }
    let symoff = u32_from_le(data, off + 8) as usize;
    let nsyms = u32_from_le(data, off + 12) as usize;
    let stroff = u32_from_le(data, off + 16) as usize;
    let strsize = u32_from_le(data, off + 20) as usize;

    if stroff + strsize > data.len() || symoff + nsyms * 16 > data.len() {
        return Ok(()); // best-effort
    }

    let strtab = &data[stroff..stroff + strsize];

    for i in 0..nsyms {
        let s_off = symoff + i * 16; // nlist_64 is 16 bytes
        if s_off + 16 > data.len() {
            break;
        }
        let str_idx = u32_from_le(data, s_off) as usize;
        let sym_type = data[s_off + 4];
        let sect = u16_from_le(data, s_off + 6);
        // let desc = u16_from_le(data, s_off + 8);
        let value = u64_from_le(data, s_off + 8);

        let name = read_strtab(strtab, str_idx).unwrap_or_default();
        if !name.is_empty() {
            file.symbols.push(Symbol {
                name,
                addr: value,
                section: sect,
                sym_type,
            });
        }
    }
    Ok(())
}

fn parse_dylib(
    data: &[u8],
    off: usize,
    size: usize,
    file: &mut MachOFile,
) -> Result<(), MachOError> {
    if size < 24 {
        return Ok(());
    }
    let name_offset = u32_from_le(data, off + 8) as usize;
    let current_version = u32_from_le(data, off + 12);
    let compat_version = u32_from_le(data, off + 16);
    let name = if off + name_offset < data.len() {
        cstr_to_string(&data[off + name_offset..])
    } else {
        String::new()
    };
    if !name.is_empty() {
        file.dylibs.push(Dylib {
            name,
            current_version,
            compatibility_version: compat_version,
        });
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// FAT PARSER
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_fat(data: &[u8]) -> Result<MachOFile, MachOError> {
    if data.len() < 8 {
        return Err(MachOError::TruncatedHeader);
    }
    // magic is big-endian
    let nfat = u32_from_be(data, 4) as usize;
    if data.len() < 8 + nfat * 20 {
        return Err(MachOError::TruncatedHeader);
    }

    let mut file = MachOFile {
        architectures: Vec::with_capacity(nfat),
        segments: Vec::new(),
        symbols: Vec::new(),
        dylibs: Vec::new(),
        entry_point: None,
    };

    for i in 0..nfat {
        let off = 8 + i * 20;
        let cputype = u32_from_be(data, off);
        let cpusubtype = u32_from_be(data, off + 4);
        let arch_offset = u32_from_be(data, off + 8) as usize;
        let arch_size = u32_from_be(data, off + 12) as usize;
        // let align = u32_from_be(data, off + 16);

        file.architectures.push(Arch {
            cpu_type: CpuType::from(cputype),
            cpu_subtype: cpusubtype,
        });

        if arch_offset + arch_size <= data.len() {
            let slice = &data[arch_offset..arch_offset + arch_size];
            let inner = if slice.len() >= 4
                && u32::from_le_bytes(slice[..4].try_into().unwrap()) == 0xfeed_face
            {
                parse_macho32(slice)
            } else {
                parse_macho64(slice)
            };
            if let Ok(inner) = inner {
                file.segments.extend(inner.segments);
                file.symbols.extend(inner.symbols);
                file.dylibs.extend(inner.dylibs);
                if file.entry_point.is_none() {
                    file.entry_point = inner.entry_point;
                }
            }
        }
    }

    Ok(file)
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOAD COMMAND CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const LC_SEGMENT_64: u32 = 0x19;
const LC_SEGMENT: u32 = 0x01;
const LC_SYMTAB: u32 = 0x02;
const LC_THREAD: u32 = 0x04;
const LC_LOAD_DYLIB: u32 = 0x0C;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18;
const LC_REEXPORT_DYLIB: u32 = 0x1F;
const LC_MAIN: u32 = 0x28 | 0x8000_0000; // 0x80000028
const LC_UNIXTHREAD: u32 = 0x05;

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

#[inline]
fn u32_from_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

#[inline]
fn u32_from_be(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}

#[inline]
fn u16_from_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}

#[inline]
fn u64_from_le(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

fn cstr_to_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .map(|b| b as char)
        .collect()
}

fn read_strtab(tab: &[u8], idx: usize) -> Option<String> {
    if idx >= tab.len() {
        return None;
    }
    let end = tab[idx..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(tab.len() - idx);
    Some(String::from_utf8_lossy(&tab[idx..idx + end]).into_owned())
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal Mach-O 64 header (not a real binary, but structurally valid).
    fn minimal_macho64() -> Vec<u8> {
        let mut v = Vec::new();
        // mach_header_64
        v.extend_from_slice(&0xfeed_facf_u32.to_le_bytes()); // magic
        v.extend_from_slice(&0x0100_000C_u32.to_le_bytes()); // cputype arm64
        v.extend_from_slice(&0x8000_0003_u32.to_le_bytes()); // cpusubtype
        v.extend_from_slice(&2_u32.to_le_bytes()); // filetype MH_EXECUTE
        v.extend_from_slice(&0_u32.to_le_bytes()); // ncmds = 0
        v.extend_from_slice(&0_u32.to_le_bytes()); // sizeofcmds = 0
        v.extend_from_slice(&0_u32.to_le_bytes()); // flags
        v.extend_from_slice(&0_u32.to_le_bytes()); // reserved
        v
    }

    #[test]
    fn parse_minimal_macho64() {
        let data = minimal_macho64();
        let file = MachOFile::parse(&data).unwrap();
        assert_eq!(file.architectures.len(), 1);
        assert!(matches!(file.architectures[0].cpu_type, CpuType::Arm64));
        assert!(file.segments.is_empty());
        assert!(file.symbols.is_empty());
    }

    /// Minimal Mach-O 32 (x86) with one `LC_SEGMENT` and one `LC_SYMTAB`.
    fn minimal_macho32() -> Vec<u8> {
        let mut v = Vec::new();
        // mach_header (28 bytes)
        v.extend_from_slice(&0xfeed_face_u32.to_le_bytes()); // magic
        v.extend_from_slice(&7_u32.to_le_bytes()); // cputype x86
        v.extend_from_slice(&3_u32.to_le_bytes()); // cpusubtype
        v.extend_from_slice(&2_u32.to_le_bytes()); // filetype MH_EXECUTE
        v.extend_from_slice(&2_u32.to_le_bytes()); // ncmds
        let sizeofcmds_pos = v.len();
        v.extend_from_slice(&0_u32.to_le_bytes()); // sizeofcmds (patched)
        v.extend_from_slice(&0_u32.to_le_bytes()); // flags
        // LC_SEGMENT (56 bytes)
        let seg_start = v.len();
        v.extend_from_slice(&LC_SEGMENT.to_le_bytes());
        v.extend_from_slice(&56_u32.to_le_bytes());
        let mut segname = [0u8; 16];
        segname[..7].copy_from_slice(b"__TEXT\x00");
        v.extend_from_slice(&segname);
        v.extend_from_slice(&0x1000_u32.to_le_bytes()); // vmaddr
        v.extend_from_slice(&0x2000_u32.to_le_bytes()); // vmsize
        v.extend_from_slice(&0_u32.to_le_bytes()); // fileoff
        v.extend_from_slice(&0x2000_u32.to_le_bytes()); // filesize
        v.extend_from_slice(&7_u32.to_le_bytes()); // maxprot rwx
        v.extend_from_slice(&5_u32.to_le_bytes()); // initprot r-x
        v.extend_from_slice(&0_u32.to_le_bytes()); // nsects
        v.extend_from_slice(&0_u32.to_le_bytes()); // flags
        // LC_SYMTAB referencing one symbol "_main" in the string table
        let sym_start = v.len();
        v.extend_from_slice(&LC_SYMTAB.to_le_bytes());
        v.extend_from_slice(&24_u32.to_le_bytes());
        let symoff_pos = v.len();
        v.extend_from_slice(&0_u32.to_le_bytes()); // symoff (patched)
        v.extend_from_slice(&1_u32.to_le_bytes()); // nsyms
        let stroff_pos = v.len();
        v.extend_from_slice(&0_u32.to_le_bytes()); // stroff (patched)
        v.extend_from_slice(&7_u32.to_le_bytes()); // strsize ("_main\0" + pad)
        // nlist (12 bytes): strx=1, type=0x0f, sect=1, desc=0, value=0x1234
        let symoff = v.len() as u32;
        v.extend_from_slice(&1_u32.to_le_bytes());
        v.push(0x0f);
        v.push(1);
        v.extend_from_slice(&0_u16.to_le_bytes());
        v.extend_from_slice(&0x1234_u32.to_le_bytes());
        // string table: "\0_main\0"
        let stroff = v.len() as u32;
        v.extend_from_slice(b"\x00_main\x00");
        // patch offsets
        v[symoff_pos..symoff_pos + 4].copy_from_slice(&symoff.to_le_bytes());
        v[stroff_pos..stroff_pos + 4].copy_from_slice(&stroff.to_le_bytes());
        let sizeofcmds = (v.len() - seg_start) as u32;
        v[sizeofcmds_pos..sizeofcmds_pos + 4].copy_from_slice(&sizeofcmds.to_le_bytes());
        let _ = sym_start;
        v
    }

    #[test]
    fn parse_macho32_with_segment_and_symbol() {
        let data = minimal_macho32();
        let file = MachOFile::parse(&data).unwrap();
        assert!(matches!(file.architectures[0].cpu_type, CpuType::X86));
        assert_eq!(file.segments.len(), 1);
        assert_eq!(file.segments[0].name, "__TEXT");
        assert_eq!(file.segments[0].vmaddr, 0x1000);
        assert_eq!(file.symbols.len(), 1);
        assert_eq!(file.symbols[0].name, "_main");
        assert_eq!(file.symbols[0].addr, 0x1234);
    }

    #[test]
    fn reject_invalid_magic() {
        let data = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF
        assert!(matches!(
            MachOFile::parse(&data),
            Err(MachOError::InvalidMagic(0x464c_457f))
        ));
    }

    #[test]
    fn reject_zero_size_load_command() {
        // A header claiming a huge `ncmds` with a first load command whose
        // `cmdsize` is 0 must be rejected immediately rather than spinning.
        let mut v = Vec::new();
        v.extend_from_slice(&0xfeed_facf_u32.to_le_bytes()); // magic
        v.extend_from_slice(&0x0100_000C_u32.to_le_bytes()); // cputype
        v.extend_from_slice(&0x8000_0003_u32.to_le_bytes()); // cpusubtype
        v.extend_from_slice(&2_u32.to_le_bytes()); // filetype
        v.extend_from_slice(&u32::MAX.to_le_bytes()); // ncmds (hostile)
        v.extend_from_slice(&8_u32.to_le_bytes()); // sizeofcmds
        v.extend_from_slice(&0_u32.to_le_bytes()); // flags
        v.extend_from_slice(&0_u32.to_le_bytes()); // reserved
        v.extend_from_slice(&LC_SYMTAB.to_le_bytes()); // cmd
        v.extend_from_slice(&0_u32.to_le_bytes()); // cmdsize = 0 (invalid)
        assert!(matches!(
            MachOFile::parse(&v),
            Err(MachOError::TruncatedLoadCommand(32))
        ));
    }

    #[test]
    fn detect_dylib_linkage() {
        let file = MachOFile {
            architectures: vec![],
            segments: vec![],
            symbols: vec![],
            dylibs: vec![Dylib {
                name: "/usr/lib/libSystem.B.dylib".into(),
                current_version: 0,
                compatibility_version: 0,
            }],
            entry_point: None,
        };
        assert!(file.links_dylib("libSystem"));
        assert!(!file.links_dylib("libfoo"));
    }
}
