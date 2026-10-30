//! Minimal zero-dependency ELF parser (replaces `goblin::elf`).
//!
//! Implements exactly the surface the OmniSec pipeline needs — ELF header,
//! program headers, section headers, string tables, static `.symtab`,
//! dynamic symbols (section-based `.dynsym` with a `PT_DYNAMIC` fallback),
//! `DT_NEEDED` / `DT_SONAME` / `DT_RPATH` / `DT_RUNPATH` and the hardening
//! bits (`PT_GNU_STACK`, `PT_GNU_RELRO`, `e_type`, dynamic flags).
//!
//! Supported: 32/64-bit, little/big-endian. Mach-O, archives and debug
//! info are intentionally out of scope.
//!
//! All reads are bounds-checked; malformed input yields `Err`, never a
//! panic. The crate forbids `unsafe` code.

use core::convert::TryInto;

// ── ELF constants (System V ABI, stable) ─────────────────────────────────

/// 32-bit objects.
pub const ELFCLASS32: u8 = 1;
/// 64-bit objects.
pub const ELFCLASS64: u8 = 2;
/// Little-endian.
pub const ELFDATA2LSB: u8 = 1;
/// Big-endian.
pub const ELFDATA2MSB: u8 = 2;

/// Relocatable object (`ET_REL`).
pub const ET_REL: u16 = 1;
/// Executable (`ET_EXEC`).
pub const ET_EXEC: u16 = 2;
/// Shared object / PIE (`ET_DYN`).
pub const ET_DYN: u16 = 3;
/// Core dump (`ET_CORE`).
pub const ET_CORE: u16 = 4;

/// x86 (`EM_386`).
pub const EM_386: u16 = 3;
/// 32-bit SPARC (`EM_SPARC`).
pub const EM_SPARC: u16 = 2;
/// 32-bit MIPS (`EM_MIPS`).
pub const EM_MIPS: u16 = 8;
/// 32-bit PowerPC (`EM_PPC`).
pub const EM_PPC: u16 = 20;
/// 64-bit PowerPC (`EM_PPC64`).
pub const EM_PPC64: u16 = 21;
/// 32-bit ARM (`EM_ARM`).
pub const EM_ARM: u16 = 40;
/// 64-bit SPARC v9 (`EM_SPARCV9`).
pub const EM_SPARCV9: u16 = 43;
/// x86-64 (`EM_X86_64`).
pub const EM_X86_64: u16 = 62;
/// 64-bit ARM (`EM_AARCH64`).
pub const EM_AARCH64: u16 = 183;
/// RISC-V (`EM_RISCV`).
pub const EM_RISCV: u16 = 243;
/// SPARC32PLUS (`EM_SPARC32PLUS`).
pub const EM_SPARC32PLUS: u16 = 18;

/// Loadable segment (`PT_LOAD`).
pub const PT_LOAD: u32 = 1;
/// Dynamic linking info (`PT_DYNAMIC`).
pub const PT_DYNAMIC: u32 = 2;
/// GNU RELRO (`PT_GNU_RELRO`).
pub const PT_GNU_RELRO: u32 = 0x6474_E552;
/// GNU stack executability (`PT_GNU_STACK`).
pub const PT_GNU_STACK: u32 = 0x6474_E551;

/// Execute flag (`PF_X`).
pub const PF_X: u32 = 1;
/// Write flag (`PF_W`).
pub const PF_W: u32 = 2;
/// Read flag (`PF_R`).
pub const PF_R: u32 = 4;

/// Writable section (`SHF_WRITE`).
pub const SHF_WRITE: u32 = 1;
/// Allocatable section (`SHF_ALLOC`).
pub const SHF_ALLOC: u32 = 2;
/// Executable section (`SHF_EXECINSTR`).
pub const SHF_EXECINSTR: u32 = 4;

/// Program data (`SHT_PROGBITS`).
pub const SHT_PROGBITS: u32 = 1;
/// Symbol table (`SHT_SYMTAB`).
pub const SHT_SYMTAB: u32 = 2;
/// String table (`SHT_STRTAB`).
pub const SHT_STRTAB: u32 = 3;
/// Dynamic linking info (`SHT_DYNAMIC`).
pub const SHT_DYNAMIC: u32 = 6;
/// Uninitialized space (`SHT_NOBITS`).
pub const SHT_NOBITS: u32 = 8;
/// Dynamic symbol table (`SHT_DYNSYM`).
pub const SHT_DYNSYM: u32 = 11;

/// Local binding (`STB_LOCAL`).
pub const STB_LOCAL: u8 = 0;
/// Global binding (`STB_GLOBAL`).
pub const STB_GLOBAL: u8 = 1;
/// Weak binding (`STB_WEAK`).
pub const STB_WEAK: u8 = 2;

/// No type (`STT_NOTYPE`).
pub const STT_NOTYPE: u8 = 0;
/// Data object (`STT_OBJECT`).
pub const STT_OBJECT: u8 = 1;
/// Function (`STT_FUNC`).
pub const STT_FUNC: u8 = 2;
/// Section symbol (`STT_SECTION`).
pub const STT_SECTION: u8 = 3;
/// File symbol (`STT_FILE`).
pub const STT_FILE: u8 = 4;

/// Undefined section index — an undefined (imported) dynamic symbol.
pub const SHN_UNDEF: u16 = 0;

/// End of dynamic array (`DT_NULL`).
pub const DT_NULL: i64 = 0;
/// Needed library (`DT_NEEDED`).
pub const DT_NEEDED: i64 = 1;
/// Address of string table (`DT_STRTAB`).
pub const DT_STRTAB: i64 = 5;
/// Address of symbol table (`DT_SYMTAB`).
pub const DT_SYMTAB: i64 = 6;
/// Size of string table (`DT_STRSZ`).
pub const DT_STRSZ: i64 = 10;
/// Size of symbol table entry (`DT_SYMENT`).
pub const DT_SYMENT: i64 = 11;
/// Shared-object name (`DT_SONAME`).
pub const DT_SONAME: i64 = 14;
/// Library search path (`DT_RPATH`).
pub const DT_RPATH: i64 = 15;
/// Relocation countdown (`DT_BIND_NOW`).
pub const DT_BIND_NOW: i64 = 24;
/// Run-time search path (`DT_RUNPATH`).
pub const DT_RUNPATH: i64 = 29;
/// Dynamic flags (`DT_FLAGS`).
pub const DT_FLAGS: i64 = 30;
/// Address of SysV hash table (`DT_HASH`).
pub const DT_HASH: i64 = 4;
/// Address of GNU hash table (`DT_GNU_HASH`).
pub const DT_GNU_HASH: i64 = 0x6FFF_FEF5;
/// Dynamic flags 1 (`DT_FLAGS_1`).
pub const DT_FLAGS_1: i64 = 0x6FFF_FFFB;

/// Bind-now flag (`DF_BIND_NOW`).
pub const DF_BIND_NOW: u64 = 0x8;
/// Bind-now flag, variant 1 (`DF_1_NOW`).
pub const DF_1_NOW: u64 = 0x1;

// ── Owned parsed view (mirrors the `goblin::elf` surface we used) ─────────

/// Parsed ELF header bits needed downstream.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfHeader {
    /// Object type (`ET_*`).
    pub e_type: u16,
    /// Machine architecture (`EM_*`).
    pub e_machine: u16,
}

/// One program header.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProgramHeader {
    /// Segment type (`PT_*`).
    pub p_type: u32,
    /// Segment flags (`PF_*`).
    pub p_flags: u32,
    /// File offset of the segment.
    pub p_offset: u64,
    /// Virtual address of the segment.
    pub p_vaddr: u64,
    /// Size of the segment in the file.
    pub p_filesz: u64,
    /// Size of the segment in memory.
    pub p_memsz: u64,
}

/// One section header.
#[derive(Debug, Clone, Copy, Default)]
pub struct SectionHeader {
    /// Offset into the section-header string table.
    pub sh_name: u32,
    /// Section type (`SHT_*`).
    pub sh_type: u32,
    /// Section flags (`SHF_*`).
    pub sh_flags: u64,
    /// Virtual address of the section.
    pub sh_addr: u64,
    /// File offset of the section.
    pub sh_offset: u64,
    /// Size of the section.
    pub sh_size: u64,
    /// Linked section index (strtab for symtabs).
    pub sh_link: u32,
    /// Extra info (symbol index for symtabs).
    pub sh_info: u32,
    /// Entry size for tables.
    pub sh_entsize: u64,
}

/// One symbol table entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfSym {
    /// Offset into the associated string table.
    pub st_name: u32,
    /// Symbol value (address).
    pub st_value: u64,
    /// Symbol size.
    pub st_size: u64,
    /// Bind and type packed (`bind << 4 | type`).
    pub st_info: u8,
    /// Section index (`SHN_UNDEF` == undefined/imported).
    pub st_shndx: u16,
}

impl ElfSym {
    /// Symbol binding (`STB_*`).
    #[must_use]
    pub const fn st_bind(&self) -> u8 {
        self.st_info >> 4
    }

    /// Symbol type (`STT_*`).
    #[must_use]
    pub const fn st_type(&self) -> u8 {
        self.st_info & 0xf
    }
}

/// One dynamic entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Dyn {
    /// Dynamic tag (`DT_*`, signed).
    pub d_tag: i64,
    /// Dynamic value / address.
    pub d_val: u64,
}

/// Dynamic section info.
#[derive(Debug, Clone, Default)]
pub struct DynamicInfo {
    /// Raw dynamic entries.
    pub dyns: Vec<Dyn>,
}

/// Borrowed string table with `goblin`-style lookup.
#[derive(Debug, Clone, Copy, Default)]
pub struct StrTab<'a> {
    /// Raw table bytes.
    bytes: &'a [u8],
}

impl<'a> StrTab<'a> {
    /// Empty table.
    #[must_use]
    pub const fn empty() -> Self {
        Self { bytes: &[] }
    }

    /// Look up a NUL-terminated string at `offset`.
    ///
    /// Returns `None` for out-of-range offsets and invalid UTF-8.
    #[must_use]
    pub fn get_at(&self, offset: usize) -> Option<&'a str> {
        let rest = self.bytes.get(offset..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        core::str::from_utf8(&rest[..end]).ok()
    }
}

/// Fully parsed ELF view used by the loaders and the native scanner.
#[derive(Debug, Clone, Default)]
pub struct ElfFile<'a> {
    /// Parsed header bits.
    pub header: ElfHeader,
    /// Entry-point virtual address.
    pub entry: u64,
    /// `true` for 64-bit objects.
    pub is_64: bool,
    /// `true` for little-endian objects.
    pub little_endian: bool,
    /// Program headers.
    pub program_headers: Vec<ProgramHeader>,
    /// Section headers.
    pub section_headers: Vec<SectionHeader>,
    /// Section-header string table.
    pub shdr_strtab: StrTab<'a>,
    /// Static string table (`.strtab`).
    pub strtab: StrTab<'a>,
    /// Static symbols (`.symtab`).
    pub syms: Vec<ElfSym>,
    /// Dynamic string table (`.dynstr` or `DT_STRTAB`).
    pub dynstrtab: StrTab<'a>,
    /// Dynamic symbols.
    pub dynsyms: Vec<ElfSym>,
    /// `DT_NEEDED` library list.
    pub libraries: Vec<&'a str>,
    /// `DT_SONAME`, if present.
    pub soname: Option<&'a str>,
    /// Dynamic entries, if a dynamic section/segment exists.
    pub dynamic: Option<DynamicInfo>,
}

// ── Low-level endian-aware readers ─────────────────────────────────────────

/// Endianness of the parsed object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Data {
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

impl Data {
    /// Read a `u16` at `off`.
    fn r16(self, bytes: &[u8], off: usize) -> Option<u16> {
        let b: [u8; 2] = bytes.get(off..off + 2)?.try_into().ok()?;
        Some(match self {
            Self::Little => u16::from_le_bytes(b),
            Self::Big => u16::from_be_bytes(b),
        })
    }

    /// Read a `u32` at `off`.
    fn r32(self, bytes: &[u8], off: usize) -> Option<u32> {
        let b: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
        Some(match self {
            Self::Little => u32::from_le_bytes(b),
            Self::Big => u32::from_be_bytes(b),
        })
    }

    /// Read a `u64` at `off`.
    fn r64(self, bytes: &[u8], off: usize) -> Option<u64> {
        let b: [u8; 8] = bytes.get(off..off + 8)?.try_into().ok()?;
        Some(match self {
            Self::Little => u64::from_le_bytes(b),
            Self::Big => u64::from_be_bytes(b),
        })
    }

    /// Read an address-sized word at `off` (`is_64` selects width).
    fn raddr(self, bytes: &[u8], off: usize, is_64: bool) -> Option<u64> {
        if is_64 {
            self.r64(bytes, off)
        } else {
            self.r32(bytes, off).map(u64::from)
        }
    }
}

/// Translate a virtual address to a file offset via `PT_LOAD` segments.
fn vaddr_to_offset(phdrs: &[ProgramHeader], vaddr: u64) -> Option<usize> {
    for ph in phdrs {
        if ph.p_type != PT_LOAD {
            continue;
        }
        if vaddr >= ph.p_vaddr {
            let delta = vaddr - ph.p_vaddr;
            // Only file-backed bytes are readable.
            if delta < ph.p_filesz {
                return usize::try_from(ph.p_offset + delta).ok();
            }
        }
    }
    None
}

/// Read a byte slice at a virtual address with `size` bytes.
fn slice_at_vaddr<'a>(
    bytes: &'a [u8],
    phdrs: &[ProgramHeader],
    vaddr: u64,
    size: u64,
) -> Option<&'a [u8]> {
    let off = vaddr_to_offset(phdrs, vaddr)?;
    let len = usize::try_from(size).ok()?;
    bytes.get(off..off.checked_add(len)?)
}

/// Parse a SysV `DT_HASH` table into a symbol count (`nchain`).
fn sysv_hash_count(bytes: &[u8], data: Data, hash_off: usize) -> Option<usize> {
    let nchain = data.r32(bytes, hash_off.checked_add(4)?)?;
    usize::try_from(nchain).ok()
}

/// Parse a GNU hash table into a symbol count.
///
/// Walks the bloom/bucket/chain structure: the count is one past the last
/// chain index reachable from the largest bucket value.
fn gnu_hash_count(bytes: &[u8], data: Data, hash_off: usize, is_64: bool) -> Option<usize> {
    let nbuckets = usize::try_from(data.r32(bytes, hash_off)?).ok()?;
    let symoffset = usize::try_from(data.r32(bytes, hash_off.checked_add(4)?)?).ok()?;
    let bloom_size = usize::try_from(data.r32(bytes, hash_off.checked_add(8)?)?).ok()?;
    let addr = if is_64 { 8usize } else { 4usize };
    let buckets_off = hash_off
        .checked_add(16)?
        .checked_add(bloom_size.checked_mul(addr)?)?;
    if nbuckets == 0 {
        return Some(symoffset);
    }
    let mut max = 0usize;
    for i in 0..nbuckets {
        let b =
            usize::try_from(data.r32(bytes, buckets_off.checked_add(i.checked_mul(4)?)?)?).ok()?;
        max = max.max(b);
    }
    if max < symoffset {
        return Some(symoffset);
    }
    let chain_off = buckets_off.checked_add(nbuckets.checked_mul(4)?)?;
    // Walk the chain from the largest bucket until the stop bit.
    let mut idx = max;
    loop {
        let rel = idx.checked_sub(symoffset)?;
        let at = chain_off.checked_add(rel.checked_mul(4)?)?;
        let word = data.r32(bytes, at)?;
        idx = idx.checked_add(1)?;
        if word & 1 != 0 {
            break;
        }
        // Bound the walk by the available bytes.
        if at.checked_add(8)? > bytes.len() {
            break;
        }
    }
    Some(idx)
}

/// Parse one symbol entry at `off`.
fn parse_sym(bytes: &[u8], data: Data, off: usize, is_64: bool) -> Option<ElfSym> {
    if is_64 {
        Some(ElfSym {
            st_name: data.r32(bytes, off)?,
            st_info: *bytes.get(off.checked_add(4)?)?,
            st_shndx: data.r16(bytes, off.checked_add(6)?)?,
            st_value: data.r64(bytes, off.checked_add(8)?)?,
            st_size: data.r64(bytes, off.checked_add(16)?)?,
        })
    } else {
        Some(ElfSym {
            st_name: data.r32(bytes, off)?,
            st_value: u64::from(data.r32(bytes, off.checked_add(4)?)?),
            st_size: u64::from(data.r32(bytes, off.checked_add(8)?)?),
            st_info: *bytes.get(off.checked_add(12)?)?,
            st_shndx: data.r16(bytes, off.checked_add(14)?)?,
        })
    }
}

/// Parse a symbol table region into `out`.
fn parse_symtab(
    bytes: &[u8],
    data: Data,
    is_64: bool,
    table: &[u8],
    table_off: usize,
    entsize: u64,
    out: &mut Vec<ElfSym>,
) {
    let mut esz = usize::try_from(entsize).unwrap_or(0);
    if esz == 0 {
        esz = if is_64 { 24 } else { 16 };
    }
    if esz == 0 {
        return;
    }
    let count = table.len() / esz;
    out.reserve(count.min(1 << 20));
    for i in 0..count {
        let off = table_off.checked_add(i.checked_mul(esz).unwrap_or(usize::MAX));
        let Some(off) = off else { break };
        if let Some(sym) = parse_sym(bytes, data, off, is_64) {
            out.push(sym);
        } else {
            break;
        }
    }
}

// ── Public entry point ─────────────────────────────────────────────────────

/// Parse ELF `bytes` into an owned [`ElfFile`] view.
///
/// Returns `Err` with a short reason for non-ELF input, truncated headers
/// or unsupported `e_ident` values.
pub fn parse_elf(bytes: &[u8]) -> Result<ElfFile<'_>, String> {
    if bytes.len() < 64 {
        return Err("too small for ELF header".into());
    }
    if bytes[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err("bad ELF magic".into());
    }
    let is_64 = match bytes[4] {
        ELFCLASS32 => false,
        ELFCLASS64 => true,
        c => return Err(format!("unsupported ELF class {c}")),
    };
    let data = match bytes[5] {
        ELFDATA2LSB => Data::Little,
        ELFDATA2MSB => Data::Big,
        d => return Err(format!("unsupported ELF data encoding {d}")),
    };
    if bytes[6] != 1 {
        return Err("unsupported ELF version".into());
    }

    let e_type = data.r16(bytes, 16).ok_or("truncated ELF header")?;
    let e_machine = data.r16(bytes, 18).ok_or("truncated ELF header")?;
    let entry = data.raddr(bytes, 24, is_64).ok_or("truncated ELF header")?;
    let e_phoff = data
        .raddr(bytes, if is_64 { 32 } else { 28 }, is_64)
        .ok_or("truncated ELF header")?;
    let e_shoff = data
        .raddr(bytes, if is_64 { 40 } else { 32 }, is_64)
        .ok_or("truncated ELF header")?;
    let e_phentsize = data
        .r16(bytes, if is_64 { 54 } else { 42 })
        .ok_or("truncated ELF header")? as usize;
    let mut e_phnum = data
        .r16(bytes, if is_64 { 56 } else { 44 })
        .ok_or("truncated ELF header")? as usize;
    let e_shentsize = data
        .r16(bytes, if is_64 { 58 } else { 46 })
        .ok_or("truncated ELF header")? as usize;
    let mut e_shnum = data
        .r16(bytes, if is_64 { 60 } else { 48 })
        .ok_or("truncated ELF header")? as usize;
    let mut e_shstrndx = data
        .r16(bytes, if is_64 { 62 } else { 50 })
        .ok_or("truncated ELF header")? as usize;

    // ── Program headers ──
    let ph_size = if is_64 { 56usize } else { 32usize };
    let mut program_headers = Vec::new();
    if e_phoff != 0 && e_phnum > 0 {
        if e_phentsize < ph_size {
            return Err("bad program header entry size".into());
        }
        let phoff = usize::try_from(e_phoff).map_err(|_| "bad e_phoff")?;
        if e_phnum == 0xFFFF {
            // PN_XNUM: the real count lives in sh_info of section 0.
            if e_shoff != 0 {
                let sh0 = usize::try_from(e_shoff).map_err(|_| "bad e_shoff")?;
                // sh_info is at +44 (64-bit) / +28 (32-bit).
                let at = sh0
                    .checked_add(if is_64 { 44 } else { 28 })
                    .ok_or("bad e_shoff")?;
                e_phnum = data.r32(bytes, at).ok_or("bad PN_XNUM")? as usize;
            } else {
                return Err("PN_XNUM without section headers".into());
            }
        }
        program_headers.reserve(e_phnum.min(1 << 16));
        for i in 0..e_phnum {
            let base = phoff.checked_add(i.checked_mul(e_phentsize).ok_or("bad phnum")?);
            let Some(base) = base else { break };
            if base.checked_add(ph_size).unwrap_or(usize::MAX) > bytes.len() {
                break;
            }
            if is_64 {
                program_headers.push(ProgramHeader {
                    p_type: data.r32(bytes, base).ok_or("truncated phdr")?,
                    p_flags: data.r32(bytes, base + 4).ok_or("truncated phdr")?,
                    p_offset: data.r64(bytes, base + 8).ok_or("truncated phdr")?,
                    p_vaddr: data.r64(bytes, base + 16).ok_or("truncated phdr")?,
                    p_filesz: data.r64(bytes, base + 32).ok_or("truncated phdr")?,
                    p_memsz: data.r64(bytes, base + 40).ok_or("truncated phdr")?,
                });
            } else {
                program_headers.push(ProgramHeader {
                    p_type: data.r32(bytes, base).ok_or("truncated phdr")?,
                    p_offset: u64::from(data.r32(bytes, base + 4).ok_or("truncated phdr")?),
                    p_vaddr: u64::from(data.r32(bytes, base + 8).ok_or("truncated phdr")?),
                    p_filesz: u64::from(data.r32(bytes, base + 16).ok_or("truncated phdr")?),
                    p_memsz: u64::from(data.r32(bytes, base + 20).ok_or("truncated phdr")?),
                    p_flags: data.r32(bytes, base + 24).ok_or("truncated phdr")?,
                });
            }
        }
    }

    // ── Section headers ──
    let sh_size = if is_64 { 64usize } else { 40usize };
    let mut section_headers = Vec::new();
    if e_shoff != 0 {
        let shoff = usize::try_from(e_shoff).map_err(|_| "bad e_shoff")?;
        if e_shentsize != 0 && e_shentsize < sh_size {
            return Err("bad section header entry size".into());
        }
        if e_shnum == 0 {
            // The real count lives in sh_size of section 0.
            let sz_at = shoff
                .checked_add(if is_64 { 32 } else { 20 })
                .ok_or("bad e_shoff")?;
            e_shnum = data.raddr(bytes, sz_at, is_64).ok_or("bad shnum")? as usize;
        }
        if e_shstrndx == 0xFFFF {
            // SHN_XINDEX: the real index lives in sh_link of section 0.
            let link_at = shoff
                .checked_add(if is_64 { 40 } else { 24 })
                .ok_or("bad e_shoff")?;
            e_shstrndx = data.r32(bytes, link_at).ok_or("bad shstrndx")? as usize;
        }
        let stride = e_shentsize.max(sh_size);
        section_headers.reserve(e_shnum.min(1 << 16));
        for i in 0..e_shnum {
            let base = shoff.checked_add(i.checked_mul(stride).ok_or("bad shnum")?);
            let Some(base) = base else { break };
            if base.checked_add(sh_size).unwrap_or(usize::MAX) > bytes.len() {
                break;
            }
            if is_64 {
                section_headers.push(SectionHeader {
                    sh_name: data.r32(bytes, base).ok_or("truncated shdr")?,
                    sh_type: data.r32(bytes, base + 4).ok_or("truncated shdr")?,
                    sh_flags: data.r64(bytes, base + 8).ok_or("truncated shdr")?,
                    sh_addr: data.r64(bytes, base + 16).ok_or("truncated shdr")?,
                    sh_offset: data.r64(bytes, base + 24).ok_or("truncated shdr")?,
                    sh_size: data.r64(bytes, base + 32).ok_or("truncated shdr")?,
                    sh_link: data.r32(bytes, base + 40).ok_or("truncated shdr")?,
                    sh_info: data.r32(bytes, base + 44).ok_or("truncated shdr")?,
                    sh_entsize: data.r64(bytes, base + 56).ok_or("truncated shdr")?,
                });
            } else {
                section_headers.push(SectionHeader {
                    sh_name: data.r32(bytes, base).ok_or("truncated shdr")?,
                    sh_type: data.r32(bytes, base + 4).ok_or("truncated shdr")?,
                    sh_flags: u64::from(data.r32(bytes, base + 8).ok_or("truncated shdr")?),
                    sh_addr: u64::from(data.r32(bytes, base + 12).ok_or("truncated shdr")?),
                    sh_offset: u64::from(data.r32(bytes, base + 16).ok_or("truncated shdr")?),
                    sh_size: u64::from(data.r32(bytes, base + 20).ok_or("truncated shdr")?),
                    sh_link: data.r32(bytes, base + 24).ok_or("truncated shdr")?,
                    sh_info: data.r32(bytes, base + 28).ok_or("truncated shdr")?,
                    sh_entsize: u64::from(data.r32(bytes, base + 36).ok_or("truncated shdr")?),
                });
            }
        }
    }

    let sec_slice = |sh: &SectionHeader| -> &[u8] {
        let Ok(off) = usize::try_from(sh.sh_offset) else {
            return &[];
        };
        let Ok(len) = usize::try_from(sh.sh_size) else {
            return &[];
        };
        // NOBITS sections occupy no file bytes.
        if sh.sh_type == SHT_NOBITS {
            return &[];
        }
        bytes
            .get(off..off.checked_add(len).unwrap_or(usize::MAX))
            .unwrap_or(&[])
    };

    // ── Section-header string table ──
    let shdr_strtab = section_headers
        .get(e_shstrndx)
        .map(sec_slice)
        .map(|b| StrTab { bytes: b })
        .unwrap_or(StrTab::empty());

    // ── Static symbols (`.symtab`) ──
    let mut syms = Vec::new();
    let mut strtab = StrTab::empty();
    for sh in &section_headers {
        if sh.sh_type == SHT_SYMTAB {
            let table = sec_slice(sh);
            let link_bytes = section_headers
                .get(sh.sh_link as usize)
                .map(sec_slice)
                .unwrap_or(&[]);
            strtab = StrTab { bytes: link_bytes };
            let off = usize::try_from(sh.sh_offset).unwrap_or(usize::MAX);
            parse_symtab(bytes, data, is_64, table, off, sh.sh_entsize, &mut syms);
        }
    }

    // ── Dynamic section / segment ──
    // Raw (tag, value) pairs plus the file range they were read from.
    let mut raw_dyns: Vec<Dyn> = Vec::new();
    // Index of the section-linked string table, if any.
    let mut dyn_link: Option<usize> = None;
    for sh in &section_headers {
        if sh.sh_type == SHT_DYNAMIC {
            dyn_link = Some(sh.sh_link as usize);
            let Ok(base) = usize::try_from(sh.sh_offset) else {
                break;
            };
            let Ok(len) = usize::try_from(sh.sh_size) else {
                break;
            };
            let Some(table) = bytes.get(base..base.checked_add(len).unwrap_or(usize::MAX)) else {
                break;
            };
            let esz = if is_64 { 16usize } else { 8usize };
            let mut off = base;
            let end = base + table.len();
            while off + esz <= end {
                let (tag, val) = if is_64 {
                    let t = data.r64(bytes, off).unwrap_or(0);
                    let v = data.r64(bytes, off + 8).unwrap_or(0);
                    (t as i64, v)
                } else {
                    let t = data.r32(bytes, off).unwrap_or(0);
                    let v = data.r32(bytes, off + 4).unwrap_or(0);
                    (i64::from(t as i32), u64::from(v))
                };
                raw_dyns.push(Dyn {
                    d_tag: tag,
                    d_val: val,
                });
                if tag == DT_NULL {
                    break;
                }
                off += esz;
            }
            break;
        }
    }
    if raw_dyns.is_empty() {
        // Fallback: PT_DYNAMIC segment (stripped binaries, e.g. UPX).
        for ph in &program_headers {
            if ph.p_type == PT_DYNAMIC {
                let Ok(off) = usize::try_from(ph.p_offset) else {
                    continue;
                };
                let Ok(len) = usize::try_from(ph.p_filesz) else {
                    continue;
                };
                let Some(table) = bytes.get(off..off.checked_add(len).unwrap_or(usize::MAX)) else {
                    continue;
                };
                let esz = if is_64 { 16usize } else { 8usize };
                for chunk in table.chunks(esz) {
                    if chunk.len() < esz {
                        break;
                    }
                    let (tag, val) = if is_64 {
                        let t = chunk[0..8].try_into().unwrap_or([0u8; 8]);
                        let v = chunk[8..16].try_into().unwrap_or([0u8; 8]);
                        match data {
                            Data::Little => (i64::from_le_bytes(t), u64::from_le_bytes(v)),
                            Data::Big => (i64::from_be_bytes(t), u64::from_be_bytes(v)),
                        }
                    } else {
                        let t = chunk[0..4].try_into().unwrap_or([0u8; 4]);
                        let v = chunk[4..8].try_into().unwrap_or([0u8; 4]);
                        match data {
                            Data::Little => (
                                i64::from(i32::from_le_bytes(t)),
                                u64::from(u32::from_le_bytes(v)),
                            ),
                            Data::Big => (
                                i64::from(i32::from_be_bytes(t)),
                                u64::from(u32::from_be_bytes(v)),
                            ),
                        }
                    };
                    raw_dyns.push(Dyn {
                        d_tag: tag,
                        d_val: val,
                    });
                    if tag == DT_NULL {
                        break;
                    }
                }
                break;
            }
        }
    }

    // ── Dynamic string table ──
    let mut dynstrtab = StrTab::empty();
    if let Some(link) = dyn_link {
        if let Some(sh) = section_headers.get(link) {
            dynstrtab = StrTab {
                bytes: sec_slice(sh),
            };
        }
    }
    // Collect dynamic values we need for the VA-based fallback.
    let mut dt_strtab = 0u64;
    let mut dt_strsz = 0u64;
    let mut dt_symtab = 0u64;
    let mut dt_syment = 0u64;
    let mut dt_hash = 0u64;
    let mut dt_gnu_hash = 0u64;
    let mut dt_soname = None;
    let mut dt_rpath = None;
    let mut dt_runpath = None;
    let mut needed: Vec<u64> = Vec::new();
    for d in &raw_dyns {
        match d.d_tag {
            DT_NEEDED => needed.push(d.d_val),
            DT_STRTAB => dt_strtab = d.d_val,
            DT_STRSZ => dt_strsz = d.d_val,
            DT_SYMTAB => dt_symtab = d.d_val,
            DT_SYMENT => dt_syment = d.d_val,
            DT_HASH => dt_hash = d.d_val,
            DT_GNU_HASH => dt_gnu_hash = d.d_val,
            DT_SONAME => dt_soname = Some(d.d_val),
            DT_RPATH => dt_rpath = Some(d.d_val),
            DT_RUNPATH => dt_runpath = Some(d.d_val),
            _ => {}
        }
    }
    if dynstrtab.bytes.is_empty() && dt_strtab != 0 && dt_strsz != 0 {
        if let Some(s) = slice_at_vaddr(bytes, &program_headers, dt_strtab, dt_strsz) {
            dynstrtab = StrTab { bytes: s };
        }
    }

    // ── Dynamic symbols ──
    let mut dynsyms = Vec::new();
    // Prefer the section-based `.dynsym` when present.
    let mut used_section_dynsym = false;
    for sh in &section_headers {
        if sh.sh_type == SHT_DYNSYM {
            let table = sec_slice(sh);
            let off = usize::try_from(sh.sh_offset).unwrap_or(usize::MAX);
            // The linked string table is the authoritative `.dynstr`.
            if let Some(link) = section_headers.get(sh.sh_link as usize) {
                let lb = sec_slice(link);
                if !lb.is_empty() {
                    dynstrtab = StrTab { bytes: lb };
                }
            }
            parse_symtab(bytes, data, is_64, table, off, sh.sh_entsize, &mut dynsyms);
            used_section_dynsym = true;
            break;
        }
    }
    if !used_section_dynsym && dt_symtab != 0 {
        // VA-based fallback: symbol count from the hash tables.
        let mut count: Option<usize> = None;
        if dt_hash != 0 {
            if let Some(off) = vaddr_to_offset(&program_headers, dt_hash) {
                count = sysv_hash_count(bytes, data, off);
            }
        }
        if count.is_none() && dt_gnu_hash != 0 {
            if let Some(off) = vaddr_to_offset(&program_headers, dt_gnu_hash) {
                // GNU hash header must be readable; count walk is bounded
                // by the file size inside `gnu_hash_count`.
                count = gnu_hash_count(bytes, data, off, is_64);
            }
        }
        if let Some(n) = count {
            let n = n.min(1 << 22);
            let mut esz = usize::try_from(dt_syment).unwrap_or(0);
            if esz == 0 {
                esz = if is_64 { 24 } else { 16 };
            }
            if let Some(sym_off) = vaddr_to_offset(&program_headers, dt_symtab) {
                let total = n.checked_mul(esz).unwrap_or(usize::MAX);
                if sym_off.checked_add(total).unwrap_or(usize::MAX) <= bytes.len() {
                    for i in 0..n {
                        let off = sym_off + i * esz;
                        if let Some(sym) = parse_sym(bytes, data, off, is_64) {
                            dynsyms.push(sym);
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    let dynamic = if raw_dyns.is_empty() {
        None
    } else {
        Some(DynamicInfo { dyns: raw_dyns })
    };

    let get_str =
        |off: u64| -> Option<&str> { usize::try_from(off).ok().and_then(|o| dynstrtab.get_at(o)) };
    let libraries: Vec<&str> = needed.iter().filter_map(|&o| get_str(o)).collect();
    let soname = dt_soname.and_then(get_str);
    // RPATH/RUNPATH are surfaced by the scanner via the dynamic table +
    // dynstrtab; keep them resolvable the same way (no separate storage).
    let _ = (dt_rpath, dt_runpath);

    Ok(ElfFile {
        header: ElfHeader { e_type, e_machine },
        entry,
        is_64,
        little_endian: matches!(data, Data::Little),
        program_headers,
        section_headers,
        shdr_strtab,
        strtab,
        syms,
        dynstrtab,
        dynsyms,
        libraries,
        soname,
        dynamic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a *stripped* ELF64 LE shared object: no section headers at
    /// all, one `PT_LOAD`, one `PT_DYNAMIC` and one `PT_GNU_STACK`.
    /// Dynamic data (strtab/symtab/hash) is resolved purely through
    /// virtual-address mapping — the UPX-shaped worst case.
    ///
    /// When `gnu_hash` is set the symbol count comes from a GNU hash
    /// table, otherwise from a SysV hash table.
    fn build_stripped_dyn_elf64(gnu_hash: bool) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];

        buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1;
        buf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..32].copy_from_slice(&0x400000u64.to_le_bytes()); // entry
        buf[32..40].copy_from_slice(&0x40u64.to_le_bytes()); // e_phoff
        buf[40..48].copy_from_slice(&0u64.to_le_bytes()); // e_shoff = none
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        buf[56..58].copy_from_slice(&3u16.to_le_bytes()); // e_phnum
        buf[58..60].copy_from_slice(&64u16.to_le_bytes());
        buf[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum

        // [0] PT_LOAD R covering the whole file image.
        let mut ph = |idx: usize, ptype: u32, flags: u32, off: u64, vaddr: u64, filesz: u64| {
            let b = 0x40 + idx * 56;
            buf[b..b + 4].copy_from_slice(&ptype.to_le_bytes());
            buf[b + 4..b + 8].copy_from_slice(&flags.to_le_bytes());
            buf[b + 8..b + 16].copy_from_slice(&off.to_le_bytes());
            buf[b + 16..b + 24].copy_from_slice(&vaddr.to_le_bytes());
            buf[b + 24..b + 32].copy_from_slice(&vaddr.to_le_bytes());
            buf[b + 32..b + 40].copy_from_slice(&filesz.to_le_bytes());
            buf[b + 40..b + 48].copy_from_slice(&filesz.to_le_bytes());
            buf[b + 48..b + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        };
        ph(0, PT_LOAD, 4, 0, 0x400000, 0x400);
        ph(1, PT_DYNAMIC, 6, 0x200, 0x400200, 8 * 16);
        ph(2, PT_GNU_STACK, 6, 0, 0, 0);

        // .dynstr at file 0x280 (VMA 0x400280): \0 libc.so.6 \0 puts \0
        let dynstr = b"\0libc.so.6\0puts\0";
        buf[0x280..0x280 + dynstr.len()].copy_from_slice(dynstr);
        // .dynsym at file 0x2A0 (VMA 0x4002A0): null + puts (UNDEF).
        let s1 = 0x2A0 + 24;
        buf[s1..s1 + 4].copy_from_slice(&11u32.to_le_bytes()); // "puts"
        buf[s1 + 4] = 0x12; // GLOBAL|FUNC, shndx stays 0 (UNDEF)
        // Hash at file 0x2E0 (VMA 0x4002E0).
        let (hash_tag, hash_vaddr) = if gnu_hash {
            // nbuckets=1, symoffset=1, bloom_size=1, shift=5, bloom, buckets=[1], chain=[stop].
            buf[0x2E0..0x2E4].copy_from_slice(&1u32.to_le_bytes());
            buf[0x2E4..0x2E8].copy_from_slice(&1u32.to_le_bytes());
            buf[0x2E8..0x2EC].copy_from_slice(&1u32.to_le_bytes());
            buf[0x2EC..0x2F0].copy_from_slice(&5u32.to_le_bytes());
            buf[0x2F0..0x2F8].copy_from_slice(&0x21u64.to_le_bytes());
            buf[0x2F8..0x2FC].copy_from_slice(&1u32.to_le_bytes());
            buf[0x2FC..0x300].copy_from_slice(&1u32.to_le_bytes());
            (DT_GNU_HASH, 0x4002E0u64)
        } else {
            // nbucket=1, nchain=2, buckets=[1], chain=[0, 0].
            buf[0x2E0..0x2E4].copy_from_slice(&1u32.to_le_bytes());
            buf[0x2E4..0x2E8].copy_from_slice(&2u32.to_le_bytes());
            buf[0x2E8..0x2EC].copy_from_slice(&1u32.to_le_bytes());
            (DT_HASH, 0x4002E0u64)
        };

        // .dynamic at file 0x200: NEEDED, HASH, STRTAB, STRSZ, SYMTAB, SYMENT, NULL.
        let mut dyn_at = 0x200usize;
        let mut entry = |tag: i64, val: u64| {
            buf[dyn_at..dyn_at + 8].copy_from_slice(&tag.to_le_bytes());
            buf[dyn_at + 8..dyn_at + 16].copy_from_slice(&val.to_le_bytes());
            dyn_at += 16;
        };
        entry(DT_NEEDED, 1);
        entry(hash_tag, hash_vaddr);
        entry(DT_STRTAB, 0x400280);
        entry(DT_STRSZ, dynstr.len() as u64);
        entry(DT_SYMTAB, 0x4002A0);
        entry(DT_SYMENT, 24);
        entry(DT_NULL, 0);

        buf
    }

    #[test]
    fn stripped_sysv_hash_resolves_imports() {
        let bytes = build_stripped_dyn_elf64(false);
        let elf = parse_elf(&bytes).expect("stripped ELF must parse");
        assert!(elf.section_headers.is_empty());
        assert_eq!(elf.libraries, vec!["libc.so.6"]);
        assert_eq!(elf.dynsyms.len(), 2);
        assert_eq!(
            elf.dynstrtab.get_at(elf.dynsyms[1].st_name as usize),
            Some("puts")
        );
        assert_eq!(elf.dynsyms[1].st_shndx, 0);
        // PT_GNU_STACK without X must be visible for the NX probe.
        assert!(
            elf.program_headers
                .iter()
                .any(|ph| ph.p_type == PT_GNU_STACK)
        );
    }

    #[test]
    fn stripped_gnu_hash_resolves_imports() {
        let bytes = build_stripped_dyn_elf64(true);
        let elf = parse_elf(&bytes).expect("stripped ELF must parse");
        assert_eq!(elf.libraries, vec!["libc.so.6"]);
        assert_eq!(elf.dynsyms.len(), 2);
        assert_eq!(
            elf.dynstrtab.get_at(elf.dynsyms[1].st_name as usize),
            Some("puts")
        );
    }

    #[test]
    fn rejects_truncated_and_non_elf() {
        assert!(parse_elf(b"").is_err());
        assert!(parse_elf(b"MZ\x90\x00").is_err());
        assert!(parse_elf(&[0x7F, b'E', b'L', b'F', 9, 9, 9]).is_err());
    }
}
