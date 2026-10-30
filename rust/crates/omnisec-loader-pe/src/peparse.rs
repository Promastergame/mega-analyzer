//! Minimal zero-dependency PE parser (replaces `goblin::pe`).
//!
//! Implements exactly the surface the OmniSec pipeline needs — COFF header,
//! optional header (entry, image base, DLL characteristics, data
//! directories), section table, imports (by name and ordinal), exports
//! (including forwarders), the DLL list and the .NET CLR presence bit.
//!
//! PE is always little-endian on disk. All reads are bounds-checked;
//! malformed input yields `Err`, never a panic. The crate forbids `unsafe`
//! code.

// ── PE constants (Microsoft PE spec, stable) ───────────────────────────────

/// Initialized data (`IMAGE_SCN_CNT_CODE` is 0x20; code flag, kept for parity).
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// Initialized data (`IMAGE_SCN_CNT_INITIALIZED_DATA`).
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
/// Uninitialized data (`IMAGE_SCN_CNT_UNINITIALIZED_DATA`).
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
/// Executable (`IMAGE_SCN_MEM_EXECUTE`).
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// Readable (`IMAGE_SCN_MEM_READ`).
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// Writable (`IMAGE_SCN_MEM_WRITE`).
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// Discardable (`IMAGE_SCN_MEM_DISCARDABLE`).
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;

/// PE32 magic (`IMAGE_NT_OPTIONAL_HDR32_MAGIC`).
pub const MAGIC_PE32: u16 = 0x010B;
/// PE32+ magic (`IMAGE_NT_OPTIONAL_HDR64_MAGIC`).
pub const MAGIC_PE32_PLUS: u16 = 0x020B;

/// Guard for import/export walk loops (corrupt binaries).
const MAX_IMPORT_DESCRIPTORS: usize = 512;
/// Guard for thunk walks.
const MAX_THUNKS: usize = 8192;
/// Guard for export names.
const MAX_EXPORT_NAMES: usize = 131_072;
/// Guard for export functions.
const MAX_EXPORT_FUNCTIONS: usize = 131_072;

// ── Owned parsed view (mirrors the `goblin::pe` surface we used) ───────────

/// COFF file header bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct CoffHeader {
    /// Target machine (`IMAGE_FILE_MACHINE_*`).
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// File characteristics (DLL flag lives here).
    pub characteristics: u16,
}

/// Windows-specific optional-header fields we need.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsFields {
    /// `DllCharacteristics` (NX_COMPAT, DYNAMIC_BASE, GUARD_CF, ...).
    pub dll_characteristics: u16,
    /// Subsystem (1 == native driver, 2 == GUI, 3 == console).
    pub subsystem: u16,
}

/// One data-directory entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImageDataDir {
    /// Relative virtual address.
    pub virtual_address: u32,
    /// Size in bytes.
    pub size: u32,
}

/// Data directories (IMAGE_NUMBEROF_DIRECTORY_ENTRIES == 16).
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectories {
    /// Raw entries (clamped to 16).
    pub entries: [ImageDataDir; 16],
}

impl DataDirectories {
    /// CLR runtime header (index 14), if present.
    #[must_use]
    pub const fn get_clr_runtime_header(&self) -> Option<ImageDataDir> {
        let d = self.entries[14];
        if d.virtual_address == 0 && d.size == 0 {
            None
        } else {
            Some(d)
        }
    }

    /// Export table (index 0).
    #[must_use]
    pub const fn export_table(&self) -> ImageDataDir {
        self.entries[0]
    }

    /// Import table (index 1).
    #[must_use]
    pub const fn import_table(&self) -> ImageDataDir {
        self.entries[1]
    }
}

/// Optional header bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct OptionalHeader {
    /// Windows-specific fields.
    pub windows_fields: WindowsFields,
    /// Data directories.
    pub data_directories: DataDirectories,
}

/// PE header pairing COFF + optional headers.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeHeader {
    /// COFF header.
    pub coff_header: CoffHeader,
    /// Optional header (`None` for object files).
    pub optional_header: Option<OptionalHeader>,
}

/// One section table entry.
#[derive(Debug, Clone, Copy)]
pub struct PeSection {
    /// Raw 8-byte name.
    pub name: [u8; 8],
    /// Virtual size.
    pub virtual_size: u32,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// On-disk size.
    pub size_of_raw_data: u32,
    /// On-disk offset.
    pub pointer_to_raw_data: u32,
    /// Characteristics (`IMAGE_SCN_*`).
    pub characteristics: u32,
}

impl PeSection {
    /// Section name as UTF-8, trimmed of trailing NULs.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..end]).ok()
    }
}

/// One import (by name or ordinal).
#[derive(Debug, Clone)]
pub struct PeImport {
    /// DLL name (e.g. `kernel32.dll`).
    pub dll: String,
    /// Symbol name (empty for ordinal-only imports).
    pub name: String,
    /// IAT slot RVA.
    pub rva: u32,
    /// Ordinal (0 == by name).
    pub ordinal: Option<u16>,
}

/// Export forwarder target.
#[derive(Debug, Clone)]
pub struct Reexport {
    /// Library part (`KERNEL32`).
    pub lib: String,
    /// Symbol part (`LoadLibraryW`).
    pub name: String,
}

/// One export.
#[derive(Debug, Clone)]
pub struct PeExport {
    /// Exported name (empty for ordinal-only exports).
    pub name: Option<String>,
    /// Export RVA (absolute forwarder strings excluded).
    pub rva: u32,
    /// Ordinal, if the format uses ordinals.
    pub ordinal: Option<u32>,
    /// Forwarder description, if re-exported.
    pub reexport: Option<Reexport>,
}

/// Fully parsed PE view used by the loader and the native scanner.
#[derive(Debug, Clone, Default)]
pub struct PeFile {
    /// Parsed headers.
    pub header: PeHeader,
    /// `true` for PE32+ (64-bit).
    pub is_64: bool,
    /// Preferred image base.
    pub image_base: u64,
    /// Entry-point RVA.
    pub entry: u32,
    /// Sections.
    pub sections: Vec<PeSection>,
    /// Imports.
    pub imports: Vec<PeImport>,
    /// Exports.
    pub exports: Vec<PeExport>,
    /// Validated SecurityCookie VA from the load config, when available.
    pub security_cookie: Option<u64>,
    /// Unique DLL names in import order.
    pub libraries: Vec<String>,
}

// ── Little-endian readers (PE is always LE) ────────────────────────────────

/// Read a `u16` at `off`.
fn r16(bytes: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(off..off.checked_add(2)?)?.try_into().ok()?,
    ))
}

/// Read a `u32` at `off`.
fn r32(bytes: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(off..off.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Read a `u64` at `off`.
fn r64(bytes: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(off..off.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// Read a NUL-terminated string at file offset `off`.
fn cstr_at(bytes: &[u8], off: usize) -> Option<&str> {
    let rest = bytes.get(off..)?;
    let rest = &rest[..rest.len().min(4097)];
    let end = rest.iter().position(|&b| b == 0)?;
    // Cap absurd lengths from corrupt binaries.
    if end > 4096 {
        return None;
    }
    core::str::from_utf8(&rest[..end]).ok()
}

// ── Public entry point ─────────────────────────────────────────────────────

/// Parse PE `bytes` into a [`PeFile`] view.
///
/// Returns `Err` with a short reason for non-PE input or truncated
/// headers/tables.
pub fn parse_pe(bytes: &[u8]) -> Result<PeFile, String> {
    if bytes.len() < 64 {
        return Err("too small for DOS header".into());
    }
    if bytes[0..2] != *b"MZ" {
        return Err("bad MZ magic".into());
    }
    let pe_off = r32(bytes, 0x3C).ok_or("truncated e_lfanew")? as usize;
    if pe_off < 64 || pe_off.checked_add(24).unwrap_or(usize::MAX) > bytes.len() {
        return Err("bad e_lfanew".into());
    }
    if bytes.get(pe_off..pe_off + 4) != Some(b"PE\0\0".as_slice()) {
        return Err("bad PE signature".into());
    }

    // ── COFF header (20 bytes) ──
    let coff = pe_off + 4;
    let machine = r16(bytes, coff).ok_or("truncated COFF header")?;
    let num_sections = r16(bytes, coff + 2).ok_or("truncated COFF header")? as usize;
    let characteristics = r16(bytes, coff + 18).ok_or("truncated COFF header")?;
    let size_opt = r16(bytes, coff + 16).ok_or("truncated COFF header")? as usize;
    if num_sections > 512 {
        return Err("absurd section count".into());
    }

    // ── Optional header ──
    let opt = coff + 20;
    if size_opt < 2 {
        return Err("missing optional header".into());
    }
    let magic = r16(bytes, opt).ok_or("missing optional header")?;
    let is_64 = match magic {
        MAGIC_PE32 => false,
        MAGIC_PE32_PLUS => true,
        m => return Err(format!("unsupported optional magic {m:#x}")),
    };
    let min_opt = if is_64 { 112 } else { 96 };
    if size_opt < min_opt || size_opt > bytes.len() - opt {
        return Err("truncated optional header".into());
    }
    let entry = r32(bytes, opt + 16).ok_or("truncated optional header")?;
    let image_base = if is_64 {
        r64(bytes, opt + 24).ok_or("truncated optional header")?
    } else {
        u64::from(r32(bytes, opt + 28).ok_or("truncated optional header")?)
    };
    let subsystem = r16(bytes, opt + 68).ok_or("truncated optional header")?;
    let dll_chars = r16(bytes, opt + 70).ok_or("truncated optional header")?;
    let num_rva = if is_64 {
        r32(bytes, opt + 108).ok_or("truncated optional header")?
    } else {
        r32(bytes, opt + 92).ok_or("truncated optional header")?
    } as usize;
    if num_rva > (size_opt - min_opt) / 8 {
        return Err("data directories exceed optional header".into());
    }
    let dirs_at = opt + min_opt;
    let mut dirs = DataDirectories {
        entries: [ImageDataDir {
            virtual_address: 0,
            size: 0,
        }; 16],
    };
    for (i, slot) in dirs.entries.iter_mut().enumerate().take(num_rva.min(16)) {
        let at = dirs_at + i * 8;
        *slot = ImageDataDir {
            virtual_address: r32(bytes, at).unwrap_or(0),
            size: r32(bytes, at + 4).unwrap_or(0),
        };
    }

    // ── Section table (40 bytes each) ──
    let sec_at = opt + size_opt;
    if num_sections * 40 > bytes.len() - sec_at {
        return Err("truncated section table".into());
    }
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let base = sec_at + i * 40;
        let mut name = [0u8; 8];
        name.copy_from_slice(&bytes[base..base + 8]);
        sections.push(PeSection {
            name,
            virtual_size: r32(bytes, base + 8).unwrap_or(0),
            virtual_address: r32(bytes, base + 12).unwrap_or(0),
            size_of_raw_data: r32(bytes, base + 16).unwrap_or(0),
            pointer_to_raw_data: r32(bytes, base + 20).unwrap_or(0),
            characteristics: r32(bytes, base + 36).unwrap_or(0),
        });
    }

    for sec in &sections {
        if sec.size_of_raw_data != 0 {
            let end = u64::from(sec.pointer_to_raw_data) + u64::from(sec.size_of_raw_data);
            if end > bytes.len() as u64 {
                return Err("section raw data exceeds file".into());
            }
        }
        if u64::from(sec.virtual_address) + u64::from(sec.virtual_size.max(sec.size_of_raw_data))
            > 1u64 << 32
        {
            return Err("section RVA overflows".into());
        }
    }
    let declared_headers = r32(bytes, opt + 60).ok_or("missing SizeOfHeaders")? as usize;
    let headers_end = if declared_headers == 0 {
        sec_at + num_sections * 40
    } else {
        declared_headers
    };
    if headers_end > bytes.len() {
        return Err("truncated headers".into());
    }
    let rva_range = |rva: u32, size: usize| -> Option<usize> {
        if rva == 0 || u64::from(rva).checked_add(size as u64)? > 1u64 << 32 {
            return None;
        }
        for sec in &sections {
            if let Some(delta) = rva.checked_sub(sec.virtual_address) {
                if delta < sec.size_of_raw_data
                    && size as u64 <= u64::from(sec.size_of_raw_data - delta)
                {
                    let off =
                        usize::try_from(u64::from(sec.pointer_to_raw_data) + u64::from(delta))
                            .ok()?;
                    bytes.get(off..off.checked_add(size)?)?;
                    return Some(off);
                }
            }
        }
        let off = usize::try_from(rva).ok()?;
        if off < headers_end && size <= headers_end - off {
            bytes.get(off..off.checked_add(size)?)?;
            return Some(off);
        }
        None
    };
    let rva_string = |rva: u32| -> Option<String> {
        let off = rva_range(rva, 1)?;
        let value = cstr_at(bytes, off)?;
        rva_range(rva, value.len() + 1)?;
        Some(value.to_string())
    };
    let mut security_cookie = None;
    let config = dirs.entries[10];
    if config.virtual_address != 0 || config.size != 0 {
        let off = rva_range(config.virtual_address, config.size as usize)
            .ok_or("invalid load config directory")?;
        if config.size < 4 {
            return Err("truncated load config".into());
        }
        let size = r32(bytes, off).ok_or("truncated load config")?;
        if size < 4 || size > config.size {
            return Err("invalid load config structure size".into());
        }
        let (cookie_at, ptr_size) = if is_64 { (88, 8) } else { (60, 4) };
        if size as usize >= cookie_at + ptr_size {
            let cookie = if is_64 {
                r64(bytes, off + cookie_at)
            } else {
                r32(bytes, off + cookie_at).map(u64::from)
            };
            security_cookie = cookie.filter(|&va| {
                va != 0
                    && va.checked_sub(image_base).is_some_and(|rva| {
                        rva < 1u64 << 32
                            && sections.iter().any(|sec| {
                                rva.checked_sub(u64::from(sec.virtual_address)).is_some_and(
                                    |delta| {
                                        delta.checked_add(ptr_size as u64).is_some_and(|end| {
                                            end <= u64::from(
                                                sec.virtual_size.max(sec.size_of_raw_data),
                                            )
                                        })
                                    },
                                )
                            })
                    })
            });
        }
    }

    // Imports: each descriptor and thunk must fit its declared/file-backed range.
    let mut imports = Vec::new();
    let mut libraries: Vec<String> = Vec::new();
    let import_dir = dirs.import_table();
    if import_dir.virtual_address != 0 || import_dir.size != 0 {
        if import_dir.size < 20 {
            return Err("truncated import directory".into());
        }
        let start = rva_range(import_dir.virtual_address, import_dir.size as usize)
            .ok_or("invalid import directory")?;
        let descriptors = (import_dir.size as usize / 20).min(MAX_IMPORT_DESCRIPTORS);
        let mut terminated = false;
        for di in 0..descriptors {
            let base = start + di * 20;
            if bytes[base..base + 20].iter().all(|&b| b == 0) {
                terminated = true;
                break;
            }
            let ilt = r32(bytes, base).ok_or("truncated import descriptor")?;
            let name_rva = r32(bytes, base + 12).ok_or("truncated import descriptor")?;
            let iat = r32(bytes, base + 16).ok_or("truncated import descriptor")?;
            let dll = rva_string(name_rva)
                .filter(|s| !s.is_empty())
                .ok_or("invalid import library name")?;
            if !libraries.contains(&dll) {
                libraries.push(dll.clone());
            }
            let thunk_rva = if ilt != 0 { ilt } else { iat };
            let ptr = if is_64 { 8u32 } else { 4u32 };
            let mut thunk_terminated = false;
            for ti in 0..MAX_THUNKS {
                let delta = (ti as u32)
                    .checked_mul(ptr)
                    .ok_or("thunk offset overflow")?;
                let at_rva = thunk_rva.checked_add(delta).ok_or("thunk RVA overflow")?;
                let at = rva_range(at_rva, ptr as usize).ok_or("truncated import thunk")?;
                let val = if is_64 {
                    r64(bytes, at).ok_or("truncated thunk")?
                } else {
                    u64::from(r32(bytes, at).ok_or("truncated thunk")?)
                };
                if val == 0 {
                    thunk_terminated = true;
                    break;
                }
                let slot = iat.checked_add(delta).ok_or("IAT RVA overflow")?;
                rva_range(slot, ptr as usize).ok_or("invalid IAT slot")?;
                let is_ord = val & if is_64 { 1u64 << 63 } else { 1u64 << 31 } != 0;
                let (name, ordinal) = if is_ord {
                    (String::new(), Some((val & 0xffff) as u16))
                } else {
                    let hn = u32::try_from(val).map_err(|_| "invalid hint/name RVA")?;
                    rva_range(hn, 2).ok_or("invalid import hint")?;
                    let name = rva_string(hn.checked_add(2).ok_or("import name overflow")?)
                        .ok_or("invalid import name")?;
                    (name, None)
                };
                imports.push(PeImport {
                    dll: dll.clone(),
                    name,
                    rva: slot,
                    ordinal,
                });
            }
            if !thunk_terminated {
                return Err("import thunk limit exceeded".into());
            }
        }
        if !terminated {
            return Err("unterminated import descriptors".into());
        }
    }

    // Walk all EAT slots, attaching names separately so NONAME exports and
    // multiple aliases of the same ordinal are both retained.
    let mut exports = Vec::new();
    let export_dir = dirs.export_table();
    if export_dir.virtual_address != 0 || export_dir.size != 0 {
        if export_dir.size < 40 {
            return Err("truncated export directory".into());
        }
        let base = rva_range(export_dir.virtual_address, export_dir.size as usize)
            .ok_or("invalid export directory")?;
        let ordinal_base = r32(bytes, base + 16).ok_or("truncated export directory")?;
        let nfunc = r32(bytes, base + 20).ok_or("truncated export directory")? as usize;
        let nnames = r32(bytes, base + 24).ok_or("truncated export directory")? as usize;
        if nfunc > MAX_EXPORT_FUNCTIONS || nnames > MAX_EXPORT_NAMES {
            return Err("export limit exceeded".into());
        }
        let addr_funcs = r32(bytes, base + 28).ok_or("truncated export directory")?;
        let addr_names = r32(bytes, base + 32).ok_or("truncated export directory")?;
        let addr_ordinals = r32(bytes, base + 36).ok_or("truncated export directory")?;
        let mut names: Vec<Vec<String>> = vec![Vec::new(); nfunc];
        if nnames > 0 {
            let name_at = rva_range(addr_names, nnames * 4).ok_or("invalid export name table")?;
            let ord_at =
                rva_range(addr_ordinals, nnames * 2).ok_or("invalid export ordinal table")?;
            for i in 0..nnames {
                let index = r16(bytes, ord_at + i * 2).ok_or("truncated export ordinal")? as usize;
                let slot = names
                    .get_mut(index)
                    .ok_or("export ordinal exceeds function count")?;
                let rva = r32(bytes, name_at + i * 4).ok_or("truncated export name")?;
                slot.push(rva_string(rva).ok_or("invalid export name")?);
            }
        }
        if nfunc > 0 {
            let funcs = rva_range(addr_funcs, nfunc * 4).ok_or("invalid export address table")?;
            let dir_end = u64::from(export_dir.virtual_address) + u64::from(export_dir.size);
            for (i, aliases) in names.into_iter().enumerate() {
                let rva = r32(bytes, funcs + i * 4).ok_or("truncated export address")?;
                if rva == 0 {
                    continue;
                } // An unused EAT slot is not an export.
                let ordinal = Some(
                    ordinal_base
                        .checked_add(i as u32)
                        .ok_or("export ordinal overflow")?,
                );
                let reexport = if rva >= export_dir.virtual_address && u64::from(rva) < dir_end {
                    let target = rva_string(rva).ok_or("invalid export forwarder")?;
                    if u64::from(rva) + target.len() as u64 + 1 > dir_end {
                        return Err("forwarder exceeds export directory".into());
                    }
                    let (lib, name) = target
                        .rsplit_once('.')
                        .ok_or("invalid export forwarder target")?;
                    if lib.is_empty() || name.is_empty() {
                        return Err("empty export forwarder target".into());
                    }
                    Some(Reexport {
                        lib: lib.to_string(),
                        name: name.to_string(),
                    })
                } else {
                    None
                };
                if aliases.is_empty() {
                    exports.push(PeExport {
                        name: None,
                        rva,
                        ordinal,
                        reexport,
                    });
                } else {
                    for name in aliases {
                        exports.push(PeExport {
                            name: Some(name),
                            rva,
                            ordinal,
                            reexport: reexport.clone(),
                        });
                    }
                }
            }
        }
    }

    Ok(PeFile {
        header: PeHeader {
            coff_header: CoffHeader {
                machine,
                number_of_sections: num_sections.min(512) as u16,
                characteristics,
            },
            optional_header: Some(OptionalHeader {
                windows_fields: WindowsFields {
                    dll_characteristics: dll_chars,
                    subsystem,
                },
                data_directories: dirs,
            }),
        },
        is_64,
        image_base,
        entry,
        sections,
        imports,
        exports,
        libraries,
        security_cookie,
    })
}
