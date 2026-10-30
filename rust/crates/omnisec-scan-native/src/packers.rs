//! Structural packer / protector detection.
//!
//! The existing [`crate::malware`] scanner only spots packers by their
//! *exported symbol* footprint (e.g. a stray `UPX` export). Real packed
//! binaries rarely export such a symbol — instead they betray themselves
//! through the **shape** of their section / segment tables:
//!
//! * UPX leaves the literal `UPX!` magic in the file and renames its
//!   loadable sections to `UPX0` / `UPX1`.
//! * Commercial Windows protectors (VMProtect, Themida, ASPack, Petite,
//!   MPRESS, Enigma, …) rename sections to well-known tags.
//! * Almost every runtime packer needs at least one **writable +
//!   executable** loadable region so it can decrypt code in place — a
//!   shape a normal toolchain never produces.
//! * UPX (and friends) strip the ELF section-header table entirely while
//!   keeping a tiny number of large `PT_LOAD` segments.
//!
//! All probes here are read-only and operate on the already-parsed
//! in-house ELF/PE view plus the raw bytes. They complement — not replace — the
//! section-entropy scan in [`crate::entropy`]: entropy says "this looks
//! compressed", this module says "and the container is shaped like a
//! packer".

use omnisec_loader_elf::elfparse::{ElfFile, PT_LOAD};
use omnisec_loader_pe::peparse::PeFile;

use crate::{Category, Confidence, Finding, Severity};

/// Known packer / protector section-name markers.
///
/// Each entry is `(needle, label)`.  The needle is matched against the
/// *full* lowercase section name, not as a substring.  Short or common
/// strings (e.g. `"nsp"`, `"vmp"`, `"packed"`) were previously matched as
/// substrings, which caused false positives on unrelated section names that
/// happen to contain those character sequences.
///
/// Matching rules (applied in order):
/// 1. Exact match after lowercasing (`name == needle`).
/// 2. Prefix match when `needle` ends with `*` (stripped before compare).
///
/// UPX is detected separately via the `UPX!` magic bytes, so `upx0`/`upx1`
/// exact-names are kept here as belt-and-suspenders for cases where the
/// magic is stripped.
const SECTION_MARKERS: &[(&str, &str)] = &[
    // UPX renames sections; belt-and-suspenders after the magic-byte probe.
    ("upx0", "UPX"),
    ("upx1", "UPX"),
    ("upx2", "UPX"),
    // VMProtect
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    // Themida / WinLicense
    (".themida", "Themida/WinLicense"),
    (".winlice", "Themida/WinLicense"),
    // ASPack
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    // Petite
    (".petite", "Petite"),
    // MPRESS
    (".mpress1", "MPRESS"),
    (".mpress2", "MPRESS"),
    // Enigma Protector
    (".enigma1", "Enigma Protector"),
    (".enigma2", "Enigma Protector"),
    // NsPack — full name only; "nsp" as a substring is too broad
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    // PKLite
    (".pklstb", "PKLite"),
    // PEBundle
    (".pebundle", "PEBundle"),
    // MoleBox
    (".molebox", "MoleBox"),
    // Y0da Protector — ".yp" alone was too short; real sections are .yp0/.yp1
    (".yp0", "Y0da Protector"),
    (".yp1", "Y0da Protector"),
    // kkrunchy
    (".kkrunchy", "kkrunchy"),
    // The Boomerang
    (".boom", "The Boomerang"),
];

/// Run every structural packer probe.
pub(crate) fn scan(
    bytes: &[u8],
    elf: Option<&ElfFile<'_>>,
    pe: Option<&PeFile>,
    findings: &mut Vec<Finding>,
) {
    // The UPX magic appears in both ELF and PE UPX-packed files, regardless of
    // whether section headers survive. Cheap and very high precision.
    detect_upx_magic(bytes, findings);

    if let Some(elf) = elf {
        scan_elf(bytes, elf, findings);
    }
    if let Some(pe) = pe {
        scan_pe(pe, findings);
    }
}

/// `UPX!` is the literal copyright/marker UPX embeds in every packed file.
fn detect_upx_magic(bytes: &[u8], findings: &mut Vec<Finding>) {
    const MAGIC: &[u8] = b"UPX!";
    // Scan only the first 64 KiB and the last 16 KiB — UPX places the marker in
    // the stub header and the trailing PackHeader, never in the middle.
    let head_end = bytes.len().min(64 * 1024);
    let mut found_at = find_sub(&bytes[..head_end], MAGIC);
    if found_at.is_none() && bytes.len() > 16 * 1024 {
        let tail_start = bytes.len() - 16 * 1024;
        found_at = find_sub(&bytes[tail_start..], MAGIC).map(|o| tail_start + o);
    }
    if let Some(off) = found_at {
        findings.push(
            Finding::new(
                "packer-upx-magic",
                Category::DynamicCode,
                Severity::Medium,
                Confidence::High,
                "UPX packer signature",
                "The file contains the literal `UPX!` marker that the UPX \
                 packer embeds in every output. The real code is compressed and \
                 only decompressed at runtime, so static import / string \
                 scanning sees the stub, not the payload. Unpack with `upx -d` \
                 before deeper analysis.",
                format!("`UPX!` magic at file offset {off}"),
            )
            .with_offset(off as u64)
            .with_remediation("Run `upx -d <file>` to obtain the original binary, then re-scan."),
        );
    }
}

/// ELF structural tells: marker section names, RWX loadable segments, and a
/// stripped section-header table over a tiny segment set.
fn scan_elf(bytes: &[u8], elf: &ElfFile<'_>, findings: &mut Vec<Finding>) {
    // 1. Marker section names.
    let strtab = &elf.shdr_strtab;
    let mut matched_marker = false;
    for sh in &elf.section_headers {
        let name = strtab.get_at(sh.sh_name as usize).unwrap_or("");
        if let Some(label) = match_section_marker(name) {
            matched_marker = true;
            findings.push(
                Finding::new(
                    "packer-section-name",
                    Category::DynamicCode,
                    Severity::Medium,
                    Confidence::High,
                    "Packer/protector section name",
                    format!(
                        "ELF section `{name}` matches the {label} packer/protector \
                         naming footprint. Packed natives in an Android app are a \
                         strong obfuscation / evasion indicator."
                    ),
                    format!("section `{name}` ⇒ {label}"),
                )
                .with_remediation("Unpack / unprotect before static analysis."),
            );
        }
    }

    // 2. Writable + executable PT_LOAD segment (self-modifying / decrypt-in-place).
    //    PF_X = 1, PF_W = 2.
    for ph in &elf.program_headers {
        if ph.p_type == PT_LOAD {
            let w = ph.p_flags & 0x2 != 0;
            let x = ph.p_flags & 0x1 != 0;
            if w && x {
                findings.push(
                    Finding::new(
                        "packer-rwx-segment",
                        Category::DynamicCode,
                        Severity::High,
                        Confidence::Medium,
                        "Writable + executable load segment",
                        "A PT_LOAD segment is mapped both writable and executable \
                         (W^X violated). A normal toolchain never emits this; it is \
                         the canonical shape of a runtime packer / self-decrypting \
                         stub that writes decompressed code into a page and then \
                         jumps into it.",
                        format!(
                            "PT_LOAD off={:#x} filesz={:#x} flags=RWX",
                            ph.p_offset, ph.p_filesz
                        ),
                    )
                    .with_offset(ph.p_offset)
                    .with_remediation("Treat the RWX region as decrypted-at-runtime code."),
                );
                break; // one RWX-segment finding is enough
            }
        }
    }

    // 3. Stripped section headers with a live segment table. UPX (and several
    //    custom ELF packers) drop the section-header table entirely while
    //    keeping a handful of large PT_LOAD segments. A loadable ELF with zero
    //    sections but present segments is therefore highly suspicious.
    let load_segments = elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .count();
    if elf.section_headers.is_empty() && load_segments > 0 && !matched_marker {
        findings.push(
            Finding::new(
                "packer-stripped-sections",
                Category::DynamicCode,
                Severity::Medium,
                Confidence::Medium,
                "Section headers stripped, segments intact",
                format!(
                    "The ELF has no section-header table but {load_segments} loadable \
                     segment(s). Compilers always emit sections; packers such as UPX \
                     and many custom ELF protectors strip them to break tooling while \
                     keeping the program loadable."
                ),
                format!("0 sections, {load_segments} PT_LOAD segment(s)"),
            )
            .with_remediation(
                "Reconstruct sections (e.g. with a section-recovery tool) before deep analysis.",
            ),
        );
    }

    let _ = bytes;
}

/// PE structural tells: marker section names, RWX section characteristics, and
/// virtual-size-without-raw-data (a packer stub that unpacks into the section).
fn scan_pe(pe: &PeFile, findings: &mut Vec<Finding>) {
    // IMAGE_SCN_MEM_EXECUTE = 0x2000_0000, IMAGE_SCN_MEM_WRITE = 0x8000_0000.
    const MEM_EXECUTE: u32 = 0x2000_0000;
    const MEM_WRITE: u32 = 0x8000_0000;

    let mut rwx_reported = false;
    for sec in &pe.sections {
        let name = sec.name().unwrap_or("");
        if let Some(label) = match_section_marker(name) {
            findings.push(
                Finding::new(
                    "packer-section-name",
                    Category::DynamicCode,
                    Severity::Medium,
                    Confidence::High,
                    "Packer/protector section name",
                    format!(
                        "PE section `{name}` matches the {label} packer/protector \
                         naming footprint."
                    ),
                    format!("section `{name}` ⇒ {label}"),
                )
                .with_remediation("Unpack / unprotect before static analysis."),
            );
        }

        let ch = sec.characteristics;
        if !rwx_reported && (ch & MEM_EXECUTE != 0) && (ch & MEM_WRITE != 0) {
            rwx_reported = true;
            findings.push(
                Finding::new(
                    "packer-rwx-section",
                    Category::DynamicCode,
                    Severity::High,
                    Confidence::Medium,
                    "Writable + executable PE section",
                    format!(
                        "PE section `{name}` is both writable and executable. Normal \
                         linkers separate code (RX) from data (RW); a self-modifying \
                         RWX section is the hallmark of a runtime packer decrypting \
                         code in place."
                    ),
                    format!("section `{name}` characteristics=RWX"),
                )
                .with_remediation("Treat the RWX section as decrypted-at-runtime code."),
            );
        }

        // A section that occupies virtual address space but has (almost) no
        // raw data on disk is what a packer's destination buffer looks like:
        // the stub fills it at runtime.
        let vsize = sec.virtual_size;
        let rawsize = sec.size_of_raw_data;
        if vsize > 0x2000 && rawsize == 0 && (ch & MEM_EXECUTE != 0) {
            findings.push(
                Finding::new(
                    "packer-virtual-only-exec",
                    Category::DynamicCode,
                    Severity::Medium,
                    Confidence::Medium,
                    "Executable section with no raw data",
                    format!(
                        "PE section `{name}` reserves {vsize:#x} bytes of executable \
                         virtual space but has no raw data on disk. The stub unpacks \
                         the real code into this region at runtime."
                    ),
                    format!("section `{name}` vsize={vsize:#x} rawsize=0 exec"),
                )
                .with_remediation("Dump the section after the unpacking stub runs."),
            );
        }
    }
}

/// Match a section name against the packer marker table.
///
/// Uses exact case-insensitive comparison only.  Substring matching was
/// removed because short needles like `"nsp"` / `"vmp"` / `"packed"`
/// produced false positives on legitimate section names.
fn match_section_marker(name: &str) -> Option<&'static str> {
    let lower = name.trim_matches(char::from(0)).to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }
    for (needle, label) in SECTION_MARKERS {
        if lower == *needle {
            return Some(label);
        }
    }
    None
}

/// Tiny Boyer-Moore-free substring search over bytes (needle is short).
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upx_magic_detected_in_head() {
        let mut bytes = vec![0u8; 4096];
        bytes[100..104].copy_from_slice(b"UPX!");
        let mut f = vec![];
        detect_upx_magic(&bytes, &mut f);
        assert!(f.iter().any(|x| x.id == "packer-upx-magic"));
        assert_eq!(f[0].file_offset, Some(100));
    }

    #[test]
    fn upx_magic_detected_in_tail() {
        let mut bytes = vec![0u8; 64 * 1024];
        let off = bytes.len() - 8;
        bytes[off..off + 4].copy_from_slice(b"UPX!");
        let mut f = vec![];
        detect_upx_magic(&bytes, &mut f);
        assert!(f.iter().any(|x| x.id == "packer-upx-magic"));
    }

    #[test]
    fn clean_bytes_no_upx() {
        let bytes = vec![0x90u8; 8192];
        let mut f = vec![];
        detect_upx_magic(&bytes, &mut f);
        assert!(f.is_empty());
    }

    #[test]
    fn section_marker_matches_case_insensitively() {
        assert_eq!(match_section_marker("UPX0"), Some("UPX"));
        assert_eq!(match_section_marker(".vmp0"), Some("VMProtect"));
        assert_eq!(match_section_marker(".themida"), Some("Themida/WinLicense"));
        assert_eq!(match_section_marker(".text"), None);
        assert_eq!(match_section_marker(""), None);
    }

    #[test]
    fn find_sub_basic() {
        assert_eq!(find_sub(b"abcUPX!def", b"UPX!"), Some(3));
        assert_eq!(find_sub(b"abcdef", b"UPX!"), None);
        assert_eq!(find_sub(b"", b"x"), None);
    }
}
