//! Magic-byte format detection.
//!
//! `detect_format` is intentionally conservative: it only classifies inputs
//! whose first few bytes are unambiguously one of our known containers.
//! Nuanced classification (PE vs .NET-PE, ZIP vs APK vs JAR) is the job of
//! the format-specific loader crates — they peek deeper and refine.
//!
//! ## Notable ambiguities handled here
//!
//! `0xCAFEBABE` is shared between **JVM ClassFile** and **Mach-O FAT**.
//! Java class files have `minor_version (u16)` immediately after the magic;
//! valid `major_version` values for any production JVM are `>= 45`
//! (Java 1.1, 1996). Mach-O FAT instead has `nfat_arch (u32 BE)` directly
//! after the magic, which in practice is `1..=64`. We distinguish on the
//! 5th and 6th bytes accordingly.

use crate::Format;

// Mach-O native (single-arch) magic bytes.
const MACHO_32_BE: [u8; 4] = [0xFE, 0xED, 0xFA, 0xCE];
const MACHO_32_LE: [u8; 4] = [0xCE, 0xFA, 0xED, 0xFE];
const MACHO_64_BE: [u8; 4] = [0xFE, 0xED, 0xFA, 0xCF];
const MACHO_64_LE: [u8; 4] = [0xCF, 0xFA, 0xED, 0xFE];

/// Best-effort container-format classification of `bytes`.
///
/// Only the first ~64 bytes are inspected. Returns [`Format::Unknown`] when
/// detection is inconclusive — *not* an error.
#[must_use]
pub fn detect_format(bytes: &[u8]) -> Format {
    // Tiny inputs can't be much.
    if bytes.len() < 4 {
        return Format::Unknown;
    }

    // ELF: 0x7F 'E' 'L' 'F'
    if bytes.starts_with(&[0x7F, b'E', b'L', b'F']) {
        return Format::Elf;
    }

    if bytes.starts_with(&MACHO_32_BE)
        || bytes.starts_with(&MACHO_32_LE)
        || bytes.starts_with(&MACHO_64_BE)
        || bytes.starts_with(&MACHO_64_LE)
    {
        return Format::MachO;
    }

    // 0xCAFEBABE — could be JVM class OR Mach-O FAT.
    if bytes.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        return disambiguate_cafebabe(bytes);
    }

    // WASM: \0 'a' 's' 'm'  +  version (u32 LE)
    if bytes.starts_with(&[0x00, b'a', b's', b'm']) {
        return Format::Wasm;
    }

    // DEX: 'd' 'e' 'x' '\n' VVV '\0'  (e.g. "dex\n035\0", "dex\n039\0").
    if bytes.len() >= 8
        && bytes.starts_with(b"dex\n")
        && bytes[4..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == 0
    {
        return Format::Dex;
    }

    // ZIP family: 'P' 'K' \x03 \x04 (local file header — most common).
    // ZIP empty archive: 'P' 'K' \x05 \x06.
    // We classify all of these as Zip and let an archive-aware loader refine
    // (APK / JAR / WAR live behind this).
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        return Format::Zip;
    }

    // PE / .NET-PE: starts with 'MZ'. Real PEs have a valid e_lfanew at 0x3C
    // pointing to "PE\0\0", but checking the MZ stub is enough at this stage.
    if bytes.starts_with(b"MZ") {
        return Format::Pe;
    }

    // ISO 9660 — primary volume descriptor at LBA 16 (offset 0x8000) with
    // signature "CD001". We only check it if the buffer is large enough.
    if bytes.len() >= 0x8006 && &bytes[0x8001..0x8006] == b"CD001" {
        return Format::Iso;
    }

    Format::Unknown
}

/// Decide whether bytes that start with `0xCAFEBABE` are a JVM class file or
/// a Mach-O Universal (FAT) binary.
///
/// **Heuristic.** Both formats are big-endian on disk and share the magic.
/// Past the magic:
///
/// - **JVM ClassFile** stores `u16 minor_version`, then `u16 major_version`,
///   where `major_version` is `>= 45` (Java 1.1 — the lowest ever shipped).
/// - **Mach-O FAT** stores `u32 nfat_arch` — the number of architectures
///   bundled inside. Real-world Mach-O FAT binaries have at most a handful
///   (`1..=8` is normal, `> 16` is unheard of).
///
/// We look at the `u16` at bytes 6..8 (Java's `major_version` *and*
/// Mach-O's lower 16 bits of `nfat_arch`). If it's `>= 45` we call it a
/// ClassFile; otherwise Mach-O FAT.
fn disambiguate_cafebabe(bytes: &[u8]) -> Format {
    if bytes.len() < 8 {
        return Format::JvmClass; // Bias toward the more common case.
    }

    let java_major = u16::from_be_bytes([bytes[6], bytes[7]]);

    if java_major >= 45 {
        Format::JvmClass
    } else {
        Format::MachO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_elf() {
        let b = [0x7F, b'E', b'L', b'F', 0, 0, 0, 0];
        assert_eq!(detect_format(&b), Format::Elf);
    }

    #[test]
    fn detects_pe_mz() {
        let b = b"MZ\x90\x00"; // truncated DOS stub start
        assert_eq!(detect_format(b), Format::Pe);
    }

    #[test]
    fn detects_macho_native_variants() {
        for magic in [
            [0xFE, 0xED, 0xFA, 0xCE],
            [0xCE, 0xFA, 0xED, 0xFE],
            [0xFE, 0xED, 0xFA, 0xCF],
            [0xCF, 0xFA, 0xED, 0xFE],
        ] {
            let b = [magic[0], magic[1], magic[2], magic[3], 0, 0, 0, 0];
            assert_eq!(detect_format(&b), Format::MachO);
        }
    }

    #[test]
    fn detects_wasm() {
        let b = [0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];
        assert_eq!(detect_format(&b), Format::Wasm);
    }

    #[test]
    fn detects_dex() {
        let b = b"dex\n035\0extra";
        assert_eq!(detect_format(b), Format::Dex);
        let b2 = b"dex\n039\0extra";
        assert_eq!(detect_format(b2), Format::Dex);
        let bad = b"dex\nXXX\0";
        assert_ne!(detect_format(bad), Format::Dex);
    }

    #[test]
    fn detects_zip() {
        let b = b"PK\x03\x04rest";
        assert_eq!(detect_format(b), Format::Zip);
    }

    #[test]
    fn detects_jvm_class_for_typical_major_versions() {
        // Java 17 = major 0x3D (61). minor_version is usually 0 except for preview classes.
        for major in [45u16, 52, 55, 61, 65] {
            let mut b = vec![0xCA, 0xFE, 0xBA, 0xBE];
            b.extend_from_slice(&0u16.to_be_bytes()); // minor
            b.extend_from_slice(&major.to_be_bytes()); // major
            let detected = detect_format(&b);
            assert_eq!(detected, Format::JvmClass, "major={major}");
        }
    }

    #[test]
    fn detects_macho_fat_with_small_nfat_arch() {
        // nfat_arch = 2  (a typical Universal binary with x86_64 + arm64).
        let mut b = vec![0xCA, 0xFE, 0xBA, 0xBE];
        b.extend_from_slice(&2u32.to_be_bytes());
        assert_eq!(detect_format(&b), Format::MachO);
    }

    #[test]
    fn unknown_for_garbage_short_input() {
        assert_eq!(detect_format(&[]), Format::Unknown);
        assert_eq!(detect_format(&[0]), Format::Unknown);
        assert_eq!(detect_format(&[0, 0, 0]), Format::Unknown);
        assert_eq!(detect_format(&[0xAA, 0xBB, 0xCC, 0xDD]), Format::Unknown);
    }

    #[test]
    fn detects_iso_9660() {
        // Volume descriptor at offset 0x8000: <type byte><'CD001'><...>.
        let mut b = vec![0u8; 0x8000 + 6];
        b[0x8000] = 0x01; // primary volume descriptor type
        b[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(detect_format(&b), Format::Iso);
    }
}
