//! End-to-end integration tests for the scanner.
//!
//! Two kinds of tests live here:
//!
//! 1. *Synthetic ELF* — a minimal valid ELF64 LE buffer is built inline,
//!    parsed via the real `omnisec-loader-elf`, and scanned. This proves
//!    the loader→scanner glue works, and that ELF-specific hardening
//!    probes (NX, PIE, W^X) fire on a real binary. We deliberately do
//!    NOT exercise dynamic-symbol parsing here: that requires a full
//!    PT_DYNAMIC + DT_SYMTAB/DT_STRTAB chain, which would add
//!    ~300 lines of header-construction noise to the test.
//!
//! 2. *Constructed `LoadedBinary`* — for the import/symbol-driven probes
//!    (vulns, malware, JNI, packers) we build the universal
//!    `LoadedBinary` directly. The scanner accepts an empty `bytes` slice
//!    for that case (the format-specific probes are skipped, but the
//!    non-ELF probes still run on the structured data).

use omnisec_core::{Arch, Endian, Format};
use omnisec_json::JsonValue;
use omnisec_loader::{Import, LoadedBinary, Loader, Symbol, SymbolKind};
use omnisec_loader_elf::ElfLoader;
use omnisec_scan_native::{AndroidAbi, Category, ElfKind, RelroLevel, Severity, Verdict, scan};

/// Build a minimal valid ELF64 LE executable. Hardening-relevant bits:
/// - `e_type = ET_EXEC` ⇒ PIE off
/// - no `PT_GNU_STACK` ⇒ NX off (loader assumes RWX)
/// - one W+R+X PT_LOAD ⇒ W^X violation
/// - no `PT_GNU_RELRO` ⇒ RELRO none
fn build_synthetic_elf() -> Vec<u8> {
    use omnisec_loader_elf::elfparse::{EM_AARCH64, ET_EXEC, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};

    let mut buf = vec![0u8; 0x600];

    // ── ELF identification ──────────────────────────────────────────────
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EI_VERSION
    buf[7] = 0; // OSABI = SYSV

    // ── ELF header ──────────────────────────────────────────────────────
    buf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    buf[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    buf[24..32].copy_from_slice(&0x4000_0200u64.to_le_bytes()); // e_entry
    buf[32..40].copy_from_slice(&0x40u64.to_le_bytes()); // e_phoff
    buf[40..48].copy_from_slice(&0x300u64.to_le_bytes()); // e_shoff
    buf[48..52].copy_from_slice(&0u32.to_le_bytes()); // e_flags
    buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    buf[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum (null + .text + .shstrtab)
    buf[62..64].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx → [2]

    // ── Program header (PT_LOAD with R+W+X to trigger W^X) ──────────────
    let ph = 0x40usize;
    buf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    buf[ph + 4..ph + 8].copy_from_slice(&7u32.to_le_bytes()); // p_flags = R+W+X (0b111)
    buf[ph + 8..ph + 16].copy_from_slice(&0x200u64.to_le_bytes()); // p_offset
    buf[ph + 16..ph + 24].copy_from_slice(&0x4000_0200u64.to_le_bytes()); // p_vaddr
    buf[ph + 24..ph + 32].copy_from_slice(&0x4000_0200u64.to_le_bytes()); // p_paddr
    buf[ph + 32..ph + 40].copy_from_slice(&0x10u64.to_le_bytes()); // p_filesz
    buf[ph + 40..ph + 48].copy_from_slice(&0x10u64.to_le_bytes()); // p_memsz
    buf[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

    // ── .shstrtab: "\0.text\0.shstrtab\0" ────────────────────────────────
    let shstrtab_off = 0x80usize;
    let shstr = b"\0.text\0.shstrtab\0";
    buf[shstrtab_off..shstrtab_off + shstr.len()].copy_from_slice(shstr);

    // ── .text: 16 nops ──────────────────────────────────────────────────
    let text_off = 0x200usize;
    for b in &mut buf[text_off..text_off + 0x10] {
        *b = 0x1F;
    }

    // ── Section headers (3 × 64 B) ──────────────────────────────────────
    let sh = 0x300usize;

    // [1] .text — name offset 1
    let sh1 = sh + 64;
    buf[sh1..sh1 + 4].copy_from_slice(&1u32.to_le_bytes());
    buf[sh1 + 4..sh1 + 8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
    buf[sh1 + 8..sh1 + 16].copy_from_slice(
        &(u64::from(SHF_ALLOC) | u64::from(SHF_WRITE) | u64::from(SHF_EXECINSTR)).to_le_bytes(),
    );
    buf[sh1 + 16..sh1 + 24].copy_from_slice(&0x4000_0200u64.to_le_bytes()); // sh_addr
    buf[sh1 + 24..sh1 + 32].copy_from_slice(&(text_off as u64).to_le_bytes()); // sh_offset
    buf[sh1 + 32..sh1 + 40].copy_from_slice(&0x10u64.to_le_bytes()); // sh_size

    // [2] .shstrtab — name offset 7
    let sh2 = sh + 128;
    buf[sh2..sh2 + 4].copy_from_slice(&7u32.to_le_bytes());
    buf[sh2 + 4..sh2 + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
    buf[sh2 + 24..sh2 + 32].copy_from_slice(&(shstrtab_off as u64).to_le_bytes());
    buf[sh2 + 32..sh2 + 40].copy_from_slice(&(shstr.len() as u64).to_le_bytes());

    buf
}

#[test]
fn synthetic_elf_triggers_hardening_findings() {
    let bytes = build_synthetic_elf();
    let bin = ElfLoader::new()
        .load(&bytes)
        .expect("synthetic ELF must parse via the real loader");

    let report = scan(&bin, &bytes).expect("scan must not fail on a valid ELF");

    // PIE: e_type = ET_EXEC ⇒ PIE off.
    assert_eq!(report.hardening.pie, Some(false));
    // NX: no PT_GNU_STACK ⇒ NX off.
    assert_eq!(report.hardening.nx, Some(false));
    // RELRO: no segment ⇒ none.
    assert_eq!(report.hardening.relro, RelroLevel::None);
    // W+X violation.
    assert!(report.hardening.wx_sections >= 1);
    assert_eq!(report.target_profile.elf_kind, Some(ElfKind::Executable));
    assert_eq!(
        report.target_profile.android_abi,
        Some(AndroidAbi::Arm64V8a)
    );

    // Findings must include all of these.
    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"no-pie"));
    assert!(ids.contains(&"no-nx"));
    assert!(ids.contains(&"no-relro"));
    assert!(ids.contains(&"wx-section"));

    // No symbol/import data, so no vuln findings.
    assert_eq!(report.count_in(Category::Vulnerability), 0);

    // Hardening alone yields a positive risk score.
    assert!(report.score > 0);
}

/// Construct a `LoadedBinary` directly with `Format::Elf`, the given
/// imports and symbols. Used to exercise the import/symbol-driven probes
/// without having to forge a complete dynamic-table ELF.
fn fake_elf(imports: &[(&str, &str)], symbols: &[(&str, SymbolKind)]) -> LoadedBinary {
    let mut bin = LoadedBinary::new(Format::Elf, Arch::Arm64, Endian::Little, 0);
    for (lib, name) in imports {
        bin.imports.push(Import {
            library: (*lib).into(),
            name: (*name).into(),
            address: None,
            ordinal: None,
            is_data: false,
        });
    }
    for (name, kind) in symbols {
        bin.symbols.push(Symbol {
            name: (*name).into(),
            address: 0x1000,
            size: 0,
            kind: *kind,
            is_global: true,
        });
    }
    bin
}

#[test]
fn imports_drive_vuln_and_malware_findings() {
    let bin = fake_elf(
        &[
            ("libc.so", "strcpy"),
            ("libc.so", "system"),
            ("libc.so", "ptrace"),
            ("libc.so", "dlopen"),
            ("libc.so", "dlsym"),
            ("libc.so", "memfd_create"),
            ("libc.so", "execveat"),
        ],
        &[],
    );
    // Empty bytes → format-specific hardening probes are skipped.
    let report = scan(&bin, b"").expect("scan should succeed");

    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();

    // Vulns.
    assert!(ids.contains(&"dangerous-api-strcpy"));
    assert!(ids.contains(&"dangerous-api-system"));

    // Malware.
    assert!(ids.contains(&"anti-debug-ptrace"));
    assert!(ids.contains(&"dynamic-code-dlopen"));
    assert!(ids.contains(&"combo-dynamic-api-resolution"));
    assert!(ids.contains(&"combo-fileless-exec"));

    // Fileless exec is critical → score ≥ 28.
    assert!(report.score >= 28);
    assert!(matches!(
        report.verdict,
        Verdict::Medium | Verdict::High | Verdict::Critical
    ));

    // Severity::Info bucket is reachable without panic.
    let _ = report.count_at(Severity::Info);
}

#[test]
fn frida_symbol_drives_high_severity_finding() {
    let bin = fake_elf(&[], &[("frida_agent_init", SymbolKind::Function)]);
    let report = scan(&bin, b"").expect("scan must succeed");
    let f = report
        .findings
        .iter()
        .find(|f| f.id == "frida-gadget")
        .expect("frida-gadget finding must be emitted");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn json_serialisation_round_trip() {
    let bytes = build_synthetic_elf();
    let bin = ElfLoader::new().load(&bytes).unwrap();
    let report = scan(&bin, &bytes).unwrap();

    let json = omnisec_json::to_json_string(&report);
    let parsed: omnisec_json::JsonValue =
        omnisec_json::from_json_str(&json).expect("re-parse JSON");
    assert!(parsed.get("findings").is_some());
    assert!(parsed.get("hardening").is_some());
    assert!(parsed.get("score").is_some());
    assert!(parsed.get("verdict").is_some());
    assert!(parsed.get("scanner_version").is_some());
}
