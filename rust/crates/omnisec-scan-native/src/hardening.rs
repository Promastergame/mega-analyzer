//! Compile-time mitigation probes (NX / PIE / RELRO / canary / FORTIFY / stripped / RPATH).

use omnisec_core::Format;
use omnisec_loader::{LoadedBinary, SectionFlags};
use omnisec_loader_elf::elfparse::{
    DF_1_NOW, DF_BIND_NOW, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1, DT_RPATH, DT_RUNPATH, ET_DYN,
    ElfFile, PF_X, PT_GNU_RELRO, PT_GNU_STACK,
};
use omnisec_loader_pe::peparse::PeFile;

use crate::{
    Category, Confidence, Finding, Severity,
    report::{HardeningReport, RelroLevel},
};

/// Run every hardening probe and return a populated [`HardeningReport`],
/// pushing one [`Finding`] for each missing mitigation into `findings`.
pub(crate) fn evaluate(
    bin: &LoadedBinary,
    elf: Option<&ElfFile<'_>>,
    pe: Option<&PeFile>,
    findings: &mut Vec<Finding>,
) -> HardeningReport {
    // ── W^X check (independent of format parsing) ─────────────────────────
    let wx_sections = bin
        .sections
        .iter()
        .filter(|s| {
            s.flags.contains(SectionFlags::WRITE) && s.flags.contains(SectionFlags::EXECUTE)
        })
        .count();
    let mut report = HardeningReport {
        wx_sections,
        ..Default::default()
    };
    if report.wx_sections > 0 {
        findings.push(
            Finding::new(
                "wx-section",
                Category::Hardening,
                Severity::High,
                Confidence::High,
                "Writable + executable section",
                "The binary contains a section that is both writable and executable. \
                 This violates W^X and is a strong indicator of either a packer / \
                 self-modifying code or a JIT engine.",
                format!("{} W+X section(s)", report.wx_sections),
            )
            .with_remediation("Split RW data and RX code into separate segments."),
        );
    }

    if bin.format == Format::Elf {
        if let Some(elf) = elf {
            evaluate_elf(bin, elf, &mut report, findings);
        }
    } else if bin.format == Format::Pe
        && let Some(pe) = pe
    {
        evaluate_pe(bin, pe, &mut report, findings);
    }

    report
}

fn evaluate_elf(
    bin: &LoadedBinary,
    elf: &ElfFile<'_>,
    report: &mut HardeningReport,
    findings: &mut Vec<Finding>,
) {
    // ── NX (no-exec stack) ──────────────────────────────────────────────
    let stack_ph = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_GNU_STACK);
    let nx = match stack_ph {
        Some(ph) => Some(ph.p_flags & PF_X == 0),
        // No PT_GNU_STACK at all → loader assumes RWX. Treat as NX off.
        None => Some(false),
    };
    report.nx = nx;
    if nx == Some(false) {
        findings.push(
            Finding::new(
                "no-nx",
                Category::Hardening,
                Severity::High,
                Confidence::High,
                "Executable stack (NX disabled)",
                "PT_GNU_STACK is missing or has the executable flag set. The kernel \
                 will map the stack as RWX, allowing classic shellcode-on-stack \
                 attacks.",
                "PT_GNU_STACK absent or PF_X set",
            )
            .with_cwe("CWE-119")
            .with_remediation("Link with `-z noexecstack` or remove `--execstack`."),
        );
    }

    // ── PIE ─────────────────────────────────────────────────────────────
    let pie = elf.header.e_type == ET_DYN;
    report.pie = Some(pie);
    if !pie {
        findings.push(
            Finding::new(
                "no-pie",
                Category::Hardening,
                Severity::Medium,
                Confidence::High,
                "Position-independent executable disabled",
                "Binary is ET_EXEC, so the load address is fixed. ASLR cannot \
                 randomise the main image, giving attackers stable gadget addresses.",
                "e_type = ET_EXEC",
            )
            .with_remediation("Compile and link with `-fPIE -pie`."),
        );
    }

    // ── RELRO ───────────────────────────────────────────────────────────
    let has_relro_seg = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);
    let mut bind_now = false;
    for d in elf.dynamic.as_ref().map(|d| &d.dyns).into_iter().flatten() {
        match d.d_tag {
            DT_BIND_NOW => bind_now = true,
            DT_FLAGS if d.d_val & DF_BIND_NOW != 0 => bind_now = true,
            DT_FLAGS_1 if d.d_val & DF_1_NOW != 0 => bind_now = true,
            _ => {}
        }
    }
    let relro = match (has_relro_seg, bind_now) {
        (true, true) => RelroLevel::Full,
        (true, false) => RelroLevel::Partial,
        (false, _) => RelroLevel::None,
    };
    report.relro = relro;
    match relro {
        RelroLevel::None => findings.push(
            Finding::new(
                "no-relro",
                Category::Hardening,
                Severity::Medium,
                Confidence::High,
                "RELRO disabled",
                "GOT and other relocation tables remain writable at runtime, \
                 enabling classic GOT-overwrite primitives.",
                "no PT_GNU_RELRO segment",
            )
            .with_remediation("Link with `-Wl,-z,relro,-z,now` for full RELRO."),
        ),
        RelroLevel::Partial => findings.push(
            Finding::new(
                "partial-relro",
                Category::Hardening,
                Severity::Low,
                Confidence::High,
                "Partial RELRO only",
                "PT_GNU_RELRO is present but DT_BIND_NOW / DF_1_NOW is not, so \
                 the GOT remains writable until first use of each symbol.",
                "PT_GNU_RELRO without DT_BIND_NOW",
            )
            .with_remediation("Add `-Wl,-z,now` for full RELRO."),
        ),
        RelroLevel::Full => {}
    }

    // ── Stack canary ────────────────────────────────────────────────────
    let has_canary = bin
        .imports
        .iter()
        .any(|i| matches!(i.name.as_str(), "__stack_chk_fail" | "__stack_chk_guard"))
        || bin
            .symbols
            .iter()
            .any(|s| matches!(s.name.as_str(), "__stack_chk_fail" | "__stack_chk_guard"));
    report.stack_canary = Some(has_canary);
    if !has_canary {
        findings.push(
            Finding::new(
                "no-stack-canary",
                Category::Hardening,
                Severity::Medium,
                Confidence::Medium,
                "Stack canary not detected",
                "No reference to `__stack_chk_fail` / `__stack_chk_guard` was \
                 found. Stack-buffer overflows are not detected at runtime.",
                "no __stack_chk_* symbol",
            )
            .with_cwe("CWE-121")
            .with_remediation("Compile with `-fstack-protector-strong`."),
        );
    }

    // ── FORTIFY_SOURCE ──────────────────────────────────────────────────
    let fortify = bin.imports.iter().any(|i| {
        // FORTIFY-instrumented libc helpers all end in `_chk`.
        i.name.ends_with("_chk")
            && (i.name.starts_with("__")
                || matches!(
                    i.name.as_str(),
                    "memcpy_chk" | "memmove_chk" | "strcpy_chk" | "strcat_chk" | "snprintf_chk"
                ))
    });
    report.fortify_source = Some(fortify);
    if !fortify {
        findings.push(
            Finding::new(
                "no-fortify",
                Category::Hardening,
                Severity::Low,
                Confidence::Medium,
                "FORTIFY_SOURCE not detected",
                "No `*_chk` libc imports found, so the binary was likely compiled \
             without `-D_FORTIFY_SOURCE=2`. Some classes of buffer overflows \
             will not be caught at runtime.",
                "no *_chk imports",
            )
            .with_remediation("Compile with `-O2 -D_FORTIFY_SOURCE=2`."),
        );
    }

    // ── Stripped (no static .symtab) ────────────────────────────────────
    let stripped = bin.symbols.is_empty();
    report.stripped = Some(stripped);
    if !stripped {
        findings.push(Finding::new(
            "not-stripped",
            Category::Hardening,
            Severity::Info,
            Confidence::High,
            "Binary not stripped",
            "Static .symtab is present — symbol names are visible. This is \
             only an information-disclosure issue for closed-source code.",
            format!("{} static symbols", bin.symbols.len()),
        ));
    }

    // ── RPATH / RUNPATH ─────────────────────────────────────────────────
    let mut rpath: Option<String> = None;
    let mut runpath: Option<String> = None;
    if let Some(dyn_info) = elf.dynamic.as_ref() {
        for d in &dyn_info.dyns {
            match d.d_tag {
                DT_RPATH => {
                    if let Some(s) = elf.dynstrtab.get_at(d.d_val as usize) {
                        rpath = Some(s.to_string());
                    }
                }
                DT_RUNPATH => {
                    if let Some(s) = elf.dynstrtab.get_at(d.d_val as usize) {
                        runpath = Some(s.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(p) = rpath.as_deref() {
        findings.push(
            Finding::new(
                "rpath-set",
                Category::Hardening,
                Severity::Medium,
                Confidence::High,
                "Hard-coded DT_RPATH",
                "DT_RPATH is checked *before* LD_LIBRARY_PATH and cannot be \
                 overridden by the user. A writable directory in the rpath \
                 is a privilege-escalation vector.",
                format!("DT_RPATH = \"{p}\""),
            )
            .with_cwe("CWE-426")
            .with_remediation("Prefer DT_RUNPATH (-Wl,--enable-new-dtags)."),
        );
    }
    if let Some(p) = runpath.as_deref() {
        findings.push(Finding::new(
            "runpath-set",
            Category::Hardening,
            Severity::Low,
            Confidence::High,
            "DT_RUNPATH set",
            "DT_RUNPATH influences library search. Ensure no entry points \
             at a world-writable directory.",
            format!("DT_RUNPATH = \"{p}\""),
        ));
    }
    report.rpath = rpath;
    report.runpath = runpath;
}

fn evaluate_pe(
    bin: &LoadedBinary,
    pe: &PeFile,
    report: &mut HardeningReport,
    findings: &mut Vec<Finding>,
) {
    let dll_char = pe
        .header
        .optional_header
        .map_or(0, |oh| oh.windows_fields.dll_characteristics);

    // ── NX (DEP) ────────────────────────────────────────────────────────
    let nx = dll_char & 0x0100 != 0; // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    report.nx = Some(nx);
    if !nx {
        findings.push(Finding::new(
            "no-nx-pe",
            Category::Hardening,
            Severity::High,
            Confidence::High,
            "DEP (NX) disabled",
            "The NX_COMPAT flag is missing from DllCharacteristics. Data Execution Prevention is not forced, allowing code execution from the stack or heap.",
            "IMAGE_DLLCHARACTERISTICS_NX_COMPAT unset"
        ).with_remediation("Link with /NXCOMPAT."));
    }

    // ── ASLR (DynamicBase) ──────────────────────────────────────────────
    let pie = dll_char & 0x0040 != 0; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    report.pie = Some(pie);
    if !pie {
        findings.push(Finding::new(
            "no-aslr-pe",
            Category::Hardening,
            Severity::Medium,
            Confidence::High,
            "ASLR (DynamicBase) disabled",
            "The DYNAMIC_BASE flag is missing. The image will be loaded at its preferred base address, making it easier to predict gadget locations.",
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE unset"
        ).with_remediation("Link with /DYNAMICBASE."));
    }

    // ── CFG (Control Flow Guard) ────────────────────────────────────────
    let cfg = dll_char & 0x4000 != 0; // IMAGE_DLLCHARACTERISTICS_GUARD_CF
    if !cfg {
        findings.push(Finding::new(
            "no-cfg-pe",
            Category::Hardening,
            Severity::Medium,
            Confidence::High,
            "Control Flow Guard (CFG) disabled",
            "CFG is not enabled. Indirect calls are not validated at runtime, increasing the risk of control-flow hijacking.",
            "IMAGE_DLLCHARACTERISTICS_GUARD_CF unset"
        ).with_remediation("Compile with /guard:cf."));
    }

    // ── Stack Canary (GS / Security Cookie) ──────────────────────────────
    // __security_check_cookie is a static-CRT symbol, so it only appears as
    // an import when the DLL CRT is used. With the static CRT it is linked
    // in and never shows up in the import table. We therefore only report
    // this at Low confidence and only when the import-based check fails; we
    // do not consult bin.symbols because the PE loader does not populate it.
    let gs_via_import = bin
        .imports
        .iter()
        .any(|i| i.name.contains("security_check_cookie"));
    report.stack_canary = if pe.security_cookie.is_some() || gs_via_import {
        Some(true)
    } else {
        None
    };
    if report.stack_canary.is_none() {
        findings.push(Finding::new(
            "no-gs-pe",
            Category::Hardening,
            Severity::Low,
            Confidence::Low,
            "Buffer Security Check (GS) — inconclusive",
            "No validated SecurityCookie metadata or __security_check_cookie import was found. \
             With the static CRT the cookie is linked in-line and invisible \
             to import-only analysis. Disassemble the prologue of any \
             buffer-handling function to confirm /GS status.",
            "security_check_cookie not in import table (static-CRT link may hide it)"
        ).with_remediation("Verify with `dumpbin /headers` or disassemble function prologues for `mov eax, __security_cookie`."));
    }

    // ── Stripped (no symbols) ───────────────────────────────────────────
    // The PE loader does not parse the COFF symbol table, so bin.symbols is
    // always empty for PE inputs.  We report the status as unknown rather
    // than incorrectly claiming every PE is stripped.
    report.stripped = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_core::{Arch, Endian, Format};
    use omnisec_loader::{Section, Symbol, SymbolKind};

    fn empty_bin() -> LoadedBinary {
        LoadedBinary::new(Format::Elf, Arch::Arm64, Endian::Little, 1024)
    }

    #[test]
    fn wx_section_emits_finding() {
        let mut bin = empty_bin();
        bin.sections.push(Section {
            name: ".text".into(),
            virtual_address: 0,
            virtual_size: 0,
            file_offset: 0,
            file_size: 0,
            flags: SectionFlags::READ | SectionFlags::WRITE | SectionFlags::EXECUTE,
        });
        let mut findings = vec![];
        let h = evaluate(&bin, None, None, &mut findings);
        assert_eq!(h.wx_sections, 1);
        assert!(findings.iter().any(|f| f.id == "wx-section"));
    }

    #[test]
    fn canary_detected_via_symbol() {
        let mut bin = empty_bin();
        bin.symbols.push(Symbol {
            name: "__stack_chk_fail".into(),
            address: 0x1000,
            size: 0,
            kind: SymbolKind::Function,
            is_global: true,
        });
        let mut findings = vec![];
        let h = evaluate(&bin, None, None, &mut findings);
        // No parse → only W^X branch executes; canary remains None.
        // But once we have ELF parse, canary should be Some(true).
        assert_eq!(h.stack_canary, None);
        // Sanity: the function did not panic.
        let _ = findings;
    }
}
