//! Pretty-printing helpers for the human-friendly subcommands.

use omnisec_loader::{LoadedBinary, SectionFlags};
use omnisec_scan_native::{
    Category, Confidence, Finding, PeKind, RelroLevel, ScanReport, Severity, Verdict,
};

use crate::ansi::{Sgr, Stylize, styles};

/// Print a high-level summary of `bin` to stdout.
pub fn render_info(bin: &LoadedBinary) {
    println!(
        "{}  {} ({}) — {} bytes",
        "OmniSec".bright_cyan(),
        bin.format.name().bright_white(),
        bin.arch.name().bright_yellow(),
        bin.raw_size,
    );

    println!("  endian:        {}", bin.endian.name().cyan());
    if let Some(b) = bin.bitness {
        println!("  bitness:       {}", b.cyan());
    }
    if let Some(ep) = bin.entry_point {
        println!("  entry_point:   {}", format!("0x{ep:x}").green());
    }
    if let Some(base) = bin.base_address {
        println!("  base_address:  {}", format!("0x{base:x}").green());
    }

    println!(
        "  sections:      {}  ({} executable, {} bytes of code)",
        bin.sections.len(),
        bin.code_section_count(),
        bin.code_bytes(),
    );
    println!("  symbols:       {}", bin.symbols.len());
    println!("  imports:       {}", bin.imports.len());
    println!("  exports:       {}", bin.exports.len());

    if !bin.notes.is_empty() {
        println!("\n  notes:");
        for n in &bin.notes {
            println!("    • {n}");
        }
    }

    if !bin.sections.is_empty() {
        println!("\n  {}", "Sections".underline());
        println!("  {:<24} {:>16} {:>10} flags", "name", "vaddr", "size");
        for s in &bin.sections {
            println!(
                "  {:<24} {:>#16x} {:>10} {}",
                truncate(&s.name, 24),
                s.virtual_address,
                s.virtual_size,
                flag_string(s.flags),
            );
        }
    }

    if !bin.imports.is_empty() {
        println!("\n  {}", "Imports (first 16)".underline());
        for imp in bin.imports.iter().take(16) {
            println!("    {} :: {}", imp.library, imp.name);
        }
        if bin.imports.len() > 16 {
            println!("    … {} more", bin.imports.len() - 16);
        }
    }

    if !bin.exports.is_empty() {
        println!("\n  {}", "Exports (first 16)".underline());
        for exp in bin.exports.iter().take(16) {
            let suffix = if exp.is_forwarder {
                format!(" -> {}", exp.forward_target.as_deref().unwrap_or("?"))
            } else {
                String::new()
            };
            println!("    {} @ {:#x}{suffix}", exp.name, exp.address);
        }
        if bin.exports.len() > 16 {
            println!("    … {} more", bin.exports.len() - 16);
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn flag_string(f: SectionFlags) -> String {
    let mut out = String::with_capacity(8);
    out.push(if f.contains(SectionFlags::READ) {
        'R'
    } else {
        '-'
    });
    out.push(if f.contains(SectionFlags::WRITE) {
        'W'
    } else {
        '-'
    });
    out.push(if f.contains(SectionFlags::EXECUTE) {
        'X'
    } else {
        '-'
    });
    if f.contains(SectionFlags::BSS) {
        out.push_str(" BSS");
    }
    if f.contains(SectionFlags::DISCARDABLE) {
        out.push_str(" DSC");
    }
    out
}

/// Render a [`ScanReport`] as a human-friendly multi-section report.
pub fn render_scan(report: &ScanReport, no_info: bool, min: Severity) {
    println!(
        "{}  {} ({})  {} bytes  scanner v{}",
        "OmniSec scan".bright_cyan().bold(),
        report.target_format.name().bright_white(),
        report.target_arch.name().bright_yellow(),
        report.target_size,
        report.scanner_version.dimmed(),
    );
    println!();

    let profile = &report.target_profile;
    let abi = profile
        .android_abi
        .map(|abi| format!(" / {}", abi.name()))
        .unwrap_or_default();

    let kind_name = if let Some(ek) = profile.elf_kind {
        ek.name()
    } else if let Some(pk) = profile.pe_kind {
        match pk {
            PeKind::Executable => "executable",
            PeKind::Dll => "dll",
            PeKind::Driver => "driver",
            PeKind::Unknown => "unknown_pe",
        }
    } else {
        "unknown"
    };

    println!(
        "  target: {}{}   JNI exports: {}   JNI_OnLoad: {}",
        kind_name.cyan(),
        abi.cyan(),
        profile.jni_exports,
        yes_no_bool(profile.has_jni_onload),
    );
    if let Some(name) = &profile.internal_name {
        println!("  name:   {}", name.cyan());
    }
    if !profile.dependencies.is_empty() {
        println!(
            "  imports: {}",
            truncate(&profile.dependencies.join(", "), 96).dimmed(),
        );
    }

    // ── Verdict + score header ──────────────────────────────────────────
    let (label, style) = verdict_label_and_style(report.verdict);
    println!(
        "  {} {}   risk score: {}/100",
        "verdict:".bold(),
        label.style(style).bold(),
        score_colored(report.score),
    );

    // ── Hardening table ─────────────────────────────────────────────────
    let h = &report.hardening;
    println!(
        "\n  {}  ({}/{} mitigations enabled)",
        "Hardening".underline(),
        h.enabled_count(),
        omnisec_scan_native::HardeningReport::total_probes(),
    );
    println!("    {:<14} {}", "NX:", yes_no(h.nx));
    println!("    {:<14} {}", "PIE:", yes_no(h.pie));
    println!("    {:<14} {}", "RELRO:", relro_str(h.relro));
    println!("    {:<14} {}", "Stack canary:", yes_no(h.stack_canary));
    println!("    {:<14} {}", "FORTIFY:", yes_no(h.fortify_source));
    println!("    {:<14} {}", "Stripped:", yes_no(h.stripped));
    if h.wx_sections > 0 {
        println!(
            "    {:<14} {}",
            "W^X violations:",
            format!("{} section(s)", h.wx_sections).red().bold(),
        );
    }
    if let Some(p) = &h.rpath {
        println!("    {:<14} {}", "DT_RPATH:", p.yellow());
    }
    if let Some(p) = &h.runpath {
        println!("    {:<14} {}", "DT_RUNPATH:", p.yellow());
    }

    // ── Findings ────────────────────────────────────────────────────────
    let visible: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| !no_info || f.severity != Severity::Info)
        .filter(|f| severity_at_least(f.severity, min))
        .collect();

    println!(
        "\n  {} ({} shown / {} total)",
        "Findings".underline(),
        visible.len(),
        report.findings.len(),
    );

    if visible.is_empty() {
        println!("    no findings at the requested severity threshold.");
    } else {
        for f in &visible {
            print_finding(f);
        }
    }

    // ── Severity breakdown ──────────────────────────────────────────────
    println!("\n  {}", "Severity breakdown".underline());
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let n = report.count_at(sev);
        if n == 0 {
            continue;
        }
        let (lbl, st) = severity_label_and_style(sev);
        println!("    {:<8}  {}", lbl.style(st).bold(), n);
    }

    // ── Category breakdown ──────────────────────────────────────────────
    let cats = [
        Category::Hardening,
        Category::Vulnerability,
        Category::AntiAnalysis,
        Category::DynamicCode,
        Category::SuspiciousBehavior,
        Category::EmbeddedPayload,
        Category::NetworkIndicator,
        Category::Info,
    ];
    let any = cats.iter().any(|c| report.count_in(*c) > 0);
    if any {
        println!("\n  {}", "Category breakdown".underline());
        for c in &cats {
            let n = report.count_in(*c);
            if n == 0 {
                continue;
            }
            println!("    {:<22} {}", c.slug(), n);
        }
    }
}

/// Print a single [`Finding`] in a compact 3-line block.
fn print_finding(f: &Finding) {
    let (sev_lbl, sev_style) = severity_label_and_style(f.severity);
    let (conf_lbl, _) = confidence_label_and_style(f.confidence);

    let cwe = f.cwe.clone().unwrap_or_default();
    let off = f
        .file_offset
        .map(|o| format!("@0x{o:x}"))
        .unwrap_or_default();

    println!(
        "    [{}] {}  {}  {}  {}",
        sev_lbl.style(sev_style).bold(),
        f.title.bright_white(),
        cwe.dimmed(),
        f.id.dimmed(),
        off.dimmed(),
    );
    println!(
        "       {} {}  evidence: {}",
        "•".dimmed(),
        format!("conf={conf_lbl}").dimmed(),
        f.evidence.cyan(),
    );
    if let Some(ref rem) = f.remediation {
        println!("       {} fix: {}", "→".green(), rem.dimmed());
    }
}

fn yes_no(v: Option<bool>) -> String {
    match v {
        Some(true) => "yes".green().to_string(),
        Some(false) => "no".red().bold().to_string(),
        None => "?".dimmed().to_string(),
    }
}

fn yes_no_bool(v: bool) -> String {
    if v {
        "yes".green().to_string()
    } else {
        "no".dimmed().to_string()
    }
}

fn relro_str(r: RelroLevel) -> String {
    match r {
        RelroLevel::Full => "full".green().to_string(),
        RelroLevel::Partial => "partial".yellow().to_string(),
        RelroLevel::None => "none".red().bold().to_string(),
    }
}

fn score_colored(s: u32) -> String {
    match s {
        0..=14 => s.to_string().green().to_string(),
        15..=39 => s.to_string().bright_green().to_string(),
        40..=69 => s.to_string().yellow().to_string(),
        70..=89 => s.to_string().red().to_string(),
        _ => s.to_string().red().bold().to_string(),
    }
}

fn verdict_label_and_style(v: Verdict) -> (&'static str, Sgr) {
    match v {
        Verdict::Clean => ("CLEAN", styles::green()),
        Verdict::Low => ("LOW", styles::bright_green()),
        Verdict::Medium => ("MEDIUM", styles::yellow()),
        Verdict::High => ("HIGH", styles::red()),
        Verdict::Critical => ("CRITICAL", styles::red_bold()),
    }
}

fn severity_label_and_style(s: Severity) -> (&'static str, Sgr) {
    match s {
        Severity::Info => (s.tag(), styles::dimmed()),
        Severity::Low => (s.tag(), styles::bright_green()),
        Severity::Medium => (s.tag(), styles::yellow()),
        Severity::High => (s.tag(), styles::red()),
        Severity::Critical => (s.tag(), styles::red_bold()),
    }
}

fn confidence_label_and_style(c: Confidence) -> (&'static str, Sgr) {
    match c {
        Confidence::Low => ("low", styles::dimmed()),
        Confidence::Medium => ("med", styles::new()),
        Confidence::High => ("high", styles::bold()),
    }
}

fn severity_at_least(actual: Severity, min: Severity) -> bool {
    severity_rank(actual) >= severity_rank(min)
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}
