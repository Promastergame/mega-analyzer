//! Subcommand implementations.

use std::path::Path;

use omnisec_core::{Arch, Format, detect_format};
use omnisec_disasm::linear_sweep;
use omnisec_hdc::{AnchorForge, AnchorStore, ForgeConfig};
use omnisec_loader::{LoadedBinary, SectionFlags};
use omnisec_scan_native::{AetriumScanConfig, Severity};

use crate::ansi::Stylize;
use crate::bail;
use crate::error::{Result, ResultExt};
use crate::{display, load};

/// `omnisec info <FILE>` — load + summarise.
pub fn run_info(target: &Path, force: Option<Format>, json: bool) -> Result<()> {
    let bin = load::open_and_dispatch(target, force)?;
    if json {
        emit_json(&bin)?;
    } else {
        display::render_info(&bin);
    }
    Ok(())
}

/// `omnisec disasm <FILE>` — linear-sweep code sections.
pub fn run_disasm(
    target: &Path,
    limit: usize,
    section_filter: Option<&str>,
    json: bool,
) -> Result<()> {
    let bin = load::open_and_dispatch(target, None)?;
    if !matches!(bin.arch, Arch::X86 | Arch::X86_64) {
        bail!(
            "disasm: arch {} is not yet supported (Phase 1 = x86 / x86_64 only)",
            bin.arch
        );
    }

    let bytes =
        std::fs::read(target).context(format!("re-reading '{}' for disasm", target.display()))?;

    let mut total_emitted = 0usize;
    let json_obj = if json {
        Some(omnisec_json::JsonValue::Array(Vec::new()))
    } else {
        None
    };
    let mut json_arr: Vec<omnisec_json::JsonValue> = Vec::new();

    for sec in &bin.sections {
        if !sec.flags.contains(SectionFlags::EXECUTE) {
            continue;
        }
        if let Some(name) = section_filter
            && sec.name != name
        {
            continue;
        }
        let off = sec.file_offset as usize;
        let len = sec.file_size as usize;
        if off >= bytes.len() {
            continue;
        }
        let end = off.saturating_add(len).min(bytes.len());
        let chunk = &bytes[off..end];

        let insts = linear_sweep(bin.arch, chunk, sec.virtual_address);
        if !json {
            println!(
                "\n{} {}  {:#x}..{:#x}  ({} bytes)",
                "==".cyan(),
                sec.name.bright_white().bold(),
                sec.virtual_address,
                sec.virtual_address + sec.virtual_size,
                sec.virtual_size,
            );
        }

        for ins in insts.iter().take(limit.saturating_sub(total_emitted)) {
            if json {
                json_arr.push(omnisec_json::json!({
                    "section": sec.name,
                    "address": format!("0x{:x}", ins.address),
                    "size": ins.size,
                    "opcode": ins.opcode,
                    "mnemonic": ins.mnemonic,
                    "raw": ins.raw,
                }));
            } else {
                println!(
                    "  {:#018x}  {:<8} {}",
                    ins.address,
                    format_raw(&ins.raw),
                    ins.mnemonic.as_deref().unwrap_or("?"),
                );
            }
            total_emitted += 1;
            if total_emitted >= limit {
                break;
            }
        }
        if total_emitted >= limit {
            break;
        }
    }

    if let Some(_arr) = json_obj {
        println!("{}", omnisec_json::to_json_pretty(&json_arr));
    } else if total_emitted == 0 {
        eprintln!(
            "no executable sections decoded (matched filter: {:?})",
            section_filter
        );
    }

    Ok(())
}

/// `omnisec scan <FILE>` — full native security scan.
pub fn run_scan(
    target: &Path,
    json: bool,
    no_info: bool,
    min_severity: Severity,
    aetrium_anchors: Option<&Path>,
    aetrium_radius: usize,
    aetrium_max_findings: usize,
) -> Result<()> {
    let bytes = std::fs::read(target).context(format!("reading '{}'", target.display()))?;
    if bytes.is_empty() {
        bail!("'{}' is empty", target.display());
    }

    let format = detect_format(&bytes);
    if format != Format::Elf && format != Format::Pe {
        bail!("scan: only ELF and PE are supported — try a libfoo.so or a Windows driver (.sys)");
    }

    let bin = load::open_and_dispatch(target, None)?;

    let anchor_store = if let Some(path) = aetrium_anchors {
        let anchor_bytes = std::fs::read(path).context(format!(
            "reading Aetrium anchor database '{}'",
            path.display()
        ))?;
        Some(AnchorStore::from_json_slice(&anchor_bytes).context(format!(
            "parsing Aetrium anchor database '{}'",
            path.display()
        ))?)
    } else {
        None
    };

    let report = if let Some(store) = &anchor_store {
        let mut config = AetriumScanConfig::new(store);
        config.radius = aetrium_radius;
        config.max_findings = aetrium_max_findings;
        omnisec_scan_native::scan_with_aetrium(&bin, &bytes, &config)
            .context(format!("scanning '{}' with ML-Aetrium", target.display()))?
    } else {
        omnisec_scan_native::scan(&bin, &bytes)
            .context(format!("scanning '{}'", target.display()))?
    };

    if json {
        println!("{}", omnisec_json::to_json_pretty(&report));
    } else {
        display::render_scan(&report, no_info, min_severity);
    }
    Ok(())
}

/// `omnisec anchors forge` — generate the built-in ML-Aetrium anchor database.
pub fn run_anchors_forge(
    output: &Path,
    seed: u64,
    examples_per_kind: usize,
    variants_per_example: usize,
    noise_ratio: f64,
    json: bool,
) -> Result<()> {
    let config = ForgeConfig {
        seed,
        examples_per_kind,
        variants_per_example,
        noise_ratio,
    };
    let mut forge = AnchorForge::with_config(config);
    let store = forge.build_default_store();
    let bytes = store.to_json_bytes();

    let wrote_stdout = output == Path::new("-");
    if wrote_stdout {
        println!("{}", std::str::from_utf8(&bytes)?);
    } else {
        if let Some(parent) = output.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).context(format!(
                "creating anchor output directory '{}'",
                parent.display()
            ))?;
        }
        std::fs::write(output, &bytes)
            .context(format!("writing anchor database '{}'", output.display()))?;
    }

    if json && !wrote_stdout {
        println!(
            "{}",
            omnisec_json::to_json_pretty(&anchor_summary(&store, Some(output)))
        );
    } else if !json && !wrote_stdout {
        println!(
            "{} forged {} ML-Aetrium anchors -> {}",
            "ok".green().bold(),
            store.len(),
            output.display()
        );
    }

    Ok(())
}

/// `omnisec anchors inspect` — summarize an ML-Aetrium anchor database.
pub fn run_anchors_inspect(database: &Path, json: bool) -> Result<()> {
    let bytes = std::fs::read(database)
        .context(format!("reading anchor database '{}'", database.display()))?;
    let store = AnchorStore::from_json_slice(&bytes)
        .context(format!("parsing anchor database '{}'", database.display()))?;

    if json {
        println!(
            "{}",
            omnisec_json::to_json_pretty(&anchor_summary(&store, Some(database)))
        );
    } else {
        println!(
            "{}  {} anchors  schema v{}",
            "ML-Aetrium anchors".bright_cyan().bold(),
            store.len(),
            store.metadata().schema_version
        );
        println!("  file:      {}", database.display());
        println!("  engine:    {}", store.metadata().engine.cyan());
        println!("  generator: {}", store.metadata().generator.cyan());
        if let Some(seed) = store.metadata().codebook_seed {
            println!("  seed:      {seed}");
        }
        println!("\n  {}", "Anchors".underline());
        for anchor in store.iter() {
            println!(
                "    {:<24} severity={:.2} threshold={:.3} examples={}",
                anchor.name.bright_white(),
                anchor.severity,
                anchor.threshold,
                anchor.example_count
            );
        }
    }

    Ok(())
}

/// `omnisec debug <FILE>` — interactive GDB-like debugger.
pub fn run_debug(target: &Path, entry: Option<u64>) -> Result<()> {
    use omnisec_debugger::{DebuggerSession, SessionConfig};

    let mut config = SessionConfig::default();
    if let Some(e) = entry {
        config.entry_point = Some(e);
    }

    let mut session = DebuggerSession::from_file(target, config)
        .map_err(|e| crate::error::Error::msg(format!("debug: {e}")))?;

    omnisec_debugger::repl::run(&mut session)
        .map_err(|e| crate::error::Error::msg(format!("debug repl: {e}")))?;

    Ok(())
}

/// `omnisec version` — print build info.
pub fn run_version(json: bool) {
    let v = omnisec_json::json!({
        "name": "omnisec",
        "version": env!("CARGO_PKG_VERSION"),
        "rustc": option_env!("RUSTC_VERSION").unwrap_or("unknown"),
        "phase": "1",
    });
    if json {
        println!("{}", omnisec_json::to_json_pretty(&v));
    } else {
        println!(
            "OmniSec v{}  (Phase 1 — Universal Loader + IR + x86 lifter)",
            env!("CARGO_PKG_VERSION")
        );
    }
}

fn anchor_summary(store: &AnchorStore, path: Option<&Path>) -> omnisec_json::JsonValue {
    omnisec_json::json!({
        "path": path.map(|p| p.display().to_string()),
        "schema_version": store.metadata().schema_version,
        "engine": &store.metadata().engine,
        "generator": &store.metadata().generator,
        "codebook_seed": store.metadata().codebook_seed,
        "examples_per_kind": store.metadata().examples_per_kind,
        "variants_per_example": store.metadata().variants_per_example,
        "noise_ratio": store.metadata().noise_ratio,
        "anchor_count": store.len(),
        "anchors": store.iter().map(|anchor| omnisec_json::json!({
            "name": &anchor.name,
            "description": &anchor.description,
            "threshold": anchor.threshold,
            "severity": anchor.severity,
            "example_count": anchor.example_count,
            "motifs": &anchor.motifs,
        })).collect::<Vec<_>>(),
    })
}

/// JSON-emit a [`LoadedBinary`].
fn emit_json(bin: &LoadedBinary) -> Result<()> {
    let s = omnisec_json::to_json_pretty(bin);
    println!("{s}");
    Ok(())
}

/// Hex-render up to 8 raw bytes as `aa bb cc dd…`.
fn format_raw(raw: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(24);
    for (i, b) in raw.iter().take(7).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(&mut s, "{b:02x}");
    }
    if raw.len() > 7 {
        s.push('…');
    }
    s
}
