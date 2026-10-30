//! Top-level CLI definition (hand-rolled argument parser, zero deps).

use std::path::PathBuf;

/// Parsed top-level CLI invocation.
#[derive(Debug)]
pub struct Cli {
    /// Increase log verbosity (can be repeated: `-v`, `-vv`, `-vvv`).
    pub verbose: u8,

    /// Emit machine-readable JSON instead of the human-friendly view.
    pub json: bool,

    /// Subcommand to run. If omitted, `info` is assumed and the next
    /// positional argument is treated as the input file.
    pub command: Option<Command>,

    /// Convenience positional: when no subcommand is given, treat as
    /// `omnisec info <FILE>`.
    pub fallback_target: Option<PathBuf>,
}

/// Subcommands.
#[derive(Debug)]
pub enum Command {
    /// Detect format and print a high-level summary of a binary.
    Info {
        /// Path to the binary.
        target: PathBuf,
        /// Force a specific format instead of magic-byte detection.
        format: Option<ForcedFormat>,
    },
    /// Linear-sweep disassemble the executable sections of a binary.
    Disasm {
        /// Path to the binary.
        target: PathBuf,
        /// Limit output to the first N instructions.
        limit: usize,
        /// Disassemble only the section with this name.
        section: Option<String>,
    },
    /// Native security scan: hardening posture, dangerous APIs, malware
    /// indicators, embedded payloads, risk score.
    ///
    /// Designed for the `lib*.so` files extracted from an APK's `lib/`
    /// directory but works on any Linux ELF.
    Scan {
        /// Path to the ELF / `.so` to scan.
        target: PathBuf,
        /// Hide informational findings from the human-readable output
        /// (no effect on JSON).
        no_info: bool,
        /// Filter findings by minimum severity.
        min_severity: MinSeverity,
        /// Optional ML-Aetrium `.anchor.json` database for graph-anchor detection.
        aetrium_anchors: Option<PathBuf>,
        /// PDG neighborhood radius for ML-Aetrium anchor matching.
        aetrium_radius: usize,
        /// Maximum ML-Aetrium findings to emit.
        aetrium_max_findings: usize,
    },
    /// Manage ML-Aetrium HDC vulnerability anchor databases.
    Anchors {
        /// Anchor database operation.
        command: AnchorCommand,
    },
    /// Interactive GDB-like debugger for machine code.
    Debug {
        /// Path to the binary to debug.
        target: PathBuf,
        /// Override entry point address.
        entry: Option<u64>,
    },
    /// Print version + build metadata and exit.
    Version,
}

/// ML-Aetrium anchor database subcommands.
#[derive(Debug)]
pub enum AnchorCommand {
    /// Forge the built-in synthetic vulnerability anchors and write a database file.
    Forge {
        /// Output path for the generated `.anchor.json`; use `-` for stdout.
        output: PathBuf,
        /// Deterministic HDC codebook seed.
        seed: u64,
        /// Exact topology examples generated per vulnerability family.
        examples_per_kind: usize,
        /// Noisy perturbations generated per exact topology example.
        variants_per_example: usize,
        /// Fraction of HV bits flipped for each noisy perturbation.
        noise_ratio: f64,
    },
    /// Inspect an existing anchor database file.
    Inspect {
        /// Path to the `.anchor.json` database.
        database: PathBuf,
    },
}

/// Minimum severity for the human-readable `scan` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinSeverity {
    /// Show informational findings as well.
    Info,
    /// Show low-severity findings and above.
    Low,
    /// Show medium-severity findings and above.
    Medium,
    /// Show only high and critical.
    High,
    /// Show only critical findings.
    Critical,
}

impl MinSeverity {
    /// Convert to the scanner's [`Severity`] enum for direct comparison.
    #[must_use]
    pub fn to_severity(self) -> omnisec_scan_native::Severity {
        match self {
            Self::Info => omnisec_scan_native::Severity::Info,
            Self::Low => omnisec_scan_native::Severity::Low,
            Self::Medium => omnisec_scan_native::Severity::Medium,
            Self::High => omnisec_scan_native::Severity::High,
            Self::Critical => omnisec_scan_native::Severity::Critical,
        }
    }
}

/// User-forceable formats, mirroring [`omnisec_core::Format`] minus the
/// `Unknown` sentinel.
#[derive(Debug, Clone, Copy)]
pub enum ForcedFormat {
    /// Force PE.
    Pe,
    /// Force ELF.
    Elf,
}

impl From<ForcedFormat> for omnisec_core::Format {
    fn from(f: ForcedFormat) -> Self {
        match f {
            ForcedFormat::Pe => Self::Pe,
            ForcedFormat::Elf => Self::Elf,
        }
    }
}

const USAGE: &str = "\
OmniSec - universal binary analysis & exploit platform

USAGE:
    omnisec [OPTIONS] [SUBCOMMAND] [FILE]

OPTIONS:
    -v, --verbose     Increase log verbosity (repeatable: -v, -vv, -vvv)
        --json        Emit machine-readable JSON output
    -h, --help        Print help

SUBCOMMANDS:
    info <FILE>       Detect format and print a high-level summary
        --format <pe|elf>   Force a specific format
    disasm <FILE>     Linear-sweep disassemble executable sections
        --limit <N>           Limit output to the first N instructions (default 64)
        --section <NAME>      Disassemble only this section
    scan <FILE>       Native security scan (hardening, dangerous APIs, risk score)
        --no-info                    Hide informational findings
        --min-severity <LEVEL>       info|low|medium|high|critical (default low)
        --aetrium-anchors <PATH>     ML-Aetrium .anchor.json database
        --aetrium-radius <N>         PDG neighborhood radius (default 2)
        --aetrium-max-findings <N>   Max ML-Aetrium findings (default 32)
    anchors           Manage ML-Aetrium HDC vulnerability anchor databases
      forge [-o,--output <PATH>] [--seed <N>] [--examples-per-kind <N>]
            [--variants-per-example <N>] [--noise-ratio <F>]
      inspect <DATABASE>
    debug <FILE>      Interactive GDB-like debugger
        --entry <ADDR>   Override entry point (hex or decimal)
    version           Print version + build metadata

If no subcommand is given, `info <FILE>` is assumed.
";

fn parse_hex_u64(s: &str) -> Result<u64, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| format!("invalid hex: {e}"))
    } else {
        s.parse().map_err(|e| format!("invalid number: {e}"))
    }
}

fn parse_num<T: std::str::FromStr>(s: &str, what: &str) -> Result<T, String> {
    s.parse().map_err(|_| format!("invalid {what}: {s}"))
}

impl Cli {
    /// Parse CLI arguments (without the program name).
    ///
    /// # Errors
    /// Returns a human-readable message for unknown flags, missing values,
    /// or `--help` (printed to stdout as part of the message).
    pub fn parse_from(args: &[String]) -> Result<Self, String> {
        let mut verbose: u8 = 0;
        let mut json = false;
        let mut it = args.iter();

        let mut pending_command: Option<Command> = None;
        let mut fallback_target: Option<PathBuf> = None;

        while let Some(arg) = it.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    println!("{USAGE}");
                    std::process::exit(0);
                }
                "-v" | "--verbose" => {
                    verbose = verbose.saturating_add(1);
                }
                "--json" => json = true,
                "--version" => pending_command = Some(Command::Version),
                "info" | "disasm" | "scan" | "anchors" | "debug" | "version" => {
                    let cmd = match arg.as_str() {
                        "info" => parse_info(&mut it)?,
                        "disasm" => parse_disasm(&mut it)?,
                        "scan" => parse_scan(&mut it)?,
                        "anchors" => parse_anchors(&mut it)?,
                        "debug" => parse_debug(&mut it)?,
                        _ => Command::Version,
                    };
                    pending_command = Some(cmd);
                    break;
                }
                s if s.starts_with('-') => {
                    return Err(format!("unknown option: {s} (try `omnisec --help`)"));
                }
                s => {
                    fallback_target = Some(PathBuf::from(s));
                    break;
                }
            }
        }

        // Remaining positionals after the fallback become an implicit `info`.
        if pending_command.is_none() {
            if let Some(target) = fallback_target.take() {
                let format = parse_info_flags(&mut it)?;
                pending_command = Some(Command::Info { target, format });
            }
        }

        Ok(Self {
            verbose,
            json,
            command: pending_command,
            fallback_target,
        })
    }

    /// Parse arguments from `std::env` (mirrors clap's `Parser::parse`).
    ///
    /// # Panics
    /// Exits the process on invalid arguments (clap-parity behaviour).
    pub fn parse() -> Self {
        let args: Vec<String> = std::env::args().skip(1).collect();
        match Self::parse_from(&args) {
            Ok(cli) => cli,
            Err(msg) => {
                eprintln!("{msg}");
                std::process::exit(2);
            }
        }
    }
}

type ArgsIt<'a> = std::slice::Iter<'a, String>;

fn parse_info(it: &mut ArgsIt<'_>) -> Result<Command, String> {
    let target = next_positional(it, "info")?;
    let format = parse_info_flags(it)?;
    Ok(Command::Info { target, format })
}

fn parse_info_flags(it: &mut ArgsIt<'_>) -> Result<Option<ForcedFormat>, String> {
    let mut format = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--format" => {
                let v = next_value(it, "--format")?;
                format = Some(match v.as_str() {
                    "pe" => ForcedFormat::Pe,
                    "elf" => ForcedFormat::Elf,
                    other => return Err(format!("invalid --format: {other} (pe|elf)")),
                });
            }
            other => return Err(format!("unexpected argument for info: {other}")),
        }
    }
    Ok(format)
}

fn parse_disasm(it: &mut ArgsIt<'_>) -> Result<Command, String> {
    let target = next_positional(it, "disasm")?;
    let mut limit = 64usize;
    let mut section = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--limit" => limit = parse_num(&next_value(it, "--limit")?, "limit")?,
            "--section" => section = Some(next_value(it, "--section")?),
            other => return Err(format!("unexpected argument for disasm: {other}")),
        }
    }
    Ok(Command::Disasm {
        target,
        limit,
        section,
    })
}

fn parse_scan(it: &mut ArgsIt<'_>) -> Result<Command, String> {
    let target = next_positional(it, "scan")?;
    let mut no_info = false;
    let mut min_severity = MinSeverity::Low;
    let mut aetrium_anchors = None;
    let mut aetrium_radius = 2usize;
    let mut aetrium_max_findings = 32usize;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--no-info" => no_info = true,
            "--min-severity" => {
                let v = next_value(it, "--min-severity")?;
                min_severity = match v.as_str() {
                    "info" => MinSeverity::Info,
                    "low" => MinSeverity::Low,
                    "medium" => MinSeverity::Medium,
                    "high" => MinSeverity::High,
                    "critical" => MinSeverity::Critical,
                    other => return Err(format!("invalid --min-severity: {other}")),
                };
            }
            "--aetrium-anchors" => {
                aetrium_anchors = Some(PathBuf::from(next_value(it, "--aetrium-anchors")?));
            }
            "--aetrium-radius" => {
                aetrium_radius = parse_num(&next_value(it, "--aetrium-radius")?, "radius")?;
            }
            "--aetrium-max-findings" => {
                aetrium_max_findings =
                    parse_num(&next_value(it, "--aetrium-max-findings")?, "max findings")?;
            }
            other => return Err(format!("unexpected argument for scan: {other}")),
        }
    }
    Ok(Command::Scan {
        target,
        no_info,
        min_severity,
        aetrium_anchors,
        aetrium_radius,
        aetrium_max_findings,
    })
}

fn parse_anchors(it: &mut ArgsIt<'_>) -> Result<Command, String> {
    let sub = it
        .next()
        .ok_or("anchors needs a subcommand (forge|inspect)")?;
    match sub.as_str() {
        "forge" => {
            let mut output = PathBuf::from("configs/aetrium/default.anchor.json");
            let mut seed = 42u64;
            let mut examples_per_kind = 3usize;
            let mut variants_per_example = 8usize;
            let mut noise_ratio = 0.025f64;
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "-o" | "--output" => output = PathBuf::from(next_value(it, "--output")?),
                    "--seed" => seed = parse_num(&next_value(it, "--seed")?, "seed")?,
                    "--examples-per-kind" => {
                        examples_per_kind = parse_num(
                            &next_value(it, "--examples-per-kind")?,
                            "examples per kind",
                        )?;
                    }
                    "--variants-per-example" => {
                        variants_per_example = parse_num(
                            &next_value(it, "--variants-per-example")?,
                            "variants per example",
                        )?;
                    }
                    "--noise-ratio" => {
                        noise_ratio = parse_num(&next_value(it, "--noise-ratio")?, "noise ratio")?;
                    }
                    other => return Err(format!("unexpected argument for anchors forge: {other}")),
                }
            }
            Ok(Command::Anchors {
                command: AnchorCommand::Forge {
                    output,
                    seed,
                    examples_per_kind,
                    variants_per_example,
                    noise_ratio,
                },
            })
        }
        "inspect" => {
            let database = next_positional(it, "anchors inspect")?;
            if let Some(arg) = it.next() {
                return Err(format!("unexpected argument for anchors inspect: {arg}"));
            }
            Ok(Command::Anchors {
                command: AnchorCommand::Inspect { database },
            })
        }
        other => Err(format!(
            "unknown anchors subcommand: {other} (forge|inspect)"
        )),
    }
}

fn parse_debug(it: &mut ArgsIt<'_>) -> Result<Command, String> {
    let target = next_positional(it, "debug")?;
    let mut entry = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--entry" => entry = Some(parse_hex_u64(&next_value(it, "--entry")?)?),
            other => return Err(format!("unexpected argument for debug: {other}")),
        }
    }
    Ok(Command::Debug { target, entry })
}

fn next_positional(it: &mut ArgsIt<'_>, cmd: &str) -> Result<PathBuf, String> {
    match it.next() {
        Some(v) if !v.starts_with('-') => Ok(PathBuf::from(v)),
        Some(v) => Err(format!("{cmd}: expected a file path, got option {v}")),
        None => Err(format!("{cmd}: missing <FILE> argument")),
    }
}

fn next_value(it: &mut ArgsIt<'_>, flag: &str) -> Result<String, String> {
    it.next()
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

impl Cli {
    /// Run the CLI. Returns the typed `Result` so `main` can render
    /// errors uniformly.
    pub fn run(self) -> crate::error::Result<()> {
        // Default subcommand: if the user wrote `omnisec foo.exe`, treat as info.
        let cmd = match (self.command, self.fallback_target) {
            (Some(c), _) => c,
            (None, Some(target)) => Command::Info {
                target,
                format: None,
            },
            (None, None) => {
                // No subcommand and no positional => point the user at help.
                crate::bail!("no input file. Try `omnisec info <FILE>` or `omnisec --help`.");
            }
        };

        match cmd {
            Command::Info { target, format } => {
                crate::commands::run_info(&target, format.map(Into::into), self.json)
            }
            Command::Disasm {
                target,
                limit,
                section,
            } => crate::commands::run_disasm(&target, limit, section.as_deref(), self.json),
            Command::Scan {
                target,
                no_info,
                min_severity,
                aetrium_anchors,
                aetrium_radius,
                aetrium_max_findings,
            } => crate::commands::run_scan(
                &target,
                self.json,
                no_info,
                min_severity.to_severity(),
                aetrium_anchors.as_deref(),
                aetrium_radius,
                aetrium_max_findings,
            ),
            Command::Anchors { command } => match command {
                AnchorCommand::Forge {
                    output,
                    seed,
                    examples_per_kind,
                    variants_per_example,
                    noise_ratio,
                } => crate::commands::run_anchors_forge(
                    &output,
                    seed,
                    examples_per_kind,
                    variants_per_example,
                    noise_ratio,
                    self.json,
                ),
                AnchorCommand::Inspect { database } => {
                    crate::commands::run_anchors_inspect(&database, self.json)
                }
            },
            Command::Debug { target, entry } => crate::commands::run_debug(&target, entry),
            Command::Version => {
                crate::commands::run_version(self.json);
                Ok(())
            }
        }
    }
}
