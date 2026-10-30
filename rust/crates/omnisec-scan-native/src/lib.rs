//! OmniSec native (ELF / `.so`) security scanner.
//!
//! Performs **purely static, read-only** analysis of a native ELF binary
//! (typically the `lib*.so` files extracted from an APK's `lib/` directory)
//! and produces a [`ScanReport`] describing:
//!
//! 1. **Hardening posture** — NX, PIE, RELRO, stack canary, `FORTIFY_SOURCE`,
//!    stripped symbols, `RPATH`/`RUNPATH`. Tells you what compile-time
//!    mitigations the author left on (or off).
//!
//! 2. **Vulnerability surface** — calls to historically dangerous CRT
//!    functions (`strcpy`, `sprintf`, `gets`, `system`, …) tagged with
//!    their CWE IDs. Pattern-level, not exploit-level: we *flag*, not
//!    *generate payloads*.
//!
//! 3. **Malware / abuse indicators** — anti-debugging primitives, emulator
//!    fingerprinting strings, suspicious dynamic-loading combos, embedded
//!    payloads, high-entropy blobs (likely crypted strings), URLs/IPs/Tor
//!    addresses inside the binary.
//!
//! 4. **Aggregate risk score** — weighted 0-100 with a categorical
//!    [`Verdict`].
//!
//! ## Design
//!
//! The scanner takes a [`LoadedBinary`] (already parsed by
//! `omnisec-loader-elf`) **plus** the raw bytes — it re-parses with the
//! in-house `elfparse`/`peparse` modules to access format-specific bits
//! (program headers, dynamic tags) that the universal loader deliberately
//! abstracts away.
//!
//! The scanner is **zero-network**: nothing is exfiltrated and no remote
//! signature DB is contacted. Detection tables are baked into the binary
//! at compile time. All logic is safe Rust except the C-ABI bridge in
//! [`ffi`], which is inherently `unsafe` and quarantined to that module —
//! hence the crate opts into `allow(unsafe_code)` rather than claiming to
//! forbid it outright.

#![deny(missing_docs)]
#![allow(unsafe_code)]

mod aetrium;
mod control_flow;
mod entropy;
pub mod ffi;
mod findings;
mod hardening;
mod limits;
mod malware;
pub mod ml_features;
mod packers;
mod profile;
mod report;
mod sarif;
mod score;
mod strings;
mod util;
mod vulns;

pub use aetrium::AetriumScanConfig;
pub use findings::{Category, Confidence, Finding, Severity};
pub use ml_features::MlFeatures;
pub use profile::{AndroidAbi, ElfKind, PeKind, TargetProfile};
pub use report::{HardeningReport, RelroLevel, ScanReport};
pub use sarif::to_sarif;
pub use score::Verdict;

use omnisec_core::{Format, Result};
use omnisec_loader::LoadedBinary;
use omnisec_loader_elf::elfparse::parse_elf;
use omnisec_loader_pe::peparse::parse_pe;

/// Run the full native-binary scan.
///
/// # Inputs
///
/// - `bin`  — already-parsed [`LoadedBinary`] from `omnisec-loader-elf`.
/// - `bytes` — the original on-disk bytes (re-parsed for ELF-specific
///   data the universal loader does not expose, e.g. `PT_GNU_STACK`).
///
/// # Errors
///
/// Returns [`omnisec_core::Error::Unsupported`] if `bin.format` is not
/// [`Format::Elf`].
pub fn scan(bin: &LoadedBinary, bytes: &[u8]) -> Result<ScanReport> {
    scan_internal(bin, bytes, None)
}

/// Run the full native-binary scan with ML-Aetrium graph-anchor detection.
///
/// This keeps the existing signature scanner intact, then adds opt-in
/// topology-aware HDC matching over lifted executable sections.
pub fn scan_with_aetrium(
    bin: &LoadedBinary,
    bytes: &[u8],
    aetrium: &AetriumScanConfig<'_>,
) -> Result<ScanReport> {
    scan_internal(bin, bytes, Some(aetrium))
}

fn scan_internal(
    bin: &LoadedBinary,
    bytes: &[u8],
    aetrium: Option<&AetriumScanConfig<'_>>,
) -> Result<ScanReport> {
    if bin.format != Format::Elf && bin.format != Format::Pe {
        return Err(omnisec_core::Error::unsupported(format!(
            "scan-native: only ELF and PE supported, got {}",
            bin.format
        )));
    }

    let elf = if bin.format == Format::Elf {
        parse_elf(bytes).ok()
    } else {
        None
    };

    let pe = if bin.format == Format::Pe {
        parse_pe(bytes).ok()
    } else {
        None
    };

    let mut findings: Vec<Finding> = Vec::with_capacity(64);

    // Emit a parse-failure warning when structural parsing fails so that
    // the verdict is never Clean on an opaque/anti-analysis input.  All other
    // scan passes still run over the raw bytes (UPX magic, strings, entropy).
    let parse_failed =
        (bin.format == Format::Elf && elf.is_none()) || (bin.format == Format::Pe && pe.is_none());
    if parse_failed {
        findings.push(
            Finding::new(
                "parse-failed",
                Category::SuspiciousBehavior,
                Severity::Medium,
                Confidence::High,
                "Binary could not be fully parsed",
                format!(
                    "The {:?} binary failed structural parsing (malformed headers or \
                     unsupported variant). Hardening mitigations cannot be assessed. \
                     Manual inspection is required — anti-analysis binaries deliberately \
                     corrupt headers to defeat static tools.",
                    bin.format
                ),
                "structural parse returned None",
            )
            .with_remediation(
                "Dump the binary at runtime or use a hex editor to inspect the header manually.",
            ),
        );
    }

    // 1. Hardening — populates the dedicated HardeningReport AND emits
    //    a finding for every missing mitigation. Runs first and on the
    //    calling thread because its `HardeningReport` feeds the score.
    let hardening = hardening::evaluate(bin, elf.as_ref(), pe.as_ref(), &mut findings);

    // 2-4. The remaining probes are mutually independent — each only reads the
    // (immutable) parsed binary + raw bytes and produces its own findings. We
    // fan them out across the rayon pool and concatenate the buckets in a
    // FIXED order afterwards, so the report stays byte-for-byte deterministic
    // regardless of thread scheduling.
    let mut bucket_vulns = Vec::new();
    let mut bucket_malware = Vec::new();
    let mut bucket_strings = Vec::new();
    let mut bucket_entropy = Vec::new();
    let mut bucket_cflow = Vec::new();
    let mut bucket_packers = Vec::new();

    std::thread::scope(|s| {
        s.spawn(|| vulns::scan_imports(bin, &mut bucket_vulns));
        s.spawn(|| {
            malware::scan_imports(bin, &mut bucket_malware);
            malware::scan_symbols(bin, &mut bucket_malware);
            malware::scan_exports(bin, &mut bucket_malware);
        });
        s.spawn(|| strings::scan(bin, bytes, &mut bucket_strings));
        s.spawn(|| {
            if let Some(ref elf) = elf {
                entropy::scan_elf(bytes, elf, &mut bucket_entropy);
            }
            if let Some(ref pe) = pe {
                entropy::scan_pe(bytes, pe, &mut bucket_entropy);
            }
        });
        s.spawn(|| control_flow::scan(bin, bytes, &mut bucket_cflow));
        s.spawn(|| packers::scan(bytes, elf.as_ref(), pe.as_ref(), &mut bucket_packers));
    });

    findings.append(&mut bucket_vulns);
    findings.append(&mut bucket_malware);
    findings.append(&mut bucket_strings);
    findings.append(&mut bucket_entropy);
    findings.append(&mut bucket_cflow);
    findings.append(&mut bucket_packers);

    // 5. Optional ML-Aetrium graph-anchor scan. Sequential: it is the
    //    heaviest pass and shares no state with the buckets above.
    if let Some(config) = aetrium {
        aetrium::scan(bin, bytes, config, &mut findings);
    }

    // 6. Aggregate risk score + verdict.
    let (score, verdict) = score::compute(&findings, &hardening);

    Ok(ScanReport {
        target_format: bin.format,
        target_arch: bin.arch,
        target_size: bin.raw_size,
        target_profile: if bin.format == Format::Elf {
            profile::TargetProfile::from_elf(bin, elf.as_ref())
        } else {
            profile::TargetProfile::from_pe(bin, pe.as_ref())
        },
        hardening,
        findings,
        score,
        verdict,
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        schema_version: report::SCHEMA_VERSION.to_string(),
        scoring_model: score::MODEL_VERSION.to_string(),
        ml_features: None,
    })
}

/// Run the full scan and additionally compute the ML feature vector.
///
/// The vector lives in [`ScanReport::ml_features`] and is produced from
/// the same hardening / findings / entropy data the scanner already
/// collects, so calling this is cheap (one extra histogram pass).
///
/// # Errors
///
/// Same as [`scan`].
pub fn scan_with_ml_features(bin: &LoadedBinary, bytes: &[u8]) -> Result<ScanReport> {
    let mut report = scan_internal(bin, bytes, None)?;
    let stripped = report.hardening.stripped.unwrap_or(false);
    let hardening_pct = report.hardening.enabled_count() * 100 / HardeningReport::total_probes();
    report.ml_features = Some(ml_features::extract(
        bin,
        bytes,
        &report.findings,
        hardening_pct,
        stripped,
    ));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_core::{Arch, Endian, Format};
    use omnisec_loader::{Import, LoadedBinary};

    fn fake_elf(imports: &[(&str, &str)]) -> LoadedBinary {
        let mut bin = LoadedBinary::new(Format::Elf, Arch::Arm64, Endian::Little, 4096);
        for (lib, name) in imports {
            bin.imports.push(Import {
                library: (*lib).to_string(),
                name: (*name).to_string(),
                address: None,
                ordinal: None,
                is_data: false,
            });
        }
        bin
    }

    #[test]
    fn rejects_unsupported_format() {
        // Mach-O is not supported by the native scanner (yet).
        let bin = LoadedBinary::new(Format::MachO, Arch::X86_64, Endian::Little, 1024);
        let err = scan(&bin, b"\xCF\xFA\xED\xFE").unwrap_err();
        assert!(matches!(err, omnisec_core::Error::Unsupported(_)));
    }

    #[test]
    fn scan_runs_on_minimal_input() {
        let bin = fake_elf(&[("libc.so", "strcpy"), ("libc.so", "system")]);
        let report = scan(&bin, b"").expect("scan should not fail");
        // Two CWE findings → score must be > 0.
        assert!(report.score > 0);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn upx_magic_surfaces_through_full_scan() {
        // Even with no parseable ELF/PE, the raw-byte UPX probe must fire and be
        // wired into the parallel scan path.
        let bin = fake_elf(&[("libc.so", "strcpy")]);
        let mut bytes = vec![0u8; 8192];
        bytes[200..204].copy_from_slice(b"UPX!");
        let report = scan(&bin, &bytes).expect("scan should not fail");
        assert!(
            report.findings.iter().any(|f| f.id == "packer-upx-magic"),
            "packer-upx-magic should be produced by the full scan"
        );
    }

    #[test]
    fn parallel_scan_is_deterministic() {
        // Same input scanned twice must produce an identical finding-id sequence
        // despite the rayon fan-out.
        let bin = fake_elf(&[
            ("libc.so", "strcpy"),
            ("libc.so", "system"),
            ("libc.so", "dlopen"),
        ]);
        let bytes = b"some strings http://evil.example/c2 and UPX! marker".to_vec();
        let ids = |r: &ScanReport| r.findings.iter().map(|f| f.id.clone()).collect::<Vec<_>>();
        let a = scan(&bin, &bytes).unwrap();
        let b = scan(&bin, &bytes).unwrap();
        assert_eq!(
            ids(&a),
            ids(&b),
            "parallel scan must be order-deterministic"
        );
    }
}
