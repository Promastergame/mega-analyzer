//! Heuristic string-level scanning: URLs, IPs, anti-emulator paths,
//! embedded ELFs, high-entropy blobs.
//!
//! All probes operate on the raw on-disk bytes — we cannot trust section
//! boundaries on a malformed / packed ELF and the cost of a single linear
//! pass is negligible for typical `.so` sizes (≤ 50 MB).

use omnisec_loader::LoadedBinary;

use crate::{Category, Confidence, Finding, Severity};

/// Minimum length of an extracted ASCII string. Shorter strings are too
/// noisy (every random integer that happens to be printable is a hit).
const MIN_STR_LEN: usize = 6;

/// Maximum number of findings produced per category, to keep reports
/// from being dominated by hundreds of identical hits.
const MAX_PER_CATEGORY: usize = 32;

/// Substrings that strongly indicate emulator / sandbox detection logic.
/// Hits inside the binary's strings = the binary *checks* for these,
/// not that it *runs in* one.
const EMULATOR_MARKERS: &[&str] = &[
    "/system/bin/qemu",
    "/system/lib/libdroid4x",
    "/system/lib/libnoxd",
    "/system/lib/libgenymotion",
    "qemu-props",
    "goldfish",
    "ranchu",
    "vbox86",
    "/dev/socket/qemud",
    "ro.kernel.qemu",
    "ro.hardware.goldfish",
    "/sys/qemu_trace",
    "/dev/qemu_pipe",
];

/// Substrings that indicate root-detection logic (often paired with
/// anti-emulator on tamper-protected apps OR with persistence on malware).
const ROOT_MARKERS: &[&str] = &[
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/",
    "magisk",
    "supersu",
    "Superuser.apk",
    "busybox",
];

/// Suspicious filesystem locations frequently abused by Android malware
/// for dropping, persistence, or staging.
const SUSPICIOUS_PATHS: &[&str] = &[
    "/data/local/tmp/",
    "/sdcard/Download/",
    "/data/data/",
    "/system/etc/init.d/",
    "/system/bin/",
    "/system/xbin/",
    "/dev/shm/",
];

const ANTI_TAMPER_MARKERS: &[&str] = &[
    "/proc/self/status",
    "/proc/self/maps",
    "/proc/self/mem",
    "/proc/self/task/",
    "TracerPid",
    "frida",
    "Frida",
    "gum-js-loop",
    "xposed",
    "Xposed",
    "substrate",
    "Substrate",
    "zygisk",
    "Zygisk",
];

const ANDROID_DYNAMIC_CODE_MARKERS: &[&str] = &[
    "DexClassLoader",
    "InMemoryDexClassLoader",
    "BaseDexClassLoader",
    "PathClassLoader",
    "dalvik/system/DexClassLoader",
    "loadDex",
    "System.loadLibrary",
    "System.load(",
];

const ANDROID_PACKER_MARKERS: &[&str] = &[
    "libjiagu",
    "jiagu",
    "Jiagu",
    "Bangcle",
    "bangcle",
    "SecNeo",
    "secneo",
    "ijiami",
    "Ijiami",
    "DexHelper",
    "protectClass",
    "libshell",
];

/// Run every string-level probe.
pub(crate) fn scan(_bin: &LoadedBinary, bytes: &[u8], findings: &mut Vec<Finding>) {
    if bytes.is_empty() {
        return;
    }

    // A hostile input can be arbitrarily large. Every whole-file probe
    // below is linear, so we bound the window we walk. The interesting
    // stubs/headers/payloads live near the front; scanning a capped prefix
    // keeps every reported offset valid while bounding worst-case CPU and
    // memory regardless of how big the attacker made the file.
    let bytes = if bytes.len() > crate::limits::MAX_CONTENT_SCAN_BYTES {
        &bytes[..crate::limits::MAX_CONTENT_SCAN_BYTES]
    } else {
        bytes
    };

    detect_embedded_elf(bytes, findings);
    detect_high_entropy_blobs(bytes, findings);
    scan_numeric_candidates(bytes, findings);

    // Single linear scan over extracted ASCII strings.
    let strings = extract_ascii_strings(bytes, MIN_STR_LEN);

    let mut url_count = 0;
    let mut ip_count = 0;
    let mut onion_count = 0;
    let mut emulator_count = 0;
    let mut root_count = 0;
    let mut path_count = 0;
    let mut anti_tamper_count = 0;
    let mut android_dyn_count = 0;
    let mut packer_count = 0;

    for (offset, s) in &strings {
        if url_count < MAX_PER_CATEGORY && is_url(s) {
            findings.push(
                Finding::new(
                    "embedded-url",
                    Category::NetworkIndicator,
                    Severity::Low,
                    Confidence::High,
                    "Embedded URL",
                    "A URL is hard-coded in the binary. Map to a known C2 \
                     list before drawing conclusions.",
                    s.clone(),
                )
                .with_offset(*offset as u64),
            );
            url_count += 1;
        }
        if onion_count < MAX_PER_CATEGORY && is_onion(s) {
            findings.push(
                Finding::new(
                    "onion-address",
                    Category::NetworkIndicator,
                    Severity::High,
                    Confidence::High,
                    "Tor .onion address",
                    "A Tor hidden-service address is hard-coded in the \
                     binary. Almost always malicious or anonymity-tooling \
                     in an Android-app context.",
                    s.clone(),
                )
                .with_offset(*offset as u64),
            );
            onion_count += 1;
        }
        if ip_count < MAX_PER_CATEGORY
            && let Some(ip) = extract_ipv4(s)
        {
            findings.push(
                Finding::new(
                    "embedded-ipv4",
                    Category::NetworkIndicator,
                    Severity::Low,
                    Confidence::Medium,
                    "Embedded IPv4 address",
                    "An IPv4 literal is hard-coded. Could be a C2 \
                         endpoint or a perfectly innocent CDN.",
                    ip,
                )
                .with_offset(*offset as u64),
            );
            ip_count += 1;
        }
        if emulator_count < MAX_PER_CATEGORY
            && let Some(m) = EMULATOR_MARKERS.iter().find(|m| s.contains(*m))
        {
            findings.push(
                Finding::new(
                    "anti-emulator-string",
                    Category::AntiAnalysis,
                    Severity::Medium,
                    Confidence::High,
                    "Anti-emulator fingerprint string",
                    "The binary contains a string that targets emulator/QEMU \
                     fingerprinting. The library probably refuses to run \
                     under sandboxed analysis, which slows automated \
                     reverse-engineering.",
                    format!("matched marker `{m}` in string `{s}`"),
                )
                .with_offset(*offset as u64),
            );
            emulator_count += 1;
        }
        if root_count < MAX_PER_CATEGORY
            && let Some(m) = ROOT_MARKERS.iter().find(|m| s.contains(*m))
        {
            findings.push(
                Finding::new(
                    "root-detection-string",
                    Category::AntiAnalysis,
                    Severity::Low,
                    Confidence::Medium,
                    "Root / Magisk fingerprint string",
                    "The binary references known root-detection / Magisk \
                     paths. Common in legitimate banking apps as well as \
                     in malware that uses root for persistence.",
                    format!("matched marker `{m}`"),
                )
                .with_offset(*offset as u64),
            );
            root_count += 1;
        }
        if path_count < MAX_PER_CATEGORY
            && let Some(m) = SUSPICIOUS_PATHS.iter().find(|m| s.contains(*m))
        {
            findings.push(
                Finding::new(
                    "suspicious-path",
                    Category::SuspiciousBehavior,
                    Severity::Low,
                    Confidence::Medium,
                    "Suspicious filesystem path",
                    "A path frequently abused by Android droppers / \
                     persistence routines is hard-coded. Consider \
                     whether the app legitimately needs that location.",
                    format!("`{m}` in string `{s}`"),
                )
                .with_offset(*offset as u64),
            );
            path_count += 1;
        }
        if anti_tamper_count < MAX_PER_CATEGORY
            && let Some(m) = ANTI_TAMPER_MARKERS.iter().find(|m| s.contains(*m))
        {
            findings.push(
                Finding::new(
                    "anti-tamper-string",
                    Category::AntiAnalysis,
                    Severity::Medium,
                    Confidence::Medium,
                    "Anti-tamper / hook-detection string",
                    "The binary references strings commonly used to detect \
                     debuggers, Frida/Xposed/Substrate hooks, or process-map \
                     tampering.",
                    format!("matched marker `{m}` in string `{s}`"),
                )
                .with_offset(*offset as u64),
            );
            anti_tamper_count += 1;
        }
        if android_dyn_count < MAX_PER_CATEGORY
            && let Some(m) = ANDROID_DYNAMIC_CODE_MARKERS.iter().find(|m| s.contains(*m))
        {
            findings.push(
                Finding::new(
                    "android-dynamic-code-string",
                    Category::DynamicCode,
                    Severity::Medium,
                    Confidence::Medium,
                    "Android dynamic-code loading string",
                    "The native library contains Java/Android dynamic loader \
                     names. Correlate with DEX payloads, encrypted strings, \
                     or dlopen before treating this as malicious.",
                    format!("matched marker `{m}` in string `{s}`"),
                )
                .with_offset(*offset as u64),
            );
            android_dyn_count += 1;
        }
        if packer_count < MAX_PER_CATEGORY
            && let Some(m) = ANDROID_PACKER_MARKERS.iter().find(|m| s.contains(*m))
        {
            findings.push(
                Finding::new(
                    "android-packer-string",
                    Category::EmbeddedPayload,
                    Severity::Medium,
                    Confidence::Medium,
                    "Android packer / shell marker",
                    "The binary contains a string associated with Android \
                     packers or shell loaders. This is a strong hint to \
                     inspect unpacking and JNI_OnLoad code paths.",
                    format!("matched marker `{m}` in string `{s}`"),
                )
                .with_offset(*offset as u64),
            );
            packer_count += 1;
        }
    }
}

/// Look for ELF magic at non-zero offsets — strong indicator of an
/// embedded native payload that will be dropped at runtime.
fn detect_embedded_elf(bytes: &[u8], findings: &mut Vec<Finding>) {
    // Skip the first byte: byte 0 is the host ELF magic itself.
    let mut count = 0usize;
    let mut first_offset = None;
    for (i, w) in bytes.windows(4).enumerate().skip(1) {
        if w == [0x7F, b'E', b'L', b'F'] {
            count += 1;
            if first_offset.is_none() {
                first_offset = Some(i);
            }
        }
    }
    if count > 0 {
        findings.push(
            Finding::new(
                "embedded-elf",
                Category::EmbeddedPayload,
                Severity::High,
                Confidence::High,
                "Embedded ELF payload",
                "Found ELF magic at non-zero offset(s). The library carries \
                 another native binary inside it — either a legitimate \
                 architecture-fat archive or a stage-2 dropper payload.",
                format!(
                    "{count} occurrence(s); first at 0x{:x}",
                    first_offset.unwrap_or(0)
                ),
            )
            .with_offset(first_offset.unwrap_or(0) as u64),
        );
    }
}

/// Sliding-window Shannon entropy detector. Reports adjacent
/// high-entropy windows as a *single* finding describing the full range
/// (start..end + average entropy), capped at [`MAX_REGIONS`] regions.
/// Threshold is ~7.4 bits/byte (close to the theoretical 8 max) over a
/// 1 KiB window — strongly suggests encrypted or compressed embedded data.
fn detect_high_entropy_blobs(bytes: &[u8], findings: &mut Vec<Finding>) {
    const WIN: usize = 1024;
    const THRESHOLD: f64 = 7.4;
    /// Maximum number of *distinct* high-entropy regions to surface.
    /// Adjacent hits are merged into a single region, so a 100 KiB
    /// packed blob still counts as one.
    const MAX_REGIONS: usize = 3;

    if bytes.len() < WIN {
        return;
    }

    let mut regions: Vec<(usize, usize, f64, u32)> = Vec::new(); // (start, end, sum_h, count)
    let mut i = 0usize;
    while i + WIN <= bytes.len() {
        let h = shannon_entropy(&bytes[i..i + WIN]);
        if h >= THRESHOLD {
            // Extend the previous region if this window is contiguous with it.
            if let Some(last) = regions.last_mut()
                && last.1 == i
            {
                last.1 = i + WIN;
                last.2 += h;
                last.3 += 1;
            } else {
                regions.push((i, i + WIN, h, 1));
            }
            i += WIN;
        } else {
            i += WIN;
        }
    }

    for (start, end, sum_h, n) in regions.into_iter().take(MAX_REGIONS) {
        let avg = sum_h / f64::from(n);
        let kib = (end - start) / 1024;
        findings.push(
            Finding::new(
                "high-entropy-blob",
                Category::EmbeddedPayload,
                Severity::Low,
                Confidence::Medium,
                "High-entropy data region",
                "A region of the binary has Shannon entropy near the \
                 maximum possible (8 bits/byte), strongly suggesting \
                 encrypted or compressed data. May be a legitimate \
                 compressed resource OR a packed payload.",
                format!("{kib} KiB starting at 0x{start:x}, avg entropy {avg:.2}"),
            )
            .with_offset(start as u64),
        );
    }
}

/// Shannon entropy in bits/byte. Used both as a probe and as a public
/// utility (re-exported via the test module).
fn shannon_entropy(window: &[u8]) -> f64 {
    // Single canonical implementation lives in `crate::entropy`; keeping a
    // thin wrapper here removes a third hand-rolled copy of the same loop.
    crate::entropy::shannon(window)
}

// ─────────────────────────────────────────────────────────────────────────
// Short numeric literals — PIN / password candidates below MIN_STR_LEN
// ─────────────────────────────────────────────────────────────────────────
//
// `extract_ascii_strings` only reports runs >= MIN_STR_LEN (6), so a 4-digit
// hardcoded password like `"1234"` never surfaces as its own finding. Two
// independent problems are handled here:
//
// 1. Standalone short digit runs (3-8 chars) bounded by non-identifier
//    bytes on both sides — trivially missed by the general extractor.
// 2. Digit runs merged into a longer sequential lookup table (e.g. the
//    "0123456789ABCDEF" hex-digit table `core::fmt` / libc emit). Linkers
//    that merge identical string *suffixes* (`SHF_MERGE|SHF_STRINGS`
//    sections) can graft a short literal into such a table as a
//    byte-identical substring with no storage of its own — invisible to
//    any purely length-based string scan. We can't prove which substring
//    is "the" real literal without following the actual code reference
//    (disassembly-based recovery, out of scope here), so we surface every
//    plausible substring for manual triage instead of guessing.

/// Digit-run lengths treated as standalone PIN/password candidates.
const NUMERIC_CANDIDATE_MIN_LEN: usize = 3;
const NUMERIC_CANDIDATE_MAX_LEN: usize = 8;

/// Hard cap on emitted numeric-candidate findings (standalone + table),
/// so a binary dense with digit runs cannot blow up the report.
const MAX_NUMERIC_FINDINGS: usize = 16;

/// Hard cap on substrings listed inside a single sequential-table finding.
const MAX_TABLE_SUBSTRINGS: usize = 24;

/// Keywords that, found within a small byte window around a digit-run
/// candidate, indicate it's more likely a real secret than a version
/// number or port. Matched case-insensitively against ASCII only —
/// non-ASCII (e.g. localized prompts) simply doesn't get the boost.
const SECRET_KEYWORDS: &[&str] = &[
    "pass",
    "pwd",
    "pin",
    "secret",
    "token",
    "apikey",
    "api_key",
    "auth",
    "credential",
    "unlock",
];

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True if every byte in `run` is exactly one more than its predecessor —
/// the shape of a compiler-emitted digit/hex lookup table ("0123456789…").
fn is_ascending_by_one(run: &[u8]) -> bool {
    run.len() >= 2 && run.windows(2).all(|w| w[1] == w[0].wrapping_add(1))
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Scan a small window around `[start, end)` for password/secret-ish
/// keywords, case-insensitively, to upgrade a low-confidence numeric
/// candidate into a medium-confidence one.
fn has_secret_keyword_nearby(bytes: &[u8], start: usize, end: usize) -> bool {
    const WINDOW: usize = 24;
    let lo = start.saturating_sub(WINDOW);
    let hi = (end + WINDOW).min(bytes.len());
    if lo >= hi {
        return false;
    }
    let lower: Vec<u8> = bytes[lo..hi].iter().map(u8::to_ascii_lowercase).collect();
    SECRET_KEYWORDS
        .iter()
        .any(|k| contains_subslice(&lower, k.as_bytes()))
}

/// Run both the standalone-PIN and sequential-table-merge probes over the
/// full byte buffer. Independent of, and cheaper than, the general ASCII
/// string extractor — a single linear pass with no allocation on the
/// non-digit fast path.
fn scan_numeric_candidates(bytes: &[u8], findings: &mut Vec<Finding>) {
    if bytes.is_empty() {
        return;
    }

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut emitted = 0usize;
    let mut skipped = 0usize;

    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }

        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let len = i - start;

        if (NUMERIC_CANDIDATE_MIN_LEN..=NUMERIC_CANDIDATE_MAX_LEN).contains(&len) {
            // Standalone candidate: must be isolated from a longer
            // identifier on both sides, or "v1234"/"1234x" would false-fire.
            let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
            let after_ok = i >= bytes.len() || !is_ident_byte(bytes[i]);
            if before_ok && after_ok {
                emit_numeric_candidate(
                    bytes,
                    start,
                    len,
                    findings,
                    &mut seen,
                    &mut emitted,
                    &mut skipped,
                );
            }
        } else if len > NUMERIC_CANDIDATE_MAX_LEN {
            // Long run: only interesting if it's a deliberate ascending
            // table. No isolation requirement here — the whole point is to
            // look *inside* a run that continues into hex letters
            // ("0123456789ABCDEF") with no real boundary at position `i`.
            emit_table_merge_candidate(
                bytes,
                start,
                len,
                findings,
                &mut seen,
                &mut emitted,
                &mut skipped,
            );
        }
    }

    if skipped > 0 {
        findings.push(Finding::new(
            "numeric-candidates-truncated",
            Category::Info,
            Severity::Info,
            Confidence::High,
            "Numeric-candidate list truncated",
            format!(
                "{skipped} additional short-digit-run candidate(s) were found but \
                 omitted to keep the report readable (cap: {MAX_NUMERIC_FINDINGS})."
            ),
            format!("{skipped} truncated"),
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_numeric_candidate(
    bytes: &[u8],
    start: usize,
    len: usize,
    findings: &mut Vec<Finding>,
    seen: &mut std::collections::HashSet<String>,
    emitted: &mut usize,
    skipped: &mut usize,
) {
    if *emitted >= MAX_NUMERIC_FINDINGS {
        *skipped += 1;
        return;
    }
    // SAFETY: the caller only passes ranges it already verified are
    // pure ASCII digits (0x30-0x39), which is always valid UTF-8.
    let Ok(value) = std::str::from_utf8(&bytes[start..start + len]) else {
        return;
    };
    if !seen.insert(format!("pin@{value}@{start:x}")) {
        return;
    }

    let boosted = has_secret_keyword_nearby(bytes, start, start + len);
    let (severity, confidence, description) = if boosted {
        (
            Severity::Medium,
            Confidence::Medium,
            "An isolated short digit sequence sits near a password/PIN/secret-\
             related keyword. Short numeric literals are invisible to the \
             general string extractor (which requires longer runs) but are \
             common hardcoded PINs, unlock codes, and debug passwords.",
        )
    } else {
        (
            Severity::Low,
            Confidence::Low,
            "An isolated short digit sequence was found. Could be a hardcoded \
             PIN/password, a version number, or a port — low confidence \
             without further context.",
        )
    };

    findings.push(
        Finding::new(
            "numeric-pin-candidate",
            Category::SuspiciousBehavior,
            severity,
            confidence,
            "Short numeric literal (PIN/password candidate)",
            description,
            format!("\"{value}\""),
        )
        .with_offset(start as u64),
    );
    *emitted += 1;
}

#[allow(clippy::too_many_arguments)]
fn emit_table_merge_candidate(
    bytes: &[u8],
    start: usize,
    len: usize,
    findings: &mut Vec<Finding>,
    seen: &mut std::collections::HashSet<String>,
    emitted: &mut usize,
    skipped: &mut usize,
) {
    let run = &bytes[start..start + len];
    if !is_ascending_by_one(run) {
        return;
    }
    if *emitted >= MAX_NUMERIC_FINDINGS {
        *skipped += 1;
        return;
    }
    // SAFETY: `run` was already verified to be pure ASCII digits.
    let Ok(table) = std::str::from_utf8(run) else {
        return;
    };
    if !seen.insert(format!("table@{start:x}")) {
        return;
    }

    let max_wlen = NUMERIC_CANDIDATE_MAX_LEN.min(len.saturating_sub(1));
    let mut substrings: Vec<&str> = Vec::new();
    'outer: for wlen in NUMERIC_CANDIDATE_MIN_LEN..=max_wlen {
        for w in run.windows(wlen) {
            let s = std::str::from_utf8(w).unwrap_or_default();
            if !substrings.contains(&s) {
                substrings.push(s);
            }
            if substrings.len() >= MAX_TABLE_SUBSTRINGS {
                break 'outer;
            }
        }
    }

    findings.push(
        Finding::new(
            "digit-sequence-table-merge-risk",
            Category::SuspiciousBehavior,
            Severity::Low,
            Confidence::Low,
            "Sequential digit table (possible linker string-merge host)",
            "A monotonically-ascending digit/hex table (the shape of a \
             fmt/printf-style digit lookup constant) was found. Compilers and \
             linkers that merge identical string suffixes \
             (SHF_MERGE|SHF_STRINGS sections) can graft an unrelated short \
             literal — e.g. a 4-digit password — into this table as a \
             byte-identical substring with no storage of its own, making it \
             invisible to a normal string scan. Review the listed substrings \
             manually; cross-referencing disassembly for the code that \
             actually loads a (pointer, length) pair into this range will \
             confirm which one, if any, is load-bearing.",
            format!(
                "table=\"{table}\" candidate substrings: {}",
                substrings.join(", ")
            ),
        )
        .with_offset(start as u64),
    );
    *emitted += 1;
}

/// Extract all printable-ASCII runs of length ≥ `min` from `bytes`,
/// returning `(file_offset, string)` pairs.
fn extract_ascii_strings(bytes: &[u8], min: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if (0x20..0x7F).contains(&b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take()
            && i - s >= min
        {
            // SAFETY: every byte in [s..i) was already checked to be in 0x20..0x7F (ASCII).
            // Use lossy as a defensive belt-and-braces.
            out.push((s, String::from_utf8_lossy(&bytes[s..i]).into_owned()));
            if out.len() >= crate::limits::MAX_EXTRACTED_STRINGS {
                return out;
            }
        }
    }
    if let Some(s) = start
        && bytes.len() - s >= min
    {
        out.push((s, String::from_utf8_lossy(&bytes[s..]).into_owned()));
    }
    out
}

/// Quick `http://` / `https://` / `ws://` / `wss://` / `ftp://` URL test.
fn is_url(s: &str) -> bool {
    const SCHEMES: &[&str] = &[
        "http://", "https://", "ws://", "wss://", "ftp://", "ftps://",
    ];
    SCHEMES.iter().any(|p| s.contains(p))
}

/// `.onion` Tor hidden-service test.
fn is_onion(s: &str) -> bool {
    // Quick filter; full check is expensive base32 validation.
    s.contains(".onion")
}

/// Very simple IPv4 dotted-quad extractor. Rejects 0.0.0.0 / 127.0.0.1 /
/// 255.255.255.255 / private RFC1918 ranges to cut false-positive noise.
fn extract_ipv4(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        if let Some((octets, _end)) = parse_dotted_quad(bytes, i)
            && is_interesting_ipv4(&octets)
        {
            return Some(format!(
                "{}.{}.{}.{}",
                octets[0], octets[1], octets[2], octets[3]
            ));
        }
        // Advance past this digit run regardless of success.
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }
    None
}

/// Parse exactly 4 dot-separated 1-3-digit octets starting at `start`.
/// Returns the parsed octets and the byte index just past the last digit.
fn parse_dotted_quad(bytes: &[u8], start: usize) -> Option<([u32; 4], usize)> {
    let mut octets = [0u32; 4];
    let mut idx = start;
    for (i, o) in octets.iter_mut().enumerate() {
        let digits_start = idx;
        while idx < bytes.len() && idx - digits_start < 3 && bytes[idx].is_ascii_digit() {
            *o = *o * 10 + u32::from(bytes[idx] - b'0');
            idx += 1;
        }
        if idx == digits_start || *o > 255 {
            return None;
        }
        // Need a dot after octets 0..2, nothing after octet 3.
        if i < 3 {
            if idx >= bytes.len() || bytes[idx] != b'.' {
                return None;
            }
            idx += 1;
        }
    }
    Some((octets, idx))
}

fn is_interesting_ipv4(o: &[u32; 4]) -> bool {
    // Reject obvious non-routable / placeholder values.
    if o[0] == 0 || o[0] >= 224 {
        return false;
    }
    // Loopback.
    if o[0] == 127 {
        return false;
    }
    // RFC1918 private ranges.
    if o[0] == 10 {
        return false;
    }
    if o[0] == 192 && o[1] == 168 {
        return false;
    }
    if o[0] == 172 && (16..=31).contains(&o[1]) {
        return false;
    }
    // Link-local.
    if o[0] == 169 && o[1] == 254 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ascii_strings_finds_runs() {
        let blob = b"\x00\x00hello world\x00\x00short";
        let s = extract_ascii_strings(blob, 5);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].1, "hello world");
        assert_eq!(s[1].1, "short");
    }

    #[test]
    fn ipv4_extracts_routable_only() {
        assert_eq!(
            extract_ipv4("connect to 8.8.8.8 now").as_deref(),
            Some("8.8.8.8")
        );
        assert_eq!(extract_ipv4("server 192.168.1.1").as_deref(), None);
        assert_eq!(extract_ipv4("loopback 127.0.0.1").as_deref(), None);
        assert_eq!(extract_ipv4("nope 999.0.0.1").as_deref(), None);
    }

    #[test]
    fn url_and_onion_detection() {
        assert!(is_url("Visit https://example.com/api"));
        assert!(!is_url("just text"));
        assert!(is_onion("foo.onion/bar"));
        assert!(!is_onion("normal.com"));
    }

    #[test]
    fn entropy_zero_for_constant_window() {
        let zeros = vec![0u8; 256];
        let h = shannon_entropy(&zeros);
        assert!(h.abs() < 0.01);
    }

    #[test]
    fn entropy_high_for_random_window() {
        // Cycle 0..=255 → uniform distribution → H = 8 bits/byte.
        let win: Vec<u8> = (0..=255u8).collect();
        let h = shannon_entropy(&win);
        assert!((h - 8.0).abs() < 0.01);
    }

    #[test]
    fn embedded_elf_detected_at_offset() {
        let mut blob = vec![0u8; 256];
        blob.extend_from_slice(&[0x7F, b'E', b'L', b'F']);
        blob.extend_from_slice(&[0u8; 64]);
        let mut f = vec![];
        detect_embedded_elf(&blob, &mut f);
        assert!(f.iter().any(|x| x.id == "embedded-elf"));
    }

    #[test]
    fn android_native_markers_are_detected() {
        let bin = omnisec_loader::LoadedBinary::new(
            omnisec_core::Format::Elf,
            omnisec_core::Arch::Arm64,
            omnisec_core::Endian::Little,
            0,
        );
        let bytes = b"abc /proc/self/maps xyz DexClassLoader xyz libjiagu.so xyz";
        let mut f = vec![];
        scan(&bin, bytes, &mut f);

        assert!(f.iter().any(|x| x.id == "anti-tamper-string"));
        assert!(f.iter().any(|x| x.id == "android-dynamic-code-string"));
        assert!(f.iter().any(|x| x.id == "android-packer-string"));
    }

    #[test]
    fn no_findings_for_empty_input() {
        let bin = omnisec_loader::LoadedBinary::new(
            omnisec_core::Format::Elf,
            omnisec_core::Arch::Arm64,
            omnisec_core::Endian::Little,
            0,
        );
        let mut f = vec![];
        scan(&bin, &[], &mut f);
        assert!(f.is_empty());
    }

    fn fake_bin() -> omnisec_loader::LoadedBinary {
        omnisec_loader::LoadedBinary::new(
            omnisec_core::Format::Elf,
            omnisec_core::Arch::Arm64,
            omnisec_core::Endian::Little,
            0,
        )
    }

    #[test]
    fn standalone_short_pin_is_detected_below_general_min_str_len() {
        // "1234" alone is 4 bytes — below MIN_STR_LEN (6) — so the general
        // extractor would never surface it as its own string.
        let mut bytes = vec![0u8; 8];
        bytes.extend_from_slice(b"1234");
        bytes.extend_from_slice(&[0u8; 8]);
        let mut f = vec![];
        scan(&fake_bin(), &bytes, &mut f);
        assert!(
            f.iter()
                .any(|x| x.id == "numeric-pin-candidate" && x.evidence.contains("1234")),
            "expected a numeric-pin-candidate for isolated \"1234\": {f:?}"
        );
    }

    #[test]
    fn digit_run_inside_identifier_is_not_flagged() {
        // Digits that are part of a longer identifier ("v1234x") must not
        // be treated as a standalone PIN candidate.
        let mut bytes = vec![0u8; 8];
        bytes.extend_from_slice(b"v1234x");
        bytes.extend_from_slice(&[0u8; 8]);
        let mut f = vec![];
        scan(&fake_bin(), &bytes, &mut f);
        assert!(!f.iter().any(|x| x.id == "numeric-pin-candidate"));
    }

    #[test]
    fn nearby_password_keyword_boosts_confidence() {
        let bytes = b"\x00\x00password=1234\x00\x00".to_vec();
        let mut f = vec![];
        scan(&fake_bin(), &bytes, &mut f);
        let cand = f
            .iter()
            .find(|x| x.id == "numeric-pin-candidate")
            .expect("candidate must be found");
        assert_eq!(cand.confidence, Confidence::Medium);
        assert_eq!(cand.severity, Severity::Medium);
    }

    #[test]
    fn non_ascending_long_digit_run_is_not_flagged_as_table() {
        // Long but NOT strictly ascending-by-one — a phone number / build
        // id / timestamp, not a compiler-emitted lookup table.
        let mut bytes = vec![0u8; 8];
        bytes.extend_from_slice(b"948271605948");
        bytes.extend_from_slice(&[0u8; 8]);
        let mut f = vec![];
        scan(&fake_bin(), &bytes, &mut f);
        assert!(!f.iter().any(|x| x.id == "digit-sequence-table-merge-risk"));
    }

    #[test]
    fn digit_table_merge_recovers_short_literal_substring() {
        // Reproduces the real byte pattern found in the `parol2` fixture
        // binary: the Rust core::fmt hex-digit lookup table
        // "0123456789ABCDEF" sits immediately next to unrelated text with
        // no separator, and — via linker string-tail-merging — can host an
        // unrelated short literal ("1234", the app's hardcoded password)
        // as a byte-identical substring with no storage of its own.
        let mut bytes = vec![0u8; 8];
        bytes.extend_from_slice(b"0123456789ABCDEFconnection reset");
        let mut f = vec![];
        scan(&fake_bin(), &bytes, &mut f);
        let table = f
            .iter()
            .find(|x| x.id == "digit-sequence-table-merge-risk")
            .expect("table-merge finding must be produced");
        assert!(
            table.evidence.contains("1234"),
            "evidence must list the embedded \"1234\" substring: {}",
            table.evidence
        );
    }
}
