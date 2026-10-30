//! Vulnerability surface — historically dangerous CRT / libc primitives.
//!
//! We work at the *import* level: presence of an undefined dynamic symbol
//! `strcpy` means the binary calls `strcpy` somewhere. We do not reason
//! about *whether* the call is reachable or operates on attacker-controlled
//! data — that requires data-flow analysis which is out of scope for the
//! native scanner. Hence confidence is `Medium` for the buffer-overflow
//! family and `High` for unconditionally bad APIs (`gets`, `tmpnam`).
//!
//! Each entry maps to a CWE for downstream tooling that wants to ingest
//! the report (SARIF, CodeQL, vendor SOC pipelines).

use omnisec_loader::LoadedBinary;

use crate::util::base_symbol_name;
use crate::{Category, Confidence, Finding, Severity};

/// Static catalogue of "if you see this import, raise N" rules.
struct Rule {
    /// Imported function name to match exactly.
    sym: &'static str,
    /// Severity tier.
    severity: Severity,
    /// Per-rule confidence (overrides "Medium" for definitely-bad calls).
    confidence: Confidence,
    /// CWE identifier.
    cwe: &'static str,
    /// Human-readable title.
    title: &'static str,
    /// Why this is bad.
    description: &'static str,
    /// Remediation hint.
    remediation: &'static str,
}

/// Master rule table. Order matters only for stable output.
const RULES: &[Rule] = &[
    // ── Buffer overflow family (CWE-120 / CWE-121 / CWE-787) ────────────
    Rule {
        sym: "strcpy",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: "CWE-120",
        title: "Unbounded string copy (strcpy)",
        description: "strcpy has no destination size check. If the source \
                      length is attacker-influenced, a buffer overflow is \
                      trivial.",
        remediation: "Use strlcpy / strncpy_s / snprintf with explicit bounds.",
    },
    Rule {
        sym: "strcat",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: "CWE-120",
        title: "Unbounded string concatenation (strcat)",
        description: "strcat doesn't know the destination size. Combine \
                      with attacker-controlled input → buffer overflow.",
        remediation: "Use strlcat / strncat_s with explicit bounds.",
    },
    Rule {
        sym: "sprintf",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: "CWE-120",
        title: "Unbounded sprintf",
        description: "sprintf writes without a size limit; %s with \
                      attacker-controlled input overflows the destination.",
        remediation: "Replace with snprintf and an explicit size argument.",
    },
    Rule {
        sym: "vsprintf",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: "CWE-120",
        title: "Unbounded vsprintf",
        description: "vsprintf has no size argument and inherits all the \
                      problems of sprintf.",
        remediation: "Use vsnprintf with an explicit size.",
    },
    Rule {
        sym: "gets",
        severity: Severity::Critical,
        confidence: Confidence::High,
        cwe: "CWE-120",
        title: "gets() — unconditionally exploitable",
        description: "gets() reads input until newline with no size limit. \
                      Removed from C11 / POSIX.1-2008. There is no safe use.",
        remediation: "Replace with fgets and an explicit size argument.",
    },
    Rule {
        sym: "scanf",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        cwe: "CWE-120",
        title: "Unbounded scanf",
        description: "%s in scanf has no size limit. Even bounded format \
                      specifiers are easy to mis-size.",
        remediation: "Always use bounded specifiers (`%128s`) or fgets+sscanf.",
    },
    Rule {
        sym: "alloca",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        cwe: "CWE-770",
        title: "Stack allocation with attacker-influenced size",
        description: "alloca on a non-constant size can overflow the stack \
                      guard page and skip canaries entirely.",
        remediation: "Use a small fixed-size buffer or heap-allocate.",
    },
    // ── Command injection (CWE-78) ──────────────────────────────────────
    Rule {
        sym: "system",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: "CWE-78",
        title: "Command injection sink (system)",
        description: "system() passes its argument to /bin/sh -c. Any \
                      attacker-controlled byte trivially escapes into a \
                      shell metacharacter.",
        remediation: "Use execve with an explicit argv vector.",
    },
    Rule {
        sym: "popen",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: "CWE-78",
        title: "Command injection sink (popen)",
        description: "popen() forks /bin/sh -c. Same shell-injection risks \
                      as system().",
        remediation: "Use pipe + fork + execve.",
    },
    Rule {
        sym: "execl",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        cwe: "CWE-78",
        title: "Process exec (execl)",
        description: "execl is safer than system but the variadic argv is \
                      easy to misuse with untrusted input.",
        remediation: "Audit argv construction or switch to execve.",
    },
    Rule {
        sym: "execlp",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: "CWE-426",
        title: "PATH-based exec (execlp)",
        description: "execlp searches PATH. A poisoned PATH entry in the \
                      target's environment gives the attacker code exec.",
        remediation: "Use execve with an absolute path.",
    },
    Rule {
        sym: "execvp",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: "CWE-426",
        title: "PATH-based exec (execvp)",
        description: "Same PATH-poisoning risk as execlp.",
        remediation: "Use execve with an absolute path.",
    },
    // ── Insecure crypto / RNG (CWE-327 / CWE-330 / CWE-338) ─────────────
    Rule {
        sym: "MD5_Init",
        severity: Severity::Medium,
        confidence: Confidence::High,
        cwe: "CWE-327",
        title: "Broken hash (MD5)",
        description: "MD5 has practical collision attacks since 2004. \
                      Unsuitable for any security purpose.",
        remediation: "Use SHA-256 or BLAKE2 / BLAKE3.",
    },
    Rule {
        sym: "SHA1_Init",
        severity: Severity::Medium,
        confidence: Confidence::High,
        cwe: "CWE-327",
        title: "Broken hash (SHA-1)",
        description: "SHA-1 has practical collision attacks (SHAttered, 2017).",
        remediation: "Use SHA-256 or SHA-3.",
    },
    Rule {
        sym: "DES_set_key",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: "CWE-327",
        title: "Broken cipher (DES)",
        description: "DES has a 56-bit key and is brute-forceable in hours \
                      on commodity hardware.",
        remediation: "Use AES-256-GCM or ChaCha20-Poly1305.",
    },
    Rule {
        sym: "RC4",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: "CWE-327",
        title: "Broken cipher (RC4)",
        description: "RC4 has biased output and is prohibited by TLS 1.3 \
                      and most modern protocols.",
        remediation: "Use AES-GCM or ChaCha20-Poly1305.",
    },
    Rule {
        sym: "rand",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        cwe: "CWE-338",
        title: "Insecure PRNG (rand)",
        description: "rand() is a non-cryptographic LCG. Output is \
                      predictable from a single observation.",
        remediation: "Use getrandom() / arc4random() / /dev/urandom.",
    },
    Rule {
        sym: "srand",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        cwe: "CWE-338",
        title: "Insecure PRNG seed (srand)",
        description: "srand seeds the predictable rand() PRNG, often with \
                      time(NULL) which is easily guessable.",
        remediation: "Use a CSPRNG instead.",
    },
    // ── Race conditions on temp files (CWE-377 / CWE-367) ───────────────
    Rule {
        sym: "tmpnam",
        severity: Severity::Medium,
        confidence: Confidence::High,
        cwe: "CWE-377",
        title: "Insecure temp file (tmpnam)",
        description: "tmpnam returns a name without atomically creating the \
                      file. Classic TOCTOU race / symlink attack vector.",
        remediation: "Use mkstemp() which atomically creates with O_EXCL.",
    },
    Rule {
        sym: "mktemp",
        severity: Severity::Medium,
        confidence: Confidence::High,
        cwe: "CWE-377",
        title: "Insecure temp file (mktemp)",
        description: "Same TOCTOU race as tmpnam.",
        remediation: "Use mkstemp() instead.",
    },
    Rule {
        sym: "tempnam",
        severity: Severity::Medium,
        confidence: Confidence::High,
        cwe: "CWE-377",
        title: "Insecure temp file (tempnam)",
        description: "Same TOCTOU race as tmpnam.",
        remediation: "Use mkstemp() instead.",
    },
    // ── Memory primitives (informational, low confidence) ───────────────
    Rule {
        sym: "memcpy",
        severity: Severity::Info,
        confidence: Confidence::Low,
        cwe: "CWE-120",
        title: "memcpy used",
        description: "memcpy itself is not insecure, but every memcpy with \
                      attacker-influenced size is a potential overflow.",
        remediation: "Audit each call site; prefer the _chk variants.",
    },
    Rule {
        sym: "memmove",
        severity: Severity::Info,
        confidence: Confidence::Low,
        cwe: "CWE-120",
        title: "memmove used",
        description: "Like memcpy, only flagged so reviewers can audit \
                      attacker-controlled lengths.",
        remediation: "Audit length calculations.",
    },
];

/// Scan `bin.imports` for entries matching any rule in [`RULES`].
pub(crate) fn scan_imports(bin: &LoadedBinary, findings: &mut Vec<Finding>) {
    use std::collections::HashSet;

    // Collect imported symbol names into a hashset for O(1) lookup;
    // a typical .so has a few hundred imports so the set is tiny.
    let imports: HashSet<&str> = bin
        .imports
        .iter()
        .map(|i| base_symbol_name(i.name.as_str()))
        .collect();

    for rule in RULES {
        if imports.contains(rule.sym) {
            findings.push(
                Finding::new(
                    format!("dangerous-api-{}", rule.sym),
                    Category::Vulnerability,
                    rule.severity,
                    rule.confidence,
                    rule.title.to_string(),
                    rule.description.to_string(),
                    format!("imported `{}`", rule.sym),
                )
                .with_cwe(rule.cwe)
                .with_remediation(rule.remediation),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_core::{Arch, Endian, Format};
    use omnisec_loader::Import;

    fn bin_with_imports(syms: &[&str]) -> LoadedBinary {
        let mut bin = LoadedBinary::new(Format::Elf, Arch::Arm64, Endian::Little, 0);
        for s in syms {
            bin.imports.push(Import {
                library: "libc.so".into(),
                name: (*s).to_string(),
                address: None,
                ordinal: None,
                is_data: false,
            });
        }
        bin
    }

    #[test]
    fn flags_strcpy_and_system() {
        let bin = bin_with_imports(&["strcpy@@LIBC", "system", "memcmp"]);
        let mut f = vec![];
        scan_imports(&bin, &mut f);
        assert!(f.iter().any(|x| x.id == "dangerous-api-strcpy"));
        assert!(f.iter().any(|x| x.id == "dangerous-api-system"));
        assert!(!f.iter().any(|x| x.id == "dangerous-api-memcmp"));
    }

    #[test]
    fn gets_is_critical() {
        let bin = bin_with_imports(&["gets"]);
        let mut f = vec![];
        scan_imports(&bin, &mut f);
        let g = f.iter().find(|x| x.id == "dangerous-api-gets").unwrap();
        assert_eq!(g.severity, Severity::Critical);
        assert_eq!(g.cwe.as_deref(), Some("CWE-120"));
    }

    #[test]
    fn no_findings_for_clean_imports() {
        let bin = bin_with_imports(&["strncpy", "snprintf", "fgets"]);
        let mut f = vec![];
        scan_imports(&bin, &mut f);
        assert!(f.is_empty());
    }
}
