# BinZAP threat model & detection coverage

## What BinZAP analyzes

Disassembled application artifacts (smali, x86 assembly). It does not execute
the target; all analysis is static.

## Vulnerability classes (INC5)

| Class | CWE | Detection |
|-------|-----|-----------|
| OS command injection | CWE-78 | taint: input → Runtime.exec/ProcessBuilder |
| SQL injection | CWE-89 | taint: input → rawQuery/execSQL |
| Path traversal | CWE-22 | taint: input → File ctor; passive BZ-PASS-007 |
| Insecure deserialization | CWE-502 | taint: input → ObjectInputStream; BZ-PASS-006 |
| SSRF | CWE-918 | taint: input → URL ctor |
| Unsafe reflection / dynamic load | CWE-470 | taint + BZ-PASS-005 |
| Insecure crypto | CWE-327 | BZ-PASS-001 |
| Hardcoded secrets | CWE-798 | secrets scanner + credential taint |
| Sensitive data in logs | CWE-532 | taint: credential/input → Log |
| Broken TLS validation | CWE-295 | mobile BZ-MOB-004 |
| Insecure WebView | CWE-749 | mobile BZ-MOB-001/002 |
| Insecure IPC | CWE-927 | mobile BZ-MOB-003 |
| Dangerous permissions | CWE-250 | mobile BZ-MOB-005 |

## Malware behaviors (INC7)

Obfuscation (reflection chains, runtime decode), anti-analysis (emulator/root/
debugger detection), dynamic code loading, command execution, data exfiltration
and SMS/toll fraud are scored; the aggregate score maps to a severity.

## Confidence model

- Taint findings: HIGH (a concrete data path exists).
- Pattern findings: rule-defined (usually MEDIUM/HIGH).
- Malware score: advisory; requires analyst triage.

## Known limitations

- Taint is intra-procedural; cross-method/interprocedural flows are future work.
- Manifest-based checks (truly exported components) require manifest input;
  current mobile rules infer risk from API usage in code.
