# BinZAP 2.0 Architecture

BinZAP is a static security analyzer for Android/Dalvik (`.smali`) and x86
(`.asm`/`.s`) artifacts. Version 2.0 replaces the previous randomized "active
fuzzer" with a real static-analysis pipeline built on a dialect-neutral IR.

## Pipeline

```
source file
   │  lex (pkg/binzap/lex)            -> []lex.Token
   ▼
lowering (pkg/binzap/ir)             -> ir.Program (methods, blocks, instrs)
   ▼
analysis (pkg/binzap/analysis)       -> CFG + intra-procedural taint
   │      passive rules (rules.go)    -> pattern findings
   │      mobile pack (mobile_rules)  -> WebView/IPC/TLS/permission findings
   │      malware pack (malware_rules)-> behavior score
   ▼
Finding[] (finding.go)               -> dedupe + sort + fingerprint + baseline
   ▼
reporter (reporter.go)               -> Markdown / JSON / SARIF 2.1.0 / HTML
```

## Packages

- **lex** — line-oriented lexers for smali and x86 producing typed tokens.
- **ir** — small SSA-lite intermediate representation. `LowerTokens` recovers
  registers (including from brace-wrapped operands the lexer marks Unknown),
  segments methods on `.method`/`.end method`, links `move-result` to the
  preceding invoke, and builds basic blocks.
- **analysis** — dependency-free source/sink catalog, CFG, and an
  intra-procedural taint engine. It has no knowledge of the binzap `Finding`
  type, so it is independently testable; binzap adapts `analysis.Finding`.
- **binzap** — orchestration: rule registry, passive/mobile/malware rules,
  baseline/suppression, parallel runner, reporters.

## Data flow / taint model

Sources (Intent extras, UI input, network, file, IPC) taint a register. Taint
propagates through `move`/`move-result`. When a tainted register flows into a
sink (exec, rawQuery, File ctor, ObjectInputStream, URL ctor, reflection,
WebView.loadUrl, Log), a finding is emitted with CWE, severity, remediation and
the full source→sink attack path.

The existing secrets scanner is integrated (not duplicated): a hardcoded
credential string becomes a `credential` taint seed, so a secret reaching an
insecure sink is reported as an exposure.

## Design principles

- Standard library only; no cloud, no network, offline-friendly.
- No import-time global state or filesystem side effects (the dynamic rule store
  loads lazily and never writes on read).
- Deterministic output: findings are fingerprinted, de-duplicated and sorted.
