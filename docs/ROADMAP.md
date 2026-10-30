# Roadmap

[Русский](ROADMAP.ru.md)

This is the honest, public roadmap — things that are planned, not things that are done. See [ML_ROADMAP.md](ML_ROADMAP.md) for the ML-specific plan.

---

## 1. Sandbox: ANY.RUN-level analysis, local and offline

The goal is a behavioral analysis experience on par with ANY.RUN — but running entirely on your own hardware, with no registration, no upload, no cloud.

**What this means in practice:**

- Full behavioral timeline: every process spawn, file write, registry change, network connection, and API call shown in real time in the browser UI
- Richer Android detonation: SSL unpinning applied automatically before launch, Frida scripts injected on start, all traffic captured and decrypted without manual setup
- Windows detonation improvements: kernel-level syscall tracing via eBPF/ETW, memory dumps on suspicious behavior, automatic string extraction from unpacked regions
- Correlated verdict: static findings + dynamic findings merged into one risk timeline so you can see "this code path ran, this network call fired, this file was dropped"
- Environment presets: clean snapshot, rooted device, emulator with Play Services, custom AVD — selectable from the UI picker

---

## 2. ML: beyond "find private key"

Most tools that claim ML either use regex dressed up as a model, or run a cloud LLM. The plan here is different — small, fast, local, and genuinely useful:

- **Smarter secret detection**: not just entropy + regex, but a context model that understands whether a string is actually used as a credential (passed to an auth function, sent over the network) vs. just sitting in a constants file
- **Vulnerability chaining**: the ML pipeline should connect related findings into attack chains — not just "SQL injection here" but "user input flows through X, reaches Y without sanitization, reaches database via Z"
- **Behavioral classification**: train the GNN on dynamic traces, not just static CFGs — so the model can recognize malware patterns from runtime behavior, not just code structure
- **Incremental learning from your own runs**: every time you mark a finding as noise or confirm it, the local model improves for your specific codebase — without sending anything anywhere
- **Confidence that means something**: Platt calibration + conformal prediction so when the model says 90% confidence, it's actually right 90% of the time

---

## 3. Detection: more signal, less noise

The goal is finding real vulnerabilities — including ones buried inside SDKs — while not drowning the report in library boilerplate.

**More signal:**

- Deeper taint tracking across the JNI boundary (Java → native → Java) for injection chains that cross the language boundary
- WebView attack surface: every `loadUrl`, `evaluateJavascript`, `addJavascriptInterface` traced to its source to find XSS and data exfiltration paths
- Deeper deserialization coverage: Kryo, Hessian, FST, Avro — not just the common Java serialization targets
- Supply-chain risk: flag when a dependency has a known CVE *and* the vulnerable code path is actually reachable from the app

**Less noise, but not blind to SDKs:**

Third-party SDK code is not skipped — it is analyzed. The difference is in how findings are presented: SDK findings that are pure boilerplate get lower priority, but SDK findings that are genuine risks (weak crypto, hardcoded credentials, command execution, unsafe WebView config) stay visible at full severity. The rule: **no finding is silently dropped, ever**.

---

## Non-goals

Things that will never be on this roadmap:

- Cloud processing of any kind
- Requiring a GPU or large model weights
- Automatic patching without explicit user confirmation
