<div align="center">

<img src=".github/assets/mega-analyzer-for-readme-above.png" alt="Mega-Analyzer" width="872">

# Mega-Analyzer

[English](README.md) · [Русский](README.ru.md) · [Quick start](QUICKSTART.md) · [Build](docs/BUILD.md)

</div>

**A lab for dissecting apps and binaries that lives entirely on your machine.**
APK, JAR, PE, ELF, firmware, a dynamic sandbox, traffic interception and reports in HTML, JSON and SARIF.
No cloud, no telemetry.

The base (core) build already covers APK, DEX, Smali, JAR and Minecraft archive analysis, plus checks of
native-binary security mitigations. To run the tutorial example you need Go 1.27.3 or newer:

```sh
go build -trimpath -o analyzer ./pkg/cmd/analyzer
./analyzer -t demo/vulnerable-app -report all -sarif
```

In Windows PowerShell run `./analyzer.exe` and look for the report in `analysis_output/REPORT.html`.
The [prebuilt core archives](https://github.com/Promastergame/mega-analyzer/releases) already contain this
example: unpack the archive and run the second command.

If you only need decompilation, without running the analyzer, build the standalone tool:
`go build -trimpath -tags noembed -o bin/decompiler.exe ./cmd/decompiler`.
Details and the Go API: [docs/DECOMPILER.ru.md](docs/DECOMPILER.ru.md) (RU).

You can also plug in a local DecisionAI: it additionally reasons over the HTML and JSON findings, classifies
Smali and answers questions about what a patch achieves. Setup instructions:
[docs/DECISION_AI.ru.md](docs/DECISION_AI.ru.md) (RU).

| Capability | In the core build | What else you need |
| :--- | :--- | :--- |
| Static analysis, reports, Web UI, REST API | Included | Nothing; static analysis needs no network |
| Native OmniSec, Zig and GNN engines | Separate build | Rust, Zig, a C toolchain and the required libraries |
| Live Android analysis, instrumentation | Via a connected device | A device or emulator, ADB, Frida and similar tools |
| Network scanning, traffic interception | Separate modes | Access to the target and a configured proxy |

Static analysis needs neither cloud nor telemetry. By default the servers listen on loopback only.
If you open access from the LAN or a container yourself, that boundary moves. What the native engines and
on-device analysis require is described in the [build guide](docs/BUILD.md).

mega-analyzer is distributed under the dual [BSD](LICENSE) OR [GPLv2](COPYING) license.

<img src=".github/assets/report.png" alt="Mega-Analyzer HTML report" width="860">

---

## <img src=".github/assets/icons/bolt.svg" width="20"> Quick start

> [!TIP]
> Want to see results right away? Run the built-in demo: it finds real issues in a few seconds and needs
> no setup. See the [Demo](#-demo) section.

### <img src=".github/assets/icons/package.svg" width="16"> Option A: prebuilt binary

Download the archive for your OS and architecture from the [Releases](https://github.com/Promastergame/mega-analyzer/releases)
page, unpack it and run:

```bash
./analyzer -t my_app.apk -report all
```

### <img src=".github/assets/icons/terminal.svg" width="16"> Option B: build from source

```bash
# Requires Go 1.27.3+
go build -trimpath -ldflags "-s -w" -o analyzer ./pkg/cmd/analyzer
```

> The default build is pure Go and works as a full analyzer. The native engines (OmniSec, Zig, GNN) are
> optional and need extra toolchains. Details in [docs/BUILD.md](docs/BUILD.md).

### <img src=".github/assets/icons/hexagon.svg" width="16"> Option C: Docker

```bash
docker build -t mega-analyzer .
docker run --rm -v "$PWD:/work" mega-analyzer -t /work/my_app.apk -report all
```

### <img src=".github/assets/icons/globe.svg" width="16"> Option D: Web UI

```bash
./analyzer -web                 # opens on http://localhost:7474
./analyzer -web -web-port 8080  # your own port
./analyzer -web -admin          # Web UI with confirmed OS privileges
```

Drag a file into the window, watch the analysis run in real time, then study the report right in the browser.
More in [Web UI and live sandbox](#-web-ui-and-live-sandbox).

---

## <img src=".github/assets/icons/flask.svg" width="20"> Demo

The built-in, intentionally vulnerable example has something to find right away. No Android SDK, emulator
or real APK required:

```console
$ ./analyzer -t demo/vulnerable-app -report all -sarif

  Mega-Analyzer · target: demo/vulnerable-app
  ---------------------------------------------
  ▸ manifest audit ........ exported components, debuggable, cleartext, StrandHogg
  ▸ smali scan ............ AWS key in code, Runtime.exec, reflection, weak crypto
  ▸ secret triage ......... AWS · Stripe · Slack · GitHub  (entropy-based)
  ▸ correlation ........... linked 6 risk chains
  ---------------------------------------------
  VERDICT: CRITICAL · 29 findings · SARIF: 67 rules
  → analysis_output/REPORT.html
```

Open `analysis_output/REPORT.html` — that is the interactive report. The `analysis_output/analysis.sarif`
file can be fed to any SARIF viewer: VS Code, GitHub, GitLab, SonarQube. What is planted in the example is
described in [`demo/`](demo/).

---

## <img src=".github/assets/icons/bolt.svg" width="20"> What Mega-Analyzer can do

This is not just a manifest scanner. Inside is a whole toolkit for dissecting apps and binaries, and all of
it runs locally and emits reports in one format.

| Area | What's inside |
| :--- | :--- |
| **Mobile static analysis** | APK, DEX, Smali, React Native and Hermes. Manifest audit, secrets, SAST (105 rules), Exodus trackers (431 signatures), APKiD packer and obfuscator detection (30 signatures) |
| **Java and backends** | JAR, WAR, deserialization, injections, XXE, weak cryptography, vulnerable dependencies by CVE |
| **Native binaries** | PE, ELF, Mach-O: security mitigations, section entropy, JNI boundaries |
| **Firmware and IoT** | rootfs hints, network services, web panels, hardcoded keys and passwords |
| **RE and deobfuscation** | The OmniSec Rust engine: SSA, dataflow, symbolic execution, micro-emulators, devirtualization, a reverse-stepping debugger |
| **Dynamic sandbox** | Sample execution on Windows (VMware) and Android, processes, network, files, API calls, key and IV extraction |
| **Traffic and MITM** | Real-time decrypted HTTP(S), PCAP, DNS, TLS SNI |
| **Frida** | An interactive REPL in the browser, `frida-server`, APK builds with the Frida Gadget |
| **Patches and crack points** | License and root check discovery, 150+ patch patterns, CFG-aware patching |
| **Private servers** | A protocol dissector, a client patcher, a ready-to-run Elixir/OTP server generator |
| **Supply chain** | SDKs in Smali, CI configs (GitHub Actions, GitLab CI, Jenkins), K8s, Docker, AWS IAM |
| **Web targets** | Vulnscan: time-based SQLi, OS command injection and other checks |
| **Media forensics** | Polyglots, steganography, Exif and GPS |
| **ML scoring** | A light offline ensemble that ranks risks and patches |
| **Reports and CI** | HTML, Markdown, JSON, CSV and SARIF for GitHub and GitLab code scanning |

### What the per-format checks find

Every finding gets a stable rule id, a severity level, confidence and the surrounding code fragment. To keep
the report from drowning in noise, a false-positive suppression layer is at work: entropy-based secret triage,
library-vs-app-code separation and credit for protection that is already enabled.

| Format | What is checked |
| :--- | :--- |
| <img src=".github/assets/icons/package.svg" width="18"> **APK / DEX** | Manifest: exported components, `debuggable`, cleartext, backup. Task hijacking and StrandHogg (custom `taskAffinity`, `singleTask` and `singleInstance`). Leaks through `grantUriPermissions`. Deep links without `assetlinks.json`. `sharedUserId`, dangerous permissions. Reflection and native-code loading in Smali. Crack points and patchable methods |
| <img src=".github/assets/icons/atom.svg" width="18"> **React Native / Hermes** | `index.android.bundle` is analyzed as application code, not as noisy framework code. The `eval` family, `addJavascriptInterface`, prototype pollution, obfuscation. WebView issues (`setAllowUniversalAccessFromFileURLs`, `injectedJavaScript`). Disabled TLS verification (`rejectUnauthorized:false`, trust-all). `cordova.exec`. Secrets via entropy-based detection across providers |
| <img src=".github/assets/icons/coffee.svg" width="18"> **JAR / Java / WAR** | RCE through deserialization (`readObject`, `XMLDecoder`, SnakeYAML, XStream). Dynamic code loading (`URLClassLoader`, ScriptEngine, Groovy). Injections: JNDI and Log4Shell, SpEL, OGNL, SQL. XXE (the finding is suppressed when the parser is already hardened). Trust-all TLS (`X509TrustManager`, `HostnameVerifier`). Weak ciphers and hashes (ECB, DES, RC4). Vulnerable dependencies by CVE |
| <img src=".github/assets/icons/window.svg" width="18"> **PE (Windows)** | ASLR, DEP/NX, CFG, SafeSEH, stack canaries (`/GS`), AppContainer, digital signature. Per-region section entropy helps locate packed and encrypted areas |
| <img src=".github/assets/icons/terminal.svg" width="18"> **ELF / Mach-O** (Linux, Android `.so`, macOS) | PIE, NX, RELRO (full and partial), stack canaries (SSP), Fortify Source, unsafe `RPATH` and `RUNPATH`, JNI boundaries |
| <img src=".github/assets/icons/compass.svg" width="18"> **Firmware / IoT** | rootfs hints, telnet, ssh, ftp and upnp services, web panels, hardcoded keys and passwords |
| <img src=".github/assets/icons/key.svg" width="18"> **Secrets in any text** | About 25 provider rules: AWS, GitHub, GitLab, Stripe, Slack, Telegram, Discord, OpenAI and Anthropic, Google, private keys, JWT and more. Entropy and charset triage: real keys keep full severity, while placeholders and low-entropy matches are downgraded and don't flood the report |
| <img src=".github/assets/icons/network.svg" width="18"> **CI, cloud, containers** | GitHub Actions, GitLab CI, Jenkinsfile (context injection, PPE, unpinned versions). K8s, Docker, AWS IAM (container escape, IAM PassRole, confused deputy). CVE-2025-55182 (RCE in React Server Components) |
| <img src=".github/assets/icons/flask.svg" width="18"> **Media files** | Polyglots, steganography, Exif and GPS, with auto-generated scripts for extracting the hidden data |

> [!IMPORTANT]
> **On false positives.** Findings never disappear silently. If confidence is low, a finding simply ranks
> lower. Context (library vs application code, whether the parser is hardened, whether the key looks like a
> placeholder) changes severity, but the signal is never hidden.

---

## <img src=".github/assets/icons/window.svg" width="20"> Web UI and live sandbox

The `analyzer -web` command opens a local browser panel. Analysis happens right there: drop in a file, watch
progress in real time via Server-Sent Events, and next to it sits an ANY.RUN-style live view of an Android
device. No clouds and no uploads to other people's servers — everything stays on `localhost`.

> [!IMPORTANT]
> **Sandbox status.** The dynamic sandbox is still under active development. Only the Windows guest in
> VMware mode is fully implemented and verified so far: isolated execution and telemetry collection inside
> the virtual machine. Linux and Android execution remain experimental and have not been comprehensively tested.

The sandbox can [extract keys and IVs from supported cryptographic calls](docs/SANDBOX_CRYPTO.ru.md) (RU) on
Windows and Android. Everything it managed to capture appears on the **Crypto keys** tab and in the JSON and
Markdown reports.

For Windows VMs in VMware and Hyper-V there is a [collector that keeps reports on your main PC](docs/SANDBOX_VM_HOST.ru.md) (RU).
The `-sandbox-remote-config` flag streams events and keys to the host Windows as they arrive. No separate
server is needed, and already-saved data survives a guest crash. This mode runs from the CLI. Native execution
of a sample on the main Windows host is blocked by default.

In the web UI you can [run Windows files in VMware via Tools](docs/VMWARE-SAFETY.ru.md) (RU): prepare a
powered-off VM, transfer the sample, observe it, stop the VM and save the report on the host. Virtual network
adapters are disconnected for the run, and guest credentials are entered for that specific run only.

| | Capability | What it does |
| :---: | :--- | :--- |
| <img src=".github/assets/icons/bolt.svg" width="18"> | **Drag-and-drop analysis** | Drop an APK, DEX, PE or ELF into the window and watch findings appear as the scan runs. The final report, the artifact browser and per-file downloads are on the same page. |
| <img src=".github/assets/icons/window.svg" width="18"> | **Live Android device view** | A real device or emulator is mirrored into the browser over H.264 via WebCodecs, with MJPEG or screenshots as the fallback. Taps, swipes, long presses and keyboard input go back to the device, so you can drive the app while the analysis runs. |
| <img src=".github/assets/icons/flask.svg" width="18"> | **ANY.RUN-style sandbox** | Run an APK on the device and watch processes, network connections, DNS queries, file changes, API calls and behavioral alerts in real time. The environment (device, emulator or AVD) is picked in the built-in selector. |
| <img src=".github/assets/icons/bug.svg" width="18"> | **Frida REPL in the browser** | Load and start `frida-server`, list processes and open an interactive Frida REPL over WebSocket. Or rebuild the APK with the bundled Frida Gadget: it comes out signed and ready to run. |
| <img src=".github/assets/icons/network.svg" width="18"> | **Live MITM and traffic capture** | Watch decrypted HTTP(S) requests as they appear (via mitmproxy) or capture a full PCAP with PCAPdroid or tcpdump on the device. DNS, HTTP and TLS SNI are extracted automatically. |
| <img src=".github/assets/icons/laptop.svg" width="18"> | **Mobile mode** | The whole panel is responsive and has a separate mobile menu, so you can analyze from a phone while everything is on the same LAN. |

> [!NOTE]
> The Web UI runs the same engine as the CLI, so the reports are identical. Each tool (decode, machine-code,
> firmware, diff, JS deobfuscation, sandbox, MITM) has its own route, such as `/sandbox` or `/mitm`. For
> automation there is a REST API: start `analyzer --api` and the web-scan and web-tool endpoints become
> available under `/api/v1/*`, with Swagger documentation included.

---

## <img src=".github/assets/icons/compass.svg" width="20"> How it compares to other tools

Mega-Analyzer doesn't try to replace Ghidra or MobSF. The idea is different: one binary that runs fully
offline and immediately covers mobile static analysis, native files, dynamic analysis, ML and CI. The table
shows what each tool can do and where its limits are.

| | **Mega-Analyzer** | MobSF | JADX | Ghidra | ANY.RUN | VirusTotal |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 100% offline, local | ✅ | ⚠️ self-host | ✅ | ✅ | ❌ cloud | ❌ cloud |
| Single binary, no JDK or SDK | ✅ | ❌ | ⚠️ JRE | ⚠️ JRE | n/a | n/a |
| APK / DEX static analysis | ✅ | ✅ | 🔍 decompilation | ➖ | ➖ | ➖ |
| Native PE / ELF / Mach-O | ✅ | ➖ | ➖ | 🥇 deep RE | ➖ | ➖ |
| Dynamic sandbox | ✅ Win + Android | ⚠️ via VM | ➖ | ➖ | ⚠️ limited free tier | ⚠️ |
| Live device view and input | ✅ | ➖ | ➖ | ➖ | ✅ | ➖ |
| Decrypted traffic, MITM | ✅ | ⚠️ | ➖ | ➖ | ✅ | ➖ |
| Offline ML scoring | ✅ | ➖ | ➖ | ➖ | ➖ | ⚠️ |
| SARIF, code scanning | ✅ | ➖ | ➖ | ➖ | ➖ | ➖ |
| License | BSD-3-Clause OR GPLv2 | GPL v3 | Apache 2.0 | Apache 2.0 | proprietary | proprietary |
| Price | free | free | free | free | freemium | freemium |

> **Where the others are stronger.** Ghidra remains the best choice for deep native reverse engineering, and
> MobSF has a mature ecosystem with many integrations. Mega-Analyzer is convenient as the first pass; when
> you need to dig deeper, move on to those tools. Detailed comparison: [docs/COMPARISON.md](docs/COMPARISON.md).

> **A note on ANY.RUN: access and privacy.** In our experience as of October 2026, the free tier has caveats.
> Cloud VMs are convenient because you don't have to configure your own. But registration requires a business
> email on your own domain, and the domain and email can cost money even when the service itself is free.
> A single run is limited to 5 minutes, and the ML features can be used 5 times. All analyses are public,
> including a recording of what you do during the session, and private mode is available only on a paid
> subscription. So for confidential samples and long interactive sessions, the free tier does not fit.

---

## <img src=".github/assets/icons/cpu.svg" width="20"> Technologies and engines

### The OmniSec Rust engine

The native side of the project is a workspace of 52 Rust crates. It is what does the heavy lifting on
machine code.

| Capability | How it works |
| :--- | :--- |
| **HDC auto-naming** | Recovers meaningful variable and function names locally on 2048-bit sparse hypervectors (Hyperdimensional Computing). Under 10 MB of RAM, microsecond latency, no neural networks or cloud involved. |
| **OmniIR, CFG, SSA, dataflow** | A single intermediate representation with dominators, loops and SSA construction. Interprocedural dataflow runs through the PDG and IPDG. |
| **Deobfuscation** | Constant propagation, dead-code elimination, opaque-predicate removal, variable and loop recovery. |
| **Symbolic and concolic execution** | Unravels obfuscated logic and proves path reachability (DPLL and SMT), which cuts false positives. |
| **x86 and ARM64 micro-emulators** | Run code in isolated memory with page permissions and unpack XOR- or RC4-encrypted strings and hidden payloads on their own. |
| **Hyperion v3** | Finds VM-dispatcher patterns (virtualization) and lifts handler semantics back into readable code. |
| **Replay debugger** | GDB-like: disassembly, breakpoints and watchpoints, patch-and-continue, YARA-style memory scanning. It can step backward in time (`reverse_step`, `reverse_continue`) on incremental snapshots. |
| **NCER** | The network-evidence correlation engine. Parses captured traffic (`ncer-parse-net`), reconciles evidence (`ncer-evidence`, `ncer-reconcile`) and hands the result to Go over FFI (`ncer-reconcile-ffi`, `ncer-types`). |
| **Graph GNN** (`omnisec-ml-graph`) | A second vulnerability-detection path built on a graph neural network. It merges code and metadata features and complements the DEX license and piracy classifier from `omnisec-ml-gnn`. |
| **Behavioral telemetry** | The `aya`-based syscall tracer was removed; `omnisec-ebpf` remains as an API stub. On Linux, real telemetry is read from `/proc`; other platforms use a simulator. |

<details>
<summary><b>▸ All 52 OmniSec crates</b></summary>

```
omnisec-analysis-symbolic   omnisec-analysis-virt       omnisec-arm64-decode
omnisec-arsc                omnisec-callgraph           omnisec-capture
omnisec-cfg                 omnisec-cli                 omnisec-collections
omnisec-core                omnisec-crypto              omnisec-dataflow
omnisec-debugger            omnisec-debugger-ffi        omnisec-deobfuscator
omnisec-disasm              omnisec-disasm-arm64        omnisec-ebpf
omnisec-emu-arm64           omnisec-emu-x86             omnisec-forge
omnisec-graph               omnisec-hdc                 omnisec-intel-pt
omnisec-ipdg                omnisec-ir                  omnisec-json
omnisec-json-derive         omnisec-lifter-dalvik       omnisec-loader
omnisec-loader-dex          omnisec-loader-elf          omnisec-loader-macho
omnisec-loader-pe           omnisec-log                 omnisec-metrics
omnisec-micro-emu           omnisec-mitm                omnisec-ml-gnn
omnisec-ml-graph            omnisec-ml-inference        omnisec-ncer-evidence
omnisec-ncer-parse-net      omnisec-ncer-reconcile      omnisec-ncer-reconcile-ffi
omnisec-ncer-types          omnisec-net-obfs            omnisec-pdg
omnisec-scan-native         omnisec-smt                 omnisec-ssa
omnisec-z3-worker
```

</details>

### Speed and scale

| What was done | Result |
| :--- | :--- |
| **Per-method SHA-256 cache** | Repeat scans up to 10× faster, because CFG, SSA, taint and metrics are reused. |
| **SIMD ULEB128 decoder** (Plan 9 assembly) | Speeds up the DEX parser's hot path by 30%: 400 MB/s vs 310 MB/s on an i5-3340. A portable fallback is included. |
| **Adaptive worker scheduler** | The pool size adapts to actual CPU, heap and GC pressure instead of being pinned to `NumCPU×2`. Huge APKs don't lead to out-of-memory failures. |

---

## <img src=".github/assets/icons/flask.svg" width="20"> Additional toolkits

Beyond static analysis, the project ships a set of separate offline modules. Each writes its own Markdown
and JSON into the output folder and never blocks the main pipeline.

| <img src=".github/assets/icons/flask.svg" width="16"> Toolkit | What it gives you |
| :--- | :--- |
| **Dynamic sandbox** | Runs samples on **Windows** (Job Objects, an optional kernel and syscall monitor, WFP network rules, file, registry, API and network data) or on **Android** (a real device or emulator over ADB: install, launch, live process, network and file capture, traffic capture, extraction of downloaded files). |
| **Private Server Toolkit** | A built-in MITM proxy and protocol dissector (Protobuf, MsgPack, JSON). A smart client patcher: IP and domain replacement in APKs and `.so` files, SSL pinning bypass. A Go server-stub generator from a recorded session. A **private Elixir/OTP server generator** that emits a ready-to-run backend with a rules engine, hot reload, failure scenarios and a live dashboard (the hand-written reference version and a playable demo live in [`elixir_privserver/`](elixir_privserver/)). Plus Lab DNS: sinkholing and DGA detection. |
| **Crack Point Discovery** | Finds checks like `isPremium`, `checkLicense`, `isRooted`, `isDebuggable`, ranks them by impact and proposes Smali patches. A patch is applied with CFG awareness: the right basic block is edited, not a blind string replacement. |
| **ML Patch Predictor** | Over 150 patch patterns (license, billing v5 to v7, premium, ads, root, SSL pinning, Play Integrity, JWT, anti-cheat), ranked by `Risk × Impact / (Cost × Detection × Breakage)`. Works for Kotlin, React Native, Flutter and Unity; `.original` backups are verified by SHA-256. |
| **TOP-5 Insights** | JNI Boundary Analyzer, Privacy Analyzer, Version Diff, Interactive Graph Explorer (HTML) and the Firmware/IoT Analyzer. |
| **MobSF analogues written from scratch** | A SAST rule scanner (**105 rules**, CVSS, CWE, OWASP, MASVS), Exodus trackers (**431 signatures**), a Network Security Config auditor, deep manifest audit, and APKiD packer and obfuscator detection (**30 signatures**). |
| **Vulnscan** | Fully rewritten: a pipeline engine, differential analysis, AIMD request rate control. New checks: time-based SQLi (CWE-89), OS command injection (CWE-78) and 11 more. Active mode requires the `--i-own-this-target` flag. |
| **Supply chain audit** | Static SDK detection in Smali (Firebase, Facebook, Yandex Metrica, Adjust) with risk scoring. CVE-2025-55182 (RCE in React Server Components). GitHub Actions, GitLab CI and Jenkinsfile audits (context injection, PPE, mutable versions). K8s, Docker and AWS IAM config audits (container escape, IAM PassRole, confused deputy). Everything runs offline. |
| **Bytecode and native-file analysis** | The `--scan-bytecode` and `--scan-native` flags. DEX goes through the **Hyperion IR** pipeline (MIR, CFG, SSA, DFG via `omnisec-lifter-dalvik`), meaning OmniIR analyzes it, not raw Smali. |
| **Media Forensics** | Polyglot and steganography hunting, Exif and GPS analysis, automatic generation of data-extraction scripts. Fully rewritten, with 14 new modules. |

<details>
<summary><b>▸ 7 more auxiliary analyzers</b></summary>

These offline modules write their results to `<output>/medium/`: Play Store metadata, SBOM extraction, a
Permission-to-Code map, deep certificate analysis (v1, v2, v3 signatures, debug key), checks against a
malicious-domain list, icon analysis and NIAP compliance.

</details>

---

## <img src=".github/assets/icons/globe.svg" width="20"> Private server and the Bit Arena demo

When the Private Server Toolkit records a session, it can emit a ready-to-run Elixir/OTP backend instead of
a stub you still have to finish. The hand-written reference version lives in
[`elixir_privserver/mock_server`](elixir_privserver/mock_server), and that is exactly the shape the generator
aims for.

| <img src=".github/assets/icons/globe.svg" width="18"> Part | What it does |
| :--- | :--- |
| **Rules engine** | Declarative request → response rules live in `priv/rules.json` (regex on `path`, `path_prefix` and `method`; the first match wins). Rules reload on the fly, so connected clients don't drop. The `$premium_token`, `$now` and `$rand_hex` placeholders are substituted on every request. |
| **Failure scenarios** | Profiles switch mid-session: `normal`, `flaky` (20 to 250 ms delays and about 20% `503` responses), `offline`, `expired`. That shows how the client copes with a backend that stopped being polite. |
| **Live dashboard** | A single self-contained HTML page on a separate admin port, no CDNs or external fonts — offline, like everything else. Request counters, a traffic log, a scenario switcher and rule reloading. |
| **Heuristic fallback** | When no rule matches, the engine recognizes auth, license and feature-flag endpoints by name and answers plausibly. An unfamiliar app usually starts working with no configuration at all. |

**Bit Arena** ([`elixir_privserver/demo_game`](elixir_privserver/demo_game)) is a small multiplayer server
with authoritative logic where the toolkit is shown in action. One process per player, one supervised
temporary `GenServer` per match, an authoritative 20 Hz tick, an ETS leaderboard, a browser client with no
build step and a dependency-free Node bot. The single place where the server trusts the client is the
**unsigned** entitlement token the game fetches from its own `/api/v1/session`. Point just that request at
the mock server and the same account gets a golden skin, doubled coins and a speed boost — all visible on
the dashboard:

```bash
# fair game on :4000, private server on :9340
cd elixir_privserver/demo_game/client
node bot.mjs --account guest                                   # tier=free
node bot.mjs --account guest --backend http://localhost:9340   # tier=premium
```

The moral is simple: entitlement the client fetches from a server is worth exactly as much as the signature
on the response. Both apps ship tests, and one of them specifically proves that a forged token is accepted —
so it will fail on the day you add a signature. Full guides:
[`elixir_privserver/mock_server/README.md`](elixir_privserver/mock_server/README.md) and
[`elixir_privserver/demo_game/README.md`](elixir_privserver/demo_game/README.md).

---

## <img src=".github/assets/icons/package.svg" width="20"> Reports and outputs

A single run can produce everything listed below. The `-profile {quick|balanced|deep|paranoid}` flag sets
analysis depth, and the `-report {short|default|full|all}` flag sets report detail.

```text
analysis_output/
├── REPORT.html                 # interactive report (open this one first)
├── REPORT.md                   # Markdown for issues and wikis
├── analysis.json               # machine-readable findings
├── analysis.sarif              # with -sarif: GitHub and GitLab code scanning
├── PATCHES.md                  # proposed patches
├── PATCHES_WITH_FIX.md         # patches with the fix applied
├── correlation_report.{md,json}# findings linked into risk chains
├── insights/                   # JNI_BRIDGE · PRIVACY · VERSION_DIFF · GRAPH_EXPLORER · FIRMWARE
├── mobsf/                      # SAST_RULES · EXODUS_TRACKERS · NSC_AUDIT · MANIFEST_AUDIT · APKID
└── medium/                     # SBOM · PERMISSION_MAP · CERT_AUDIT · MALWARE_DOMAINS · ICON · NIAP · PLAYSTORE
```

| Format | What it is for |
| :--- | :--- |
| **HTML** | Reading by eye: risk summary, finding breakdown, artifact browser, crack-point view |
| **Markdown** | Pasting into issues, PRs and wikis |
| **JSON and CSV** | Scripts and dashboards |
| **SARIF** | GitHub and GitLab code scanning, VS Code SARIF Viewer, SonarQube |

Full flag reference: [docs/USAGE.md](docs/USAGE.md) and `FlagiFiles.md`.

---

## <img src=".github/assets/icons/cpu.svg" width="20"> Architecture

```mermaid
flowchart TD
    IN["APK · DEX · Smali · PE · ELF · Mach-O · RN · JAR · Firmware · Web"]
    UI["CLI · TUI · Web UI (:7474) · REST API"]
    IN --> UI

    UI --> A["Android and bytecode<br/>Go pipeline"]
    UI --> B["OmniSec native<br/>Rust · 52 crates"]
    UI --> C["Dynamic sandbox<br/>Windows + Android"]
    UI --> D["Toolkits<br/>privsrv · crack · insights · mobsf"]
    UI --> E["ML pipeline<br/>GNN · GBT · RF · LR · HDC"]

    A --> COR["Correlation engine<br/>risk chains"]
    B --> COR
    C --> COR
    D --> COR
    E --> COR

    COR --> OUT["Reports<br/>HTML · MD · JSON · CSV · SARIF"]
```

| Layer | Language | Where it lives |
| :--- | :--- | :--- |
| CLI, TUI, Web UI, REST API | Go | `pkg/cmd/analyzer`, `pkg/api` |
| Static pipeline, taint, SMT, SSA IR | Go | `pkg/internal/{pipeline,taint,smt,ssair}` |
| Dynamic sandbox (Windows and Android) | Go + Zig | `pkg/internal/sandbox`, `zig/sandbox` |
| OmniSec native engine (52 crates) | Rust | `rust/crates/omnisec-*` |
| SIMD ML runtime (XNOR-GEMM, Hamming, SpMV) | Zig | `zig/src` |
| APK Editor IDE (desktop and Android port) | Zig + Java | `apk-editor` (separate repository) |
| Distributed analysis server (optional) | Elixir/OTP | `server/` |
| Private-server engine and Bit Arena demo | Elixir/OTP | `elixir_privserver/` |

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## <img src=".github/assets/icons/cpu.svg" width="20"> Machine learning

ML here assists the audit and is deliberately lightweight: it runs on CPU, fully offline, with no LLMs and
no gigabyte-sized weights.

- <img src=".github/assets/icons/search.svg" width="14"> **HDC auto-naming.** Recovers the names of obfuscated variables and functions locally on sparse associative memory.
- <img src=".github/assets/icons/target.svg" width="14"> **Risk scoring.** An ensemble of GNN, GBT, Random Forest and Logistic Regression hunts dangerous patterns. Platt calibration and SHAP-style feature attribution are used.
- <img src=".github/assets/icons/gear.svg" width="14"> **ML Patcher.** Over 150 patch patterns ranked by `Risk × Impact / (Cost × Detection × Breakage)`, applied with CFG awareness and SHA-256-verified backups.

What is planned next (conformal prediction, incremental on-device retraining, drift monitoring) is described
in [docs/ML_ROADMAP.md](docs/ML_ROADMAP.md).

---

## <img src=".github/assets/icons/globe.svg" width="20"> GitHub code scanning

Mega-Analyzer can emit **SARIF**, so findings appear right on the **Security → Code scanning** tab and in
pull-request comments. Just add the analyzer to your workflow:

```yaml
# After building/installing analyzer in the workflow:
- run: ./analyzer -t app-release.apk -report all -sarif -no-profile

- uses: github/codeql-action/upload-sarif@1190a975f95ce23525efb6a3fc21ea29567c1b52 # v3
  with:
    sarif_file: analysis_output/analysis.sarif
```

The full guide: [docs/CODE_SCANNING.md](docs/CODE_SCANNING.md).

---

## <img src=".github/assets/icons/shield.svg" width="20"> Principles

These rules are non-negotiable; the whole project rests on them.

| | |
| :---: | :--- |
| <img src=".github/assets/icons/lock.svg" width="20"> | **Static analysis stays local.** No cloud services and no telemetry. Servers listen on loopback by default, and the explicit network modes only touch the targets and tools you configured yourself. |
| <img src=".github/assets/icons/cpu.svg" width="20"> | **Lightweight is a requirement.** The target is modest hardware, for example 4 cores from around 2012 and 8 GB of RAM. Peak memory is roughly 1.5 to 2 GB; everyday runs sit at 500 to 800 MB. No heavy LLMs and no gigabyte-sized weights. |
| <img src=".github/assets/icons/shield.svg" width="20"> | **Defensive use only.** The project was created for security research, auditing and defense. It is not intended for creating or distributing malware. |

---

## <img src=".github/assets/icons/search.svg" width="20"> Documentation

| | |
| :--- | :--- |
| [QUICKSTART.md](QUICKSTART.md) | The 60-second version |
| [FlagiFiles.md](FlagiFiles.md) | Full reference: every flag, environment variable and build command |
| [docs/USAGE.md](docs/USAGE.md) | Flags, profiles and recipes (cheat sheet) |
| [docs/BUILD.md](docs/BUILD.md) | The core build and the full native one, toolchains, tests |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Directory layout, how Go, Rust, Zig and Elixir interact, the adaptive scheduler |
| [docs/COMPARISON.md](docs/COMPARISON.md) | An honest comparison with MobSF, JADX, Ghidra, ANY.RUN and VirusTotal |
| [docs/FAQ.md](docs/FAQ.md) | Common questions, pitfalls and design decisions |
| [docs/CODE_SCANNING.md](docs/CODE_SCANNING.md) | SARIF and the GitHub Action integration |
| [docs/DOCKER_DEPLOYMENT.md](docs/DOCKER_DEPLOYMENT.md) | Deployment with Docker, Compose and Kubernetes |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Plans for the sandbox, ML and detections |
| [docs/ML_ROADMAP.md](docs/ML_ROADMAP.md) | Machine-learning strategy and plans |
| [docs/RELEASING.md](docs/RELEASING.md) | How releases are cut and the signature is verified |
| [docs/SECURITY.md](docs/SECURITY.md) | How to report a vulnerability (private advisory) |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | How to report bugs and suggest ideas (PRs are not accepted) |
| [docs/CODE_OF_CONDUCT.md](docs/CODE_OF_CONDUCT.md) | Community rules |
| [docs/DONATION.md](docs/DONATION.md) | How to support the project |

---

## <img src=".github/assets/icons/bolt.svg" width="20"> Support the project

If Mega-Analyzer turned out to be useful, you can send a voluntary
[donation via DonationAlerts](https://www.donationalerts.com/r/promastergame).

---

## <img src=".github/assets/icons/compass.svg" width="20"> Project status

| | |
| :--- | :--- |
| **Version** | v1.0.0-beta.1 |
| **Author** | [@Promastergame](https://github.com/Promastergame). Designed and written by one developer with AI assistance |
| **License** | [BSD](LICENSE) OR [GPLv2](COPYING) |

---

<div align="center">

**Mega-Analyzer** · a whole malware lab on `localhost`

<sub>Dual-licensed BSD or GPLv2 · see <a href="LICENSE">LICENSE</a> and <a href="COPYING">COPYING</a> · static analysis works even with the network cable unplugged</sub>

</div>
