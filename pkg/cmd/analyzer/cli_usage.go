package main

import (
	"fmt"

	"mega-analyzer/pkg/internal/config"
)

// ═══════════════════════════════════════════════════════════════════════════════
// USAGE
// ═══════════════════════════════════════════════════════════════════════════════

func (p *CLIParser) printUsage() {
	fmt.Printf(`%s v%s

USAGE:
  analyzer                               # Standard CLI analysis (default profile)
  analyzer -t ./app.apk -artifacts -o ./out  # Analyze APK with extracted media/binary artifacts
   analyzer -web                          # Launch local web UI (drag & drop any file)
  analyzer -web -admin                   # OS-confirmed administrator/root web server
  analyzer -tui                          # Interactive TUI settings cockpit
  analyzer -tui -target <path>           # TUI with preselected target
  analyzer -target <dir> -profile deep   # CLI analysis with deep profile
  analyzer --suggest                     # ML assistant
  analyzer --sandbox -t sample.exe       # Built-in sandbox / detonation
  analyzer edit <target.apk>             # Launch native Zig APK Patch Editor
  analyzer decode -t app.apk -o out      # Decode APK to Smali without analysis
  analyzer build -t smali_dir -o app.apk # Rebuild APK from Smali directory

TARGET:
  -target, -t <dir|file>  Target: directory, APK file, DEX, PE/ELF binary, or media file
  -minecraft             Inspect Minecraft mods/packs: -minecraft -t mod.jar -o out
                         Supports ZIP, MCPACK, MCADDON and extracted pack directories.
  -output, -o <dir>       Output directory (default: analysis_output)

ANALYSIS:
  -profile, -p <name>     Profile: quick | balanced | deep | paranoid
  -callgraph              Enable call graph analysis
  -correlations           Enable cross-file correlations
  -deep-scan              Enable deep bytecode scanning

LIMITS:
  -max-file-size <MB>     Max code file size in MB (0=profile default)
  -max-resource-size <MB> Max resource/XML size in MB (0=profile default)

  Profile defaults:
    quick:    code 16 MB, resources 32 MB
    balanced: code 32 MB, resources 64 MB
    deep:     unlimited
    paranoid: unlimited

PERFORMANCE:
  -workers, -w <N>        Worker goroutines (default: CPU cores)
  -timeout <seconds>      Analysis timeout (default: 300)
  -max-files <N>          Limit number of files (0=unlimited)
  -pprof <addr>           Enable pprof HTTP server (default off; e.g. localhost:6060)
  -cpu-profile <file>     Write CPU profile to file
  -mem-profile <file>     Write heap profile to file
  -debug                  Enable debug logging

WEB UI & REST API:
  -web                    Launch local web UI — drag & drop any file, see results in browser
  -admin                 OS elevation; requires -web, loopback + token, no profiles
  -admin-reexec          Internal: re-exec elevated helper (used by -admin)
  -admin-cwd <dir>       Internal: working directory for the elevated helper
  -web-port <port>        Port for the web UI server (default: 7474)
  -web-ui-token <token>   Fixed pairing token for the web UI API (default: random, printed at startup)
  -api                    Launch the REST API from the same analyzer executable
  -api-port <port>        REST API port (default: 5000)

WEBSITE ANALYSIS (integrated vulnscan):
  -web-scan                         Enable website analysis
  -web-scan-target <url>            HTTP/HTTPS target
  -web-scan-mode, -web-mode <mode>  status | passive | active (default: active)
      status                        One GET; report whether the response is HTTP 200
      passive                       One GET; inspect headers/body without fuzzing
      active                        Full vulnerability scan; requires -i-own-this-target
  -i-own-this-target                Confirm authorization for active mode
  -lab-mode                         Enable destructive lab-only features (OAST, Desync)
  -target-allowlist <domains>       Comma-separated list of allowed domains
  -fsm-config <path>                Path to YAML file for state-machine fuzzing
  -html-body <path>                 Path to HTML body file for passive analysis
  -curl <command>                   Scan request expressed as cURL command
  -raw-request <path>               Path to raw HTTP request file (Burp format)
  -raw-scheme <http|https>          Scheme for raw HTTP request (default: https)

OUTPUT:
  -quiet, -q              Minimal output
  -no-color               Disable colors
  -tui                    Enable interactive TUI settings cockpit
  -no-tui                 Disable TUI panels (CLI mode)
  -no-profile             Do not load settings from analyzer.flags.*.txt files
  -json                   Output as JSON to stdout
  -no-html                Skip HTML report generation
  -no-json                Skip JSON report generation
  -sarif                  Write analysis.sarif for code scanning UIs
  -clean-output           Clean output dir before writing reports
  -report <preset>        Report: short | default | full | all

FALSE POSITIVE / LIBRARY TRIAGE:
  -fp-strict              Show only confirmed app/SDK risks
  -fp-show-suppressed     Keep full suppressed-noise log
  -fp-min-score <N>       Minimum FP-filter score (-1=profile default)
  -fp-suppressed-limit <N> Max suppressed findings (-1=default, 0=unlimited)

APK/DEX:
  -keep-temp              Keep temporary extraction files
  -dex-only               Analyze DEX code only (skip resources)
  -no-headers             Omit '# Disassembled from DEX' comment headers from smali files
  -no-smali-header        Omit smali metadata comment headers (alias of -no-headers)

ASSET SCAN (3D / textures / encrypted media - no full analysis):
  -assets <path>           Walk a file, folder or APK/ZIP looking for .glb, .gltf,
                           textures and obfuscated images; renders every asset it
                           can decode - including XOR/rotate/byte-swapped ones - to PNG
  -assets-out <dir>        Preview directory (default: <target>-assets, next to the target)
  -assets-open             Open the rendered previews in the native Zig APK Patch Editor
  -assets-json             Print the machine-readable report on stdout (what the editor reads)
  -assets-deep             Widen the recovery search and the embedded-frame scan window
  -assets-all              List every file walked, not only recognised assets
  -assets-max-mb <N>       Per-entry size cap in MB (default: 64)
  -assets-max-dim <N>      Longest preview side in pixels (default: 512)
  -assets-max-previews <N> Maximum number of PNGs written (default: 256)
  -assets-no-textures      Skip textures embedded in 3D models; the material map
                           (which slot, which UV set, which wrap mode) is still reported
  -assets-textures <N>     Embedded textures rendered per model (default: 4)
  -assets-no-bytemap       Suppress byte-map fallback images, keeping only real decodes
  -assets-no-zstd          Do not inflate zstd payloads (.sctx, KTX2 supercompression);
                           report the frame header only, as older builds did
  -assets-no-astc          Do not decode ASTC block-compressed textures; headerless
                           payloads go back to being byte maps, as older builds did

ARTIFACTS (Non-smali / Media / Binary extraction):
  -artifacts              Enable Artifacts panel (images, 3D, .so, other)
  -allow-export           Allow Export buttons in HTML viewer (off by default)
  -artifacts-max-mb <N>   Per-file embed cap (default: 10)
  -artifacts-budget <N>   Total embed cap in MB (default: 200)
  -no-image-blur          Disable blur for possibly sensitive content

MEDIA FORENSICS:
  -enable-media           Enable deep media forensics (polyglots, steganography, GPS/EXIF)
  -extract-ps1            Generate PowerShell script to unpack embedded media payloads
  -media-scan             Enable media file analysis (detect steganography, extract GPS, find payloads)
  -media-payload <str>    Inject this payload into media metadata (e.g. SQLi string)
  -media-stego <path>     Path to a file to hide inside media via steganography (appended to EOF)
  -media-scrub            Scrub all metadata from media files (remove GPS, EXIF)
  -media-recursive-polyglot Feed a polyglot APK/DEX found inside a media file back into analyzer

OBB / DATA / CACHE SCANNERS:
  -obb-scan               Deep-scan OBB expansion files, app data, and cache directories
  -obb-data-dir <path>    Path to Android/data/<pkg>/ or OBB directory (auto-detect if unset)
  -obb-max-size <MB>      Max OBB file size to scan (default: 100, 0=unlimited)
  -obb-json               Write OBB_SCAN_REPORT.json (default: true)
  -cache-scan             Scan app cache for unencrypted saves, API keys, weak crypto
  -cache-data-dir <path>  Override cache directory (default: Android/data/<pkg>/cache)
  -ml-cache-script        Run ML-Apli-Cache predictive exploitation analysis on cache

CONTENT CACHE & DATA-FLOW:
  -enable-content-cache          Enable persistent content-addressed method cache (default: off)
  -content-cache-dir <path>      Path to content cache directory
  -content-cache-max-disk-mb <N> Max disk space for content cache in MB (default: 2048)
  -enable-data-flow              Enable summary-based IFDS/IDE taint & data-flow analysis (default: true)
  -data-flow-max-methods <N>     Max methods for data-flow analysis (default: 200000)
  -data-flow-max-findings <N>    Max findings for data-flow analysis (default: 2000)
  -net-json-events               Emit @@NETEVENT@@ JSON lines on stdout for the DevMega network panel
  -net-remote-edit               Drive packet editing from a remote DevMega client
  -net-filter <expr>             Display filter for intercepted traffic
                                 fields: proto ip[.src|.dst] port[.src|.dst] len dir sni payload
  -net-flows                     Reassemble packets into classified bidirectional flows

NATIVE BINARIES (Machine Code):
  -scan-native           Analyze a PE / ELF / EXE / DLL / SO binary
  -scan-native-reveal-secrets
                         Show unmasked embedded secrets (default: masked)
                          (also auto-detected from .so .dll .exe .elf .dylib .bin .o .a .sys)
                          Output: <output>/machine_code/MACHINE_CODE.md + machine_code.json
  -debugger              Launch interactive machine-code debugger (pass binary path as target)
  -debug-entry <hex|dec> Override entry point for machine-code debugger

BYTECODE:
  -scan-bytecode         Analyze APK, Smali, or textual ASM
  -scan-bytecode-deep    Add offline taint/dataflow analysis (does not execute the target)
                          Output: <output>/bytecode/ reports

TOP-5 INSIGHTS:
  -top5                   Enable JNI + privacy + graph sidecar reports
  -jni-bridge             Java/DEX ↔ native JNI boundary analyzer
  -privacy                Mobile privacy score, sources/sinks, tracker SDKs
  -graph-explorer         Interactive HTML graph (implies JNI + privacy)
  -version-diff, -diff    Compare two APKs/directories: analyzer --diff old.apk new.apk
  -diff-old <path>        Old input for --version-diff
  -diff-new <path>        New input for --version-diff
  -firmware               Firmware / IoT analyzer for a firmware image, archive, or rootfs

MOBSF-DERIVED ANALYZERS:
  -mobsf-all              Enable all MobSF-derived analyzers at once
  -sast-rules             MobSF regex SAST scanner (137 rules incl. gov-SSO/WebView auth, CVSS/CWE/OWASP/MASVS)
  -trackers               Exodus Privacy tracker detection (431 signatures)
  -nsc-audit              Audit res/xml/network_security_config.xml
  -manifest-audit         Deep AndroidManifest audit (exported components, debuggable, deep-links)
  -apkid                  APKiD-style packer / obfuscator / anti-debug fingerprinting

MEDIUM-PRIORITY ANALYZERS:
  -medium-all             Enable all medium-priority analyzers at once
  -playstore              Play Store metadata lookup by package name
  -sbom                   Extract SBOM from Kotlin/Java .version files
  -permmap                Map declared permissions to actual code usage
  -cert-audit             Deep certificate analysis (expiry, debug key, v1/v2/v3 signing)
  -malware-domains        Check extracted URLs against malware domain blacklist
  -niap                   Run NIAP compliance rule scanner
  -known-set <path>       knownset-build bundle: known-bad = loud alert, known-good = info note (never skips analysis)

APK REBUILDING / DECODING (apktool-style) & PATCH EDITOR:
  -apk-editor, -edit      Launch native Zig APK Patch Editor GUI
  -rebuild, -r            Rebuild APK from directory
  -build, -b              Build APK from directory (alias for --rebuild)
  -decode                 Decode APK or DEX to directory (no analysis)
  -no-sign                Skip APK signing (faster rebuild)
  -no-align               Skip ZIP alignment
  -preserve-signature     Experimental: keep original META-INF/signing blocks, skip re-sign (valid only if signed bytes unchanged)
  -ks <path>              Keystore (JKS) for rebuild signing via apksigner; empty = generated debug key
  -ks-alias <name>        Key alias inside -ks (empty = keystore default)
                          Passwords are NEVER flags: ANALYZER_KEYSTORE_PASS / ANALYZER_KEY_PASS env
  -no-resources           Skip resource decoding
  -no-smali               Skip smali generation
  -headers                Include source/hash comments in native Smali
  -no-headers             Omit Smali comment headers (overrides -headers)
  -copy-original          Copy original META-INF for rebuild fidelity
  -framework-dir <path>   Framework directory for resource decoding
  -dex-backend <mode>     Decode backend: auto|native|baksmali (default: auto; native avoids JVM + enables class cache)
  -class-cache            Cache native DEX->Smali per class in .mega-analyzer-cache.db (default: true; use -class-cache=false to disable)
  -smali-jar <path>       Path to smali.jar for smali->dex assembly (auto-detect if unset)
  -baksmali-jar <path>    Path to baksmali.jar for dex->smali disassembly (auto-detect if unset)
  -aapt2 <path>           Path to aapt2 binary for resource compile+link (auto-detect if unset)
  -use-smali              Enable smali->dex assembly during rebuild (default: true)
  -use-aapt2              Enable aapt2 resource compile+link during rebuild (default: true)
  -smali-api <N>          smali/baksmali API level (-a); 0 keeps tool default
  -smali-jobs <N>         smali/baksmali workers (-j); 0 auto-limits per process
  -smali-verbose          Pass --verbose to smali for richer diagnostics
  -smali-incremental      Incremental smali->dex via .mega-analyzer-build-cache.json (default: true; use -smali-incremental=false for full rebuild)
  -baksmali-use-locals    Pass --use-locals to baksmali
  -baksmali-seq-labels    Pass --sequential-labels to baksmali
  -baksmali-no-param-regs Pass --parameter-registers=false to baksmali
  -compression-mode <m>   Rebuild ZIP mode: fast|balanced|best (default: balanced)
  -spool-threshold-mb <N> Spool ZIP entries larger than N MB to temp files (0 = default 128MB)

SANDBOX:
  -sandbox                Run built-in sandbox mode for local sample or Android artifact
  -sandbox-args <args>    Raw arguments for sandbox target
  -sandbox-duration <sec> Auto-stop after N seconds (0 = until stopped; default: 0)
  -sandbox-memory <MB>    Per-process memory cap (default: 512)
  -sandbox-allow-net      Allow real network egress (default: blocked)
  -sandbox-profile <p>    Component preset: basic|trace|forensic|paranoid
  -android-sandbox        Enable Android-native dynamic sandbox execution via ADB
  -sandbox-privserver, -sandbox-private-server <addr>  Private server / MITM proxy address
  -sandbox-avd <name>     Specific AVD name to launch if no device is connected
  -sandbox-auto-avd       Automatically launch the first available AVD
  -sandbox-device <id>    Exact adb serial for the selected device
  -sandbox-uninstall-after Uninstall the app after the sandbox run completes
  -sandbox-capture-traffic Capture raw network traffic via tcpdump on device
  -sandbox-mitm           Run mitmproxy on host for HTTPS interception
  -sandbox-frida          Attach Frida to the detonated app and record instrumentation events
  -sandbox-frida-spawn    Respawn the app under Frida to hook before application code runs
  -sandbox-frida-script <path>
                          Custom Frida instrumentation script (implies -sandbox-frida)
  -sandbox-cpu-cores <N>  Cap guest to N logical CPU cores (0=engine default)
  -sandbox-locale <bcp47> Guest locale, e.g. en-US (Android only)
  -sandbox-timezone <tz>  Guest IANA timezone, e.g. Europe/Moscow (Android only)
  -sandbox-resolution <r> Guest screen resolution WxH or 720p|1080p|1440p (Android only)
  -sandbox-orientation <o> Guest orientation: portrait|landscape (Android only)

PRIVATE SERVER TOOLKIT & LAB DNS:
  -intercept              Run MITM proxy to intercept game traffic
  -port <port>            Port to listen on for interception (default: 9339)
  -upstream <host:port>   Upstream server to proxy to
  -record <file>          File to record intercepted packets (.pcap-like JSON)
  -interactive, -i        Enable live console prompting for altering packet payloads
  -frame <spec>           Reassemble TCP into protocol frames: supercell or len:HDR,OFF,SZ[,inclhdr]
  -fuzz                   Generate protocol-aware mutated frames from a capture
  -fuzz-capture <file>    Recorded -record capture to mutate
  -fuzz-target <host:port> Optional loopback/private host:port to replay mutations against
  -fuzz-out <file>        Path to write the mutation corpus as a JSON manifest
  -servgen                Generate server stub from recorded protocol
  -protocol-spec <file>   Protocol specification JSON
  -from-capture <file>    Build the protocol spec by replaying a -record capture
  -make-server, -privserver Generate authorized-lab Elixir/OTP private server skeleton
  -privserver-game <name> Game name written into the generated project
  -privserver-module <name> Elixir module prefix for the generated project
  -privserver-output <dir> Output directory for the generated Elixir project
  -privserver-port <port> TCP listen port for the generated server (default: 9339)
  -privserver-admin <port> HTTP port for the generated admin dashboard (default: 8765)
  -lab-dns                Run local intercepting DNS server
  -dns-addr <addr>        Listen address for Lab DNS (default: 127.0.0.1:15353)
  -dns-upstream <addr>    Upstream DNS server (empty = offline/refuse non-sinkholed queries)
  -dns-sinkhole <ip>      Sinkhole IP for blocked domains (default: 127.0.0.1)

WINDOWS-NATIVE SANDBOX:
  -win-sandbox            Enable Windows-native sandbox with kernel monitoring
  -sandbox-vss-revert     Automatically revert system changes using VSS after execution
  -sandbox-time-scale <N> Time acceleration factor (1.0=real-time, 10.0=10x faster)
  -sandbox-output <dir>   Output directory for sandbox artifacts (PCAPs, logs, snapshots)
  
  Component Toggles:
  -enable-kernel-monitor  Enable kernel-level filesystem/registry monitoring
  -enable-vss             Enable Volume Shadow Copy snapshots
  -enable-wfp             Enable Windows Filtering Platform network capture
  -enable-api-tracing     Enable Windows API call tracing
  -enable-time-manip      Enable time manipulation (skip sleep delays)
  -sandbox-stream         Stream real-time sandbox telemetry in JSON to stdout

ML ASSISTANT:
  -suggest, -ml           Run ML suggester (rule optimization)
  -history                Show analysis history
  -stats                  Show aggregated statistics
  -ml-train               Train keyword-relevance model from history.json
  -ml-train-ensemble      Train ensemble risk model from history.json
  -ml-train-soft          Include soft labels when training
  -export-suggestions <f> Export suggestions to JSON file
  -ml-confidence <0-1>    Min confidence threshold (default: 0.5)
  -ml-max <N>             Max suggestions to show (default: 10)

ML PATCHER:
  -ml-patch-direct-smali  IDE mode: scan decoded Smali directly, skip duplicate DEX/resource analysis
  -ml-patch               Run Smali patch generator
  -ml-patch-fix           Include generated code and diffs in report
  -mode <name>            Mode: research
                            research  - Generate patches for security research
  -ml-patch-confidence <N> Min confidence for patches (default: 0.3)
  -ml-patch-priority      Sort results by priority (default: true)
  -ml-patch-combination   Enable pattern combination detection (default: true)
  -ml-patch-cross-lang    Enable cross-language detection (default: true)
  -explain                Show detailed explanations in terminal output
  -ml-patch-export-format, -export-format <f> Export format (e.g. md, json, csv)
  -ml-patch-export-output, -export-output <p> Custom output path for patches
  -confidence-threshold <N> Filter output by confidence (0.0-1.0)
  -ml-patch-min-score <0-100> Minimum patch risk score to include (default: 30)
  -ml-patch-min-tier <val> Minimum pattern tier: elite, normal, trash
  -ml-patch-include-libs  Include library code in patch scan
  -ml-patch-deprecated    Enable deprecated patterns
  -ml-patch-sdk           Enable SDK-specific detection (default: true)
  -ml-patch-apply <mode>  dry-run (default) or write
  -ml-patch-backend <e>   Patch apply backend: smali (default) or dex
  -ml-patch-output <dir>  Output directory for patch artifacts
  -ml-patch-feedback-import <f> Import ML patch feedback metrics JSON before scoring
  -ml-patch-feedback-export <f> Export ML patch feedback metrics JSON after scoring
  -save_log, -save-log    Save full console output to a file
  -format, -log-format <f> Log file format: txt (default) | md | ansi
  -log-output, -save-log-output <p> Log file path (default: analysis_log.<ext>)

GAME MODE:
  -gamemode               Включить Epic-режим вывода (ретро-консоль, XP, ранги)
  -gamemode-output <f>    Формат вывода Game Mode: terminal | markdown | json (default: terminal)
  -gamemode-persist       Сохранять XP и прогресс в локальную БД
  -decoy-detection        Поиск ложных приманок и обманных переходов
  -interesting-score      Расчёт индекса интересности кода (Interesting Score)
  -ml-patch-confidence-min <N> Мин. порог доверия для рекомендаций в игровом режиме (default: 0.3)
  -ml-patch-priority-sort Сортировать точки патча по приоритету (default: true)
  -ml-patch-cross-language Кросс-языковой детект (Dalvik ↔ Native) (default: true)

FEEDBACK & LEARNING:
  -mark-relevant <path>   Mark finding/keyword as relevant
  -mark-noise <path>      Mark finding/keyword as noise
  -show-feedback          Show all saved user feedback and export to file
  -ml-apply <ids>         Apply ML suggestions by numbers (e.g. 1,3,5 or 1-10 or all)

EXPERIMENTAL (--ml-ex):
  -aeg                    Run Automated Exploit Generation only (shorthand)
  -ml-ex                  Enable experimental modules
  -ml-ex-apply <selector> Select modules:
                            1-4               by index
                            macho,binsim,...  by id
                            ios,clones,reach  by alias
                            alice|all|hunter  preset bundles
                            offense|mobile    preset bundles
  -ml-ex-list             List available experimental modules and exit
  -ml-ex-output <dir>     Custom dir for experimental artifacts
  -ml-ex-timeout <sec>    Per-module timeout (default: 120, 0=no cap)
  -ml-ex-parallel         Run modules concurrently
  -ml-ex-json             Emit experimental_report.json (default: true)

  Modules:
    1) macho   Mach-O / iOS support           (aliases: ios, ipa, darwin)
    2) binsim  Binary similarity / clones     (aliases: clones, dup, similarity)
    3) reach   Reachability analysis          (aliases: reachability, callgraph-ex)
    4) aeg     Automated Exploit Generation   (aliases: exploit, poc)

  Presets:
    all      every module
    alice    macho + binsim + reach (safe research bundle)
    hunter   binsim + reach
    mobile   macho + reach
    offense  reach + aeg

PATTERN EFFECTIVENESS:
  -pattern-stats          Display pattern effectiveness statistics
  -export-pattern-stats <file> Export pattern stats to JSON file
  -feedback-file <file>   Import feedback from JSON to adjust pattern weights

GNN / PROGUARD:
  -gnn-model <path>       Path to GNN weights JSON (auto-discovers ~/.analyzer/models/gnn_weights.json)
  -skip-gnn               Skip optional GNN classification even when weights are available
  -proguard-map <path>    Path to ProGuard/R8 mapping.txt for name recovery

EVIDENCE EXPLAIN:
  -explain-result <json>  Explain evidence graph results from an analysis JSON
  -explain-node <id>      Restrict explanation to a single evidence graph node
  -explain-file <path>    Restrict explanation to a single file
  -explain-format <fmt>   Explanation output format: text (default) or json

CRACK POINT & ANOMALY:
  -crackpoint-analysis    Enable crack point discovery (default: true)
  -crackpoint-threshold <0-1> Confidence threshold for crack points (default: 0.75)
  -anomaly-detection      Enable anomaly detection (default: true)

DEOBFUSCATION ENGINE:
  -deobf-iterations <N>   Max iterations for deobfuscation loop (0=use default)
  -deobf-min-confidence <0-100> Min confidence threshold (0=use default)
  -enable-deobf-cp        Enable Constant Propagation (default: true)
  -enable-deobf-dce       Enable Dead Code Elimination (default: true)
  -enable-deobf-opr       Enable Opaque Predicate Removal (default: true)
  -enable-deobf-ps        Enable Pattern Simplification (default: true)
  -enable-deobf-vr        Enable Variable Name Recovery (default: true)
  -enable-deobf-mr        Enable Method Name Recovery (default: true)
  -enable-name-quality    Enable Name Quality Analysis (default: true)

JS BUNDLE PATCHER & DEOBF:
  -js-deobf               Enable standalone JS bundle deobfuscator
  -js-deobf-out <file>    Output file for deobfuscated JS bundle
  -js-patch               Enable smart React Native / Hermes bundle patcher
  -js-patch-apply <mode>  dry-run (default) or write
  -js-patch-server-ip <ip> New server address for URL replacement (e.g. 127.0.0.1:9339)
  -js-patch-backup        Create .orig backup before writing patches
  -js-patch-categories <c> Comma-separated category whitelist (empty = all)
  -js-patch-min-conf <N>  Minimum confidence threshold 0-100 (default: 40)
  -js-patch-output <dir>  Output dir for JSPATCH.md / jspatch.json

CACHE MANAGEMENT:
  -cache-stats            Show cache statistics
  -cache-clear            Clear all cache
  -cache-prune            Prune old cache files
  -cache-prune-days <N>   Prune files older than N days (default: 7)
  -validate-config <path> Validate config file

INFO:
  -version, -v            Show version
  -help, -h               Show this help
  -list-profiles          List analysis profiles
  -completion <shell>     Generate shell completion script (bash|zsh|fish)

PROFILES:
  quick      Fast scan, critical patterns only (~30s)
  balanced   Balanced speed and depth (~2min) [default]
  deep       Deep analysis with call graph (~5min)
  paranoid   Maximum depth, all patterns (~10min+)

EXAMPLES:
  # TUI
  analyzer ./decompiled_app                          # Open CLI analysis (default profile)
  analyzer -tui                                      # Open full TUI wizard
  analyzer -tui -t ./app.apk                         # TUI with target preselected

  # Analysis
  analyzer ./decompiled_app                          # Directory analysis
  analyzer -t ./app.apk -artifacts -o ./results      # Analyze APK with non-smali artifacts
  analyzer -t ./classes.dex                          # Analyze DEX file
  analyzer -t ./app -p deep -callgraph               # Deep analysis
  analyzer ./app -workers 8 -dex-only                # Fast DEX-only scan
  analyzer ./app -q -json > results.json             # JSON output

  # Native Binary / Debugger
  analyzer -scan-native -t ./binary.so               # Analyze native ELF/PE binary
  analyzer -debugger -t ./binary.dll                 # Launch interactive machine-code debugger

  # APK Decoding & Building
  analyzer edit ./app.apk                            # Open in native Zig APK Patch Editor GUI
  analyzer decode -t ./app.apk -o ./decompiled_app   # Decode APK
  analyzer build -t ./decompiled_app -o ./app.apk    # Rebuild APK

  # Sandbox
  analyzer --sandbox -t .\sample.exe                 # Run sample offline in sandbox
  analyzer --sandbox -t .\sample.exe --sandbox-args "--check -v"
  analyzer --sandbox -t .\app.apk                    # Static Android profile + permissions
  analyzer --sandbox -t .\decompiled_app             # Static folder inspection

  # Windows-Native Sandbox
  analyzer --win-sandbox -t .\malware.exe            # Full Windows-native sandbox
  analyzer --win-sandbox -t .\sample.exe --enable-kernel-monitor --enable-vss

  # ML Assistant & Patcher
  analyzer --suggest                                 # Get optimization suggestions
  analyzer --ml --ml-confidence 0.7                  # High confidence only
  analyzer -t ./app --ml-patch --mode research       # Generate patches
  analyzer -t ./app --ml-patch --mode research --explain # With detailed explanations

NOTE:
  ML assistant learns from your analysis history.
  Run multiple analyses to improve suggestion quality.
  Use --mark-relevant / --mark-noise to provide feedback.


`+config.GetEnvHelp()+`
`+LookupProfilingHelp()+`
`, AppName, Version)
}
