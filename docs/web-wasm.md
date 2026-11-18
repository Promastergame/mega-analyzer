# Browser deployment

`python scripts/build_web_site.py` compiles the current Go CLI for `js/wasm`
and exports the existing `analyzer --web` assets into `dist/web`. The matching
`wasm_exec.js` is taken from the same installed Go toolchain. For an already
compiled binary, pass `--wasm path/to/analyzer.wasm`.
The builder also compiles `omnisec-ml-gnn` in Rust release mode with SIMD,
LTO and stripped symbols. Install the target once with
`rustup target add wasm32-unknown-unknown`. Prebuilt exports must include
`gnn.wasm` and `gnn_weights.json` next to the Go artifact.

The output folder is a standalone static Netlify project. Publish this folder
through the separate `Promastergame/mega-analyzer-site` repository. Its
`netlify.toml` uses `publish = "."`; no build command, functions or upstream
analysis server are needed. Do not publish the main project's private Git
history or unrelated working-tree files.

The browser bridge routes the existing UI's API calls to local workers.
Each analysis has a fresh worker pool with independent Go runtimes and
in-memory filesystems. Inputs never leave the browser. Stop and the selected
timeout terminate the entire pool, including workers starting up. Timeout
accepts integer seconds from 0 to 3600 (default 300); 0 disables it.
Supported file sizes are at most 32 MiB, with 256 MiB of
virtual file content and 20,000 virtual filesystem entries per worker.
Runtime memory also depends on the input and analysis settings.

The engine is served as `static/analyzer.wasm.gz` with `Content-Encoding:
gzip` and the WASM MIME type. Browsers decompress it before streaming
compilation. The bridge caches the compiled `WebAssembly.Module` for the tab
and clones it into fresh workers, so another job does not download or compile
the engine again. Keep the raw `analyzer.wasm` for integration tests and source
hash verification. `build-info.json` records the gzip size as well as the raw
SHA, selected source fingerprint, compiler, revision and optimization flags.

The pipeline uses feature-only method analysis where the result's CFG and
presentation fields would be discarded. XOR candidate keys are screened with
byte-frequency counts before decoding, preserving the existing printable-byte
thresholds. Detector timings are logged individually to identify remaining
costs. A high-priority licensing match is labelled `Priority matches` in the
CLI summary rather than being presented as a critical vulnerability.

The Go `js/wasm` runtime is single-threaded per Worker. Full and Minecraft
analysis use 1–4 browser Workers (default 2), including the coordinator.
At 4, three helpers scan individual files/classes for pattern matches and
piracy indicators and 22 audited independent detectors through MessageChannels.
Helpers parse a local class AST for operand-aware detectors. They receive no complete APK.
Smali/CFG processing, stateful detectors, cross-class analysis, call graphs,
data flow, detector finalization and reports run once in the coordinator.
Matches retain their original ordering; a failed file task falls back to
local scanning. Other tools perform an indivisible transformation in one
Worker. Each runtime has separate memory, so larger pools increase memory
usage and do not guarantee a speedup. Go goroutines alone do not add CPU cores.
When the browser helper executor is active, one physical-file producer feeds
the selected class workers. This prevents other file goroutines from starving
helper replies in the coordinator's single Go event loop. Native file
concurrency retains its configured value. Helpers initialize only the
detectors they actually execute.

The trained GNN uses `static/gnn.wasm.gz` and `static/gnn_weights.json`.
The coordinator instantiates Rust WASM and passes packed graph tensors from
Go to Rust memory. It reuses the desktop classification stage, confidence
gates and library attribution; no random dummy weights or server are used.
The model and module are reused within the tab, while each scan gets fresh
Rust memory. Browser scans do not write training datasets. `-skip-gnn` is
honored. Build provenance records both module and weight hashes.

Browser progress emits `progress` events so the UI updates one live row
instead of appending every percentage. All raw lines remain in `scan.log`.
The final 99% row names unfinished work rather than claiming a hung scan.

The browser filesystem grows append buffers geometrically rather than copying
the entire report on each template write. Logical content and allocated file
capacity stay within the filesystem quota; spare buffers compact under pressure.
Truncation/regrowth and holes are zero-filled, and result transfers contain
exactly the logical file bytes.

Workers and timeout can be set with a slider or an exact numeric input.
`ma-browser-workers` and `ma-browser-timeout` in localStorage remember them.
A centered native dialog replaces the persistent browser-analysis banner.
It closes with its button, cross, Escape or backdrop; checking “Don't show
again” before closing saves `ma-browser-notice-hidden=1`. The dialog supports
English and Russian and reminds users to download results before reloading.

The piracy detector skips a regular expression on ASCII-only content only
when the expression provably requires a non-ASCII rune (including Unicode
case-fold checks). Two-byte XOR candidates are screened against configured
domains before decoding, preserving the key order, attempt budget and ASCII
case variants. Multiline Base64 stops collecting at the existing 50-candidate
limit rather than scanning every remaining candidate and discarding it.
Mandatory Unicode literals and conjunctions further reduce candidate rules.
For rules with a safe ASCII prefix, a byte scan locates candidate positions
and the original regex checks them anchored there. Leading assertions and
non-ASCII fold classes use the original search. Raw offsets are preserved.
On the local 1,011,505-byte resources JSON, the uncached piracy benchmark
fell from 1.867 seconds to 0.079 seconds; full browser timing is measured
separately, since this is one detector rather than the whole pipeline.

A paired Node/WASM run on `base.apk` (Balanced, same computer and settings,
2026-11-17) took 127.22 seconds before and 102.24 seconds after these changes
(19.6% less time). The piracy detector's recorded cost fell from roughly
37 seconds to 18.55 seconds. All 147 typed findings, category counts, risk
profile and data-flow counters matched after normalizing per-run IDs and
random extraction-directory names. This is one paired measurement, not a
guaranteed speedup for other inputs or computers.

A Chromium comparison of the new pool on the same APK and Balanced settings
(2026-11-17) took 159.14 seconds for analysis with one Worker and 134.33
seconds with four (15.6% less time). End-to-end time, including startup and
reports, was 206.34 and 186.01 seconds respectively; the four-Worker run also
included the initial engine load. The three helpers completed 88, 87 and 84
file tasks. All 147 typed findings, category counts, risk profile and
data-flow counters matched after the same per-run normalization. This is one
paired browser measurement; it is separate from the earlier Node comparison.

After the Rust GNN bridge, independent-detector dispatch and physical-file
scheduling changes (same APK, Balanced, four Workers, 2026-11-17), Chromium
scan time was 67.42 seconds. Post-processing took 28.51 seconds and trained
GNN inference 2.46 seconds: 98.40 seconds for analysis, 133.34 seconds from
start to results. A second run with geometric filesystem buffers took
66.83 seconds to scan, 44.17 seconds in post-processing and 2.45 seconds in
GNN: 113.45 seconds for analysis and 149.39 seconds end-to-end. Post-processing
varied substantially; these measurements do not establish an overall gain
from buffer growth. Helpers completed 772 and 795 tasks, respectively.
All 147 typed findings, risk/category/data-flow counters and 56 accepted
GNN results matched; GNN probabilities differed from native by at most
1.4e-7. Paths and run IDs were normalized for the native comparison.
The coordinator still builds CFGs and performs global data flow, so browser
performance has not reached the native CLI's 14.63 seconds on this input.

Reflection flows track the selected `Method` object. A tainted target object
passed to a fixed method is not evidence of attacker-selected code. Bundle
and Parcel reads retain an unknown-origin marker unless their receiver is
traced to an external source; those candidates remain informational inventory
and do not raise overall risk. Binder `onTransact` data parcels remain IPC
entry points. Explicit external sources and unresolved paths are retained.

Go HTTP requests are blocked inside the worker after the engine loader is
captured, so optional modules cannot transmit inputs to remote services.
Results exist only in this tab. Download them before closing or refreshing
the page. Decode ZIPs preserve hidden project metadata needed to rebuild.
HTML report previews use a sandboxed iframe. Device/VM execution, external
processes, the network proxy and the local DecisionAI HTTP app require the
desktop version and are absent from browser navigation. Native binary
analysis uses the built-in Go fallback; GNN has its own Rust WASM bridge.

Verification:

```sh
node scripts/test_web_wasm.cjs
node scripts/test_gnn_wasm.cjs dist/web
node scripts/test_web_memfs.cjs
go test ./pkg/internal/piracy ./pkg/internal/pipeline
go test ./pkg/cmd/analyzer/web ./pkg/cmd/analyzer
node scripts/test-scan-ui.cjs
node scripts/test-workspace-ui.cjs
```

The WASM integration suite executes the production bridge and worker with
the real binary, browser filesystem callbacks and network access blocked
except for loading the engine. It covers APK build, Smali decode, static
analysis, version comparison, ZIP metadata, workspace files, rejected
paths/modes, 1/4-worker result parity, helper task dispatch, option bounds,
and terminating the full pool on Stop or timeout. Browser checks additionally
verify exact numeric input below/above 300 seconds, settings persistence,
notice dismissal and persistence, actual file selection, parallel worker
execution and report previews under the deployment's CSP.
ZIP output is verified by the integration suite. The current browser test
environment cancels downloads, including a plain text Blob unrelated to
the analyzer, so native downloading still needs verification after deploy.
The Rust bridge test compares trained-model probabilities with the native DLL
on several graphs and rejects malformed CSR, column indices, features and
weights. The detector tests compare JSON-transported results and local fallback
with the coordinator, plus regex offsets and Unicode matching semantics.

## Проверка ложных срабатываний

Для GNN `license-check` одного score/графа недостаточно: runner_gnn_semantics.go требует независимый вызов Android licensing API либо лицензионный протокол вместе с ветвлением/проверкой подписи. Условные wrappers допускаются на один вызов от подтверждённого verifier; метка не распространяется по всему графу. Предсказания без подтверждения сохраняются в GNN_DIAGNOSTICS.json как observation с причиной license_semantics_not_corroborated и счётчиком uncorroborated_predictions. Не повышать порог confidence вместо проверки семантики.

Data-flow CHA может развернуть интерфейсный/виртуальный вызов на несколько реализаций, включая несвязанные Parcelable.Creator и ветки R8 merged classes. Пока receiver не разрешён, шаг помечается unresolved_dispatch. Пути к Class.forName/reflection через такой шаг — inventory с сохранённым source, sink и path. Имя пакета/IsAppCode и отрицательный GNN не являются доказательством безопасности: прямой внешний input→loader остаётся vulnerability даже в library namespace. Проверяй отрицательные и положительные controls в unresolved_dispatch_test.go и fp_dispatch_test.go.

allowBackup=true — наблюдение о политике, не доказательство извлечения private data через adb. Проверяй Android/device API, target SDK, backup rules и включённые чувствительные данные. Импорт syscall — inventory; сам импорт не доказывает обход hooks. При наличии массива typed findings сводка сайта берёт его как итоговую проекцию и не добавляет повторно raw artifact_findings с прежней severity.

Incomplete analysis сохраняется при реальном лимите охвата. Run limitations и сводка показывают число truncated data-flow slices и stop_reason; это ограничение анализа, не обнаруженная угроза.
