// pkg/internal/pipeline/vuln_dynload_smali.go
//
// AST-based dynamic code loading detection (audit item P2-10).
//
// Before this detector the pipeline only had (a) byte heuristics that flag
// the mere string "DexClassLoader" as malware-level critical (massive false
// positives — hot-patch frameworks use it legitimately) and (b) the dlopen
// obfuscation detector, which only catches StringBuilder-assembled
// loadLibrary names with 2+ appends.
//
// This detector resolves the ACTUAL operand of each load call site:
//
//   - DexClassLoader / PathClassLoader <init>: literal path on world-writable
//     external storage → critical; runtime-computed path → critical
//     (download & execute); literal app-private path → not flagged.
//   - InMemoryDexClassLoader <init>: always critical (payload never touches
//     disk — evasion / shellcode-loader pattern).
//   - System.load / Runtime.load: computed absolute path → high; literal
//     external-storage path → critical; normal literal → not flagged.
//   - System.loadLibrary / Runtime.loadLibrary: computed name → medium
//     (literal names are ordinary JNI and must stay silent).

package pipeline

import (
	pathpkg "path"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// dynLoadWorldWritable prefixes that any other app (or adb) can write to.
var dynLoadWorldWritable = []string{
	"/sdcard", "mnt/sdcard", "/storage/emulated", "/mnt/media_rw",
}

type VulnDynamicLoadDetector struct{}

func NewVulnDynamicLoadDetector() *VulnDynamicLoadDetector {
	return &VulnDynamicLoadDetector{}
}

func (d *VulnDynamicLoadDetector) Name() string { return "vuln_dynamic_load" }

func (d *VulnDynamicLoadDetector) SupportsFile(fileType types.FileType, _ string) bool {
	return fileType == types.FileTypeSmali
}

func (d *VulnDynamicLoadDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType != types.FileTypeSmali || ctx.Class == nil {
		return
	}
	for i := range ctx.Class.Methods {
		detectDynamicLoadInMethod(&ctx.Class.Methods[i], ctx.Class, analysis)
	}
}

func detectDynamicLoadInMethod(m *types.SmaliMethod, class *types.SmaliClass, analysis *types.FileAnalysis) {
	if len(m.Body) == 0 {
		return
	}
	// const-string provenance: present ⇒ literal value known; absent ⇒ the
	// register was written by computation/parameter/invoke (⇒ "computed").
	strs := make(map[string]string, 8)

	emit := func(desc, evidence string, severity types.Severity, critical bool, confidence string, line int) {
		match := newMatch(types.CategoryDynamicLoad, analysis.Path, line, desc, evidence, critical)
		match.Severity = severity
		match.MethodName = m.Name
		match.ClassName = class.Name
		match.Confidence = confidence
		match.EvidenceType = "smali_ast_dataflow"
		analysis.Matches = append(analysis.Matches, match)
	}

	for bodyIdx, raw := range m.Body {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, ".") || strings.HasPrefix(line, ":") {
			continue
		}
		lineNumber := m.LineStart + bodyIdx

		if !strings.HasPrefix(line, "invoke-") {
			dest := parseDestRegister(line)
			if dest == "" {
				continue
			}
			if strings.HasPrefix(line, "const-string") {
				if reg, val, ok := parseConstStringLine(line); ok {
					strs[reg] = val
					continue
				}
			}
			if strings.HasPrefix(line, "move") {
				src := strings.Fields(strings.ReplaceAll(line, ",", ""))
				if len(src) >= 3 {
					if s, ok := strs[src[2]]; ok {
						strs[dest] = s
						continue
					}
				}
			}
			delete(strs, dest)
			continue
		}

		call, ok := parseCryptoInvoke(line)
		if !ok {
			continue
		}

		switch {
		// ── DEX class loaders ──
		case call.classDesc == "Ldalvik/system/InMemoryDexClassLoader;" && call.method == "<init>":
			// Loading DEX from memory alone is not proof of an untrusted payload:
			// legitimate packers and modular runtimes use it too. A critical result
			// requires an independently proven untrusted source → ByteBuffer flow.
			emit("InMemoryDexClassLoader used — verify that the DEX ByteBuffer comes from a "+
				"trusted, integrity-checked source",
				"InMemoryDexClassLoader.<init>", types.SeverityMedium, false, "medium", lineNumber)

		case (call.classDesc == "Ldalvik/system/DexClassLoader;" ||
			call.classDesc == "Ldalvik/system/PathClassLoader;") && call.method == "<init>":
			loader := strings.TrimSuffix(strings.TrimPrefix(call.classDesc, "Ldalvik/system/"), ";")
			if len(call.registers) < 2 {
				continue
			}
			path, literal := strs[call.registers[1]]
			switch {
			case literal && externalStoragePath(path):
				emit(loader+" loads DEX from world-writable external storage ("+path+
					") — any app can replace the payload for code execution (CWE-829)",
					loader+".<init> external path", types.SeverityCritical, true, "high", lineNumber)
			case literal:
				// Literal app-private path: ordinary hot-patch/loader usage.
			default:
				emit(loader+" invoked with a runtime-computed DEX path — "+
					"download & execute pattern; the payload source must be verified (CWE-494)",
					loader+".<init> computed path", types.SeverityCritical, true, "medium", lineNumber)
			}

		// ── Absolute-path native loading ──
		case (call.classDesc == "Ljava/lang/System;" || call.classDesc == "Ljava/lang/Runtime;") &&
			call.method == "load":
			path, literal := libNameRegister(call, strs)
			if literal && externalStoragePath(path) {
				emit("System.load loads a native library from world-writable external storage ("+
					path+") — any app can replace the .so for code execution (CWE-829)",
					"System.load external path", types.SeverityCritical, true, "high", lineNumber)
			} else if !literal {
				emit("System.load invoked with a runtime-computed absolute library path — "+
					"the .so origin cannot be verified (CWE-427)",
					"System.load computed path", types.SeverityHigh, false, "medium", lineNumber)
			}

		// ── Named native loading ──
		case (call.classDesc == "Ljava/lang/System;" || call.classDesc == "Ljava/lang/Runtime;") &&
			call.method == "loadLibrary":
			if _, literal := libNameRegister(call, strs); !literal {
				emit("loadLibrary invoked with a runtime-computed library name — "+
					"obfuscated or input-driven native loading (CWE-427)",
					"loadLibrary computed name", types.SeverityMedium, false, "medium", lineNumber)
			}
		}
	}
}

// libNameRegister returns the String operand of a System (static) or Runtime
// (instance) load/loadLibrary call and whether it resolved to a literal.
func libNameRegister(call cryptoInvoke, strs map[string]string) (string, bool) {
	argIndex := 0 // System.load/loadLibrary are static: {stringArg}
	if call.classDesc == "Ljava/lang/Runtime;" {
		argIndex = 1 // Runtime methods are virtual: {runtimeReceiver, stringArg}
	}
	if len(call.registers) <= argIndex {
		return "", false
	}
	value, ok := strs[call.registers[argIndex]]
	return value, ok
}

func externalStoragePath(path string) bool {
	clean := pathpkg.Clean(strings.ReplaceAll(path, "\\", "/"))
	for _, prefix := range dynLoadWorldWritable {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return true
		}
	}
	// Removable/shared external volumes use IDs such as /storage/ABCD-1234.
	if strings.HasPrefix(clean, "/storage/") {
		return true
	}
	return false
}
