// pkg/internal/pipeline/vuln_storage_smali.go
//
// AST-based insecure storage detection (audit item P2-11).
//
// Before this detector the pipeline had no coverage for data written to
// world-readable locations: SharedPreferences opened with the deprecated
// MODE_WORLD_READABLE/WRITEABLE (any app on the device can read/modify
// the prefs XML) and files written onto shared external storage
// (/sdcard, Environment.getExternalStorageDirectory) which every app
// holding READ_EXTERNAL_STORAGE can see.
//
// Detection resolves the ACTUAL mode/operand of each call site:
//
//   - getSharedPreferences(name, mode) / openFileOutput(name, mode):
//     int-mode constant tracked per register; MODE_WORLD_READABLE (0x1)
//     or MODE_WORLD_WRITEABLE (0x2) bits → finding; MODE_PRIVATE (0x0)
//     → silent; unresolved mode → silent (precision over recall).
//   - Writes to external storage: Environment.getExternalStorageDirectory()
//     File provenance is tracked through File(File,String) constructors;
//     FileOutputStream/FileWriter on such a File, or on a literal
//     /sdcard-style path, → finding.

package pipeline

import (
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

const (
	storageModeWorldReadable  int64 = 0x1 // Context.MODE_WORLD_READABLE (deprecated)
	storageModeWorldWriteable int64 = 0x2 // Context.MODE_WORLD_WRITEABLE (deprecated)
)

type VulnInsecureStorageDetector struct{}

func NewVulnInsecureStorageDetector() *VulnInsecureStorageDetector {
	return &VulnInsecureStorageDetector{}
}

func (d *VulnInsecureStorageDetector) Name() string { return "vuln_insecure_storage" }

func (d *VulnInsecureStorageDetector) SupportsFile(fileType types.FileType, _ string) bool {
	return fileType == types.FileTypeSmali
}

func (d *VulnInsecureStorageDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType != types.FileTypeSmali || ctx.Class == nil {
		return
	}
	for i := range ctx.Class.Methods {
		detectInsecureStorageInMethod(&ctx.Class.Methods[i], ctx.Class, analysis)
	}
}

func detectInsecureStorageInMethod(m *types.SmaliMethod, class *types.SmaliClass, analysis *types.FileAnalysis) {
	if len(m.Body) == 0 {
		return
	}
	ints := make(map[string]int64, 16) // mode constant provenance
	strs := make(map[string]string, 8) // literal path provenance
	exts := make(map[string]bool, 4)   // registers holding an external-storage File
	pendingExternal := false           // last invoke was getExternalStorageDirectory

	emit := func(desc, evidence string, severity types.Severity, confidence string, line int) {
		match := newMatch(types.CategoryInsecureStorage, analysis.Path, line, desc, evidence, false)
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

		// move-result consumes the pending invoke result.
		if fields := strings.Fields(strings.ReplaceAll(line, ",", "")); len(fields) >= 2 && strings.HasPrefix(fields[0], "move-result") {
			if pendingExternal {
				exts[fields[1]] = true
			}
			pendingExternal = false
			delete(ints, fields[1])
			delete(strs, fields[1])
			if !exts[fields[1]] {
				delete(exts, fields[1])
			}
			continue
		}

		if strings.HasPrefix(line, "invoke-") {
			pendingExternal = false
			call, ok := parseCryptoInvoke(line)
			if !ok {
				continue
			}
			evalStorageCallSite(call, ints, strs, exts, emit, &pendingExternal, lineNumber)
			continue
		}

		pendingExternal = false
		dest := parseDestRegister(line)
		if dest == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "const-string"):
			if reg, val, ok := parseConstStringLine(line); ok {
				strs[reg] = val
			} else {
				delete(strs, dest)
			}
			delete(ints, dest)
			delete(exts, dest)
		case strings.HasPrefix(line, "const"):
			if strings.HasPrefix(line, "const-wide") {
				delete(ints, dest)
			} else if v, ok := parseSmaliIntOperand(line); ok {
				ints[dest] = v
			} else {
				delete(ints, dest)
			}
			delete(strs, dest)
			delete(exts, dest)
		case strings.HasPrefix(line, "move"):
			src := strings.Fields(strings.ReplaceAll(line, ",", ""))
			if len(src) >= 3 {
				storageCopyOrDelete(ints, dest, src[2])
				storageCopyOrDeleteStr(strs, dest, src[2])
				if exts[src[2]] {
					exts[dest] = true
				} else {
					delete(exts, dest)
				}
			}
		default:
			delete(ints, dest)
			delete(strs, dest)
			delete(exts, dest)
		}
	}
}

func evalStorageCallSite(
	call cryptoInvoke,
	ints map[string]int64,
	strs map[string]string,
	exts map[string]bool,
	emit func(desc, evidence string, severity types.Severity, confidence string, line int),
	pendingExternal *bool,
	lineNumber int,
) {
	switch {
	// ── World-readable/writeable preferences & private files ──
	case call.classDesc == "Landroid/content/Context;" &&
		(call.method == "getSharedPreferences" || call.method == "openFileOutput"):
		if len(call.registers) != 3 {
			return // {receiver, name, mode}
		}
		mode, resolved := ints[call.registers[2]]
		if !resolved {
			return
		}
		worldR := mode&storageModeWorldReadable != 0
		worldW := mode&storageModeWorldWriteable != 0
		if !worldR && !worldW {
			return // MODE_PRIVATE etc.
		}
		desc := call.method + " called with deprecated world-accessible mode:"
		severity := types.SeverityHigh
		if worldR {
			desc += " MODE_WORLD_READABLE — any app on the device can read this data (CWE-732)"
		}
		if worldW {
			desc += " MODE_WORLD_WRITEABLE — any app on the device can modify this data (CWE-732)"
			severity = types.SeverityCritical
		}
		emit(desc, call.method+" mode=0x"+strconv.FormatInt(mode, 16), severity, "high", lineNumber)

	// ── External storage File provenance ──
	case call.classDesc == "Landroid/os/Environment;" && call.method == "getExternalStorageDirectory":
		*pendingExternal = true

	case call.classDesc == "Ljava/io/File;" && call.method == "<init>":
		if len(call.registers) < 2 {
			return
		}
		// File(File parent, String child) / File(String path): receiver
		// inherits externality of the parent or of a literal path.
		if exts[call.registers[1]] {
			exts[call.registers[0]] = true
		} else if path, ok := strs[call.registers[1]]; ok && externalStoragePath(path) {
			exts[call.registers[0]] = true
		} else {
			delete(exts, call.registers[0])
		}

	// ── Writes onto shared external storage ──
	case (call.classDesc == "Ljava/io/FileOutputStream;" || call.classDesc == "Ljava/io/FileWriter;") &&
		call.method == "<init>":
		if len(call.registers) < 2 {
			return
		}
		arg := call.registers[1]
		switch {
		case exts[arg]:
			emit(call.classDesc[1:len(call.classDesc)-1]+" opened on Environment.getExternalStorageDirectory() "+
				"content — written data is visible to every app with storage permission (CWE-312)",
				"external storage write", types.SeverityHigh, "high", lineNumber)
		default:
			if path, ok := strs[arg]; ok && externalStoragePath(path) {
				emit("Write to world-readable external storage path "+path+
					" — data is visible to every app with storage permission (CWE-312)",
					"external storage write", types.SeverityHigh, "high", lineNumber)
			}
		}
	}
}

func storageCopyOrDelete(m map[string]int64, dest, src string) {
	if v, ok := m[src]; ok {
		m[dest] = v
	} else {
		delete(m, dest)
	}
}

func storageCopyOrDeleteStr(m map[string]string, dest, src string) {
	if v, ok := m[src]; ok {
		m[dest] = v
	} else {
		delete(m, dest)
	}
}
