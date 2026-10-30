package insights

import (
	"bytes"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/nativeartifacts"
)

var constStringRe = regexp.MustCompile(`const-string(?:/jumbo)?\s+([vp]\d+),\s+"([^"]*)"`)
var invokeRegsRe = regexp.MustCompile(`\{([^}]*)\}`)
var jniSymbolRe = regexp.MustCompile(`Java_[A-Za-z0-9_]+`)

func AnalyzeJNI(target string) (*JNIReport, error) {
	files, err := LoadFiles(target, LoadOptions{MaxBytesPerFile: 32 << 20, IncludeBinary: true})
	if err != nil {
		return nil, err
	}
	report := &JNIReport{GeneratedAt: time.Now(), Target: target}
	classFiles := map[string]string{}
	methodsByKey := map[string]NativeMethod{}
	loadsByClass := map[string][]LibraryLoad{}
	libsByName := map[string]NativeLibrary{}

	for _, f := range files {
		lower := strings.ToLower(f.Path)
		switch {
		case strings.HasSuffix(lower, ".smali"):
			cls, loads, methods := scanSmaliJNI(f)
			if cls != "" {
				classFiles[cls] = f.Path
			}
			report.LoadLibraries = append(report.LoadLibraries, loads...)
			report.NativeMethods = append(report.NativeMethods, methods...)
			for _, l := range loads {
				loadsByClass[l.Class] = append(loadsByClass[l.Class], l)
			}
			for _, m := range methods {
				methodsByKey[m.Class+"->"+m.Method] = m
			}
		case strings.HasSuffix(lower, ".so") || strings.HasSuffix(lower, ".dylib") || strings.HasSuffix(lower, ".dll"):
			lib := scanNativeLibraryJNI(f)
			report.NativeLibraries = append(report.NativeLibraries, lib)
			libsByName[lib.Name] = lib
			if lib.RegisterNatives {
				report.RegisterNatives = append(report.RegisterNatives, Evidence{Path: f.Path, Snippet: "RegisterNatives"})
			}
		}
	}

	classes := make([]string, 0, len(classFiles))
	for cls := range classFiles {
		classes = append(classes, cls)
	}
	sort.Strings(classes)
	matched := map[string]struct{}{}

	for _, lib := range report.NativeLibraries {
		for _, sym := range lib.JNIExports {
			ref, ok := nativeartifacts.ResolveJNI(sym, classes)
			if ref == "" {
				continue
			}
			cls, method := splitSmaliRef(ref)
			key := cls + "->" + method
			confidence := 0.75
			reason := "JNI export resolved but class was not found in Smali"
			if ok {
				confidence = 0.95
				reason = "JNI export resolved to a Smali class"
			}
			if _, exists := methodsByKey[key]; exists {
				confidence = 1.0
				reason = "JNI export matches declared native method"
				matched[key] = struct{}{}
			}
			report.Bindings = append(report.Bindings, JNIBinding{
				JavaClass:    cls,
				JavaMethod:   method,
				NativeSymbol: sym,
				Library:      lib.Name,
				LibraryPath:  lib.Path,
				Confidence:   confidence,
				Reason:       reason,
			})
		}
	}

	for _, m := range report.NativeMethods {
		key := m.Class + "->" + m.Method
		if _, ok := matched[key]; ok {
			continue
		}
		for _, load := range loadsByClass[m.Class] {
			lib, exists := libsByName[load.Library]
			if !exists {
				continue
			}
			report.Bindings = append(report.Bindings, JNIBinding{
				JavaClass:   m.Class,
				JavaMethod:  m.Method,
				Library:     load.Library,
				LibraryPath: lib.Path,
				Confidence:  0.55,
				Reason:      "same Smali class declares native method and loads this library",
			})
			matched[key] = struct{}{}
			break
		}
	}

	for _, m := range report.NativeMethods {
		if _, ok := matched[m.Class+"->"+m.Method]; !ok {
			report.UnresolvedMethods = append(report.UnresolvedMethods, m)
		}
	}

	sort.Slice(report.Bindings, func(i, j int) bool {
		if report.Bindings[i].JavaClass != report.Bindings[j].JavaClass {
			return report.Bindings[i].JavaClass < report.Bindings[j].JavaClass
		}
		return report.Bindings[i].JavaMethod < report.Bindings[j].JavaMethod
	})
	report.Score = scoreJNI(report)
	report.Findings = buildJNIFindings(report)
	return report, nil
}

func scanSmaliJNI(f ScannedFile) (string, []LibraryLoad, []NativeMethod) {
	lines := bytes.Split(f.Data, []byte{'\n'})
	className := ""
	currentMethod := ""
	consts := map[string]string{}
	var loads []LibraryLoad
	var methods []NativeMethod
	for i, raw := range lines {
		line := strings.TrimSpace(string(raw))
		if strings.HasPrefix(line, ".class") {
			if cls := parseSmaliClass(line); cls != "" {
				className = cls
			}
		}
		if strings.HasPrefix(line, ".method") {
			consts = map[string]string{}
			currentMethod = parseSmaliMethodName(line)
			if strings.Contains(" "+line+" ", " native ") {
				if nm := parseNativeMethod(line, className, f.Path, i+1); nm.Method != "" {
					methods = append(methods, nm)
				}
			}
		}
		if strings.HasPrefix(line, ".end method") {
			currentMethod = ""
			consts = map[string]string{}
		}
		if m := constStringRe.FindStringSubmatch(line); len(m) == 3 {
			consts[m[1]] = m[2]
		}
		if strings.Contains(strings.ToLower(line), "ljava/lang/system;->loadlibrary") {
			lib := "unknown"
			if regs := invokeRegsRe.FindStringSubmatch(line); len(regs) == 2 {
				parts := strings.Split(regs[1], ",")
				if len(parts) > 0 {
					reg := strings.TrimSpace(parts[0])
					if v := consts[reg]; v != "" {
						lib = strings.TrimPrefix(strings.TrimSuffix(v, ".so"), "lib")
					}
				}
			}
			loads = append(loads, LibraryLoad{Library: lib, Class: className, Method: currentMethod, File: f.Path, Line: i + 1})
		}
	}
	return className, loads, methods
}

func scanNativeLibraryJNI(f ScannedFile) NativeLibrary {
	name := filepath.Base(f.Path)
	name = strings.TrimSuffix(strings.TrimPrefix(name, "lib"), filepath.Ext(name))
	stringsList := extractASCIIStrings(f.Data, 6)
	seen := map[string]struct{}{}
	var exports []string
	register := false
	for _, s := range stringsList {
		if strings.Contains(s, "RegisterNatives") || strings.Contains(s, "JNI_OnLoad") {
			register = register || strings.Contains(s, "RegisterNatives")
		}
		for _, sym := range jniSymbolRe.FindAllString(s, -1) {
			if _, ok := seen[sym]; ok {
				continue
			}
			seen[sym] = struct{}{}
			exports = append(exports, sym)
		}
	}
	sort.Strings(exports)
	lib := NativeLibrary{Name: name, Path: f.Path, Size: f.Size, JNIExports: exports, RegisterNatives: register}
	if bytes.Contains(f.Data, []byte("JNI_OnLoad")) {
		lib.Signals = append(lib.Signals, Evidence{Path: f.Path, Snippet: "JNI_OnLoad"})
	}
	if register {
		lib.Signals = append(lib.Signals, Evidence{Path: f.Path, Snippet: "RegisterNatives"})
	}
	return lib
}

func parseSmaliClass(line string) string {
	fields := strings.Fields(line)
	for i := len(fields) - 1; i >= 0; i-- {
		if strings.HasPrefix(fields[i], "L") && strings.HasSuffix(fields[i], ";") {
			return fields[i]
		}
	}
	return ""
}

func parseSmaliMethodName(line string) string {
	idx := strings.Index(line, "(")
	if idx < 0 {
		return ""
	}
	before := strings.TrimSpace(line[:idx])
	fields := strings.Fields(before)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func parseNativeMethod(line, className, file string, lineNo int) NativeMethod {
	method := parseSmaliMethodName(line)
	if method == "" {
		return NativeMethod{}
	}
	idx := strings.Index(line, method+"(")
	sig := ""
	if idx >= 0 {
		sig = strings.TrimSpace(line[idx+len(method):])
	}
	return NativeMethod{Class: className, Method: method, Signature: sig, File: file, Line: lineNo}
}

func splitSmaliRef(ref string) (string, string) {
	parts := strings.SplitN(ref, "->", 2)
	if len(parts) != 2 {
		return ref, ""
	}
	method := parts[1]
	if idx := strings.Index(method, "("); idx >= 0 {
		method = method[:idx]
	}
	return parts[0], method
}

func scoreJNI(report *JNIReport) int {
	score := 0
	if len(report.Bindings) > 0 {
		score += 20
	}
	if len(report.NativeLibraries) > 0 {
		score += 10
	}
	if len(report.RegisterNatives) > 0 {
		score += 20
	}
	for _, m := range report.NativeMethods {
		if isSensitiveNativeName(m.Method) {
			score += 8
		}
	}
	if len(report.UnresolvedMethods) > 0 {
		score += 10
	}
	if score > 100 {
		return 100
	}
	return score
}

func buildJNIFindings(report *JNIReport) []Finding {
	var out []Finding
	if len(report.Bindings) > 0 {
		out = append(out, Finding{Severity: "medium", Category: "jni", Title: "Java to native boundary mapped", Detail: "JNI bindings: " + intString(len(report.Bindings))})
	}
	if len(report.RegisterNatives) > 0 {
		out = append(out, Finding{Severity: "high", Category: "jni", Title: "Dynamic JNI registration detected", Detail: "RegisterNatives can hide Java to native mapping from static exports"})
	}
	for _, m := range report.NativeMethods {
		if isSensitiveNativeName(m.Method) {
			out = append(out, Finding{Severity: "high", Category: "jni", Path: m.File, Line: m.Line, Title: "Sensitive native method", Detail: m.Class + "->" + m.Method + m.Signature})
		}
	}
	return out
}

func isSensitiveNativeName(name string) bool {
	lower := strings.ToLower(name)
	for _, token := range []string{"root", "debug", "frida", "xposed", "emulator", "license", "premium", "integrity", "signature", "decrypt", "token"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func intString(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
