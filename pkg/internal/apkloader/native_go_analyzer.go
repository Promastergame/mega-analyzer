package apkloader

// native_go_analyzer.go — pure-Go machine-code analyzer.
//
// This is the fallback (and corroborating) native scanner used when the Rust
// `omnisec-scan-native` FFI library is not linked, or to enrich its output. It
// relies only on the Go standard library (`debug/elf`, `debug/pe`, `debug/macho`)
// so machine-code analysis works on every build with zero native toolchain.
//
// It is intentionally fast and read-only: parse the headers, read the hardening
// posture, sweep strings/symbols for high-signal indicators. No emulation.

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"math"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/peinspect"
)

// AnalyzeNativeGo inspects a native binary (ELF / PE / Mach-O) using only the
// Go standard library and returns a NativeScanReport compatible with the Rust
// scanner's output shape. Returns (nil, false) if the bytes are not a
// recognized native format.
func AnalyzeNativeGo(data []byte) (*NativeScanReport, bool) {
	switch {
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return analyzeELFGo(data), true
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return analyzePEGo(data), true
	case isJavaClassFile(data):
		// JVM classes share 0xCAFEBABE with Mach-O fat binaries. Kotlin
		// coroutines ship DebugProbesKt.bin inside the APK, and routing it to
		// the Mach-O parser produced a bogus "Mach-O parse failed" finding.
		return nil, false
	case isMachOMagic(data):
		return analyzeMachOGo(data), true
	}
	return nil, false
}

// isJavaClassFile reports whether data is a JVM class file. The magic is shared
// with Mach-O fat binaries, so the version words disambiguate: a class has a
// minor version of 0/1 and a major version of 45 (Java 1.1) or newer, while a
// fat binary stores its small architecture count in those bytes.
func isJavaClassFile(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	if data[0] != 0xCA || data[1] != 0xFE || data[2] != 0xBA || data[3] != 0xBE {
		return false
	}
	minor := uint16(data[4])<<8 | uint16(data[5])
	major := uint16(data[6])<<8 | uint16(data[7])
	return minor <= 1 && major >= 45 && major <= 80
}

func isMachOMagic(data []byte) bool {
	if len(data) < 4 || isJavaClassFile(data) {
		return false
	}
	m := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	switch m {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, // thin (BE/LE, 32/64)
		0xCAFEBABE, 0xBEBAFECA: // fat
		return true
	}
	return false
}

// ── ELF ──────────────────────────────────────────────────────────────────────

func analyzeELFGo(data []byte) *NativeScanReport {
	rep := &NativeScanReport{
		TargetFormat:   "elf",
		TargetSize:     len(data),
		ScannerVersion: "go-native/1.0",
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		rep.Verdict = "parse-error"
		rep.Findings = append(rep.Findings, mkFinding("elf-parse", "format",
			"low", "ELF parse failed", err.Error()))
		return rep
	}
	defer f.Close()

	rep.TargetArch = elfArch(f.Machine)

	// Hardening posture.
	nx := elfHasNX(f)
	pie := f.Type == elf.ET_DYN
	relro := elfRelro(f)
	canary := elfHasSymbol(f, "__stack_chk_fail", "__stack_chk_guard")
	fortify := elfHasFortify(f)
	stripped := !elfHasSection(f, ".symtab")
	rep.Hardening = HardeningReport{
		NX: &nx, PIE: &pie, Relro: relro,
		StackCanary: &canary, FortifySource: &fortify, Stripped: &stripped,
		WxSections: elfWXSections(f),
	}

	addHardeningFindings(rep, nx, pie, relro, canary)
	if rep.Hardening.WxSections > 0 {
		rep.Findings = append(rep.Findings, mkFinding("wx-section", "hardening",
			"high", "Writable + executable segment",
			fmt.Sprintf("%d W^X-violating segment(s)", rep.Hardening.WxSections)))
	}

	// String / import / export sweep.
	strs := extractStrings(data, 5)
	scanNativeStrings(rep, strs)
	scanELFImports(rep, f)
	scanELFExports(rep, f)
	addEntropyAndPacker(rep, data)

	finalizeNativeReport(rep)
	return rep
}

// scanELFExports inspects exported dynamic symbols for the JNI surface. A large
// `Java_*` export table plus `JNI_OnLoad` means meaningful logic lives in native
// code (and feeds the APK JNI binding resolver downstream).
func scanELFExports(rep *NativeScanReport, f *elf.File) {
	syms, err := f.DynamicSymbols()
	if err != nil {
		return
	}
	jniCount := 0
	onLoad := false
	for _, s := range syms {
		if s.Name == "JNI_OnLoad" {
			onLoad = true
		}
		if strings.HasPrefix(s.Name, "Java_") {
			jniCount++
		}
	}
	if jniCount > 0 || onLoad {
		rep.Findings = append(rep.Findings, mkFinding("jni-surface", "jni", "low",
			"JNI native surface",
			fmt.Sprintf("%d exported Java_* symbol(s); JNI_OnLoad=%t — logic implemented in native code",
				jniCount, onLoad)))
	}
}

func elfArch(m elf.Machine) string {
	switch m {
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_X86_64:
		return "x86_64"
	case elf.EM_386:
		return "x86"
	case elf.EM_RISCV:
		return "riscv"
	case elf.EM_MIPS:
		return "mips"
	}
	return m.String()
}

func elfHasNX(f *elf.File) bool {
	// NX present == there is a GNU_STACK program header WITHOUT the execute bit.
	for _, p := range f.Progs {
		if p.Type == elf.PT_GNU_STACK {
			return p.Flags&elf.PF_X == 0
		}
	}
	// No GNU_STACK header → kernel default is non-exec stack on modern targets.
	return true
}

func elfRelro(f *elf.File) string {
	hasRelro := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_GNU_RELRO {
			hasRelro = true
			break
		}
	}
	if !hasRelro {
		return "none"
	}
	// Full RELRO requires BIND_NOW in the dynamic flags.
	if ds := f.Section(".dynamic"); ds != nil {
		if d, err := f.DynValue(elf.DT_FLAGS); err == nil {
			for _, v := range d {
				if v&uint64(elf.DF_BIND_NOW) != 0 {
					return "full"
				}
			}
		}
		if d, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
			for _, v := range d {
				if v&uint64(elf.DF_1_NOW) != 0 {
					return "full"
				}
			}
		}
	}
	return "partial"
}

func elfHasFortify(f *elf.File) bool {
	syms, _ := f.DynamicSymbols()
	for _, s := range syms {
		if strings.HasSuffix(s.Name, "_chk") {
			return true
		}
	}
	return false
}

func elfHasSymbol(f *elf.File, names ...string) bool {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if want[s.Name] {
				return true
			}
		}
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		for _, s := range syms {
			if want[s.Name] {
				return true
			}
		}
	}
	return false
}

func elfHasSection(f *elf.File, name string) bool { return f.Section(name) != nil }

func elfWXSections(f *elf.File) int {
	n := 0
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X != 0 {
			n++
		}
	}
	return n
}

func scanELFImports(rep *NativeScanReport, f *elf.File) {
	syms, err := f.ImportedSymbols()
	if err != nil {
		return
	}
	names := make([]string, 0, len(syms))
	for _, s := range syms {
		names = append(names, s.Name)
	}
	scanNativeImports(rep, names)
}

// ── PE ───────────────────────────────────────────────────────────────────────

func analyzePEGo(data []byte) *NativeScanReport {
	rep := &NativeScanReport{
		TargetFormat:   "pe",
		TargetSize:     len(data),
		ScannerVersion: "go-native/1.0",
	}
	meta, err := peinspect.Inspect(data)
	if err != nil {
		rep.Verdict = "parse-error"
		rep.Findings = append(rep.Findings, mkFinding("pe-parse", "format", "low", "PE parse failed", err.Error()))
		return rep
	}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		rep.Verdict = "parse-error"
		rep.Findings = append(rep.Findings, mkFinding("pe-parse", "format",
			"low", "PE parse failed", err.Error()))
		return rep
	}
	defer f.Close()

	rep.TargetArch = meta.Architecture
	rep.PE = meta
	dllChar := meta.DllCharacteristics

	// Managed (.NET) images carry their real logic in CLI metadata, not in
	// native imports (which are just mscoree._CorExeMain). Surface assembly
	// identity, entry point and trust-relevant attributes as findings.
	if dn, err := peinspect.ParseDotNet(data); err == nil && dn != nil {
		rep.TargetFormat = "pe-dotnet"
		rep.DotNet = dn
		rep.Findings = append(rep.Findings, dotnetFindings(dn)...)
	}

	const (
		dynamicBase    = 0x0040 // ASLR
		nxCompat       = 0x0100 // DEP/NX
		guardCF        = 0x4000 // Control Flow Guard
		relocsStripped = 0x0001 // COFF IMAGE_FILE_RELOCS_STRIPPED
	)
	// ASLR is only effective with a relocation table the loader can apply:
	// the DYNAMICBASE flag alone does nothing once relocations are stripped
	// or the base-relocation directory is empty. CFG likewise arms itself
	// through the load config; without that directory the flag is inert.
	aslr := dllChar&dynamicBase != 0 &&
		meta.FileCharacteristics&relocsStripped == 0 &&
		meta.HasRelocations && meta.RelocValid
	nx := dllChar&nxCompat != 0
	cfg := dllChar&guardCF != 0 && meta.CFValid
	stripped := len(f.Symbols) == 0

	wx := 0
	for _, s := range f.Sections {
		if s.Characteristics&0x80000000 != 0 && s.Characteristics&0x20000000 != 0 {
			wx++
		}
	}
	rep.Hardening = HardeningReport{
		NX: &nx, PIE: &aslr, StackCanary: meta.StackCookie, Stripped: &stripped,
		WxSections: wx,
	}
	if wx > 0 {
		rep.Findings = append(rep.Findings, mkFinding("wx-section", "hardening",
			"high", "Writable + executable section",
			fmt.Sprintf("%d W+X section(s)", wx)))
	}
	if !nx {
		rep.Findings = append(rep.Findings, mkFinding("no-dep", "hardening", "medium",
			"DEP/NX disabled", "NXCOMPAT bit not set in DllCharacteristics"))
	}
	if !aslr {
		why := "DYNAMICBASE bit not set in DllCharacteristics"
		switch {
		case dllChar&dynamicBase != 0 && meta.FileCharacteristics&relocsStripped != 0:
			why = "DYNAMICBASE set but IMAGE_FILE_RELOCS_STRIPPED — nothing to relocate through"
		case dllChar&dynamicBase != 0:
			why = "DYNAMICBASE set but the base-relocation directory is empty"
		}
		rep.Findings = append(rep.Findings, mkFinding("no-aslr", "hardening", "medium",
			"ASLR disabled", why))
	}
	if !cfg {
		why := "GUARD_CF bit not set"
		if dllChar&guardCF != 0 {
			why = "GUARD_CF set but no load config — CFG is not armed"
		}
		rep.Findings = append(rep.Findings, mkFinding("no-cfg", "hardening", "low",
			"Control Flow Guard disabled", why))
	}

	// Always walk both import directories: debug/pe can return a non-empty
	// but incomplete result when a later descriptor uses FirstThunk only.
	imports := inspectPEImports(data)
	scanNativeImports(rep, imports.Names)
	if imports.Delayed > 0 {
		rep.Findings = append(rep.Findings, mkFinding("pe-delay-imports", "import", "info",
			"Delay-loaded imports inspected", fmt.Sprintf("Inspected %d named delay-load import(s); these are static capabilities, not observed API calls", imports.Delayed)))
	}
	if len(imports.Warnings) > 0 {
		rep.Findings = append(rep.Findings, mkFinding("pe-imports-incomplete", "format", "low",
			"Import analysis has incomplete coverage", strings.Join(imports.Warnings, "; ")))
	}
	scanNativeStrings(rep, extractStrings(data, 5))
	addEntropyAndPacker(rep, data)

	finalizeNativeReport(rep)
	return rep
}

// ── Mach-O ─────────────────────────────────────────────────────────────────

func analyzeMachOGo(data []byte) *NativeScanReport {
	rep := &NativeScanReport{
		TargetFormat:   "macho",
		TargetSize:     len(data),
		ScannerVersion: "go-native/1.0",
	}
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		rep.Verdict = "parse-error"
		rep.Findings = append(rep.Findings, mkFinding("macho-parse", "format",
			"low", "Mach-O parse failed", err.Error()))
		return rep
	}
	defer f.Close()

	switch f.Cpu {
	case macho.CpuArm64:
		rep.TargetArch = "arm64"
	case macho.CpuAmd64:
		rep.TargetArch = "x86_64"
	case macho.Cpu386:
		rep.TargetArch = "x86"
	default:
		rep.TargetArch = f.Cpu.String()
	}

	// PIE flag lives in the Mach-O header flags (MH_PIE = 0x200000).
	const mhPIE = 0x200000
	pie := f.Flags&mhPIE != 0
	rep.Hardening = HardeningReport{PIE: &pie}
	if !pie {
		rep.Findings = append(rep.Findings, mkFinding("no-pie", "hardening", "medium",
			"PIE disabled", "MH_PIE flag not set"))
	}

	if imps, err := f.ImportedSymbols(); err == nil {
		scanNativeImports(rep, imps)
	}
	scanNativeStrings(rep, extractStrings(data, 5))
	addEntropyAndPacker(rep, data)

	finalizeNativeReport(rep)
	return rep
}

// ── Shared helpers ───────────────────────────────────────────────────────────

func addHardeningFindings(rep *NativeScanReport, nx, pie bool, relro string, canary bool) {
	if !nx {
		rep.Findings = append(rep.Findings, mkFinding("no-nx", "hardening", "medium",
			"NX (No-Execute) disabled", "executable stack permitted"))
	}
	if !pie {
		rep.Findings = append(rep.Findings, mkFinding("no-pie", "hardening", "medium",
			"PIE disabled", "binary is not position-independent (ET_EXEC)"))
	}
	if relro == "none" {
		rep.Findings = append(rep.Findings, mkFinding("no-relro", "hardening", "medium",
			"RELRO disabled", "GOT is writable for the lifetime of the process"))
	} else if relro == "partial" {
		rep.Findings = append(rep.Findings, mkFinding("partial-relro", "hardening", "low",
			"Partial RELRO", "GOT is not bound at load time (no BIND_NOW)"))
	}
	if !canary {
		rep.Findings = append(rep.Findings, mkFinding("no-canary", "hardening", "low",
			"Stack canary missing", "no __stack_chk_fail reference found"))
	}
}

// nativeImportRules maps a dangerous imported symbol to a finding.
var nativeImportRules = []struct {
	sym, sev, title, desc string
}{
	{"system", "high", "Process execution via system()", "libc system() import"},
	{"popen", "high", "Process execution via popen()", "libc popen() import"},
	{"execve", "high", "Process execution via execve()", "exec-family import"},
	{"execvp", "high", "Process execution via execvp()", "exec-family import"},
	{"dlopen", "medium", "Dynamic library loading", "dlopen() import — runtime code loading"},
	{"dlsym", "medium", "Dynamic symbol resolution", "dlsym() import"},
	{"ptrace", "medium", "Anti-debugging / process tracing", "ptrace() import"},
	{"mprotect", "medium", "Runtime memory protection change", "mprotect() — possible self-modifying / JIT / unpacker"},
	{"mmap", "low", "Runtime memory mapping", "mmap() import"},
	{"WinExec", "high", "Process execution (WinExec)", "WinExec import"},
	{"ShellExecuteA", "high", "Process execution (ShellExecute)", "ShellExecute import"},
	{"ShellExecuteW", "high", "Process execution (ShellExecute)", "ShellExecute import"},
	{"CreateProcessA", "high", "Process creation", "CreateProcess import"},
	{"CreateProcessW", "high", "Process creation", "CreateProcess import"},
	{"VirtualProtect", "medium", "Runtime memory protection change", "VirtualProtect — possible unpacker / shellcode loader"},
	{"VirtualAllocEx", "high", "Remote memory allocation", "VirtualAllocEx — process injection primitive"},
	{"WriteProcessMemory", "high", "Remote memory write", "WriteProcessMemory — process injection primitive"},
	{"IsDebuggerPresent", "medium", "Anti-debugging", "IsDebuggerPresent import"},
	{"LoadLibraryA", "low", "Dynamic library loading", "LoadLibrary import"},
	{"GetProcAddress", "low", "Dynamic symbol resolution", "GetProcAddress import"},
	{"CreateRemoteThread", "high", "Remote thread creation", "CreateRemoteThread — process injection primitive"},
	{"NtUnmapViewOfSection", "high", "Process hollowing", "NtUnmapViewOfSection — process hollowing primitive"},
	{"SetWindowsHookExA", "medium", "Global hook / keylogging", "SetWindowsHookEx — input hooking"},
	{"SetWindowsHookExW", "medium", "Global hook / keylogging", "SetWindowsHookEx — input hooking"},
	{"GetAsyncKeyState", "medium", "Keylogging", "GetAsyncKeyState — keylogger primitive"},
	// POSIX / Android
	{"memfd_create", "high", "Fileless execution", "memfd_create — in-memory (fileless) payload"},
	{"prctl", "medium", "Process control / anti-debug", "prctl — PR_SET_DUMPABLE / anti-debug"},
	{"syscall", "info", "Raw syscall import", "syscall() is imported; call sites and purpose require verification"},
	{"inotify_init", "low", "Filesystem watch", "inotify — tamper/watch detection"},
	{"__system_property_get", "low", "Android property read", "__system_property_get — device/emulator fingerprinting"},
	{"socket", "low", "Network socket", "socket() import"},
	{"connect", "low", "Outbound connection", "connect() import"},
	{"setuid", "medium", "Privilege change", "setuid() — privilege manipulation"},
	{"chmod", "low", "Permission change", "chmod() import"},
}

func scanNativeImports(rep *NativeScanReport, imports []string) {
	seen := map[string]bool{}
	for _, imp := range imports {
		// PE imports look like "func:DLL"; take the function part.
		name := imp
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		for _, r := range nativeImportRules {
			if name == r.sym && !seen[r.sym] {
				seen[r.sym] = true
				rep.Findings = append(rep.Findings, mkFinding(
					"import-"+r.sym, "import", r.sev, r.title, r.desc))
			}
		}
	}
}

// nativeStringRules flag high-signal substrings inside the binary's strings.
var nativeStringRules = []struct {
	needle, sev, title, cat string
}{
	{"/system/bin/su", "high", "Root path reference", "root"},
	{"/system/xbin/su", "high", "Root path reference", "root"},
	{"magisk", "high", "Magisk (root) reference", "root"},
	{"superuser", "medium", "Superuser reference", "root"},
	{"frida", "high", "Frida instrumentation reference", "anti-analysis"},
	{"xposed", "high", "Xposed framework reference", "anti-analysis"},
	{"ptrace", "medium", "Anti-debug (ptrace) reference", "anti-debug"},
	{"/proc/self/status", "medium", "Debugger-detection probe", "anti-debug"},
	{"ro.debuggable", "low", "Emulator/debug property probe", "anti-emulator"},
	{"ro.kernel.qemu", "medium", "QEMU/emulator detection", "anti-emulator"},
	{"goldfish", "medium", "Android emulator (goldfish) detection", "anti-emulator"},
	{"reverse_tcp", "high", "Reverse-shell payload string", "malware"},
	{"meterpreter", "high", "Metasploit payload string", "malware"},
	{"/dev/tcp/", "high", "Bash reverse-shell primitive", "malware"},
	{"-----BEGIN", "medium", "Embedded PEM key/cert block", "secret"},
	{"http://", "low", "Cleartext HTTP URL", "network"},
	{"su -c", "high", "Root command execution", "root"},
	{"pm install", "medium", "Silent package install", "android"},
	{"/data/local/tmp", "medium", "Common dropper/staging path", "android"},
	{"ld_preload", "medium", "LD_PRELOAD library hijack", "anti-analysis"},
	{"/proc/net/tcp", "low", "Network connection enumeration", "recon"},
	{"getprop", "low", "System property probe (emulator detection)", "anti-emulator"},
	{".onion", "high", "Tor hidden-service C2", "network"},
	{"chmod 777", "medium", "World-writable permission change", "android"},
	{"dex2oat", "low", "Runtime DEX compilation", "android"},
	{"libfrida", "high", "Frida gadget library", "anti-analysis"},
	{"/system/bin/sh", "low", "Shell invocation", "exec"},
}

func scanNativeStrings(rep *NativeScanReport, strs []string) {
	seen := map[string]bool{}
	for _, s := range strs {
		lower := strings.ToLower(s)
		for _, r := range nativeStringRules {
			if seen[r.needle] {
				continue
			}
			if nativeStringRuleMatches(lower, r.needle) {
				seen[r.needle] = true
				rep.Findings = append(rep.Findings, mkFinding(
					"str-"+r.needle, r.cat, r.sev, r.title,
					"string: "+truncate(s, 80)))
			}
		}
	}
}

func nativeStringRuleMatches(lower, needle string) bool {
	if needle != "frida" && needle != "xposed" {
		return strings.Contains(lower, needle)
	}
	for start := 0; start < len(lower); {
		idx := strings.Index(lower[start:], needle)
		if idx < 0 {
			return false
		}
		idx += start
		end := idx + len(needle)
		alphaNumeric := func(b byte) bool { return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' }
		if (idx == 0 || !alphaNumeric(lower[idx-1])) && (end == len(lower) || !alphaNumeric(lower[end])) {
			return true
		}
		start = idx + 1
	}
	return false
}

// shannonEntropy returns the Shannon entropy (0..8 bits/byte) of data.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	ent := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// addEntropyAndPacker flags packed/encrypted payloads (high entropy) and known
// packer signatures. Packing is one of the strongest single indicators that a
// native library is hiding something from static analysis.
func addEntropyAndPacker(rep *NativeScanReport, data []byte) {
	ent := shannonEntropy(data)
	switch {
	case ent >= 7.2:
		rep.Findings = append(rep.Findings, mkFinding("entropy-high", "packing", "high",
			"Packed or encrypted payload",
			fmt.Sprintf("whole-file Shannon entropy %.2f/8.0 — likely packed/encrypted", ent)))
	case ent >= 6.8:
		rep.Findings = append(rep.Findings, mkFinding("entropy-elevated", "packing", "low",
			"Elevated entropy",
			fmt.Sprintf("whole-file Shannon entropy %.2f/8.0 — partially compressed/obfuscated", ent)))
	}

	for _, sig := range packerSignatures {
		if bytes.Contains(data, []byte(sig.magic)) {
			rep.Findings = append(rep.Findings, mkFinding(
				"packer-"+sig.id, "packing", "high", sig.title, sig.desc))
		}
	}
}

// packerSignatures are byte markers left by common native packers.
var packerSignatures = []struct{ id, magic, title, desc string }{
	{"upx", "UPX!", "UPX packer", "UPX signature present — executable is packed"},
	{"upx2", "$Info: This file is packed with the UPX", "UPX packer", "UPX banner present"},
	{"mpress", "MPRESS1", "MPRESS packer", "MPRESS signature present"},
	{"aspack", ".aspack", "ASPack packer", "ASPack section signature present"},
	{"themida", ".themida", "Themida protector", "Themida/WinLicense section present"},
	{"jiagu", "libjiagu", "Android packer (Jiagu)", "Qihoo Jiagu packer reference"},
	{"bangcle", "libsecexe", "Android packer (Bangcle)", "Bangcle/SecShell packer reference"},
	{"tencent", "libshella", "Android packer (Tencent Legu)", "Tencent Legu packer reference"},
}

// extractStrings pulls printable ASCII runs of at least minLen from data.
// Built on extractStringOccurrences (native_crackpoints.go) so the two
// call sites share a single string-scanning loop instead of running two
// near-identical hand-written ones over the same buffer.
func extractStrings(data []byte, minLen int) []string {
	occs := extractStringOccurrences(data, minLen)
	if len(occs) == 0 {
		return nil
	}
	out := make([]string, len(occs))
	for i, occ := range occs {
		out[i] = occ.val
	}
	return out
}

func mkFinding(id, cat, sev, title, desc string) NativeFinding {
	return NativeFinding{
		ID: id, Category: cat, Assessment: assessmentFor(id, cat), Severity: sev, Confidence: "medium",
		Title: title, Description: desc, Evidence: desc,
	}
}

// assessmentFor separates weak protections, potential capabilities and
// observed behavior so a lone import or high entropy never reads as malicious.
// hardening: missing mitigations; capability: usable but unobserved ability;
// behavior: observed/dynamic; inventory: neutral facts.
func assessmentFor(id, cat string) string {
	switch cat {
	case "hardening":
		return "hardening"
	case "inventory", "sbom", "integrity", "format":
		if cat == "integrity" {
			return "hardening"
		}
		return "inventory"
	case "capability":
		return "capability"
	}
	switch id {
	case "wx-section", "no-dep", "no-aslr", "no-cfg", "no-canary", "pe-unsigned",
		"pe-invalid-certificate", "dotnet-unsigned", "dotnet-skipverification", "dotnet-debug-jit",
		"dotnet-legacy-framework", "dotnet-assembly":
		if id == "dotnet-assembly" || id == "dotnet-debug-jit" || id == "dotnet-legacy-framework" {
			return "inventory"
		}
		return "hardening"
	case "dotnet-pinvoke", "dotnet-dynamic-load", "pe-imports-incomplete", "high-entropy":
		return "capability"
	}
	if strings.Contains(id, "behavior") || strings.Contains(id, "inject") ||
		strings.Contains(id, "hollow") || strings.Contains(id, "ransom") {
		return "behavior"
	}
	return "capability"
}

// dotnetFindings converts CLI metadata into report findings: assembly
// identity/entry point plus trust-relevant attributes (strong name,
// SkipVerification, debug JIT mode, legacy framework).
func dotnetFindings(dn *peinspect.DotNetInfo) []NativeFinding {
	pkt := dn.PublicKeyToken
	if pkt == "" {
		pkt = "null"
	}
	identity := dn.AssemblyName + ", Version=" + dn.AssemblyVersion +
		", Culture=" + dn.Culture + ", PublicKeyToken=" + pkt
	out := []NativeFinding{
		mkFinding("dotnet-assembly", "inventory", "info",
			"Managed .NET assembly: "+identity,
			"Entry point: "+dn.EntryPoint+" | Runtime: "+dn.RuntimeVersion+
				" | Types/Methods: "+itoa(dn.TypeDefCount)+"/"+itoa(dn.MethodDefCount)),
	}
	if dn.PublicKeyToken == "" {
		out = append(out, mkFinding("dotnet-unsigned", "integrity", "low",
			"Assembly has no strong name (PublicKeyToken=null)",
			"Unsigned assemblies can be replaced/tampered without a key check: "+identity))
	}
	if dn.SkipVerification != nil && *dn.SkipVerification {
		out = append(out, mkFinding("dotnet-skipverification", "hardening", "medium",
			"SkipVerification=true allows unverifiable code",
			"SecurityPermission(SkipVerification) lets the assembly run unverifiable IL"))
	}
	if dn.DebuggableModes != nil && *dn.DebuggableModes&peinspect.DebuggableDisableOptimizations != 0 {
		out = append(out, mkFinding("dotnet-debug-jit", "inventory", "low",
			"Debug JIT mode (optimizations disabled)",
			"DebuggableAttribute modes: "+peinspect.DebuggableModesString(*dn.DebuggableModes)))
	}
	if isLegacyTFM(dn.TargetFramework) {
		out = append(out, mkFinding("dotnet-legacy-framework", "sbom", "low",
			"Legacy target framework: "+dn.TargetFramework,
			"Out-of-support frameworks stop receiving security fixes"))
	}
	if len(dn.PInvokes) > 0 {
		sev := "low"
		for _, p := range dn.PInvokes {
			l := strings.ToLower(p)
			if strings.Contains(l, "writeprocessmemory") || strings.Contains(l, "virtualallocex") ||
				strings.Contains(l, "createremotethread") || strings.Contains(l, "virtualprotect") {
				sev = "medium"
				break
			}
		}
		out = append(out, mkFinding("dotnet-pinvoke", "capability", sev,
			fmt.Sprintf("P/Invoke to native code (%d import(s))", dn.PInvokeCount),
			"Targets: "+strings.Join(dn.PInvokes, ", ")))
	}
	for _, h := range dn.DynamicLoadHints {
		out = append(out, mkFinding("dotnet-dynamic-load", "capability", "medium",
			"Dynamic code/reflection call: "+h,
			"MemberRef "+h+" resolved from CLI metadata (origin: MemberRef table)"))
	}
	return out
}

func isLegacyTFM(tfm string) bool {
	t := strings.ToLower(tfm)
	return strings.Contains(t, "version=v2.0") || strings.Contains(t, "version=v3.0") ||
		strings.Contains(t, "version=v3.5") ||
		(strings.Contains(t, "version=v4.0") && !strings.Contains(t, "version=v4.0.")) ||
		strings.Contains(t, "profile=client")
}

func itoa(v uint32) string { return fmt.Sprintf("%d", v) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// finalizeNativeReport computes a 0..100 score and a verdict from the findings.
func finalizeNativeReport(rep *NativeScanReport) {
	score := 0
	for _, f := range rep.Findings {
		switch f.Severity {
		case "critical":
			score += 40
		case "high":
			score += 20
		case "medium":
			score += 8
		case "low":
			score += 2
		}
	}
	if score > 100 {
		score = 100
	}
	rep.Score = uint32(score)
	switch {
	case score >= 60:
		rep.Verdict = "high-risk"
	case score >= 25:
		rep.Verdict = "suspicious"
	case score > 0:
		rep.Verdict = "low-risk"
	default:
		rep.Verdict = "clean"
	}
	// Stable order: severity desc, then id.
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		si, sj := sevRank(rep.Findings[i].Severity), sevRank(rep.Findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return rep.Findings[i].ID < rep.Findings[j].ID
	})
}

// goFindingAliases maps the pure-Go analyzer's finding IDs onto the Rust
// scanner's IDs for the same weakness, so corroborating a Rust report with
// the Go pass does not duplicate findings the user has already seen.
var goFindingAliases = map[string]string{
	"no-dep":     "no-nx-pe",
	"no-aslr":    "no-aslr-pe",
	"no-cfg":     "no-cfg-pe",
	"no-canary":  "no-stack-canary",
	"wx-segment": "wx-section",
}

// enrichNativeReport merges corroborating findings from the pure-Go analyzer
// (src) into the primary report (dst, typically from the Rust scanner),
// deduplicating by finding ID across both scanners' naming schemes and
// backfilling hardening posture the primary scanner left unset.
//
// The primary scanner keeps ownership of Score and Verdict: the Rust score is
// a severity×confidence sum with decay and caps, and re-deriving it from the
// Go severity table (as this merge once did) silently re-scaled every merged
// report. Added findings still surface on their own through Findings and the
// per-finding artifact pipeline.
func enrichNativeReport(dst, src *NativeScanReport) {
	if dst == nil || src == nil {
		return
	}
	seen := make(map[string]struct{}, len(dst.Findings))
	for _, f := range dst.Findings {
		seen[f.ID] = struct{}{}
	}
	for _, f := range src.Findings {
		if canonical, ok := goFindingAliases[f.ID]; ok {
			f.ID = canonical
		}
		if _, ok := seen[f.ID]; ok {
			continue
		}
		seen[f.ID] = struct{}{}
		dst.Findings = append(dst.Findings, f)
	}
	// Backfill hardening posture the primary scanner left unset.
	if dst.Hardening.NX == nil {
		dst.Hardening.NX = src.Hardening.NX
	}
	if dst.Hardening.PIE == nil {
		dst.Hardening.PIE = src.Hardening.PIE
	}
	if dst.Hardening.Relro == "" {
		dst.Hardening.Relro = src.Hardening.Relro
	}
	if dst.Hardening.StackCanary == nil {
		dst.Hardening.StackCanary = src.Hardening.StackCanary
	}
	if dst.Hardening.WxSections == 0 {
		dst.Hardening.WxSections = src.Hardening.WxSections
	}
	// Backfill structured PE/CLI analysis the primary scanner did not produce.
	if dst.PE == nil {
		dst.PE = src.PE
	}
	if dst.DotNet == nil {
		dst.DotNet = src.DotNet
	}
	// Stable order: severity desc, then id — same key as finalizeNativeReport,
	// applied without touching score or verdict.
	sort.SliceStable(dst.Findings, func(i, j int) bool {
		si, sj := sevRank(dst.Findings[i].Severity), sevRank(dst.Findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return dst.Findings[i].ID < dst.Findings[j].ID
	})
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
