package apkid

import (
	"regexp"
	"strings"
)

// RulesVersion is the version tag of the built-in rule database.
const RulesVersion = "2025-07"

// ─── Scope ──────────────────────────────────────────────────────────────────

// ScopeMask is a bitfield of file-type scopes a rule applies to.
// An empty mask (0) means "any scope".
type ScopeMask uint8

const (
	ScopeDex   ScopeMask = 1 << iota // *.dex binary
	ScopeSmali                       // *.smali text (apktool-extracted)
	ScopeText                        // xml, json, properties, manifest, etc.
	ScopeELF                         // *.so native libraries
)

// ScopeAny means "match in any scope" (value 0).
const ScopeAny ScopeMask = 0

// scopeOf converts the classify() string to a ScopeMask bit.
func scopeOf(kind string) ScopeMask {
	switch kind {
	case "dex":
		return ScopeDex
	case "smali":
		return ScopeSmali
	case "text":
		return ScopeText
	case "elf":
		return ScopeELF
	}
	return ScopeAny
}

// ─── Matcher ─────────────────────────────────────────────────────────────────

// MatcherKind selects what a Matcher checks.
type MatcherKind string

const (
	// KindContentLiteral looks for a literal byte sequence in file content.
	// Accelerated via the shared Aho-Corasick automaton.
	KindContentLiteral MatcherKind = "content_literal"

	// KindContentRegex runs a compiled regexp against file content.
	KindContentRegex MatcherKind = "content_regex"

	// KindEntryName matches the zip entry filename (case-insensitive contains).
	// Works against the full slash-separated path inside the archive.
	KindEntryName MatcherKind = "entry_name"

	// KindDexString searches in the DEX string pool only (not raw binary).
	// Requires a successful dex.ParseDEX; falls back to content_literal on
	// non-DEX or parse failure.
	KindDexString MatcherKind = "dex_string"
)

// Matcher is one condition inside a Rule.
type Matcher struct {
	Kind    MatcherKind
	Pattern string

	// compiled is populated by compileMatchers; nil for non-regex kinds.
	compiled *regexp.Regexp
}

// ─── Logic ───────────────────────────────────────────────────────────────────

// LogicMode controls how multiple Matchers inside a Rule are combined.
type LogicMode string

const (
	// AnyOf — at least one Matcher must hit (OR). Default.
	AnyOf LogicMode = "any_of"
	// AllOf — every Matcher must hit (AND). Use for precision-critical rules.
	AllOf LogicMode = "all_of"
)

// ─── Rule ────────────────────────────────────────────────────────────────────

// Rule is a single fingerprint detection rule.
type Rule struct {
	ID          string
	Name        string
	Category    Category
	Description string
	// References: CVEs, blog posts, tool docs, etc.
	References []string

	// Confidence in [0.0, 1.0]. 1.0 = unique, dedicated signature.
	Confidence float64
	// Score contribution to the global risk score when this rule fires.
	Score int

	// Scopes restricts which file types are checked. ScopeAny (0) = all files.
	Scopes ScopeMask

	// Logic defines how Matchers are combined. Defaults to AnyOf.
	Logic LogicMode

	// Matchers are the individual detection conditions.
	Matchers []Matcher
}

// lit is a shorthand to create a KindContentLiteral matcher.
func lit(s string) Matcher { return Matcher{Kind: KindContentLiteral, Pattern: s} }

// re creates a KindContentRegex matcher.
func re(pattern string) Matcher {
	return Matcher{Kind: KindContentRegex, Pattern: pattern}
}

// entryName creates a KindEntryName matcher (case-insensitive contains).
func entryName(s string) Matcher { return Matcher{Kind: KindEntryName, Pattern: s} }

// dexStr creates a KindDexString matcher (DEX string pool search).
func dexStr(s string) Matcher { return Matcher{Kind: KindDexString, Pattern: s} }

// compileMatchers compiles regex patterns in-place.
func compileMatchers(rules []Rule) []Rule {
	for ri := range rules {
		for mi := range rules[ri].Matchers {
			m := &rules[ri].Matchers[mi]
			if m.Kind == KindContentRegex && m.compiled == nil {
				m.compiled = regexp.MustCompile(m.Pattern)
			}
		}
		if rules[ri].Logic == "" {
			rules[ri].Logic = AnyOf
		}
	}
	return rules
}

// ─── Rule Database ───────────────────────────────────────────────────────────

// allRules is the complete built-in rule database.
// Rules are evaluated in order; break as soon as the first match is found per
// (rule, file) pair.
var allRules = compileMatchers([]Rule{

	// ══════════════════════════════════════════════════════════════════════════
	// COMPILERS
	// ══════════════════════════════════════════════════════════════════════════

	// Note: the old "emitter: com.android.dx / r8" strings come from baksmali
	// output headers, NOT from the DEX binary itself.  Those strings are
	// retained here as secondary evidence (smali scope), while the primary
	// detection for real APKs comes from the DEX structural heuristics in
	// dex/parser.go (compiler.d8_r8_struct, compiler.dx_struct).

	{
		ID:          "compiler.dx",
		Name:        "dx (legacy Android SDK)",
		Category:    CategoryCompiler,
		Description: "Classic dx tool from old Android SDKs (pre-Android Studio 3.1). Detected via baksmali header strings in smali files or string pool.",
		Confidence:  0.85,
		Score:       2,
		Scopes:      ScopeSmali | ScopeDex,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("emitter: com.android.dx"),
			lit("created by dx version"),
			dexStr("emitter: com.android.dx"),
		},
	},
	{
		ID:          "compiler.d8_r8",
		Name:        "d8 / r8 (modern Android)",
		Category:    CategoryCompiler,
		Description: "Modern d8/r8 toolchain shipped with Android Gradle Plugin 3.1+. Detected via string pool, smali headers, or structural map_list heuristics.",
		References:  []string{"https://developer.android.com/tools/releases/gradle-plugin"},
		Confidence:  0.9,
		Score:       1,
		Scopes:      ScopeSmali | ScopeDex,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("emitter: com.android.tools.r8"),
			lit("compiled by R8"),
			dexStr("com.android.tools.r8"),
		},
	},
	{
		ID:          "compiler.dexlib2",
		Name:        "dexlib2 (smali / baksmali)",
		Category:    CategoryCompiler,
		Description: "Built or rebuilt with dexlib2 — strong smali/apktool round-trip indicator. High suspicion of repackaging.",
		References:  []string{"https://github.com/JesusFreke/smali"},
		Confidence:  0.95,
		Score:       6,
		Scopes:      ScopeSmali | ScopeDex,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("emitter: jf.dexlib2"),
			lit("dexlib2.writer"),
			dexStr("jf.dexlib2"),
		},
	},
	{
		ID:          "compiler.jack",
		Name:        "Jack (deprecated)",
		Category:    CategoryCompiler,
		Description: "Jack toolchain — Google deprecated this in 2017. Rare in the wild.",
		Confidence:  0.9,
		Score:       2,
		Scopes:      ScopeSmali | ScopeDex,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("emitter: jack-"),
			dexStr("com.android.jack"),
		},
	},
	{
		ID:          "compiler.dexmerge",
		Name:        "dexmerge",
		Category:    CategoryCompiler,
		Description: "Multiple DEX files merged via dexmerge — often library / multidex artefact.",
		Confidence:  0.8,
		Score:       1,
		Scopes:      ScopeSmali | ScopeDex,
		Logic:       AnyOf,
		Matchers:    []Matcher{lit("emitter: dexmerger")},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// OBFUSCATORS
	// ══════════════════════════════════════════════════════════════════════════

	// Scope: ScopeDex|ScopeSmali — fires on both real DEX (string pool via
	// dex_string matchers) AND on apktool-extracted smali (content_literal).
	// This fixes the original bug where scope:"smali" made these rules dead
	// on real APKs.

	{
		ID:          "obfuscator.proguard",
		Name:        "ProGuard",
		Category:    CategoryObfuscator,
		Description: "ProGuard shrinker/obfuscator — annotation classes present in string pool.",
		References:  []string{"https://www.guardsquare.com/proguard"},
		Confidence:  0.7,
		Score:       4,
		Scopes:      ScopeDex | ScopeSmali,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("proguard.annotation.Keep"),
			lit("proguard/annotation"),
			dexStr("proguard/annotation"),
			dexStr("proguard.annotation.Keep"),
		},
	},
	{
		ID:          "obfuscator.r8_optimizing",
		Name:        "R8 (full-mode obfuscator)",
		Category:    CategoryObfuscator,
		Description: "R8 in shrink+optimize mode — synthetic helper classes are visible in string pool.",
		Confidence:  0.7,
		Score:       4,
		Scopes:      ScopeDex | ScopeSmali,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("$$ExternalSyntheticLambda"),
			lit("$$ExternalSyntheticOutline"),
			dexStr("$$ExternalSyntheticLambda"),
			dexStr("$$ExternalSyntheticOutline"),
		},
	},
	{
		ID:          "obfuscator.dexguard",
		Name:        "DexGuard (commercial)",
		Category:    CategoryObfuscator,
		Description: "Commercial DexGuard from Guardsquare — string + control-flow obfuscation. Class path or runtime lib found in DEX string pool.",
		References:  []string{"https://www.guardsquare.com/dexguard"},
		Confidence:  0.95,
		Score:       12,
		Scopes:      ScopeDex | ScopeSmali,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/guardsquare/dexguard"),
			lit("dexguard.runtime"),
			dexStr("com/guardsquare/dexguard"),
			dexStr("dexguard.runtime"),
		},
	},
	{
		ID:          "obfuscator.allatori",
		Name:        "Allatori",
		Category:    CategoryObfuscator,
		Description: "Allatori Java obfuscator — strong string encryption, watermarking.",
		References:  []string{"https://allatori.com"},
		Confidence:  0.95,
		Score:       12,
		Scopes:      ScopeDex | ScopeSmali,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/allatori"),
			lit("allatori.annotations"),
			dexStr("com/allatori"),
			dexStr("allatori.annotations"),
		},
	},
	{
		ID:          "obfuscator.zelix",
		Name:        "Zelix KlassMaster",
		Category:    CategoryObfuscator,
		Description: "Zelix KlassMaster — flow obfuscation, string encryption.",
		References:  []string{"https://www.zelix.com/klassmaster"},
		Confidence:  0.95,
		Score:       10,
		Scopes:      ScopeDex | ScopeSmali,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/zelix/"),
			dexStr("com/zelix/"),
		},
	},
	{
		ID:          "obfuscator.obfuscapk",
		Name:        "Obfuscapk",
		Category:    CategoryObfuscator,
		Description: "Obfuscapk open-source obfuscator — used by malware authors and researchers.",
		References:  []string{"https://github.com/ClaudiuGeorgiu/Obfuscapk"},
		Confidence:  0.9,
		Score:       10,
		Scopes:      ScopeDex | ScopeSmali,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("obfuscapk"),
			dexStr("obfuscapk"),
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PACKERS / PROTECTORS
	// ══════════════════════════════════════════════════════════════════════════
	// These rules now use BOTH content_literal (for smali/string-in-dex) AND
	// entry_name (for the SO filename in the ZIP directory) — fixing the
	// original bug where packer SO names were searched in file *content*.

	{
		ID:          "packer.bangcle",
		Name:        "Bangcle / SecNeo",
		Category:    CategoryPacker,
		Description: "Bangcle (a.k.a. SecNeo) DEX packer — encrypted classes loaded via libsecexe / libsecmain.",
		References:  []string{"https://github.com/rednaga/APKiD"},
		Confidence:  0.95,
		Score:       18,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/secneo/apkwrapper"),
			dexStr("com/secneo/apkwrapper"),
			entryName("libsecexe.so"),
			entryName("libsecmain.so"),
			entryName("libsecpreload.so"),
		},
	},
	{
		ID:          "packer.qihoo_360",
		Name:        "Qihoo 360 Jiagu",
		Category:    CategoryPacker,
		Description: "Qihoo 360 Jiagu / Bao packer — libjiagu*.so + StubApp class.",
		References:  []string{"https://jiagu.360.cn"},
		Confidence:  0.95,
		Score:       18,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/qihoo/util/StubApp"),
			dexStr("com/qihoo/util/StubApp"),
			entryName("libjiagu.so"),
			entryName("libjiagu_a64.so"),
			entryName("libjiagu_x86.so"),
		},
	},
	{
		ID:          "packer.tencent_legu",
		Name:        "Tencent Legu",
		Category:    CategoryPacker,
		Description: "Tencent Legu APK protector.",
		Confidence:  0.95,
		Score:       18,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/tencent/StubShell"),
			dexStr("com/tencent/StubShell"),
			entryName("libshella"),
			entryName("libshellx"),
		},
	},
	{
		ID:          "packer.ali",
		Name:        "Alibaba Protector",
		Category:    CategoryPacker,
		Description: "Alibaba mobile security DEX protector.",
		Confidence:  0.9,
		Score:       17,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/ali/mobisecenhance"),
			dexStr("com/ali/mobisecenhance"),
			entryName("libmobisec.so"),
			entryName("libmobisecy.so"),
		},
	},
	{
		ID:          "packer.baidu",
		Name:        "Baidu Protector",
		Category:    CategoryPacker,
		Description: "Baidu APK protector.",
		Confidence:  0.9,
		Score:       17,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/baidu/protect/StubApplication"),
			dexStr("com/baidu/protect/StubApplication"),
			entryName("libbaiduprotect.so"),
		},
	},
	{
		ID:          "packer.ijiami",
		Name:        "iJiami (爱加密)",
		Category:    CategoryPacker,
		Description: "iJiami (爱加密) DEX packer.",
		Confidence:  0.95,
		Score:       18,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/shell/SuperApplication"),
			lit("com/ijiami"),
			dexStr("com/ijiami"),
			entryName("libexec.so"),
			entryName("libexecmain.so"),
		},
	},
	{
		ID:          "packer.naga",
		Name:        "Naga (NQ Shield)",
		Category:    CategoryPacker,
		Description: "NQ Mobile shield (Naga) protector.",
		Confidence:  0.9,
		Score:       17,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/nqshield"),
			dexStr("com/nqshield"),
			entryName("libnqshield.so"),
		},
	},
	{
		ID:          "packer.appsuit",
		Name:        "AppSuit (SoftSecurity)",
		Category:    CategoryPacker,
		Description: "AppSuit Korean APK protector.",
		Confidence:  0.9,
		Score:       17,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/stub/StubApp"),
			dexStr("com/stub/StubApp"),
			entryName("libcovault-appsec.so"),
		},
	},
	{
		ID:          "packer.dexprotector",
		Name:        "DexProtector",
		Category:    CategoryPacker,
		Description: "Licel DexProtector commercial protector.",
		References:  []string{"https://dexprotector.com"},
		Confidence:  0.95,
		Score:       18,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com/licel/dexprotector"),
			dexStr("com/licel/dexprotector"),
		},
	},
	{
		ID:          "packer.upx_native",
		Name:        "UPX-packed native library",
		Category:    CategoryPacker,
		Description: "One or more .so libraries are UPX-compressed. Suspicious when stripped.",
		Confidence:  0.85,
		Score:       10,
		Scopes:      ScopeELF,
		Logic:       AnyOf,
		Matchers:    []Matcher{lit("UPX!")},
	},
	{
		ID:          "packer.encrypted_asset",
		Name:        "High-entropy asset blob",
		Category:    CategoryPacker,
		Description: "Large asset blob with Shannon entropy > 7.8 bits/byte — likely encrypted or compressed payload.",
		Confidence:  0.7,
		Score:       8,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		// Matched programmatically via entropy check in engine; no bytewise matchers.
		Matchers: nil,
	},

	// ══════════════════════════════════════════════════════════════════════════
	// ANTI-VM / EMULATOR DETECTION
	// ══════════════════════════════════════════════════════════════════════════

	{
		ID:          "anti_vm.qemu_props",
		Name:        "QEMU / emulator props probe",
		Category:    CategoryAntiVM,
		Description: "Reads QEMU / Goldfish device properties. Rule requires /dev/qemu_pipe OR ro.kernel.qemu together with goldfish/ranchu — reduces noise from legitimate uses.",
		References:  []string{"https://github.com/strazzere/anti-emulator"},
		Confidence:  0.85,
		Score:       6,
		Scopes:      ScopeAny,
		// AllOf removed — QEMU probe only needs ONE specific indicator to be suspicious.
		// The high-FP terms (goldfish alone) are excluded.
		Logic: AnyOf,
		Matchers: []Matcher{
			lit("ro.kernel.qemu"),
			lit("/dev/qemu_pipe"),
			lit("/dev/socket/qemud"),
			dexStr("ro.kernel.qemu"),
		},
	},
	{
		ID:          "anti_vm.build_fingerprint",
		Name:        "Build.FINGERPRINT generic check",
		Category:    CategoryAntiVM,
		Description: "Uses Build.FINGERPRINT / Build.MODEL to detect generic/sdk_gphone/google_sdk emulators. Requires sdk_gphone or Genymotion for precision (generic_x86 alone is too noisy).",
		Confidence:  0.75,
		Score:       4,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("sdk_gphone"),
			lit("google_sdk"),
			lit("Genymotion"),
			dexStr("sdk_gphone"),
			dexStr("Genymotion"),
		},
	},
	{
		ID:          "anti_vm.bluestacks",
		Name:        "BlueStacks detection",
		Category:    CategoryAntiVM,
		Description: "Looks for BlueStacks-specific files or packages.",
		Confidence:  0.9,
		Score:       5,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("com.bluestacks"),
			lit("/sdcard/windows/BstSharedFolder"),
			dexStr("com.bluestacks"),
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// ANTI-DEBUG
	// ══════════════════════════════════════════════════════════════════════════

	{
		ID:          "anti_debug.is_debugger_connected",
		Name:        "Debug.isDebuggerConnected()",
		Category:    CategoryAntiDebug,
		Description: "Calls android.os.Debug.isDebuggerConnected to detect attached debugger. Full Dalvik descriptor is high-confidence.",
		Confidence:  0.95,
		Score:       5,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			// Full Dalvik descriptor = very precise
			lit("Landroid/os/Debug;->isDebuggerConnected"),
			dexStr("Landroid/os/Debug;->isDebuggerConnected"),
		},
	},
	{
		ID:          "anti_debug.tracerpid",
		Name:        "/proc/self/status TracerPid",
		Category:    CategoryAntiDebug,
		Description: "Reads TracerPid from /proc/self/status — classic ptrace detection. Requires BOTH path and field name to reduce false positives.",
		Confidence:  0.9,
		Score:       6,
		Scopes:      ScopeAny,
		// AllOf: must see BOTH /proc/self/status AND TracerPid — fixes the original OR bug.
		Logic: AllOf,
		Matchers: []Matcher{
			lit("/proc/self/status"),
			lit("TracerPid"),
		},
	},
	{
		ID:          "anti_debug.frida",
		Name:        "Frida instrumentation detection",
		Category:    CategoryAntiDebug,
		Description: "Probes Frida server by package name or port. Requires frida-server package name OR frida named pipe — port 27042 alone is too noisy.",
		References:  []string{"https://frida.re"},
		Confidence:  0.9,
		Score:       6,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			// frida-server or re.frida.server are definitive
			lit("frida-server"),
			lit("re.frida.server"),
			lit("gum-js-loop"),
			dexStr("re.frida.server"),
		},
	},
	{
		ID:          "anti_debug.xposed",
		Name:        "Xposed framework probe",
		Category:    CategoryAntiDebug,
		Description: "Looks for Xposed installer / bridge classes.",
		References:  []string{"https://repo.xposed.info"},
		Confidence:  0.9,
		Score:       6,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("de.robv.android.xposed"),
			lit("XposedBridge"),
			dexStr("de.robv.android.xposed"),
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// ANTI-DISASSEMBLY
	// ══════════════════════════════════════════════════════════════════════════

	{
		ID:          "anti_disasm.illegal_class_name",
		Name:        "Illegal class names (smali confusion)",
		Category:    CategoryAntiDisasm,
		Description: "Class names containing reserved/illegal characters used to confuse static tools.",
		Confidence:  0.85,
		Score:       6,
		Scopes:      ScopeDex | ScopeSmali,
		Logic:       AnyOf,
		Matchers: []Matcher{
			re(`L[a-zA-Z]+/[a-zA-Z]*[\x00-\x1f<>][a-zA-Z]*;`),
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// MANIPULATOR (DYNAMIC LOADING)
	// ══════════════════════════════════════════════════════════════════════════

	{
		ID:          "manipulator.dex_class_loader",
		Name:        "DexClassLoader runtime DEX load",
		Category:    CategoryManipulator,
		Description: "Uses DexClassLoader to load DEX at runtime — common in packers and plugin frameworks.",
		Confidence:  0.85,
		Score:       4,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("Ldalvik/system/DexClassLoader;"),
			dexStr("Ldalvik/system/DexClassLoader;"),
		},
	},
	{
		ID:          "manipulator.path_class_loader",
		Name:        "PathClassLoader / InMemoryDexClassLoader",
		Category:    CategoryManipulator,
		Description: "Uses PathClassLoader or InMemoryDexClassLoader for runtime class loading.",
		Confidence:  0.7,
		Score:       2,
		Scopes:      ScopeAny,
		Logic:       AnyOf,
		Matchers: []Matcher{
			lit("Ldalvik/system/PathClassLoader;"),
			lit("Ldalvik/system/InMemoryDexClassLoader;"),
			dexStr("Ldalvik/system/InMemoryDexClassLoader;"),
		},
	},
})

// ─── Helper ──────────────────────────────────────────────────────────────────

// allLiteralPatterns collects every KindContentLiteral pattern across all
// rules so the caller can build a single Aho-Corasick automaton.
func allLiteralPatterns() [][]byte {
	var out [][]byte
	for _, r := range allRules {
		for _, m := range r.Matchers {
			if m.Kind == KindContentLiteral {
				out = append(out, []byte(m.Pattern))
			}
		}
	}
	return out
}

// matcherContains is a case-insensitive substring check used for KindEntryName.
func matcherContains(entryPath, pattern string) bool {
	return strings.Contains(strings.ToLower(entryPath), strings.ToLower(pattern))
}
