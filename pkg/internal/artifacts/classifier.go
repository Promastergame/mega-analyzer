package artifacts

import (
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE CLASSIFIER
//
// Classifies a file based on its extension AND magic bytes. Smali files are
// EXPLICITLY excluded — plan §0 makes them out-of-scope.
// ═══════════════════════════════════════════════════════════════════════════════

// Type is the canonical artifact category.
type Type string

const (
	TypeImage   Type = "image"
	TypeModel3D Type = "model3d"
	TypeNative  Type = "native"
	TypeFont    Type = "font"
	TypeAudio   Type = "audio"
	TypeVideo   Type = "video"
	TypeArchive Type = "archive"
	TypeCode    Type = "code" // JS / HTML / proto / JSON / WASM / scripts / config text
	TypeOther   Type = "other"
	TypeIgnored Type = "" // smali / dex / xml / known noise — skipped entirely
)

// CodeLanguage identifies the concrete language for a TypeCode artifact.
// Returned alongside Classify via ClassifyDetailed for richer downstream
// scanners (xss/eval/proto-bombs/...).
type CodeLanguage string

const (
	LangJS         CodeLanguage = "javascript"
	LangTS         CodeLanguage = "typescript"
	LangHTML       CodeLanguage = "html"
	LangCSS        CodeLanguage = "css"
	LangProto      CodeLanguage = "proto"
	LangJSON       CodeLanguage = "json"
	LangWASM       CodeLanguage = "wasm"
	LangLua        CodeLanguage = "lua"
	LangPython     CodeLanguage = "python"
	LangShell      CodeLanguage = "shell"
	LangSQL        CodeLanguage = "sql"
	LangYAML       CodeLanguage = "yaml"
	LangTOML       CodeLanguage = "toml"
	LangINI        CodeLanguage = "ini"
	LangText       CodeLanguage = "text"
	LangBundle     CodeLanguage = "bundle" // RN/Webpack bundles — special-cased
	LangGo         CodeLanguage = "go"
	LangRust       CodeLanguage = "rust"
	LangC          CodeLanguage = "c"
	LangCPP        CodeLanguage = "cpp"
	LangJava       CodeLanguage = "java"
	LangKotlin     CodeLanguage = "kotlin"
	LangSwift      CodeLanguage = "swift"
	LangDart       CodeLanguage = "dart"
	LangRuby       CodeLanguage = "ruby"
	LangPHP        CodeLanguage = "php"
	LangCSharp     CodeLanguage = "csharp"
	LangProperties CodeLanguage = "properties"
	LangXML        CodeLanguage = "xml"
	LangProf       CodeLanguage = "prof"
)

// Classify returns the Type for a given filename. data may be nil. We
// pre-screen on extension because magic detection is expensive for
// thousands of files in an APK.
func Classify(path string, data []byte) Type {
	lower := strings.ToLower(path)

	// Excluded entirely.
	switch {
	case strings.HasSuffix(lower, ".smali"),
		strings.HasSuffix(lower, ".class"),
		strings.HasSuffix(lower, ".dex"),
		strings.HasSuffix(lower, ".odex"),
		strings.HasSuffix(lower, ".arsc"),
		strings.HasSuffix(lower, ".rsa"),
		strings.HasSuffix(lower, ".sf"),
		strings.HasSuffix(lower, ".mf"),
		strings.HasSuffix(lower, ".pro"),
		strings.HasSuffix(lower, ".version"),
		strings.HasSuffix(lower, ".kotlin_metadata"),
		strings.HasSuffix(lower, ".kotlin_module"),
		strings.HasSuffix(lower, ".kotlin_builtins"),
		// Analyzer-generated meta files — not user artifacts
		lower == "omnisec-meta.json",
		lower == "apktool.json": // legacy name — exclude if still present
		return TypeIgnored
	}

	switch {
	case strings.HasSuffix(lower, ".png"),
		strings.HasSuffix(lower, ".jpg"),
		strings.HasSuffix(lower, ".jpeg"),
		strings.HasSuffix(lower, ".jfif"),
		strings.HasSuffix(lower, ".gif"),
		strings.HasSuffix(lower, ".webp"),
		strings.HasSuffix(lower, ".bmp"),
		strings.HasSuffix(lower, ".tiff"),
		strings.HasSuffix(lower, ".tif"),
		strings.HasSuffix(lower, ".ico"),
		strings.HasSuffix(lower, ".heic"),
		strings.HasSuffix(lower, ".heif"),
		strings.HasSuffix(lower, ".avif"),
		strings.HasSuffix(lower, ".svg"):
		return TypeImage

	case strings.HasSuffix(lower, ".obj"),
		strings.HasSuffix(lower, ".gltf"),
		strings.HasSuffix(lower, ".glb"),
		strings.HasSuffix(lower, ".fbx"),
		strings.HasSuffix(lower, ".dae"),
		strings.HasSuffix(lower, ".stl"),
		strings.HasSuffix(lower, ".ply"),
		strings.HasSuffix(lower, ".3ds"):
		return TypeModel3D

	case strings.HasSuffix(lower, ".so"),
		strings.HasSuffix(lower, ".a"),
		strings.HasSuffix(lower, ".dll"),
		strings.HasSuffix(lower, ".dylib"):
		return TypeNative

	case strings.HasSuffix(lower, ".ttf"),
		strings.HasSuffix(lower, ".otf"),
		strings.HasSuffix(lower, ".woff"),
		strings.HasSuffix(lower, ".woff2"),
		strings.HasSuffix(lower, ".eot"):
		return TypeFont

	case strings.HasSuffix(lower, ".mp3"),
		strings.HasSuffix(lower, ".wav"),
		strings.HasSuffix(lower, ".ogg"),
		strings.HasSuffix(lower, ".m4a"),
		strings.HasSuffix(lower, ".flac"):
		return TypeAudio

	case strings.HasSuffix(lower, ".mp4"),
		strings.HasSuffix(lower, ".mov"),
		strings.HasSuffix(lower, ".webm"),
		strings.HasSuffix(lower, ".mkv"),
		strings.HasSuffix(lower, ".avi"):
		return TypeVideo

	case strings.HasSuffix(lower, ".zip"),
		strings.HasSuffix(lower, ".apk"),
		strings.HasSuffix(lower, ".jar"),
		strings.HasSuffix(lower, ".tar"),
		strings.HasSuffix(lower, ".gz"),
		strings.HasSuffix(lower, ".bz2"),
		strings.HasSuffix(lower, ".7z"),
		strings.HasSuffix(lower, ".rar"):
		return TypeArchive

	// ── Code / text payloads. APKs frequently bundle JS bridges, RN/Hermes
	// bundles, HTML help pages, .proto schemas (Wire / gRPC), JSON configs,
	// shell scripts, etc. These were previously dumped into TypeOther which
	// hides them from the deep-analysis pass.
	case strings.HasSuffix(lower, ".js"),
		strings.HasSuffix(lower, ".mjs"),
		strings.HasSuffix(lower, ".cjs"),
		strings.HasSuffix(lower, ".jsx"),
		strings.HasSuffix(lower, ".ts"),
		strings.HasSuffix(lower, ".tsx"),
		strings.HasSuffix(lower, ".html"),
		strings.HasSuffix(lower, ".htm"),
		strings.HasSuffix(lower, ".xhtml"),
		strings.HasSuffix(lower, ".css"),
		strings.HasSuffix(lower, ".proto"),
		strings.HasSuffix(lower, ".json"),
		strings.HasSuffix(lower, ".json5"),
		strings.HasSuffix(lower, ".wasm"),
		strings.HasSuffix(lower, ".lua"),
		strings.HasSuffix(lower, ".py"),
		strings.HasSuffix(lower, ".sh"),
		strings.HasSuffix(lower, ".bash"),
		strings.HasSuffix(lower, ".sql"),
		strings.HasSuffix(lower, ".yaml"),
		strings.HasSuffix(lower, ".yml"),
		strings.HasSuffix(lower, ".toml"),
		strings.HasSuffix(lower, ".ini"),
		strings.HasSuffix(lower, ".cfg"),
		strings.HasSuffix(lower, ".conf"),
		strings.HasSuffix(lower, ".txt"),
		strings.HasSuffix(lower, ".md"),
		strings.HasSuffix(lower, ".bundle"),
		strings.HasSuffix(lower, ".go"),
		strings.HasSuffix(lower, ".rs"),
		strings.HasSuffix(lower, ".c"),
		strings.HasSuffix(lower, ".h"),
		strings.HasSuffix(lower, ".cpp"),
		strings.HasSuffix(lower, ".hpp"),
		strings.HasSuffix(lower, ".cc"),
		strings.HasSuffix(lower, ".cxx"),
		strings.HasSuffix(lower, ".hh"),
		strings.HasSuffix(lower, ".cs"),
		strings.HasSuffix(lower, ".rb"),
		strings.HasSuffix(lower, ".php"),
		strings.HasSuffix(lower, ".swift"),
		strings.HasSuffix(lower, ".dart"),
		strings.HasSuffix(lower, ".java"),
		strings.HasSuffix(lower, ".kt"),
		strings.HasSuffix(lower, ".kts"),
		strings.HasSuffix(lower, ".groovy"),
		strings.HasSuffix(lower, ".gradle"),
		strings.HasSuffix(lower, ".scala"),
		strings.HasSuffix(lower, ".r"),
		strings.HasSuffix(lower, ".pl"),
		strings.HasSuffix(lower, ".pm"),
		strings.HasSuffix(lower, ".properties"),
		strings.HasSuffix(lower, ".prof"),
		strings.HasSuffix(lower, ".plist"),
		strings.HasSuffix(lower, ".xml"),
		strings.HasSuffix(lower, ".cmake"),
		strings.HasSuffix(lower, ".makefile"),
		strings.HasSuffix(lower, ".mk"),
		strings.HasSuffix(lower, ".bat"),
		strings.HasSuffix(lower, ".cmd"),
		strings.HasSuffix(lower, ".ps1"),
		strings.HasSuffix(lower, ".env"),
		strings.HasSuffix(lower, ".csv"),
		strings.HasSuffix(lower, ".tsv"),
		strings.HasSuffix(lower, ".log"):
		return TypeCode
	}

	// Unknown extension, but with magic bytes we may still classify.
	if len(data) >= 4 {
		switch {
		case data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G':
			return TypeImage
		case data[0] == 0xFF && data[1] == 0xD8:
			return TypeImage
		case data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F':
			return TypeNative
		case data[0] == 0x00 && data[1] == 'a' && data[2] == 's' && data[3] == 'm':
			return TypeCode // WebAssembly
		case string(data[:4]) == "RIFF":
			return TypeImage // WEBP or WAV — cards differentiate later
		}
	}
	return TypeOther
}

// DetectLanguage returns the concrete CodeLanguage for a TypeCode artifact.
// It is a best-effort sniff based on extension first, then magic bytes /
// shebang. Callers should only invoke this when Classify returned TypeCode.
func DetectLanguage(path string, data []byte) CodeLanguage {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".js"),
		strings.HasSuffix(lower, ".mjs"),
		strings.HasSuffix(lower, ".cjs"),
		strings.HasSuffix(lower, ".jsx"):
		return LangJS
	case strings.HasSuffix(lower, ".bundle"):
		return LangBundle
	case strings.HasSuffix(lower, ".ts"),
		strings.HasSuffix(lower, ".tsx"):
		return LangTS
	case strings.HasSuffix(lower, ".html"),
		strings.HasSuffix(lower, ".htm"),
		strings.HasSuffix(lower, ".xhtml"):
		return LangHTML
	case strings.HasSuffix(lower, ".css"):
		return LangCSS
	case strings.HasSuffix(lower, ".proto"):
		return LangProto
	case strings.HasSuffix(lower, ".json"),
		strings.HasSuffix(lower, ".json5"):
		return LangJSON
	case strings.HasSuffix(lower, ".wasm"):
		return LangWASM
	case strings.HasSuffix(lower, ".lua"):
		return LangLua
	case strings.HasSuffix(lower, ".py"):
		return LangPython
	case strings.HasSuffix(lower, ".sh"),
		strings.HasSuffix(lower, ".bash"),
		strings.HasSuffix(lower, ".bat"),
		strings.HasSuffix(lower, ".cmd"),
		strings.HasSuffix(lower, ".ps1"):
		return LangShell
	case strings.HasSuffix(lower, ".sql"):
		return LangSQL
	case strings.HasSuffix(lower, ".yaml"),
		strings.HasSuffix(lower, ".yml"):
		return LangYAML
	case strings.HasSuffix(lower, ".toml"):
		return LangTOML
	case strings.HasSuffix(lower, ".ini"),
		strings.HasSuffix(lower, ".cfg"),
		strings.HasSuffix(lower, ".conf"),
		strings.HasSuffix(lower, ".env"):
		return LangINI
	case strings.HasSuffix(lower, ".go"):
		return LangGo
	case strings.HasSuffix(lower, ".rs"):
		return LangRust
	case strings.HasSuffix(lower, ".c"),
		strings.HasSuffix(lower, ".h"):
		return LangC
	case strings.HasSuffix(lower, ".cpp"),
		strings.HasSuffix(lower, ".hpp"),
		strings.HasSuffix(lower, ".cc"),
		strings.HasSuffix(lower, ".cxx"),
		strings.HasSuffix(lower, ".hh"):
		return LangCPP
	case strings.HasSuffix(lower, ".java"):
		return LangJava
	case strings.HasSuffix(lower, ".kt"),
		strings.HasSuffix(lower, ".kts"):
		return LangKotlin
	case strings.HasSuffix(lower, ".swift"):
		return LangSwift
	case strings.HasSuffix(lower, ".dart"):
		return LangDart
	case strings.HasSuffix(lower, ".rb"):
		return LangRuby
	case strings.HasSuffix(lower, ".php"):
		return LangPHP
	case strings.HasSuffix(lower, ".cs"):
		return LangCSharp
	case strings.HasSuffix(lower, ".properties"):
		return LangProperties
	case strings.HasSuffix(lower, ".xml"),
		strings.HasSuffix(lower, ".plist"):
		return LangXML
	case strings.HasSuffix(lower, ".prof"),
		strings.HasSuffix(lower, ".log"):
		return LangProf
	case strings.HasSuffix(lower, ".groovy"),
		strings.HasSuffix(lower, ".gradle"),
		strings.HasSuffix(lower, ".scala"):
		return LangJava // close enough for highlighting
	case strings.HasSuffix(lower, ".r"):
		return LangPython // R is close enough for basic highlighting
	case strings.HasSuffix(lower, ".pl"),
		strings.HasSuffix(lower, ".pm"):
		return LangShell // Perl — shell-like highlighting
	case strings.HasSuffix(lower, ".cmake"),
		strings.HasSuffix(lower, ".makefile"),
		strings.HasSuffix(lower, ".mk"):
		return LangShell // Makefile — shell-like
	}

	// Magic / shebang fallbacks.
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 'a' && data[2] == 's' && data[3] == 'm' {
		return LangWASM
	}
	if len(data) >= 2 && data[0] == '#' && data[1] == '!' {
		// Shebang scripts.
		end := 80
		if len(data) < end {
			end = len(data)
		}
		first := strings.ToLower(string(data[:end]))
		switch {
		case strings.Contains(first, "python"):
			return LangPython
		case strings.Contains(first, "node"):
			return LangJS
		case strings.Contains(first, "lua"):
			return LangLua
		case strings.Contains(first, "ruby"):
			return LangRuby
		case strings.Contains(first, "perl"):
			return LangShell
		case strings.Contains(first, "bash"), strings.Contains(first, "/sh"):
			return LangShell
		}
	}
	return LangText
}
