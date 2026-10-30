package analysis

// DefaultSources returns the built-in taint sources covering user input,
// network, file and IPC entry points on Android/JVM and common native inputs.
func DefaultSources() []Source {
	return []Source{
		{ID: "SRC-INTENT-EXTRA", Kind: KindIPC, Substr: "getStringExtra", Label: "Intent extra (IPC input)"},
		{ID: "SRC-INTENT-DATA", Kind: KindIPC, Substr: "getData", Label: "Intent data (IPC input)"},
		{ID: "SRC-INTENT-BUNDLE", Kind: KindIPC, Substr: "getExtras", Label: "Intent extras bundle"},
		{ID: "SRC-PARCEL", Kind: KindIPC, Substr: "readString", Label: "Parcel input"},
		{ID: "SRC-EDITTEXT", Kind: KindUserInput, Substr: "getText", Label: "UI text input"},
		{ID: "SRC-URI-QUERY", Kind: KindUserInput, Substr: "getQueryParameter", Label: "URI query parameter"},
		{ID: "SRC-HTTP-IN", Kind: KindNetwork, Substr: "getInputStream", Label: "Network input stream"},
		{ID: "SRC-SOCKET", Kind: KindNetwork, Substr: "getRemoteSocketAddress", Label: "Socket input"},
		{ID: "SRC-FILE-READ", Kind: KindFile, Substr: "readLine", Label: "File input"},
		{ID: "SRC-EXTERNAL", Kind: KindFile, Substr: "getExternalStorageDirectory", Label: "External storage path"},
	}
}

// DefaultSinks returns the built-in dangerous sinks with CWE, severity and
// remediation. Category enables profile/pack filtering upstream.
func DefaultSinks() []Sink {
	return []Sink{
		{ID: "SINK-CMD-EXEC", Substr: "Runtime;->exec", CWE: "CWE-78", Severity: SevCritical, Category: "cmdi",
			Title:       "OS command execution with tainted input",
			Remediation: "Avoid Runtime.exec with external input; use allowlists / ProcessBuilder with fixed args."},
		{ID: "SINK-CMD-PB", Substr: "ProcessBuilder", CWE: "CWE-78", Severity: SevCritical, Category: "cmdi",
			Title:       "Process launched with tainted input",
			Remediation: "Never pass untrusted data as command arguments; validate against an allowlist."},
		{ID: "SINK-SQL-RAW", Substr: "rawQuery", CWE: "CWE-89", Severity: SevHigh, Category: "sqli",
			Title:       "SQL query built from tainted input",
			Remediation: "Use parameterized queries / query() with selectionArgs instead of string concatenation."},
		{ID: "SINK-SQL-EXEC", Substr: "execSQL", CWE: "CWE-89", Severity: SevHigh, Category: "sqli",
			Title:       "execSQL with tainted input",
			Remediation: "Use parameterized statements; never concatenate user data into SQL."},
		{ID: "SINK-PATH-FILE", Substr: "Ljava/io/File;-><init>", CWE: "CWE-22", Severity: SevHigh, Category: "path",
			Title:       "File path constructed from tainted input",
			Remediation: "Canonicalize and validate paths; confine to an allowed base directory."},
		{ID: "SINK-DESER", Substr: "ObjectInputStream", CWE: "CWE-502", Severity: SevHigh, Category: "deser",
			Title:       "Deserialization of tainted data",
			Remediation: "Avoid Java serialization of untrusted data; use a safe format with a strict allowlist."},
		{ID: "SINK-SSRF-URL", Substr: "Ljava/net/URL;-><init>", CWE: "CWE-918", Severity: SevHigh, Category: "ssrf",
			Title:       "URL opened from tainted input (SSRF)",
			Remediation: "Validate host against an allowlist; block internal address ranges."},
		{ID: "SINK-REFLECT", Substr: "Class;->forName", CWE: "CWE-470", Severity: SevHigh, Category: "reflection",
			Title:       "Reflection class name from tainted input",
			Remediation: "Do not resolve class names from external input; use a fixed mapping."},
		{ID: "SINK-DEX-LOAD", Substr: "DexClassLoader", CWE: "CWE-470", Severity: SevCritical, Category: "reflection",
			Title:       "Dynamic code loading with tainted path",
			Remediation: "Never load code from writable/untrusted locations; verify signatures."},
		{ID: "SINK-WEBVIEW-URL", Substr: "loadUrl", CWE: "CWE-749", Severity: SevMedium, Category: "webview",
			Title:       "WebView loads tainted URL",
			Remediation: "Validate URLs; disable JavaScript and file access where possible."},
		{ID: "SINK-LOG", Substr: "Landroid/util/Log;", CWE: "CWE-532", Severity: SevMedium, Category: "leak",
			Title:       "Sensitive/tainted data written to log",
			Remediation: "Never log credentials or user data; strip sensitive fields."},
	}
}
