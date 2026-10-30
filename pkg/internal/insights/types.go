package insights

import "time"

type Finding struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

type Evidence struct {
	Path    string `json:"path"`
	Line    int    `json:"line,omitempty"`
	Snippet string `json:"snippet,omitempty"`
}

type JNIReport struct {
	GeneratedAt       time.Time       `json:"generated_at"`
	Target            string          `json:"target"`
	Score             int             `json:"score"`
	LoadLibraries     []LibraryLoad   `json:"load_libraries,omitempty"`
	NativeMethods     []NativeMethod  `json:"native_methods,omitempty"`
	NativeLibraries   []NativeLibrary `json:"native_libraries,omitempty"`
	Bindings          []JNIBinding    `json:"bindings,omitempty"`
	RegisterNatives   []Evidence      `json:"register_natives,omitempty"`
	UnresolvedMethods []NativeMethod  `json:"unresolved_methods,omitempty"`
	Findings          []Finding       `json:"findings,omitempty"`
}

type LibraryLoad struct {
	Library string `json:"library"`
	Class   string `json:"class,omitempty"`
	Method  string `json:"method,omitempty"`
	File    string `json:"file"`
	Line    int    `json:"line"`
}

type NativeMethod struct {
	Class     string `json:"class"`
	Method    string `json:"method"`
	Signature string `json:"signature"`
	File      string `json:"file"`
	Line      int    `json:"line"`
}

type NativeLibrary struct {
	Name            string     `json:"name"`
	Path            string     `json:"path"`
	Size            int64      `json:"size"`
	JNIExports      []string   `json:"jni_exports,omitempty"`
	RegisterNatives bool       `json:"register_natives"`
	Signals         []Evidence `json:"signals,omitempty"`
}

type JNIBinding struct {
	JavaClass    string  `json:"java_class"`
	JavaMethod   string  `json:"java_method"`
	NativeSymbol string  `json:"native_symbol,omitempty"`
	Library      string  `json:"library,omitempty"`
	LibraryPath  string  `json:"library_path,omitempty"`
	Confidence   float64 `json:"confidence"`
	Reason       string  `json:"reason"`
}

type PrivacyReport struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Target      string          `json:"target"`
	Score       int             `json:"score"`
	Risk        string          `json:"risk"`
	Permissions []PrivacySignal `json:"permissions,omitempty"`
	Sources     []PrivacySignal `json:"sources,omitempty"`
	Sinks       []PrivacySignal `json:"sinks,omitempty"`
	Trackers    []PrivacySignal `json:"trackers,omitempty"`
	Endpoints   []PrivacySignal `json:"endpoints,omitempty"`
	Flows       []PrivacyFlow   `json:"flows,omitempty"`
	Findings    []Finding       `json:"findings,omitempty"`
}

type PrivacySignal struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	// Origin distinguishes ground truth from heuristic signals. For
	// permissions: "manifest" means the entry was declared via
	// <uses-permission> in AndroidManifest.xml — that's an actual
	// runtime grant the OS will request. "code" means the literal
	// string was found inside an SDK or app class — these are the
	// permissions the SDK *might* check or request, not necessarily
	// what the app declares. Empty Origin keeps backward compat for
	// non-permission signals.
	Origin string `json:"origin,omitempty"`
}

type PrivacyFlow struct {
	Source   string `json:"source"`
	Sink     string `json:"sink"`
	Endpoint string `json:"endpoint,omitempty"`
	Path     string `json:"path"`
	Reason   string `json:"reason"`
}

type GraphReport struct {
	GeneratedAt time.Time   `json:"generated_at"`
	Target      string      `json:"target"`
	Nodes       []GraphNode `json:"nodes"`
	Edges       []GraphEdge `json:"edges"`
	Summary     GraphStats  `json:"summary"`
}

type GraphStats struct {
	Nodes int `json:"nodes"`
	Edges int `json:"edges"`
}

type GraphNode struct {
	ID       string            `json:"id"`
	Label    string            `json:"label"`
	Kind     string            `json:"kind"`
	Severity string            `json:"severity,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
}

type GraphEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label"`
}

type DiffReport struct {
	GeneratedAt time.Time    `json:"generated_at"`
	OldPath     string       `json:"old_path"`
	NewPath     string       `json:"new_path"`
	Old         TargetDigest `json:"old"`
	New         TargetDigest `json:"new"`
	Added       DiffChanges  `json:"added"`
	Removed     DiffChanges  `json:"removed"`
	Changed     DiffChanges  `json:"changed"`
	RiskOld     int          `json:"risk_old"`
	RiskNew     int          `json:"risk_new"`
	RiskDelta   int          `json:"risk_delta"`
	Findings    []Finding    `json:"findings,omitempty"`
}

type TargetDigest struct {
	Path         string            `json:"path"`
	Kind         string            `json:"kind"`
	FileCount    int               `json:"file_count"`
	TotalSize    int64             `json:"total_size"`
	SHA256       string            `json:"sha256,omitempty"`
	Permissions  []string          `json:"permissions,omitempty"`
	Endpoints    []string          `json:"endpoints,omitempty"`
	NativeLibs   map[string]string `json:"native_libs,omitempty"`
	Certificates map[string]string `json:"certificates,omitempty"`
	Trackers     []string          `json:"trackers,omitempty"`
	Secrets      []string          `json:"secrets,omitempty"`
}

type DiffChanges struct {
	Permissions  []string `json:"permissions,omitempty"`
	Endpoints    []string `json:"endpoints,omitempty"`
	NativeLibs   []string `json:"native_libs,omitempty"`
	Certificates []string `json:"certificates,omitempty"`
	Trackers     []string `json:"trackers,omitempty"`
	Secrets      []string `json:"secrets,omitempty"`
	Files        []string `json:"files,omitempty"`
}

type FirmwareReport struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Target      string         `json:"target"`
	Kind        string         `json:"kind"`
	Score       int            `json:"score"`
	Risk        string         `json:"risk"`
	FileCount   int            `json:"file_count"`
	RootFSHints []string       `json:"rootfs_hints,omitempty"`
	Services    []FirmwareItem `json:"services,omitempty"`
	WebPanels   []FirmwareItem `json:"web_panels,omitempty"`
	Secrets     []FirmwareItem `json:"secrets,omitempty"`
	Packages    []FirmwareItem `json:"packages,omitempty"`
	Findings    []Finding      `json:"findings,omitempty"`
}

type FirmwareItem struct {
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
	Severity string `json:"severity,omitempty"`
	Detail   string `json:"detail,omitempty"`
}
