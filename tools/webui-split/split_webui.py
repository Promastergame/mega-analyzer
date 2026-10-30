#!/usr/bin/env python3
"""Deterministic refactor kit generator for web_ui.go.

Splits one 5954-line `package main` file into:
  pkg/internal/webui/*.go          (Go code, grouped by concern)
  pkg/internal/webui/assets/*      (index.html + app.css + app.js + error.html)
  web_ui.go                        (thin main-package shim)

Everything is mechanical: code is MOVED, never rewritten by hand, except for a
small list of explicit, documented patches (see PATCHES).
"""
import os, re, sys, hashlib, shutil

SRC = os.environ.get("WEBUI_SRC", "/data/src/web_ui.go")
OUT = os.environ.get("WEBUI_OUT", "/data/out")
WEBUI = os.path.join(OUT, "pkg", "internal", "webui")
ASSETS = os.path.join(WEBUI, "assets")
IMPORT_PATH = "mega-analyzer/pkg/internal"
report = []


def log(msg):
    report.append(msg)
    print(msg)


# ---------------------------------------------------------------- masking ----
def code_mask(text):
    """Blank out string/rune/comment payloads, preserving length and newlines."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j])); i = j
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2; continue
                if text[j] in ('"', "\n"):
                    break
                j += 1
            j = min(j + 1, n)
            seg = text[i:j]
            out.append('"' + " " * (len(seg) - 2) + '"' if len(seg) >= 2 else " " * len(seg))
            i = j
        elif c == "`":
            j = text.find("`", i + 1)
            j = n if j < 0 else j + 1
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j])); i = j
        elif c == "'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2; continue
                if text[j] in ("'", "\n"):
                    break
                j += 1
            j = min(j + 1, n)
            out.append(" " * (j - i)); i = j
        else:
            out.append(c); i += 1
    return "".join(out)


def delta(s):
    d = 0
    for ch in s:
        if ch in "{([":
            d += 1
        elif ch in "})]":
            d -= 1
    return d


src = open(SRC, encoding="utf-8").read().replace("\r\n", "\n")
masked = code_mask(src)
assert len(masked) == len(src), "mask changed length"
lines = src.split("\n")
mlines = masked.split("\n")
log("source: %s (%d lines, %d bytes)" % (SRC, len(lines), len(src)))


# ------------------------------------------------------- top-level decls -----
DECL_RE = re.compile(r"^(func|type|var|const)\b")


def scan_decls():
    decls, depth, i = [], 0, 0
    while i < len(lines):
        if depth == 0 and DECL_RE.match(mlines[i]):
            d, j = 0, i
            while j < len(lines):
                d += delta(mlines[j])
                if d <= 0:
                    break
                j += 1
            doc = i
            while doc - 1 >= 0 and lines[doc - 1].lstrip().startswith("//"):
                doc -= 1
            decls.append({"doc": doc, "start": i, "end": j, "head": lines[i]})
            i = j + 1
            depth = 0
            continue
        depth += delta(mlines[i])
        i += 1
    return decls


def decl_name(head):
    m = re.match(r"^func\s+\(\s*\w+\s+\*?(\w+)\s*\)\s+(\w+)", head)
    if m:
        return m.group(1) + "." + m.group(2)
    m = re.match(r"^func\s+(\w+)", head)
    if m:
        return m.group(1)
    m = re.match(r"^(?:type|var|const)\s+(\w+)", head)
    if m:
        return m.group(1)
    return "GROUP"


decls = scan_decls()
for d in decls:
    d["name"] = decl_name(d["head"])
    d["text"] = "\n".join(lines[d["doc"]:d["end"] + 1])
log("top-level declarations found: %d" % len(decls))
by_name = {}
for d in decls:
    by_name.setdefault(d["name"], []).append(d)


# ------------------------------------------------------------- assets --------
os.makedirs(ASSETS, exist_ok=True)

blob_key = "const webUIHTML = `"
i0 = src.index(blob_key) + len(blob_key)
i1 = src.index("`", i0)
blob = src[i0:i1]
assert "`" not in blob

m = re.search(r"<style>\n(.*?)\n</style>", blob, re.S)
css = m.group(1)
blob_no_css = blob[:m.start()] + '<link rel="stylesheet" href="/static/app.css">' + blob[m.end():]
m2 = re.search(r"<script>\n(.*?)\n</script>", blob_no_css, re.S)
js = m2.group(1)
html_doc = blob_no_css[:m2.start()] + '<script src="/static/app.js" defer></script>' + blob_no_css[m2.end():]

open(os.path.join(ASSETS, "app.css"), "w", encoding="utf-8").write(css + "\n")
open(os.path.join(ASSETS, "app.js"), "w", encoding="utf-8").write(js + "\n")
open(os.path.join(ASSETS, "index.html"), "w", encoding="utf-8").write(html_doc + "\n")

# round-trip proof: index.html + app.css + app.js must rebuild the old constant
rebuilt = html_doc.replace('<link rel="stylesheet" href="/static/app.css">',
                           "<style>\n" + css + "\n</style>")
rebuilt = rebuilt.replace('<script src="/static/app.js" defer></script>',
                          "<script>\n" + js + "\n</script>")
assert rebuilt == blob, "asset split is NOT byte-identical"
log("assets: index.html %d B / app.css %d B / app.js %d B  (round-trip byte-identical: OK)"
    % (len(html_doc), len(css), len(js)))

# error page -> html/template (auto-escaping instead of manual html.EscapeString)
ekey = "const errorPageHTML = `"
j0 = src.index(ekey) + len(ekey)
j1 = src.index("`", j0)
err_html = src[j0:j1].replace("%%", "%")
for field in ("{{.Code}}", "{{.Status}}", "{{.Code}}", "{{.Status}}", "{{.Detail}}", "{{.Path}}"):
    err_html = re.sub(r"%[ds]", field, err_html, count=1)
assert "%d" not in err_html and "%s" not in err_html
open(os.path.join(ASSETS, "error.html"), "w", encoding="utf-8").write(err_html)
log("assets: error.html %d B (printf verbs -> html/template fields)" % len(err_html))


# ------------------------------------------------------------ file map -------
FILEMAP = {
    "maxJobLines": "logstream.go", "webUIHeartbeat": "logstream.go",
    "progressThrottle": "logstream.go", "progressEventName": "logstream.go",
    "progressLineRE": "logstream.go", "isProgressLine": "logstream.go",
    "scanLinesAnyBreak": "logstream.go", "ansiRE": "logstream.go", "stripANSI": "logstream.go",
    "httpError": "httperr.go", "requireMethod": "httperr.go",
    "scanJob": "job.go", "newScanJob": "job.go",
    "scanJob.wakeLocked": "job.go", "scanJob.broadcast": "job.go", "scanJob.read": "job.go",
    "scanJob.finish": "job.go", "scanJob.isDone": "job.go", "scanJob.stop": "job.go",
    "pruneJobs": "store.go",
    "isSafeArg": "validate.go", "isDigits": "validate.go", "isSafeHostPort": "validate.go",
    "isSafeURL": "validate.go", "isSafeOutputPath": "validate.go",
    "validModes": "modes.go", "filelessModes": "modes.go", "buildModeArgs": "modes.go",
    "liveADB": "device_android.go", "liveSerial": "device_android.go",
    "deviceSize": "device_android.go", "liveDeviceSize": "device_android.go",
    "liveSafeKey": "device_android.go", "listAVDs": "device_android.go",
    "vmEntry": "device_vm.go", "vboxVMLine": "device_vm.go", "findTool": "device_vm.go",
    "detectVBoxVMs": "device_vm.go", "detectVMwareVMs": "device_vm.go",
    "runToolBounded": "exec.go",
    "uiBadgeCounts": "meta.go",
    "saveUpload": "upload.go", "sandboxListFiles": "upload.go", "sandboxDownloadFile": "upload.go",
    "runAnalysis": "runner.go",
    "hostInfo": "hostinfo.go", "androidSystemMarkers": "hostinfo.go", "looksLikeAndroid": "hostinfo.go",
    "androidProp": "hostinfo.go", "readPropFile": "hostinfo.go", "osReleasePrettyName": "hostinfo.go",
    "vendorPrefix": "hostinfo.go", "describeHost": "hostinfo.go", "detectHostPlatform": "hostinfo.go",
    "hostPlatform": "hostinfo.go", "hostInfo.payload": "hostinfo.go",
    "openBrowser": "browser.go", "shouldOpenWebUIBrowser": "browser.go",
    # handled by dedicated generators / replaced
    "errorPageHTML": None, "webUIHTML": None, "runWebUI": None, "newJobID": None,
}
GROUPMAP = [("jobsMu", "store.go"), ("deviceSizeCache", "device_android.go"),
            ("hostPlatformOnce", "hostinfo.go")]

files = {}


def add(fname, text):
    files.setdefault(fname, []).append(text.rstrip("\n"))


unmapped = []
for d in decls:
    name = d["name"]
    if name == "GROUP":
        target = None
        for needle, fname in GROUPMAP:
            if re.search(r"\b%s\b" % needle, d["text"]):
                target = fname
                break
        if target is None:
            unmapped.append(d["head"])
            continue
        text = d["text"]
        if target == "store.go":
            # activeServer/activeServerMu move to server.go with the Server type
            text = ("var (\n\tjobsMu sync.Mutex\n\tjobs   = map[string]*scanJob{}\n)")
        add(target, text)
        continue
    if name not in FILEMAP:
        unmapped.append(d["head"])
        continue
    target = FILEMAP[name]
    if target:
        add(target, d["text"])
if unmapped:
    log("WARNING unmapped declarations:\n  " + "\n  ".join(unmapped))


# ------------------------------------------------ runWebUI -> handlers -------
run = by_name["runWebUI"][0]
bstart, bend = run["start"] + 1, run["end"] - 1
body, mbody = lines[bstart:bend + 1], mlines[bstart:bend + 1]

NAMES = {
    "/": "serveApp", "/api/live/status": "handleLiveStatus", "/api/live/screen": "handleLiveScreen",
    "/api/live/stream": "handleLiveStream", "/api/live/input": "handleLiveInput",
    "/api/pkg-version": "handlePkgVersion", "/api/env": "handleEnv", "/api/meta": "handleMeta",
    "/api/scan": "handleScan", "/api/events/": "handleEvents", "/api/evidence/": "handleEvidence",
    "/api/result/": "handleResult", "/api/sandbox/": "handleSandbox", "/api/report/": "handleReport",
    "/api/stop/": "handleStop",
}
GROUPS = {
    "serveApp": "handlers_app.go", "handleLiveStatus": "handlers_live.go",
    "handleLiveScreen": "handlers_live.go", "handleLiveStream": "handlers_live.go",
    "handleLiveInput": "handlers_live.go", "handlePkgVersion": "handlers_env.go",
    "handleEnv": "handlers_env.go", "handleMeta": "handlers_env.go",
    "handleAPKEditorOpen": "handlers_apkeditor.go", "handleScan": "handlers_scan.go",
    "handleEvents": "handlers_events.go", "handleEvidence": "handlers_result.go",
    "handleResult": "handlers_result.go", "handleReport": "handlers_result.go",
    "handleSandbox": "handlers_sandbox.go", "handleStop": "handlers_jobs.go",
}
DEPS = {
    "handleLiveVideo": "LiveVideo", "handleLiveAudio": "LiveAudio",
    "handleFridaStatus": "FridaStatus", "handleFridaStart": "FridaStart",
    "handleFridaProcesses": "FridaProcesses", "handleFridaREPL": "FridaREPL",
    "handleFridaRepackAPK": "FridaRepack",
}

H_INLINE = re.compile(r'^\tmux\.HandleFunc\("([^"]+)",\s*func\(w http\.ResponseWriter, r \*http\.Request\)\s*\{\s*$')
H_NAMED = re.compile(r'^\tmux\.HandleFunc\("([^"]+)",\s*(\w+)\)\s*$')
H_LOCAL = re.compile(r'^\t(\w+)\s*:=\s*func\(w http\.ResponseWriter, r \*http\.Request\)\s*\{\s*$')


def dedent(block):
    return "\n".join(l[1:] if l.startswith("\t") else l for l in block)


def rewrite(text):
    text = re.sub(r"(?<![\w.])exe(?![\w])", "s.exe", text)
    text = text.replace("LaunchAPKEditor(", "s.deps.LaunchAPKEditor(")
    return text


def block_end(k):
    d, j = 0, k
    while j < len(body):
        d += delta(mbody[j])
        if d <= 0:
            return j
        j += 1
    raise SystemExit("unterminated block at %d" % k)


def doc_above(k):
    ds = k
    while ds - 1 >= 0 and body[ds - 1].strip().startswith("//"):
        ds -= 1
    return [l.strip() for l in body[ds:k]]


routes, methods, seen_paths = [], [], set()
k = 0
while k < len(body):
    line = body[k]
    m = H_INLINE.match(line)
    if m:
        path = m.group(1)
        name = NAMES.get(path) or ("handle" + re.sub(r"[^A-Za-z0-9]", "", path.title()))
        end = block_end(k)
        doc = doc_above(k)
        if path != "/":
            inner = dedent(body[k + 1:end])
            head = ["// %s serves %s." % (name, path)] + ["// " + d[2:].strip() for d in doc if d.startswith("//")]
            methods.append((name, "\n".join(head) + "\nfunc (s *Server) %s(w http.ResponseWriter, r *http.Request) {\n%s\n}" % (name, rewrite(inner))))
        routes.append((path, "s." + name))
        seen_paths.add(path)
        k = end + 1
        continue
    m = H_NAMED.match(line)
    if m:
        path, ident = m.group(1), m.group(2)
        if ident in DEPS:
            routes.append((path, "s.deps." + DEPS[ident]))
        elif ident in ("handleAPKEditorOpen",):
            routes.append((path, "s.handleAPKEditorOpen"))
        else:
            routes.append((path, "s." + ident))
        k += 1
        continue
    m = H_LOCAL.match(line)
    if m:
        name = m.group(1)
        end = block_end(k)
        inner = dedent(body[k + 1:end])
        methods.append((name, "// %s launches the native APK patch editor.\nfunc (s *Server) %s(w http.ResponseWriter, r *http.Request) {\n%s\n}" % (name, name, rewrite(inner))))
        k = end + 1
        continue
    k += 1

log("routes extracted: %d   handler methods generated: %d" % (len(routes), len(methods)))
for name, text in methods:
    add(GROUPS.get(name, "handlers_misc.go"), text)


# ------------------------------------------------------------ router.go ------
rl = ["// routes wires every endpoint. One table, no 780-line closure soup:",
      "// adding an endpoint means adding one line here plus one method.",
      "func (s *Server) routes() http.Handler {", "\tmux := http.NewServeMux()", "",
      "\t// static SPA assets (embedded, ETag + immutable caching)",
      '\tmux.Handle("/static/", s.staticHandler())', ""]
for path, h in routes:
    rl.append('\tmux.HandleFunc(%-24s %s)' % ('"%s",' % path, h))
rl += ["", "\treturn s.middleware(mux)", "}"]
add("router.go", "\n".join(rl))


# ------------------------------------------------- hand-written new files ----
HAND = {}

HAND["doc.go"] = '''// Package webui serves the Mega-Analyzer control surface: the single-page app,
// the scan/job API, the SSE log stream, the live-device bridge and the artifact
// downloads.
//
// Layout
//
//\tserver.go          Server type, Options, bind + graceful shutdown
//\trouter.go          the one and only route table
//\tsecurity.go        panic recovery, security headers, local-origin guard, token
//\tstatic.go          embedded asset serving (ETag, Range, 304)
//\tassets.go          //go:embed of assets/*, content hashes
//\tassets/            index.html, app.css, app.js, error.html
//\thandlers_*.go      one file per endpoint family, methods on *Server
//\tjob.go / store.go  scan job buffer + registry
//\trunner.go          spawning the analyzer, log fan-out
//\tlogstream.go       line splitting, ANSI stripping, progress detection
//\tvalidate.go        argument / path / URL allowlists
//\tmodes.go           analysis modes and CLI argument building
//\tdevice_*.go        adb, AVD, VirtualBox, VMware discovery
//\thostinfo.go        host platform detection (incl. Android/Termux)
//\tupload.go          multipart intake, sandbox file listing/download
//\tdeps.go            handlers owned by other packages, injected
//
// Everything that used to be a package-level closure inside a 780-line
// runWebUI is now a method on Server, so state is injected instead of global.
package webui
'''

HAND["deps.go"] = '''// Handlers that live outside this package (live video/audio, Frida, the native
// APK editor) are injected instead of imported, which keeps webui free of
// import cycles and makes every endpoint mockable in tests.

package webui

import "net/http"

// Deps are the collaborators the web UI does not own.
type Deps struct {
	LiveVideo      http.HandlerFunc
	LiveAudio      http.HandlerFunc
	FridaStatus    http.HandlerFunc
	FridaStart     http.HandlerFunc
	FridaProcesses http.HandlerFunc
	FridaREPL      http.HandlerFunc
	FridaRepack    http.HandlerFunc

	// LaunchAPKEditor opens the native patch editor for a local file.
	LaunchAPKEditor func(path string) error
}

// fill replaces missing collaborators with a 501 stub so a partially wired
// Server can never panic on a nil handler at registration time.
func (d *Deps) fill() {
	stub := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			httpError(w, r, http.StatusNotImplemented, name+" is not wired into this build.")
		}
	}
	for _, f := range []struct {
		p    *http.HandlerFunc
		name string
	}{
		{&d.LiveVideo, "Live video"}, {&d.LiveAudio, "Live audio"},
		{&d.FridaStatus, "Frida status"}, {&d.FridaStart, "Frida start"},
		{&d.FridaProcesses, "Frida process list"}, {&d.FridaREPL, "Frida REPL"},
		{&d.FridaRepack, "Frida repack"},
	} {
		if *f.p == nil {
			*f.p = stub(f.name)
		}
	}
	if d.LaunchAPKEditor == nil {
		d.LaunchAPKEditor = func(string) error { return errNoAPKEditor }
	}
}
'''

HAND["assets.go"] = '''// The single-page app used to be a 204 KB Go string constant (76%% of the old
// web_ui.go). It now lives in assets/ as real .html/.css/.js files: editors
// lint and highlight them, and the "no backtick may appear anywhere in this
// file" trap is gone.

package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

//go:embed assets/index.html assets/app.css assets/app.js assets/error.html
var assetFS embed.FS

type staticAsset struct {
	body []byte
	mime string
	etag string
}

var staticAssets = map[string]*staticAsset{}

func init() {
	for name, mime := range map[string]string{
		"index.html": "text/html; charset=utf-8",
		"app.css":    "text/css; charset=utf-8",
		"app.js":     "text/javascript; charset=utf-8",
	} {
		body := []byte(mustAsset("assets/" + name))
		sum := sha256.Sum256(body)
		staticAssets[name] = &staticAsset{
			body: body,
			mime: mime,
			etag: `"` + hex.EncodeToString(sum[:8]) + `"`,
		}
	}
}

func mustAsset(name string) string {
	b, err := assetFS.ReadFile(name)
	if err != nil {
		panic("webui: embedded asset missing: " + name)
	}
	return string(b)
}
'''

HAND["static.go"] = '''package webui

import (
	"bytes"
	"net/http"
	"path"
	"strings"
	"time"
)

// staticHandler serves assets/ from the binary. ServeContent gives us ETag
// revalidation, HEAD and Range for free -- the old code wrote a fresh 200 KB
// copy of the whole app on every navigation.
func (s *Server) staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		name := path.Base(path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/static/")))
		a, ok := staticAssets[name]
		if !ok || name == "index.html" {
			httpError(w, r, http.StatusNotFound, "No asset is served at this address.")
			return
		}
		w.Header().Set("Content-Type", a.mime)
		w.Header().Set("ETag", a.etag)
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(a.body))
	})
}
'''

HAND["server.go"] = '''package webui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

var errNoAPKEditor = errors.New("the APK editor is not available in this build")

// Options configures a web UI server. Zero values are sensible defaults.
type Options struct {
	Port        int    // TCP port; required
	Host        string // bind host; defaults to $MEGA_ANALYZER_HOST or 127.0.0.1
	Exe         string // analyzer binary; defaults to os.Executable()
	OpenBrowser bool   // open the default browser once the listener is bound
	Token       string // shared secret required by /api/*; auto-generated off-loopback
	Deps        Deps
}

// Server holds what used to be five package-level globals plus a 780-line
// closure. Two Servers can now run side by side, which is what makes the
// handler tests parallelisable.
type Server struct {
	exe   string
	host  string
	port  int
	token string
	opts  Options
	deps  Deps

	mu  sync.Mutex
	srv *http.Server
}

// legacy test hook: the old package-level handle on the running server.
var (
	activeServer   *http.Server
	activeServerMu sync.Mutex
)

// New validates options and resolves defaults; it performs no I/O on the network.
func New(opts Options) (*Server, error) {
	exe := opts.Exe
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("cannot determine executable path: %w", err)
		}
	}
	host := opts.Host
	if host == "" {
		host = os.Getenv("MEGA_ANALYZER_HOST")
	}
	if host == "" {
		host = "127.0.0.1"
	}
	opts.Deps.fill()
	s := &Server{exe: exe, host: host, port: opts.Port, token: opts.Token, opts: opts, deps: opts.Deps}
	if s.token == "" && !isLoopbackHost(host) {
		// Binding off-loopback exposes process spawning and file downloads to
		// the whole network, so that mode is token-gated by default.
		s.token = newToken()
	}
	return s, nil
}

// ListenAndServe binds first and only then opens the browser: the old code did
// it the other way round and could hand the browser a port nothing listened on.
func (s *Server) ListenAndServe() error {
	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler: s.routes(),
		// Header timeout only: bodies are uploads and responses are SSE streams,
		// so Read/Write deadlines must stay unset.
		ReadHeaderTimeout: 20 * time.Second,
	}
	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()
	activeServerMu.Lock()
	activeServer = srv
	activeServerMu.Unlock()

	url := "http://" + net.JoinHostPort(browserHost(s.host), strconv.Itoa(s.port)) + "/"
	if s.token != "" {
		url += "?t=" + s.token
	}
	s.banner(url)
	if s.opts.OpenBrowser {
		go openBrowser(url)
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops accepting connections and waits for in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

func (s *Server) banner(url string) {
	fmt.Printf("\\n  Mega-Analyzer web UI  ->  %s\\n", url)
	if !isLoopbackHost(s.host) {
		fmt.Printf("  WARNING: bound to %s -- reachable from the network. Token required.\\n", s.host)
	}
	fmt.Printf("  Press Ctrl+C to stop.\\n\\n")
}

func browserHost(host string) string {
	if host == "0.0.0.0" || host == "::" || host == "" {
		return "127.0.0.1"
	}
	return host
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
'''

HAND["security.go"] = '''package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const tokenCookie = "ma_token"

// middleware is the one place every request passes through.
func (s *Server) middleware(next http.Handler) http.Handler {
	return s.recoverPanics(s.securityHeaders(s.guard(next)))
}

// recoverPanics keeps one bad request from tearing down the whole run.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil && rec != http.ErrAbortHandler {
				fmt.Printf("[webui] panic on %s %s: %v\\n", r.Method, r.URL.Path, rec)
				httpError(w, r, http.StatusInternalServerError, "The server hit an internal error handling this request.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		// Phase 1 CSP: still allows inline handlers/styles that the current SPA
		// relies on. Tighten to script-src 'self' once the inline onclick=
		// attributes are replaced by delegated listeners.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; "+
				"style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "+
				"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		next.ServeHTTP(w, r)
	})
}

// guard closes the hole that mattered most: the API had no authentication and
// no origin checks, so any web page the user happened to open could drive the
// local analyzer (spawn processes, control the attached phone, read reports)
// via DNS rebinding or a plain cross-site form post.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			httpError(w, r, http.StatusForbidden, "Unexpected Host header; refusing to serve (DNS-rebinding guard).")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				httpError(w, r, http.StatusForbidden, "Cross-site requests to the API are not allowed.")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(origin) {
				httpError(w, r, http.StatusForbidden, "Unexpected Origin header.")
				return
			}
			if !s.tokenOK(r) {
				httpError(w, r, http.StatusUnauthorized, "A session token is required when the UI is not bound to loopback.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(host string) bool {
	if host == "" {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if isLoopbackHost(h) || h == s.host || h == browserHost(s.host) {
		return true
	}
	// Off-loopback binds are token-gated, so any resolvable name is acceptable
	// there; loopback binds are not, so they stay strict.
	return !isLoopbackHost(s.host)
}

func (s *Server) originAllowed(origin string) bool {
	for _, scheme := range []string{"http://", "https://"} {
		if !strings.HasPrefix(origin, scheme) {
			continue
		}
		return s.hostAllowed(strings.TrimPrefix(origin, scheme))
	}
	return false
}

func (s *Server) tokenOK(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	if eq(r.Header.Get("X-MA-Token"), s.token) || eq(r.URL.Query().Get("t"), s.token) {
		return true
	}
	if c, err := r.Cookie(tokenCookie); err == nil && eq(c.Value, s.token) {
		return true
	}
	return false
}

func eq(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func newToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// newJobID replaces time.Now().UnixNano(): job IDs are the only thing standing
// between a caller and someone else\'s scan output, so they must not be guessable.
func newJobID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(int64(len(b)), 10)
	}
	return strconv.FormatUint(binary.BigEndian.Uint64(b[:])>>1, 10)
}
'''

HAND["handlers_app.go"] = '''package webui

import (
	"bytes"
	"net/http"
	"time"
)

// Tool slugs are served the same SPA so a reload of /sandbox or /mitm is not a 404.
var toolSlugs = map[string]bool{
	"/full": true, "/decode": true, "/machine-code": true, "/firmware": true,
	"/diff": true, "/js": true, "/js-patch": true,
	"/sandbox": true, "/scan": true, "/mitm": true,
}

// serveApp serves the single-page app from the embedded assets.
func (s *Server) serveApp(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	if r.URL.Path != "/" && !toolSlugs[r.URL.Path] {
		httpError(w, r, http.StatusNotFound, "No page is served at this address.")
		return
	}
	// Landing with ?t=<token> stores the token so the SPA\'s own fetch/EventSource
	// calls keep working unchanged in network-bound mode.
	if s.token != "" && eq(r.URL.Query().Get("t"), s.token) {
		http.SetCookie(w, &http.Cookie{
			Name: tokenCookie, Value: s.token, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
	}
	a := staticAssets["index.html"]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("ETag", a.etag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method == http.MethodHead {
		return
	}
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(a.body))
}
'''

HAND["compat.go"] = '''package webui

// runWebUI keeps the old entry point alive for the migrated tests. Production
// code should build a Server explicitly so it can be shut down and injected.
func runWebUI(port int) error {
	s, err := New(Options{Port: port, OpenBrowser: shouldOpenWebUIBrowser()})
	if err != nil {
		return err
	}
	return s.ListenAndServe()
}
'''


# ---------------------------------------------------- explicit patches -------
PATCHES = [
    ("httperr.go",
     '\tfmt.Fprintf(w, errorPageHTML, code, status, code, status,\n\t\thtml.EscapeString(detail), html.EscapeString(r.URL.Path))',
     '\t_ = errorPage.Execute(w, errorPageData{\n\t\tCode:   code,\n\t\tStatus: status,\n\t\tDetail: detail,\n\t\tPath:   r.URL.Path,\n\t})'),
    ("job.go",
     '\tif len(j.lines) > maxJobLines {\n\t\tdrop := len(j.lines) - maxJobLines\n\t\tj.lines = append([]string(nil), j.lines[drop:]...)\n\t\tj.base += drop\n\t}',
     '\tif len(j.lines) > maxJobLines {\n\t\t// Trim in batches: dropping exactly one line per append re-copied the\n\t\t// whole 200k-entry buffer on every single log line (O(n) per line).\n\t\tdrop := len(j.lines) - maxJobLines + jobTrimBatch\n\t\tif drop > len(j.lines) {\n\t\t\tdrop = len(j.lines)\n\t\t}\n\t\tcopy(j.lines, j.lines[drop:])\n\t\tfor i := len(j.lines) - drop; i < len(j.lines); i++ {\n\t\t\tj.lines[i] = ""\n\t\t}\n\t\tj.lines = j.lines[:len(j.lines)-drop]\n\t\tj.base += drop\n\t}'),
    ("runner.go",
     'func runAnalysis(exe string, job *scanJob, args []string) {',
     'func runAnalysis(exe string, job *scanJob, args []string) {\n\t// This runs on its own goroutine: an unrecovered panic here used to take\n\t// the whole analyzer process down, browser session included.\n\tdefer func() {\n\t\tif rec := recover(); rec != nil {\n\t\t\tjob.broadcast(fmt.Sprintf("[error] internal panic: %v", rec))\n\t\t\tjob.finish(2)\n\t\t}\n\t}()'),
    ("runner.go",
     '\t\t}\n\t\tflush()\n\t}\n\tgo pipe(stdout)',
     '\t\t}\n\t\tflush()\n\t\tif err := sc.Err(); err != nil {\n\t\t\t// A single line longer than the 1 MiB buffer stopped the scanner\n\t\t\t// silently, so the log just ended mid-run with no explanation.\n\t\t\tjob.broadcast("[warn] log stream truncated: " + err.Error())\n\t\t}\n\t}\n\tgo pipe(stdout)'),
]

extra_head = {
    "job.go": '// jobTrimBatch is how many lines are dropped at once when the buffer is full.\nconst jobTrimBatch = 4096',
    "httperr.go": ('// errorPage renders assets/error.html. html/template escapes Detail and Path\n'
                   '// automatically, so a future field cannot be forgotten the way a manual\n'
                   '// html.EscapeString call can.\n'
                   'var errorPage = template.Must(template.New("error").Parse(mustAsset("assets/error.html")))\n\n'
                   'type errorPageData struct {\n\tCode   int\n\tStatus string\n\tDetail string\n\tPath   string\n}'),
}
for _fname, _text in extra_head.items():
    files.setdefault(_fname, []).insert(0, _text)

bodies = {f: "\n\n".join(chunks) for f, chunks in files.items()}
for _fname, _old, _new in PATCHES:
    if _fname not in bodies or _old not in bodies[_fname]:
        log("WARNING patch did not apply in %s: %s" % (_fname, _old.strip().splitlines()[0][:50]))
        continue
    bodies[_fname] = bodies[_fname].replace(_old, _new, 1)
    log("patch applied in %s: %s" % (_fname, _new.strip().splitlines()[0][:52]))

# ------------------------------------------------------ import synthesis -----
STD = {"bufio": "bufio", "bytes": "bytes", "context": "context", "json": "encoding/json",
       "fmt": "fmt", "html": "html", "io": "io", "http": "net/http", "os": "os",
       "exec": "os/exec", "filepath": "path/filepath", "regexp": "regexp", "runtime": "runtime",
       "sort": "sort", "strconv": "strconv", "strings": "strings", "sync": "sync",
       "time": "time", "template": "html/template", "net": "net", "errors": "errors"}
INTERNAL = ["androidsdk", "evidencegraph", "sastrules", "trackers", "types"]
HEADER = "// Moved out of the monolithic web_ui.go. See doc.go for the package map.\n\npackage webui\n"


def render(fname, body):
    mt = code_mask(body)
    std = sorted({p for a, p in STD.items() if re.search(r"(?<![\w.])%s\." % a, mt)})
    internal = sorted({"%s/%s" % (IMPORT_PATH, a) for a in INTERNAL
                       if re.search(r"(?<![\w.])%s\." % a, mt)})
    imp = ""
    if std or internal:
        block = ["\t\"%s\"" % p for p in std]
        if internal:
            block += [""] + ["\t\"%s\"" % p for p in internal]
        imp = "\nimport (\n" + "\n".join(block) + "\n)\n"
    return HEADER + imp + "\n" + body.rstrip("\n") + "\n"


# ---------------------------------------------------------- write it out -----
os.makedirs(WEBUI, exist_ok=True)
written = []
for fname, body in sorted(bodies.items()):
    text = render(fname, body)
    open(os.path.join(WEBUI, fname), "w", encoding="utf-8", newline="\n").write(text)
    written.append((fname, text))
for fname, text in sorted(HAND.items()):
    open(os.path.join(WEBUI, fname), "w", encoding="utf-8", newline="\n").write(text)
    written.append((fname, text))

SHIM = '''package main

import (
	"mega-analyzer/pkg/internal/webui"
)

// runWebUI is now a 20-line wiring function: the 5954-line implementation moved
// to pkg/internal/webui. Handlers owned by other files stay here and are
// injected, so webui has no dependency on package main.
func runWebUI(port int) error {
	srv, err := webui.New(webui.Options{
		Port:        port,
		OpenBrowser: !isTruthyEnv("MEGA_ANALYZER_NO_BROWSER"),
		Deps: webui.Deps{
			LiveVideo:      handleLiveVideo,
			LiveAudio:      handleLiveAudio,
			FridaStatus:    handleFridaStatus,
			FridaStart:     handleFridaStart,
			FridaProcesses: handleFridaProcesses,
			FridaREPL:      handleFridaREPL,
			FridaRepack:    handleFridaRepackAPK,
			LaunchAPKEditor: func(path string) error {
				return LaunchAPKEditor(path)
			},
		},
	})
	if err != nil {
		return err
	}
	return srv.ListenAndServe()
}
'''
open(os.path.join(OUT, "web_ui.go"), "w", encoding="utf-8", newline="\n").write(SHIM)

TESTSHIM = '''// spaHTML is the single seam every UI test goes through. Pointing it at the
// embedded assets is the only change the ~40 existing markup/CSS/JS tests need.

package webui

func spaHTML() string {
	return mustAsset("assets/index.html")
}

// webUIHTML reassembles the old single-string form for tests that assert across
// the <style>/<script> boundary. Test-only: it exists in test builds alone.
var webUIHTML = func() string {
	h := mustAsset("assets/index.html")
	h = replaceOnce(h, `<link rel="stylesheet" href="/static/app.css">`,
		"<style>\\n"+mustAsset("assets/app.css")+"</style>")
	h = replaceOnce(h, `<script src="/static/app.js" defer></script>`,
		"<script>\\n"+mustAsset("assets/app.js")+"</script>")
	return h
}()

func replaceOnce(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		panic("webui: asset seam not found: " + old)
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
'''
open(os.path.join(WEBUI, "assets_legacy_test.go"), "w", encoding="utf-8", newline="\n").write(TESTSHIM)

VERIFY = '''#!/usr/bin/env bash
# Run from the repository root after copying the kit in.
set -euo pipefail
gofmt -l ./pkg/internal/webui | tee /tmp/gofmt.out
test ! -s /tmp/gofmt.out
go vet ./pkg/internal/webui/... .
go build ./...
go test ./pkg/internal/webui/... . -count=1
go test -race ./pkg/internal/webui/... -run "Job|Stream|Host" -count=1
'''
open(os.path.join(OUT, "verify.sh"), "w", encoding="utf-8", newline="\n").write(VERIFY)
os.chmod(os.path.join(OUT, "verify.sh"), 0o755)


# ------------------------------------------------------------ verification ---
log("")
log("generated files:")
total = 0
for fname, text in sorted(written):
    n = text.count("\n")
    total += n
    mt = code_mask(text)
    bal = sum(delta(l) for l in mt.split("\n"))
    log("  %-26s %5d lines  balance=%d %s" % (fname, n, bal, "OK" if bal == 0 else "<<< BROKEN"))
log("  %-26s %5d lines" % ("TOTAL Go", total))
log("")
log("assets: %d + %d + %d lines (html/css/js)"
    % (html_doc.count("\n") + 1, css.count("\n") + 1, js.count("\n") + 1))
open("/data/split_report.txt", "w", encoding="utf-8").write("\n".join(report) + "\n")
