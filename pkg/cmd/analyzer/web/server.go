package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/decisionai"
	"mega-analyzer/pkg/internal/vmware"
)

var errNoAPKEditor = errors.New("the APK editor is not available in this build")

// Options configures a web UI server. Zero values are sensible defaults.
type Options struct {
	Workspace             string // persistent results root; default user config directory
	Port                  int    // TCP port; required
	Host                  string // bind host; defaults to $MEGA_ANALYZER_HOST or 127.0.0.1
	Exe                   string // analyzer binary; defaults to os.Executable()
	OpenBrowser           bool   // open the default browser once the listener is bound
	Token                 string // shared secret required by /api/*; auto-generated off-loopback
	Privileged            bool   // loopback-only, mandatory pairing, no root browser
	Deps                  Deps
	ScanConcurrency       int    // default 2; MEGA_ANALYZER_SCAN_CONCURRENCY
	ScanQueueSize         int    // default 8; MEGA_ANALYZER_WEB_QUEUE_SIZE
	DecisionAIURL         string // operator configuration, never supplied by an upload
	DecisionAIMaxFindings int
	DecisionAIBudget      int
}

// Server holds what used to be five package-level globals plus a 780-line
// closure. Two Servers can now run side by side, which is what makes the
// handler tests parallelisable.
type Server struct {
	vmwareOnce     sync.Once
	vmwareControl  *vmware.Controller
	vmwareDiscover func() []vmEntry
	queueOnce      sync.Once
	queue          *scanQueue
	workspaceOnce  sync.Once
	workspaceStore *workspaceStore
	workspaceErr   error
	exe            string
	host           string
	port           int
	token          string
	opts           Options
	deps           Deps

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
	if opts.DecisionAIURL != "" {
		base, err := decisionai.NormalizeURL(opts.DecisionAIURL)
		if err != nil {
			return nil, err
		}
		opts.DecisionAIURL = base
		if opts.DecisionAIMaxFindings == 0 {
			opts.DecisionAIMaxFindings = 64
		}
		if opts.DecisionAIBudget == 0 {
			opts.DecisionAIBudget = 30
		}
		if opts.DecisionAIMaxFindings < 1 || opts.DecisionAIMaxFindings > 512 || opts.DecisionAIBudget < 1 || opts.DecisionAIBudget > 300 {
			return nil, fmt.Errorf("DecisionAI requires 1..512 findings and a 1..300 second budget")
		}
	}
	for _, item := range []struct {
		name          string
		value         *int
		fallback, max int
	}{
		{"MEGA_ANALYZER_SCAN_CONCURRENCY", &opts.ScanConcurrency, 2, 64},
		{"MEGA_ANALYZER_WEB_QUEUE_SIZE", &opts.ScanQueueSize, 8, 128},
	} {
		if *item.value == 0 {
			*item.value = item.fallback
			if raw := os.Getenv(item.name); raw != "" {
				n, err := strconv.Atoi(raw)
				if err != nil {
					return nil, fmt.Errorf("invalid %s", item.name)
				}
				*item.value = n
			}
		}
		if *item.value < 1 || *item.value > item.max {
			return nil, fmt.Errorf("%s must be between 1 and %d", item.name, item.max)
		}
	}
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
	if opts.Privileged {
		host = strings.TrimSpace(host)
		if host == "" || strings.EqualFold(host, "localhost") {
			host = "127.0.0.1"
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("administrator/root web UI must bind to a literal loopback address")
		}
		if opts.Token != "" && !validPrivilegedToken(opts.Token) {
			return nil, fmt.Errorf("administrator token requires 32–256 URL-safe ASCII characters")
		}
		opts.OpenBrowser = false
	}
	opts.Deps.fill()
	s := &Server{exe: exe, host: host, port: opts.Port, token: opts.Token, opts: opts, deps: opts.Deps}
	if s.token == "" && (opts.Privileged || !isLoopbackHost(host)) {
		// Binding off-loopback exposes process spawning and file downloads to
		// the whole network, so that mode is token-gated by default.
		s.token = newToken()
		if s.token == "" {
			return nil, fmt.Errorf("cannot generate a secure web token; refusing to start")
		}
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

	pageURL := "http://" + net.JoinHostPort(browserHost(s.host), strconv.Itoa(s.port)) + "/"
	if s.token != "" {
		pageURL += "?" + url.Values{"t": {s.token}}.Encode()
	}
	s.banner(pageURL)
	if s.opts.OpenBrowser {
		go openBrowser(pageURL)
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops accepting connections and waits for in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	s.scanQueue().shutdown()
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

func (s *Server) banner(url string) {
	fmt.Printf("\n  Mega-Analyzer web UI  ->  %s\n", url)
	if !isLoopbackHost(s.host) {
		fmt.Printf("  WARNING: bound to %s -- reachable from the network. Token required.\n", s.host)
	}
	if s.opts.Privileged {
		fmt.Printf("  ADMIN/ROOT: loopback + pairing required. Open the URL in your normal browser.\n")
		fmt.Printf("  Analyses inherit these rights. This is NOT a VM or a malware isolation boundary.\n")
	}
	fmt.Printf("  Press Ctrl+C to stop.\n\n")
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
