package labkit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// HTTPConfig configures an HTTP service.
type HTTPConfig struct {
	// Routes are user-defined endpoints served in addition to the built-ins.
	Routes []RouteConfig `json:"routes"`
	// DisableEcho removes the built-in /_echo reflector.
	DisableEcho bool `json:"disable_echo"`
	// DisableMetrics removes the built-in /_metrics endpoint.
	DisableMetrics bool `json:"disable_metrics"`
	// ReadTimeout and WriteTimeout bound a single request (default 15s each).
	ReadTimeout  Duration `json:"read_timeout"`
	WriteTimeout Duration `json:"write_timeout"`
	// MaxHeaderBytes bounds request header size (default 1 MiB).
	MaxHeaderBytes int `json:"max_header_bytes"`
}

// RouteConfig is a single canned endpoint. If WebSocket is true the route is
// upgraded to an RFC 6455 echo socket and Status/Body/Headers are ignored.
type RouteConfig struct {
	Path      string            `json:"path"`
	Status    int               `json:"status"`
	Body      string            `json:"body"`
	Headers   map[string]string `json:"headers"`
	WebSocket bool              `json:"websocket"`
}

// HTTPServer is a supervised net/http service with a middleware pipeline.
type HTTPServer struct {
	name    string
	srv     *http.Server
	ln      net.Listener
	log     *Logger
	metrics *Metrics
	errCh   chan error
}

func newHTTPServer(sc ServerConfig, d deps) (*HTTPServer, error) {
	cfg := sc.HTTP
	if cfg == nil {
		cfg = &HTTPConfig{}
	}
	readTimeout := cfg.ReadTimeout.D()
	if readTimeout == 0 {
		readTimeout = 15 * time.Second
	}
	writeTimeout := cfg.WriteTimeout.D()
	if writeTimeout == 0 {
		writeTimeout = 15 * time.Second
	}
	maxHeader := cfg.MaxHeaderBytes
	if maxHeader == 0 {
		maxHeader = 1 << 20
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "server": sc.Name})
	})
	if !cfg.DisableMetrics {
		mux.HandleFunc("/_metrics", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(d.metrics.Snapshot())
		})
	}
	if !cfg.DisableEcho {
		mux.HandleFunc("/_echo", echoHandler)
	}
	for _, rt := range cfg.Routes {
		if rt.Path == "" {
			return nil, fmt.Errorf("route with empty path")
		}
		if rt.WebSocket {
			mux.Handle(rt.Path, webSocketEcho(d.log, d.metrics))
			continue
		}
		mux.Handle(rt.Path, cannedRoute(rt))
	}

	handler := chain(mux,
		recovery(d.log),
		requestLogger(d.log, d.metrics),
		scenarioMiddleware(d.scenario, d.metrics),
	)

	ln, err := net.Listen("tcp", sc.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", sc.Addr, err)
	}
	return &HTTPServer{
		name:    sc.Name,
		log:     d.log,
		metrics: d.metrics,
		ln:      ln,
		errCh:   make(chan error, 1),
		srv: &http.Server{
			Handler:        handler,
			ReadTimeout:    readTimeout,
			WriteTimeout:   writeTimeout,
			MaxHeaderBytes: maxHeader,
		},
	}, nil
}

// Name implements Service.
func (s *HTTPServer) Name() string { return s.name }

// Addr implements Service.
func (s *HTTPServer) Addr() string { return s.ln.Addr().String() }

// Start implements Service.
func (s *HTTPServer) Start() error {
	go func() {
		err := s.srv.Serve(s.ln)
		if err != nil && err != http.ErrServerClosed {
			s.log.Error("http serve failed", Fields{"err": err.Error()})
		}
		s.errCh <- err
	}()
	return nil
}

// Close implements Service.
func (s *HTTPServer) Close(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func cannedRoute(rt RouteConfig) http.Handler {
	status := rt.Status
	if status == 0 {
		status = http.StatusOK
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range rt.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, rt.Body)
	})
}

// echoResponse is the JSON body returned by the built-in /_echo route.
type echoResponse struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Proto   string              `json:"proto"`
	Remote  string              `json:"remote"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	resp := echoResponse{
		Method:  r.Method,
		Path:    r.URL.Path,
		Query:   r.URL.RawQuery,
		Proto:   r.Proto,
		Remote:  r.RemoteAddr,
		Headers: r.Header,
		Body:    string(body),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}
