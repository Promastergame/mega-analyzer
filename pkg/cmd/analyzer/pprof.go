package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	httppprof "net/http/pprof"
	"os"
	"runtime/pprof"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// pprof Profiling Server
// ═══════════════════════════════════════════════════════════════════════════════

// Profiler manages pprof HTTP server for runtime profiling
type Profiler struct {
	server  *http.Server
	addr    string
	cpuFile *os.File
	memFile *os.File
	enabled bool
}

// NewProfiler creates a new pprof profiler
func NewProfiler(addr string) *Profiler {
	if addr == "" {
		addr = "localhost:6060"
	}

	return &Profiler{
		addr: addr,
	}
}

// Start starts the pprof HTTP server
func (p *Profiler) Start() error {
	if !p.enabled {
		return nil
	}

	mux := http.NewServeMux()

	// pprof endpoints - use httppprof handlers
	mux.Handle("/debug/pprof/", http.HandlerFunc(httppprof.Index))
	mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(httppprof.Cmdline))
	mux.Handle("/debug/pprof/profile", http.HandlerFunc(httppprof.Profile))
	mux.Handle("/debug/pprof/symbol", http.HandlerFunc(httppprof.Symbol))
	mux.Handle("/debug/pprof/trace", http.HandlerFunc(httppprof.Trace))
	mux.Handle("/debug/pprof/goroutine", httppprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/heap", httppprof.Handler("heap"))
	mux.Handle("/debug/pprof/threadcreate", httppprof.Handler("threadcreate"))
	mux.Handle("/debug/pprof/block", httppprof.Handler("block"))

	p.server = &http.Server{
		Addr:    p.addr,
		Handler: mux,
	}

	listener, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.addr, err)
	}

	go func() {
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "pprof server error: %v\n", err)
		}
	}()

	fmt.Fprintf(os.Stderr, "pprof server started on http://%s\n", p.addr)
	return nil
}

// Stop stops the pprof server
func (p *Profiler) Stop() error {
	if !p.enabled || p.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := p.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown pprof server: %w", err)
	}

	fmt.Fprintf(os.Stderr, "pprof server stopped\n")
	return nil
}

// Enable enables the profiler
func (p *Profiler) Enable() {
	p.enabled = true
}

// IsEnabled returns true if profiler is enabled
func (p *Profiler) IsEnabled() bool {
	return p.enabled
}

// StartCPUProfile starts CPU profiling to a file
func (p *Profiler) StartCPUProfile(filename string) error {
	if !p.enabled {
		return nil
	}

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CPU profile file: %w", err)
	}

	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		return fmt.Errorf("failed to start CPU profiling: %w", err)
	}

	p.cpuFile = f
	fmt.Fprintf(os.Stderr, "CPU profiling started: %s\n", filename)
	return nil
}

// StopCPUProfile stops CPU profiling
func (p *Profiler) StopCPUProfile() {
	if p.cpuFile == nil {
		return
	}

	pprof.StopCPUProfile()
	p.cpuFile.Close()
	p.cpuFile = nil
	fmt.Fprintf(os.Stderr, "CPU profiling stopped\n")
}

// WriteHeapProfile writes heap profile to a file
func (p *Profiler) WriteHeapProfile(filename string) error {
	if !p.enabled {
		return nil
	}

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create heap profile file: %w", err)
	}

	if err := pprof.WriteHeapProfile(f); err != nil {
		f.Close()
		return fmt.Errorf("failed to write heap profile: %w", err)
	}

	f.Close()
	fmt.Fprintf(os.Stderr, "Heap profile written: %s\n", filename)
	return nil
}

// LookupProfilingHelp returns help text for profiling
func LookupProfilingHelp() string {
	return `
Profiling:
  --pprof <addr>         Enable pprof HTTP server (default: localhost:6060)
  --cpu-profile <file>   Write CPU profile to file
  --mem-profile <file>   Write heap profile to file

Examples:
  analyzer -t ./app --pprof localhost:6060
  # Visit http://localhost:6060/debug/pprof/ in browser

  analyzer -t ./app --cpu-profile cpu.prof
  # Analyze with: go tool pprof cpu.prof

  analyzer -t ./app --mem-profile heap.prof
  # Analyze with: go tool pprof heap.prof

Common pprof commands:
  go tool pprof http://localhost:6060/debug/pprof/profile
  go tool pprof http://localhost:6060/debug/pprof/heap
  go tool pprof -http=:8080 cpu.prof
`
}
