package labkit

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// startManager builds and starts a manager from cfg and registers cleanup.
func startManager(t testing.TB, cfg *Config) *Manager {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	mgr := NewManager(NewLogger(io.Discard, LevelError))
	if err := mgr.BuildFromConfig(cfg); err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Shutdown(ctx)
	})
	return mgr
}

func serviceAddr(t testing.TB, mgr *Manager, name string) string {
	t.Helper()
	for _, s := range mgr.Services() {
		if s.Name() == name {
			return s.Addr()
		}
	}
	t.Fatalf("service %q not found", name)
	return ""
}

func TestHTTPBuiltinRoutesAndCanned(t *testing.T) {
	cfg := &Config{Servers: []ServerConfig{{
		Name: "web", Kind: "http", Addr: "127.0.0.1:0",
		HTTP: &HTTPConfig{Routes: []RouteConfig{{
			Path: "/hello", Status: 201, Body: "hi there",
			Headers: map[string]string{"X-Lab": "yes"},
		}}},
	}}}
	mgr := startManager(t, cfg)
	base := "http://" + serviceAddr(t, mgr, "web")

	// Health
	resp, err := http.Get(base + "/_health")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("health bad: %d %s", resp.StatusCode, body)
	}

	// Canned route
	resp, err = http.Get(base + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 || string(body) != "hi there" || resp.Header.Get("X-Lab") != "yes" {
		t.Fatalf("canned route bad: %d %q hdr=%q", resp.StatusCode, body, resp.Header.Get("X-Lab"))
	}

	// Echo reflects method + body
	resp, err = http.Post(base+"/_echo", "text/plain", strings.NewReader("ping"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"method": "POST"`) || !strings.Contains(string(body), `"body": "ping"`) {
		t.Fatalf("echo body unexpected: %s", body)
	}

	// Metrics exposes counters
	resp, err = http.Get(base + "/_metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "http.requests") {
		t.Fatalf("metrics missing counters: %s", body)
	}
}

func TestHTTPScenarioErrorInjection(t *testing.T) {
	cfg := &Config{Servers: []ServerConfig{{
		Name: "flaky", Kind: "http", Addr: "127.0.0.1:0",
		Scenario: ScenarioConfig{ErrorRate: 1.0, ErrorStatus: 502, Seed: 7},
		HTTP:     &HTTPConfig{},
	}}}
	mgr := startManager(t, cfg)
	base := "http://" + serviceAddr(t, mgr, "flaky")

	resp, err := http.Get(base + "/_health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("expected injected 502, got %d", resp.StatusCode)
	}
}
