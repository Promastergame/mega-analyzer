package labkit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLoggerLevelFilterAndFields(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, LevelInfo)
	log.Debug("dropped", nil)
	log.Info("kept", Fields{"k": "v"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d: %q", len(lines), buf.String())
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("log line not valid JSON: %v", err)
	}
	if entry["level"] != "info" || entry["msg"] != "kept" || entry["k"] != "v" {
		t.Fatalf("unexpected entry: %#v", entry)
	}
}

func TestLoggerWithIsIsolated(t *testing.T) {
	var buf bytes.Buffer
	base := NewLogger(&buf, LevelDebug)
	child := base.With(Fields{"server": "a"})
	child.Info("hi", nil)
	base.Info("bye", nil)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], `"server":"a"`) {
		t.Errorf("child line should carry field: %s", lines[0])
	}
	if strings.Contains(lines[1], `"server"`) {
		t.Errorf("base line must not inherit child field: %s", lines[1])
	}
}

func TestMetricsCountersAndLatency(t *testing.T) {
	m := NewMetrics()
	for i := 0; i < 5; i++ {
		m.Inc("hits")
	}
	m.Add("bytes", 100)
	m.Observe("lat", 2*time.Millisecond)
	m.Observe("lat", 8*time.Millisecond)

	s := m.Snapshot()
	if s.Counters["hits"] != 5 {
		t.Errorf("hits = %d, want 5", s.Counters["hits"])
	}
	if s.Counters["bytes"] != 100 {
		t.Errorf("bytes = %d, want 100", s.Counters["bytes"])
	}
	lat := s.Latencies["lat"]
	if lat.Count != 2 {
		t.Errorf("lat count = %d, want 2", lat.Count)
	}
	if lat.MinMS <= 0 || lat.MaxMS < lat.MinMS {
		t.Errorf("min/max implausible: %+v", lat)
	}
	if lat.MeanMS < 4 || lat.MeanMS > 6 {
		t.Errorf("mean = %.2f, want ~5ms", lat.MeanMS)
	}
}

func TestScenarioDeterministicWithSeed(t *testing.T) {
	cfg := ScenarioConfig{ErrorRate: 0.4, TimeoutRate: 0.1, Seed: 1234}
	seq := func() []FaultKind {
		s := NewScenario(cfg)
		out := make([]FaultKind, 20)
		for i := range out {
			out[i] = s.Roll().Fault
		}
		return out
	}
	a, b := seq(), seq()
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("seeded scenario not deterministic at %d: %v vs %v", i, a[i], b[i])
		}
	}
}

func TestScenarioLatencyAndDefaults(t *testing.T) {
	s := NewScenario(ScenarioConfig{FixedLatency: Duration(3 * time.Millisecond)})
	if got := s.Config().ErrorStatus; got != 503 {
		t.Errorf("default error status = %d, want 503", got)
	}
	out := s.Roll()
	if out.Latency < 3*time.Millisecond {
		t.Errorf("latency = %v, want >= 3ms", out.Latency)
	}
	if out.Fault != FaultNone {
		t.Errorf("no fault expected with zero rates, got %v", out.Fault)
	}
}

func TestDurationJSONRoundTrip(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"250ms"`), &d); err != nil {
		t.Fatal(err)
	}
	if d.D() != 250*time.Millisecond {
		t.Fatalf("got %v", d.D())
	}
	if err := json.Unmarshal([]byte(`1000000`), &d); err != nil {
		t.Fatal(err)
	}
	if d.D() != time.Millisecond {
		t.Fatalf("numeric ns parse got %v", d.D())
	}
	out, err := json.Marshal(Duration(1500 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `"1.5s"` {
		t.Fatalf("marshal got %s", out)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid http loopback",
			cfg:  Config{Servers: []ServerConfig{{Name: "a", Kind: "http", Addr: "127.0.0.1:0"}}},
		},
		{
			name: "empty host defaults loopback",
			cfg:  Config{Servers: []ServerConfig{{Name: "a", Kind: "tcp", Addr: ":0"}}},
		},
		{
			name:    "non-loopback rejected",
			cfg:     Config{Servers: []ServerConfig{{Name: "a", Kind: "http", Addr: "0.0.0.0:0"}}},
			wantErr: true,
		},
		{
			name: "non-loopback allowed with override",
			cfg:  Config{AllowNonLoopback: true, Servers: []ServerConfig{{Name: "a", Kind: "http", Addr: "0.0.0.0:0"}}},
		},
		{
			name:    "unknown kind",
			cfg:     Config{Servers: []ServerConfig{{Name: "a", Kind: "smtp", Addr: "127.0.0.1:0"}}},
			wantErr: true,
		},
		{
			name:    "duplicate names",
			cfg:     Config{Servers: []ServerConfig{{Name: "a", Kind: "http", Addr: "127.0.0.1:0"}, {Name: "a", Kind: "tcp", Addr: "127.0.0.1:0"}}},
			wantErr: true,
		},
		{
			name:    "no servers",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name:    "mismatched block",
			cfg:     Config{Servers: []ServerConfig{{Name: "a", Kind: "http", Addr: "127.0.0.1:0", TCP: &TCPConfig{}}}},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
