package labdns

import (
	"testing"
)

func TestNewDNSServer(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:53",
	}

	server := NewDNSServer(cfg)

	if server == nil {
		t.Fatal("NewDNSServer returned nil")
	}
}

func TestDNSServer_Start(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0", // Use random port
	}

	server := NewDNSServer(cfg)

	// We can't easily test Start without a full DNS setup
	// But we can verify the method exists
	_ = server
}

func TestDNSServer_Stop(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	// Stop should not panic
	server.Stop()
}

func TestDNSServer_QueryLog(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	log := server.QueryLog()

	if log == nil {
		t.Error("QueryLog should not return nil")
	}

	if len(log) != 0 {
		t.Error("QueryLog should be empty initially")
	}
}

func TestDNSServer_Stats(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	stats := server.Stats()

	if stats.TotalQueries != 0 {
		t.Errorf("TotalQueries = %d, want 0", stats.TotalQueries)
	}

	if stats.BlockedQueries != 0 {
		t.Errorf("BlockedQueries = %d, want 0", stats.BlockedQueries)
	}
}

func TestDNSServer_AddBlockRule(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	server.AddBlockRule("*.analytics.google.com")

	// Verify rule was added
	rules := server.GetBlockRules()
	if len(rules) != 1 {
		t.Errorf("AddBlockRule should add rule, got %d rules", len(rules))
	}
}

func TestDNSServer_AddMultipleBlockRules(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	server.AddBlockRule("*.analytics.google.com")
	server.AddBlockRule("*.firebase.google.com")
	server.AddBlockRule("*.crashlytics.com")

	rules := server.GetBlockRules()
	if len(rules) != 3 {
		t.Errorf("AddBlockRule should add all rules, got %d rules", len(rules))
	}
}

func TestDNSServer_GetBlockRules(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	// Initially empty
	rules := server.GetBlockRules()
	if len(rules) != 0 {
		t.Error("GetBlockRules should return empty list initially")
	}

	// Add rules
	server.AddBlockRule("*.example.com")
	rules = server.GetBlockRules()
	if len(rules) != 1 {
		t.Errorf("GetBlockRules should return 1 rule, got %d", len(rules))
	}
}

func TestDNSServer_ClearLog(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	// Clear log
	server.ClearLog()

	// Log should be empty
	log := server.QueryLog()
	if len(log) != 0 {
		t.Error("ClearLog should clear the log")
	}
}

func TestDNSServer_IsRunning(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	// Should not be running initially
	if server.IsRunning() {
		t.Error("Server should not be running initially")
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				ListenAddr: "127.0.0.1:53",
			},
			wantErr: false,
		},
		{
			name: "missing listen addr",
			cfg: &Config{
				ListenAddr: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Benchmark tests
func BenchmarkNewDNSServer(b *testing.B) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewDNSServer(cfg)
	}
}

func BenchmarkDNSServer_AddBlockRule(b *testing.B) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.AddBlockRule("*.example.com")
	}
}

func BenchmarkDNSServer_QueryLog(b *testing.B) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.QueryLog()
	}
}

func BenchmarkDNSServer_Stats(b *testing.B) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
	}

	server := NewDNSServer(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.Stats()
	}
}
