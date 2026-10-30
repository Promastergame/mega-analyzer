package config

import (
	"testing"
)

func TestNewConfig(t *testing.T) {
	cfg := New()

	if cfg == nil {
		t.Fatal("New returned nil")
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
				Workers:               4,
				MaxFiles:              100,
				MaxFileSize:           10 * 1024 * 1024,
				OutputFormat:          "json",
				OutputDir:             "test_output",
				ScoreNormalizationCap: 1.0,
			},
			wantErr: false,
		},
		{
			name: "zero workers",
			cfg: &Config{
				Workers:  -1,
				MaxFiles: 100,
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

func TestConfig_GetWorkers(t *testing.T) {
	cfg := &Config{
		Workers: 8,
	}

	workers := cfg.GetWorkers()

	if workers != 8 {
		t.Errorf("GetWorkers() = %d, want 8", workers)
	}
}

func TestConfig_CloneExtended(t *testing.T) {
	cfg := &Config{
		Workers:  4,
		MaxFiles: 100,
	}

	cloned := cfg.Clone()

	if cloned == nil {
		t.Fatal("Clone returned nil")
	}

	if cloned.Workers != cfg.Workers {
		t.Errorf("Cloned Workers = %d, want %d", cloned.Workers, cfg.Workers)
	}

	if cloned.MaxFiles != cfg.MaxFiles {
		t.Errorf("Cloned MaxFiles = %d, want %d", cloned.MaxFiles, cfg.MaxFiles)
	}

	// Verify it's a different instance
	if cloned == cfg {
		t.Error("Clone should return different instance")
	}
}

func TestConfig_StringExtended(t *testing.T) {
	cfg := &Config{
		Workers:  4,
		MaxFiles: 100,
	}

	str := cfg.String()

	if str == "" {
		t.Error("String should return non-empty string")
	}
}

// Benchmark tests
func BenchmarkDefaultConfig(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DefaultConfig()
	}
}

func BenchmarkConfig_Validate(b *testing.B) {
	cfg := &Config{
		Workers:  4,
		MaxFiles: 100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg.Validate()
	}
}

func BenchmarkConfig_Clone(b *testing.B) {
	cfg := &Config{
		Workers:  4,
		MaxFiles: 100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg.Clone()
	}
}
