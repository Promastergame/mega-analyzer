package sandbox

import (
	"testing"
	"time"
)

func TestConfig_Validate_Basic(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				TargetPath:  "test.exe",
				Duration:    60 * time.Second,
				MaxMemoryMB: 512,
			},
			wantErr: false,
		},
		{
			name: "missing target",
			cfg: Config{
				TargetPath:  "",
				Duration:    60 * time.Second,
				MaxMemoryMB: 512,
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
