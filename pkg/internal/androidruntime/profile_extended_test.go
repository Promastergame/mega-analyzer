package androidruntime

import (
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/antivm"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ANTI-VM PROFILE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestAntiVMProfile_ToEvasionConfig_Extended(t *testing.T) {
	tests := []struct {
		name    string
		profile AntiVMProfile
		checkFn func(*testing.T, antivm.EvasionConfig)
	}{
		{
			name: "default profile",
			profile: AntiVMProfile{
				Enabled: true,
			},
			checkFn: func(t *testing.T, cfg antivm.EvasionConfig) {
				if !cfg.Enabled {
					t.Error("Enabled should be true")
				}
			},
		},
		{
			name: "with custom device model",
			profile: AntiVMProfile{
				Enabled:     true,
				DeviceModel: "pixel_6",
			},
			checkFn: func(t *testing.T, cfg antivm.EvasionConfig) {
				if cfg.DeviceModel != "pixel_6" {
					t.Errorf("DeviceModel = %q, want %q", cfg.DeviceModel, "pixel_6")
				}
			},
		},
		{
			name: "with sensor noise",
			profile: AntiVMProfile{
				Enabled:     true,
				SensorNoise: true,
			},
			checkFn: func(t *testing.T, cfg antivm.EvasionConfig) {
				if !cfg.SensorNoise {
					t.Error("SensorNoise should be true")
				}
			},
		},
		{
			name: "disabled profile",
			profile: AntiVMProfile{
				Enabled: false,
			},
			checkFn: func(t *testing.T, cfg antivm.EvasionConfig) {
				if cfg.Enabled {
					t.Error("Enabled should be false")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.profile.ToEvasionConfig()
			if tt.checkFn != nil {
				tt.checkFn(t, cfg)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT PROFILE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestDefaultProfile_Extended(t *testing.T) {
	profile := DefaultProfile()

	if profile.AVDName == "" {
		t.Error("AVDName should not be empty")
	}

	if profile.Mode != ModeAndroidSDK {
		t.Errorf("Mode = %q, want %q", profile.Mode, ModeAndroidSDK)
	}

	if profile.Locale == "" {
		t.Error("Locale should not be empty")
	}

	if profile.Timezone == "" {
		t.Error("Timezone should not be empty")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOAD PROFILE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestLoadProfile_NonExistent_Extended(t *testing.T) {
	_, err := LoadProfile("/nonexistent/profile.json")
	if err == nil {
		t.Error("LoadProfile() should error for non-existent file")
	}
}

func TestLoadProfile_InvalidJSON_Extended(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "invalid.json")

	if err := os.WriteFile(profilePath, []byte("invalid json {"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, err := LoadProfile(profilePath)
	if err == nil {
		t.Error("LoadProfile() should error for invalid JSON")
	}
}

func TestLoadProfile_ValidJSON_Extended(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "valid.json")

	jsonData := `{
		"name": "test-profile",
		"mode": "android-sdk",
		"avd_name": "test_avd",
		"locale": "en-GB"
	}`

	if err := os.WriteFile(profilePath, []byte(jsonData), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	profile, err := LoadProfile(profilePath)
	if err != nil {
		t.Fatalf("LoadProfile() error = %v", err)
	}

	if profile.Name != "test-profile" {
		t.Errorf("Name = %q, want %q", profile.Name, "test-profile")
	}

	if profile.AVDName != "test_avd" {
		t.Errorf("AVDName = %q, want %q", profile.AVDName, "test_avd")
	}

	if profile.Locale != "en-GB" {
		t.Errorf("Locale = %q, want %q", profile.Locale, "en-GB")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE NORMALIZE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestProfile_Normalize_Extended(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
		checkFn func(*testing.T, Profile)
	}{
		{
			name: "empty profile gets defaults",
			profile: Profile{
				Name:    "",
				AVDName: "",
			},
			checkFn: func(t *testing.T, p Profile) {
				if p.Name == "" {
					t.Error("Name should be set to default")
				}
				if p.AVDName == "" {
					t.Error("AVDName should be set to default")
				}
			},
		},
		{
			name: "empty locale gets default",
			profile: Profile{
				Locale: "",
			},
			checkFn: func(t *testing.T, p Profile) {
				if p.Locale == "" {
					t.Error("Locale should be set to default")
				}
			},
		},
		{
			name: "empty timezone gets default",
			profile: Profile{
				Timezone: "",
			},
			checkFn: func(t *testing.T, p Profile) {
				if p.Timezone == "" {
					t.Error("Timezone should be set to default")
				}
			},
		},
		{
			name: "custom values preserved",
			profile: Profile{
				Name:     "custom",
				AVDName:  "custom_avd",
				Locale:   "fr-FR",
				Timezone: "Europe/Paris",
			},
			checkFn: func(t *testing.T, p Profile) {
				if p.Name != "custom" {
					t.Error("Custom Name should be preserved")
				}
				if p.AVDName != "custom_avd" {
					t.Error("Custom AVDName should be preserved")
				}
				if p.Locale != "fr-FR" {
					t.Error("Custom Locale should be preserved")
				}
				if p.Timezone != "Europe/Paris" {
					t.Error("Custom Timezone should be preserved")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := tt.profile
			profile.Normalize()

			if tt.checkFn != nil {
				tt.checkFn(t, profile)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE VALIDATE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestProfile_Validate_Extended(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
		wantErr bool
	}{
		{
			name: "valid profile",
			profile: Profile{
				Mode:    ModeAndroidSDK,
				AVDName: "test_avd",
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			profile: Profile{
				Mode: "invalid",
			},
			wantErr: true,
		},
		{
			name: "empty AVD name in SDK mode",
			profile: Profile{
				Mode:    ModeAndroidSDK,
				AVDName: "",
			},
			wantErr: true,
		},
		{
			name: "valid mini mode",
			profile: Profile{
				Mode: ModeMini,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.profile.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkDefaultProfile_Extended_Bench(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DefaultProfile()
	}
}

func BenchmarkProfile_Normalize_Extended_Bench(b *testing.B) {
	profile := Profile{
		Name:    "",
		AVDName: "",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := profile
		p.Normalize()
	}
}

func BenchmarkProfile_Validate_Extended_Bench(b *testing.B) {
	profile := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test_avd",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = profile.Validate()
	}
}

func BenchmarkAntiVMProfile_ToEvasionConfig_Extended_Bench(b *testing.B) {
	profile := AntiVMProfile{
		Enabled:     true,
		DeviceModel: "pixel_6",
		SensorNoise: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = profile.ToEvasionConfig()
	}
}
