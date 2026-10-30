package main

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// WINDOWS-NATIVE SANDBOX CLI FLAG TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestWindowsSandboxFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		check   func(*testing.T, *CLIOptions)
	}{
		{
			name: "win-sandbox flag",
			args: []string{"--sandbox", "-t", "./sample.exe", "--win-sandbox"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.WinSandbox {
					t.Error("WinSandbox should be true")
				}
			},
		},
		{
			name: "sandbox-vss-revert flag",
			args: []string{"--sandbox", "-t", "./sample.exe", "--sandbox-vss-revert"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.SandboxVSSRevert {
					t.Error("SandboxVSSRevert should be true")
				}
			},
		},
		{
			name: "sandbox-time-scale with default",
			args: []string{"--sandbox", "-t", "./sample.exe"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.SandboxTimeScale != 1.0 {
					t.Errorf("SandboxTimeScale = %.2f, want 1.0", opts.SandboxTimeScale)
				}
			},
		},
		{
			name: "sandbox-time-scale with custom value",
			args: []string{"--sandbox", "-t", "./sample.exe", "--sandbox-time-scale", "10.0"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.SandboxTimeScale != 10.0 {
					t.Errorf("SandboxTimeScale = %.2f, want 10.0", opts.SandboxTimeScale)
				}
			},
		},
		{
			name: "sandbox-time-scale with fractional value",
			args: []string{"--sandbox", "-t", "./sample.exe", "--sandbox-time-scale", "2.5"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.SandboxTimeScale != 2.5 {
					t.Errorf("SandboxTimeScale = %.2f, want 2.5", opts.SandboxTimeScale)
				}
			},
		},
		{
			name: "sandbox-output directory",
			args: []string{"--sandbox", "-t", "./sample.exe", "--sandbox-output", "./sandbox_artifacts"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.SandboxOutput != "./sandbox_artifacts" {
					t.Errorf("SandboxOutput = %q, want %q", opts.SandboxOutput, "./sandbox_artifacts")
				}
			},
		},
		{
			name: "enable-kernel-monitor flag",
			args: []string{"--sandbox", "-t", "./sample.exe", "--enable-kernel-monitor"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.EnableKernelMonitor {
					t.Error("EnableKernelMonitor should be true")
				}
			},
		},
		{
			name: "enable-vss flag",
			args: []string{"--sandbox", "-t", "./sample.exe", "--enable-vss"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.EnableVSS {
					t.Error("EnableVSS should be true")
				}
			},
		},
		{
			name: "enable-wfp flag",
			args: []string{"--sandbox", "-t", "./sample.exe", "--enable-wfp"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.EnableWFP {
					t.Error("EnableWFP should be true")
				}
			},
		},
		{
			name: "enable-api-tracing flag",
			args: []string{"--sandbox", "-t", "./sample.exe", "--enable-api-tracing"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.EnableAPITracing {
					t.Error("EnableAPITracing should be true")
				}
			},
		},
		{
			name: "enable-time-manip flag",
			args: []string{"--sandbox", "-t", "./sample.exe", "--enable-time-manip"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.EnableTimeManip {
					t.Error("EnableTimeManip should be true")
				}
			},
		},
		{
			name: "all windows sandbox flags combined",
			args: []string{
				"--sandbox",
				"-t", "./sample.exe",
				"--win-sandbox",
				"--sandbox-vss-revert",
				"--sandbox-time-scale", "5.0",
				"--sandbox-output", "./artifacts",
				"--enable-kernel-monitor",
				"--enable-vss",
				"--enable-wfp",
				"--enable-api-tracing",
				"--enable-time-manip",
			},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.WinSandbox {
					t.Error("WinSandbox should be true")
				}
				if !opts.SandboxVSSRevert {
					t.Error("SandboxVSSRevert should be true")
				}
				if opts.SandboxTimeScale != 5.0 {
					t.Errorf("SandboxTimeScale = %.2f, want 5.0", opts.SandboxTimeScale)
				}
				if opts.SandboxOutput != "./artifacts" {
					t.Errorf("SandboxOutput = %q, want %q", opts.SandboxOutput, "./artifacts")
				}
				if !opts.EnableKernelMonitor {
					t.Error("EnableKernelMonitor should be true")
				}
				if !opts.EnableVSS {
					t.Error("EnableVSS should be true")
				}
				if !opts.EnableWFP {
					t.Error("EnableWFP should be true")
				}
				if !opts.EnableAPITracing {
					t.Error("EnableAPITracing should be true")
				}
				if !opts.EnableTimeManip {
					t.Error("EnableTimeManip should be true")
				}
			},
		},
		{
			name: "minimal windows sandbox flags",
			args: []string{
				"--sandbox",
				"-t", "./sample.exe",
				"--enable-kernel-monitor",
			},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.EnableKernelMonitor {
					t.Error("EnableKernelMonitor should be true")
				}
				// Other flags should have default values
				if opts.SandboxTimeScale != 1.0 {
					t.Errorf("SandboxTimeScale should default to 1.0, got %.2f", opts.SandboxTimeScale)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCLIParser()
			opts, err := parser.Parse(tt.args)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil && tt.check != nil {
				tt.check(t, opts)
			}
		})
	}
}

func TestWindowsSandboxFlagValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    *CLIOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid sandbox-time-scale",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 10.0,
			},
			wantErr: false,
		},
		{
			name: "sandbox-time-scale too low",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 0.05,
			},
			wantErr: true,
			errMsg:  "sandbox-time-scale must be between 0.1 and 1000.0",
		},
		{
			name: "sandbox-time-scale too high",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 1500.0,
			},
			wantErr: true,
			errMsg:  "sandbox-time-scale must be between 0.1 and 1000.0",
		},
		{
			name: "sandbox-time-scale minimum boundary",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 0.1,
			},
			wantErr: false,
		},
		{
			name: "sandbox-time-scale maximum boundary",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 1000.0,
			},
			wantErr: false,
		},
		{
			name: "sandbox-time-scale zero defaults to 1.0",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 0.0,
			},
			wantErr: false,
		},
		{
			name: "component flag auto-enables win-sandbox",
			opts: &CLIOptions{
				Sandbox:             true,
				Target:              "./sample.exe",
				SandboxDuration:     60,
				SandboxMemoryMB:     512,
				EnableKernelMonitor: true,
			},
			wantErr: false,
		},
		{
			name: "vss-revert auto-enables vss",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxVSSRevert: true,
			},
			wantErr: false,
		},
		{
			name: "time-scale > 1.0 auto-enables time-manip",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 5.0,
			},
			wantErr: false,
		},
		{
			name: "all windows sandbox components enabled",
			opts: &CLIOptions{
				Sandbox:             true,
				Target:              "./sample.exe",
				SandboxDuration:     60,
				SandboxMemoryMB:     512,
				WinSandbox:          true,
				SandboxVSSRevert:    true,
				SandboxTimeScale:    10.0,
				SandboxOutput:       "./artifacts",
				EnableKernelMonitor: true,
				EnableVSS:           true,
				EnableWFP:           true,
				EnableAPITracing:    true,
				EnableTimeManip:     true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Validate() error = %v, should contain %q", err, tt.errMsg)
			}
		})
	}
}

func TestWindowsSandboxAutoEnablement(t *testing.T) {
	tests := []struct {
		name        string
		opts        *CLIOptions
		checkAfter  func(*testing.T, *CLIOptions)
		description string
	}{
		{
			name: "enable-kernel-monitor auto-enables win-sandbox",
			opts: &CLIOptions{
				Sandbox:             true,
				Target:              "./sample.exe",
				SandboxDuration:     60,
				SandboxMemoryMB:     512,
				EnableKernelMonitor: true,
			},
			checkAfter: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if !opts.WinSandbox {
					t.Error("WinSandbox should be auto-enabled when EnableKernelMonitor is true")
				}
			},
			description: "Enabling kernel monitor should auto-enable win-sandbox",
		},
		{
			name: "enable-vss auto-enables win-sandbox",
			opts: &CLIOptions{
				Sandbox:         true,
				Target:          "./sample.exe",
				SandboxDuration: 60,
				SandboxMemoryMB: 512,
				EnableVSS:       true,
			},
			checkAfter: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if !opts.WinSandbox {
					t.Error("WinSandbox should be auto-enabled when EnableVSS is true")
				}
			},
			description: "Enabling VSS should auto-enable win-sandbox",
		},
		{
			name: "enable-wfp auto-enables win-sandbox",
			opts: &CLIOptions{
				Sandbox:         true,
				Target:          "./sample.exe",
				SandboxDuration: 60,
				SandboxMemoryMB: 512,
				EnableWFP:       true,
			},
			checkAfter: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if !opts.WinSandbox {
					t.Error("WinSandbox should be auto-enabled when EnableWFP is true")
				}
			},
			description: "Enabling WFP should auto-enable win-sandbox",
		},
		{
			name: "enable-api-tracing auto-enables win-sandbox",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				EnableAPITracing: true,
			},
			checkAfter: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if !opts.WinSandbox {
					t.Error("WinSandbox should be auto-enabled when EnableAPITracing is true")
				}
			},
			description: "Enabling API tracing should auto-enable win-sandbox",
		},
		{
			name: "enable-time-manip auto-enables win-sandbox",
			opts: &CLIOptions{
				Sandbox:         true,
				Target:          "./sample.exe",
				SandboxDuration: 60,
				SandboxMemoryMB: 512,
				EnableTimeManip: true,
			},
			checkAfter: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if !opts.WinSandbox {
					t.Error("WinSandbox should be auto-enabled when EnableTimeManip is true")
				}
			},
			description: "Enabling time manipulation should auto-enable win-sandbox",
		},
		{
			name: "sandbox-vss-revert auto-enables enable-vss",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxVSSRevert: true,
			},
			checkAfter: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if !opts.EnableVSS {
					t.Error("EnableVSS should be auto-enabled when SandboxVSSRevert is true")
				}
			},
			description: "VSS revert should auto-enable VSS component",
		},
		{
			name: "sandbox-time-scale > 1.0 auto-enables enable-time-manip",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 5.0,
			},
			checkAfter: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if !opts.EnableTimeManip {
					t.Error("EnableTimeManip should be auto-enabled when SandboxTimeScale > 1.0")
				}
			},
			description: "Time scale > 1.0 should auto-enable time manipulation",
		},
		{
			name: "sandbox-time-scale = 1.0 does not auto-enable time-manip",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 1.0,
			},
			checkAfter: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if opts.EnableTimeManip {
					t.Error("EnableTimeManip should not be auto-enabled when SandboxTimeScale = 1.0")
				}
			},
			description: "Time scale = 1.0 (real-time) should not auto-enable time manipulation",
		},
		{
			name: "sandbox-time-scale = 0.0 defaults to 1.0",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 0.0,
			},
			checkAfter: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if opts.SandboxTimeScale != 1.0 {
					t.Errorf("SandboxTimeScale should default to 1.0, got %.2f", opts.SandboxTimeScale)
				}
			},
			description: "Zero time scale should default to 1.0 (real-time)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.checkAfter != nil {
				tt.checkAfter(t, tt.opts)
			}
		})
	}
}

func TestWindowsSandboxFlagCombinations(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		check   func(*testing.T, *CLIOptions)
	}{
		{
			name: "full windows sandbox with all components",
			args: []string{
				"--sandbox",
				"-t", "./malware.exe",
				"--win-sandbox",
				"--sandbox-vss-revert",
				"--sandbox-time-scale", "10.0",
				"--sandbox-output", "./sandbox_results",
				"--enable-kernel-monitor",
				"--enable-vss",
				"--enable-wfp",
				"--enable-api-tracing",
				"--enable-time-manip",
				"--sandbox-duration", "120",
				"--sandbox-memory", "1024",
			},
			check: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}

				if !opts.Sandbox {
					t.Error("Sandbox should be enabled")
				}
				if !opts.WinSandbox {
					t.Error("WinSandbox should be enabled")
				}
				if !opts.SandboxVSSRevert {
					t.Error("SandboxVSSRevert should be enabled")
				}
				if opts.SandboxTimeScale != 10.0 {
					t.Errorf("SandboxTimeScale = %.2f, want 10.0", opts.SandboxTimeScale)
				}
				if opts.SandboxOutput != "./sandbox_results" {
					t.Errorf("SandboxOutput = %q", opts.SandboxOutput)
				}
				if !opts.EnableKernelMonitor {
					t.Error("EnableKernelMonitor should be enabled")
				}
				if !opts.EnableVSS {
					t.Error("EnableVSS should be enabled")
				}
				if !opts.EnableWFP {
					t.Error("EnableWFP should be enabled")
				}
				if !opts.EnableAPITracing {
					t.Error("EnableAPITracing should be enabled")
				}
				if !opts.EnableTimeManip {
					t.Error("EnableTimeManip should be enabled")
				}
				if opts.SandboxDuration != 120 {
					t.Errorf("SandboxDuration = %d, want 120", opts.SandboxDuration)
				}
				if opts.SandboxMemoryMB != 1024 {
					t.Errorf("SandboxMemoryMB = %d, want 1024", opts.SandboxMemoryMB)
				}
			},
		},
		{
			name: "windows sandbox with selective components",
			args: []string{
				"--sandbox",
				"-t", "./sample.exe",
				"--enable-kernel-monitor",
				"--enable-wfp",
				"--sandbox-time-scale", "5.0",
			},
			check: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}

				if !opts.EnableKernelMonitor {
					t.Error("EnableKernelMonitor should be enabled")
				}
				if !opts.EnableWFP {
					t.Error("EnableWFP should be enabled")
				}
				if opts.SandboxTimeScale != 5.0 {
					t.Errorf("SandboxTimeScale = %.2f, want 5.0", opts.SandboxTimeScale)
				}
				// These should be auto-enabled
				if !opts.WinSandbox {
					t.Error("WinSandbox should be auto-enabled")
				}
				if !opts.EnableTimeManip {
					t.Error("EnableTimeManip should be auto-enabled")
				}
				// These should remain disabled
				if opts.EnableVSS {
					t.Error("EnableVSS should not be enabled")
				}
				if opts.EnableAPITracing {
					t.Error("EnableAPITracing should not be enabled")
				}
			},
		},
		{
			name: "windows sandbox with basic sandbox flags",
			args: []string{
				"--sandbox",
				"-t", "./sample.exe",
				"--sandbox-args", "--verbose",
				"--sandbox-allow-net",
				"--enable-kernel-monitor",
			},
			check: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}

				if opts.SandboxArgs != "--verbose" {
					t.Errorf("SandboxArgs = %q", opts.SandboxArgs)
				}
				if !opts.SandboxAllowNet {
					t.Error("SandboxAllowNet should be enabled")
				}
				if !opts.EnableKernelMonitor {
					t.Error("EnableKernelMonitor should be enabled")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCLIParser()
			opts, err := parser.Parse(tt.args)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil && tt.check != nil {
				tt.check(t, opts)
			}
		})
	}
}

func TestWindowsSandboxDefaultValues(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(*testing.T, *CLIOptions)
	}{
		{
			name: "default sandbox-time-scale",
			args: []string{"--sandbox", "-t", "./sample.exe"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.SandboxTimeScale != 1.0 {
					t.Errorf("Default SandboxTimeScale = %.2f, want 1.0", opts.SandboxTimeScale)
				}
			},
		},
		{
			name: "default sandbox-output (empty)",
			args: []string{"--sandbox", "-t", "./sample.exe"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.SandboxOutput != "" {
					t.Errorf("Default SandboxOutput = %q, want empty", opts.SandboxOutput)
				}
			},
		},
		{
			name: "default component flags (all false)",
			args: []string{"--sandbox", "-t", "./sample.exe"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.WinSandbox {
					t.Error("Default WinSandbox should be false")
				}
				if opts.SandboxVSSRevert {
					t.Error("Default SandboxVSSRevert should be false")
				}
				if opts.EnableKernelMonitor {
					t.Error("Default EnableKernelMonitor should be false")
				}
				if opts.EnableVSS {
					t.Error("Default EnableVSS should be false")
				}
				if opts.EnableWFP {
					t.Error("Default EnableWFP should be false")
				}
				if opts.EnableAPITracing {
					t.Error("Default EnableAPITracing should be false")
				}
				if opts.EnableTimeManip {
					t.Error("Default EnableTimeManip should be false")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCLIParser()
			opts, err := parser.Parse(tt.args)

			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			if tt.check != nil {
				tt.check(t, opts)
			}
		})
	}
}

func TestSandboxProfilePresets(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(*testing.T, *CLIOptions)
	}{
		{
			name: "trace enables api tracing and wfp",
			args: []string{"--sandbox", "-t", "./sample.exe", "--sandbox-profile", "trace"},
			check: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if !opts.WinSandbox || !opts.EnableAPITracing || !opts.EnableWFP {
					t.Fatalf("trace profile did not enable expected components: %+v", opts)
				}
				if opts.EnableVSS || opts.EnableKernelMonitor {
					t.Fatalf("trace profile enabled forensic components unexpectedly: %+v", opts)
				}
			},
		},
		{
			name: "paranoid enables every component and time scale",
			args: []string{"--sandbox", "-t", "./sample.exe", "--sandbox-profile", "paranoid"},
			check: func(t *testing.T, opts *CLIOptions) {
				if err := opts.Validate(); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if !opts.EnableKernelMonitor || !opts.EnableVSS || !opts.EnableWFP ||
					!opts.EnableAPITracing || !opts.EnableTimeManip {
					t.Fatalf("paranoid profile did not enable every component: %+v", opts)
				}
				if opts.SandboxTimeScale != 10.0 {
					t.Fatalf("SandboxTimeScale = %.1f, want 10.0", opts.SandboxTimeScale)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCLIParser()
			opts, err := parser.Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			tt.check(t, opts)
		})
	}
}

func TestWindowsSandboxInvalidFlagValues(t *testing.T) {
	tests := []struct {
		name    string
		opts    *CLIOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "negative sandbox-time-scale",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: -1.0,
			},
			wantErr: true,
			errMsg:  "sandbox-time-scale must be between 0.1 and 1000.0",
		},
		{
			name: "sandbox-time-scale below minimum",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 0.09,
			},
			wantErr: true,
			errMsg:  "sandbox-time-scale must be between 0.1 and 1000.0",
		},
		{
			name: "sandbox-time-scale above maximum",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 1001.0,
			},
			wantErr: true,
			errMsg:  "sandbox-time-scale must be between 0.1 and 1000.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Validate() error = %v, should contain %q", err, tt.errMsg)
			}
		})
	}
}
