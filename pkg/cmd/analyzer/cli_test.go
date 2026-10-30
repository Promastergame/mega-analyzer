package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

// referenceFlagSet builds a fully-registered FlagSet the same way Parse()
// does (by running Parse with no args), so tests exercising normalizeArgs
// directly use the real, current set of registered flags instead of a
// hand-maintained duplicate that can drift out of sync.
func referenceFlagSet(t *testing.T) *flag.FlagSet {
	t.Helper()
	p := NewCLIParser()
	if _, err := p.Parse(nil); err != nil {
		t.Fatalf("failed to build reference flag set: %v", err)
	}
	return p.fs
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLI PARSER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCLIParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		check   func(*testing.T, *CLIOptions)
	}{
		{
			name: "basic target",
			args: []string{"./decompiled_app"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Target != "./decompiled_app" {
					t.Errorf("Target = %q, want %q", opts.Target, "./decompiled_app")
				}
			},
		},
		{
			name:    "target validation failures",
			args:    []string{"--build"},
			wantErr: false,
			check: func(t *testing.T, opts *CLIOptions) {
				err := opts.Validate()
				if err == nil {
					t.Error("expected validate error")
				}
			},
		},
		{
			name: "is command helpers",
			args: []string{"--decode", "foo.apk"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.IsDecodeCommand() {
					t.Error("expected IsDecodeCommand to be true")
				}
				if opts.IsSandboxCommand() {
					t.Error("did not expect IsSandboxCommand")
				}
			},
		},
		{
			name: "target with -t flag",
			args: []string{"-t", "./app"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Target != "./app" {
					t.Errorf("Target = %q, want %q", opts.Target, "./app")
				}
			},
		},
		{
			name: "target with --target flag",
			args: []string{"--target", "./app"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Target != "./app" {
					t.Errorf("Target = %q, want %q", opts.Target, "./app")
				}
			},
		},
		{
			name: "output directory",
			args: []string{"-t", "./app", "-o", "./results"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Output != "./results" {
					t.Errorf("Output = %q, want %q", opts.Output, "./results")
				}
			},
		},
		{
			name: "workers flag",
			args: []string{"-t", "./app", "-w", "8"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Workers != 8 {
					t.Errorf("Workers = %d, want 8", opts.Workers)
				}
			},
		},
		{
			name: "profile quick",
			args: []string{"-t", "./app", "-p", "quick"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Profile != ProfileQuick {
					t.Errorf("Profile = %v, want %v", opts.Profile, ProfileQuick)
				}
			},
		},
		{
			name: "profile deep",
			args: []string{"-t", "./app", "--profile", "deep"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Profile != ProfileDeep {
					t.Errorf("Profile = %v, want %v", opts.Profile, ProfileDeep)
				}
			},
		},
		{
			name: "enable callgraph",
			args: []string{"-t", "./app", "--callgraph"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.EnableCallGraph {
					t.Error("EnableCallGraph should be true")
				}
				if !opts.CallGraphExplicit {
					t.Error("CallGraphExplicit should be true")
				}
			},
		},
		{
			name: "enable correlations",
			args: []string{"-t", "./app", "--correlations"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.EnableCorrelations {
					t.Error("EnableCorrelations should be true")
				}
				if !opts.CorrelationsExplicit {
					t.Error("CorrelationsExplicit should be true")
				}
			},
		},
		{
			name: "deep scan",
			args: []string{"-t", "./app", "--deep-scan"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.EnableDeepScan {
					t.Error("EnableDeepScan should be true")
				}
				if !opts.DeepScanExplicit {
					t.Error("DeepScanExplicit should be true")
				}
			},
		},
		{
			name: "max files limit",
			args: []string{"-t", "./app", "--max-files", "1000"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.MaxFiles != 1000 {
					t.Errorf("MaxFiles = %d, want 1000", opts.MaxFiles)
				}
			},
		},
		{
			name: "timeout",
			args: []string{"-t", "./app", "--timeout", "600"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Timeout != 600 {
					t.Errorf("Timeout = %d, want 600", opts.Timeout)
				}
			},
		},
		{
			name: "debug flag",
			args: []string{"-t", "./app", "-d"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.DebugVerbose {
					t.Error("Debug should be true")
				}
			},
		},
		{
			name: "quiet flag",
			args: []string{"-t", "./app", "-q"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.Quiet {
					t.Error("Quiet should be true")
				}
			},
		},
		{
			name: "no-color flag",
			args: []string{"-t", "./app", "--no-color"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.NoColor {
					t.Error("NoColor should be true")
				}
			},
		},
		{
			name: "tui flag",
			args: []string{"-t", "./app", "-tui"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.NoTUI {
					t.Error("NoTUI should be false when -tui is passed")
				}
			},
		},
		{
			name: "no-profile flag",
			args: []string{"-t", "./app", "-no-profile"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.NoProfile {
					t.Error("NoProfile should be true when -no-profile is passed")
				}
			},
		},
		{
			name: "json output",
			args: []string{"-t", "./app", "--json"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.JSON {
					t.Error("JSON should be true")
				}
			},
		},
		{
			name: "no-html flag",
			args: []string{"-t", "./app", "--no-html"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.NoHTML {
					t.Error("NoHTML should be true")
				}
			},
		},
		{
			name: "keep-temp flag",
			args: []string{"-t", "./app", "--keep-temp"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.KeepTemp {
					t.Error("KeepTemp should be true")
				}
			},
		},
		{
			name: "dex-only flag",
			args: []string{"-t", "./app", "--dex-only"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.DEXOnly {
					t.Error("DEXOnly should be true")
				}
			},
		},
		{
			name: "version flag",
			args: []string{"--version"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.Version {
					t.Error("Version should be true")
				}
			},
		},
		{
			name: "help flag",
			args: []string{"-h"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.Help {
					t.Error("Help should be true")
				}
			},
		},
		{
			name: "list-profiles",
			args: []string{"--list-profiles"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.ListProfiles {
					t.Error("ListProfiles should be true")
				}
			},
		},
		{
			name: "ML suggest",
			args: []string{"--suggest"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.MLSuggest {
					t.Error("MLSuggest should be true")
				}
			},
		},
		{
			name: "ML history",
			args: []string{"--history"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.MLHistory {
					t.Error("MLHistory should be true")
				}
			},
		},
		{
			name: "ML stats",
			args: []string{"--stats"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.MLStats {
					t.Error("MLStats should be true")
				}
			},
		},
		{
			name: "ML export",
			args: []string{"--export-suggestions", "suggestions.json"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.MLExport != "suggestions.json" {
					t.Errorf("MLExport = %q, want %q", opts.MLExport, "suggestions.json")
				}
				// Note: MLSuggest is auto-enabled in Validate(), not Parse()
			},
		},
		{
			name: "ML confidence",
			args: []string{"--suggest", "--ml-confidence", "0.8"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.MLConfidence != 0.8 {
					t.Errorf("MLConfidence = %.2f, want 0.8", opts.MLConfidence)
				}
			},
		},
		{
			name: "ML max suggestions",
			args: []string{"--suggest", "--ml-max", "20"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.MLMaxSuggestions != 20 {
					t.Errorf("MLMaxSuggestions = %d, want 20", opts.MLMaxSuggestions)
				}
			},
		},
		{
			name: "ML patch flags",
			args: []string{"-t", "./app", "--ml-patch", "--ml-patch-fix", "--ml-patch-include-libs", "--ml-patch-min-score", "42"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.MLPatch {
					t.Error("MLPatch should be true")
				}
				if !opts.MLPatchFix {
					t.Error("MLPatchFix should be true")
				}
				if !opts.MLPatchIncludeLibs {
					t.Error("MLPatchIncludeLibs should be true")
				}
				if opts.MLPatchMinScore != 42 {
					t.Errorf("MLPatchMinScore = %.1f, want 42", opts.MLPatchMinScore)
				}
			},
		},

		{
			name: "mark relevant",
			args: []string{"--mark-relevant", "com/example/Class"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.MarkRelevant != "com/example/Class" {
					t.Errorf("MarkRelevant = %q", opts.MarkRelevant)
				}
			},
		},
		{
			name: "mark noise",
			args: []string{"--mark-noise", "com/google/ads"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.MarkNoise != "com/google/ads" {
					t.Errorf("MarkNoise = %q", opts.MarkNoise)
				}
			},
		},
		{
			name: "report preset short",
			args: []string{"-t", "./app", "--report", "short"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Report != "short" {
					t.Errorf("Report = %q, want %q", opts.Report, "short")
				}
			},
		},
		{
			name: "clean output",
			args: []string{"-t", "./app", "--clean-output"},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.CleanOutput {
					t.Error("CleanOutput should be true")
				}
			},
		},
		{
			name: "complex command",
			args: []string{
				"-t", "./app",
				"-o", "./results",
				"-p", "deep",
				"--callgraph",
				"--correlations",
				"-w", "16",
				"--timeout", "600",
				"--max-files", "5000",
			},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Target != "./app" {
					t.Error("Target mismatch")
				}
				if opts.Output != "./results" {
					t.Error("Output mismatch")
				}
				if opts.Profile != ProfileDeep {
					t.Error("Profile mismatch")
				}
				if !opts.EnableCallGraph {
					t.Error("CallGraph should be enabled")
				}
				if !opts.EnableCorrelations {
					t.Error("Correlations should be enabled")
				}
				if opts.Workers != 16 {
					t.Error("Workers mismatch")
				}
			},
		},
		{
			name: "sandbox flags",
			args: []string{
				"--sandbox",
				"-t", "./sample.exe",
				"--sandbox-args", "--check --fast",
				"--sandbox-duration", "90",
				"--sandbox-memory", "768",
				"--sandbox-allow-net",
			},
			check: func(t *testing.T, opts *CLIOptions) {
				if !opts.Sandbox {
					t.Error("Sandbox should be true")
				}
				if opts.Target != "./sample.exe" {
					t.Errorf("Target = %q, want %q", opts.Target, "./sample.exe")
				}
				if opts.SandboxArgs != "--check --fast" {
					t.Errorf("SandboxArgs = %q", opts.SandboxArgs)
				}
				if opts.SandboxDuration != 90 {
					t.Errorf("SandboxDuration = %d, want 90", opts.SandboxDuration)
				}
				if opts.SandboxMemoryMB != 768 {
					t.Errorf("SandboxMemoryMB = %d, want 768", opts.SandboxMemoryMB)
				}
				if !opts.SandboxAllowNet {
					t.Error("SandboxAllowNet should be true")
				}
			},
		},
		{
			name: "positional after flags",
			args: []string{"-p", "quick", "./app"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.Target != "./app" {
					t.Error("Positional target not parsed")
				}
			},
		},
		{
			name: "deobfuscation iterations",
			args: []string{"-t", "./app", "--deobf-iterations", "5"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.DeobfIterations != 5 {
					t.Errorf("DeobfIterations = %d, want 5", opts.DeobfIterations)
				}
				if !opts.DeobfIterationsExplicit {
					t.Error("DeobfIterationsExplicit should be true")
				}
			},
		},
		{
			name: "deobfuscation confidence",
			args: []string{"-t", "./app", "--deobf-min-confidence", "75"},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.DeobfMinConfidence != 75 {
					t.Errorf("DeobfMinConfidence = %d, want 75", opts.DeobfMinConfidence)
				}
				if !opts.DeobfMinConfidenceExplicit {
					t.Error("DeobfMinConfidenceExplicit should be true")
				}
			},
		},
		{
			name: "deobfuscation toggles",
			args: []string{
				"-t", "./app",
				"--enable-deobf-cp=false",
				"--enable-deobf-dce=false",
				"--enable-deobf-opr=false",
				"--enable-deobf-ps=false",
				"--enable-deobf-vr=false",
				"--enable-deobf-mr=false",
				"--enable-name-quality=false",
			},
			check: func(t *testing.T, opts *CLIOptions) {
				if opts.EnableDeobfCP {
					t.Error("CP should be disabled")
				}
				if opts.EnableDeobfDCE {
					t.Error("DCE should be disabled")
				}
				if opts.EnableDeobfOPR {
					t.Error("OPR should be disabled")
				}
				if opts.EnableDeobfPS {
					t.Error("PS should be disabled")
				}
				if opts.EnableDeobfVR {
					t.Error("VR should be disabled")
				}
				if opts.EnableDeobfMR {
					t.Error("MR should be disabled")
				}
				if opts.EnableNameQuality {
					t.Error("NameQuality should be disabled")
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

// ═══════════════════════════════════════════════════════════════════════════════
// VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCLIOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		opts    *CLIOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid options",
			opts: &CLIOptions{
				Target:  "./app",
				Profile: ProfileBalanced,
				Workers: 4,
				Timeout: 300,
			},
			wantErr: false,
		},
		{
			name: "missing target",
			opts: &CLIOptions{
				Target:  "",
				Profile: ProfileBalanced,
			},
			wantErr: true,
			errMsg:  "target directory is required",
		},
		{
			name: "invalid profile",
			opts: &CLIOptions{
				Target:  "./app",
				Profile: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid profile",
		},
		{
			name: "workers=0 uses CPU cores (auto-fixed)",
			opts: &CLIOptions{
				Target:  "./app",
				Profile: ProfileBalanced,
				Workers: 0,
				Timeout: 300,
			},
			wantErr: false,
		},
		{
			name: "workers negative error",
			opts: &CLIOptions{
				Target:  "./app",
				Profile: ProfileBalanced,
				Workers: -1,
			},
			wantErr: true,
			errMsg:  "workers must be at least 1",
		},
		{
			name: "workers capped at 64",
			opts: &CLIOptions{
				Target:  "./app",
				Profile: ProfileBalanced,
				Workers: 100,
				Timeout: 300,
			},
			wantErr: false,
		},
		{
			name: "timeout too low (auto-fixed)",
			opts: &CLIOptions{
				Target:  "./app",
				Profile: ProfileBalanced,
				Workers: 4,
				Timeout: 5,
			},
			wantErr: false,
		},
		{
			name: "timeout=0 unlimited",
			opts: &CLIOptions{
				Target:  "./app",
				Profile: ProfileBalanced,
				Workers: 4,
				Timeout: 0,
			},
			wantErr: false,
		},
		{
			name: "timeout negative error",
			opts: &CLIOptions{
				Target:  "./app",
				Profile: ProfileBalanced,
				Workers: 4,
				Timeout: -1,
			},
			wantErr: true,
			errMsg:  "timeout cannot be negative",
		},
		{
			name: "negative max files",
			opts: &CLIOptions{
				Target:   "./app",
				Profile:  ProfileBalanced,
				Workers:  4,
				Timeout:  300,
				MaxFiles: -1,
			},
			wantErr: true,
			errMsg:  "max-files must be >= 0",
		},
		{
			name: "negative content cache disk limit",
			opts: &CLIOptions{
				Target:                "./app",
				Profile:               ProfileBalanced,
				Workers:               4,
				Timeout:               300,
				ContentCacheMaxDiskMB: -1,
			},
			wantErr: true,
			errMsg:  "content-cache-max-disk-mb must be >= 0",
		},
		{
			name: "debug and quiet conflict",
			opts: &CLIOptions{
				Target:       "./app",
				Profile:      ProfileBalanced,
				Workers:      4,
				Timeout:      300,
				DebugVerbose: true,
				Quiet:        true,
			},
			wantErr: true,
			errMsg:  "mutually exclusive",
		},
		{
			name: "invalid report preset",
			opts: &CLIOptions{
				Target:  "./app",
				Profile: ProfileBalanced,
				Workers: 4,
				Timeout: 300,
				Report:  "invalid",
			},
			wantErr: true,
			errMsg:  "invalid report preset",
		},
		{
			name: "ML command without target (valid)",
			opts: &CLIOptions{
				MLSuggest: true,
			},
			wantErr: false,
		},
		{
			name: "valid sandbox options",
			opts: &CLIOptions{
				Sandbox:         true,
				Target:          "./sample.exe",
				SandboxDuration: 60,
				SandboxMemoryMB: 512,
			},
			wantErr: false,
		},
		{
			name: "sandbox missing target",
			opts: &CLIOptions{
				Sandbox:         true,
				SandboxDuration: 60,
				SandboxMemoryMB: 512,
			},
			wantErr: true,
			errMsg:  "sandbox mode requires a target path",
		},
		{
			name: "sandbox duration too low",
			opts: &CLIOptions{
				Sandbox:         true,
				Target:          "./sample.exe",
				SandboxDuration: 3,
				SandboxMemoryMB: 512,
			},
			wantErr: true,
			errMsg:  "sandbox-duration must be at least 5 seconds",
		},
		{
			name: "sandbox memory too low",
			opts: &CLIOptions{
				Sandbox:         true,
				Target:          "./sample.exe",
				SandboxDuration: 60,
				SandboxMemoryMB: 64,
			},
			wantErr: true,
			errMsg:  "sandbox-memory must be at least 128 MB",
		},
		{
			name: "ML confidence out of range",
			opts: &CLIOptions{
				MLSuggest:    true,
				MLConfidence: 1.5,
			},
			wantErr: true,
			errMsg:  "ml-confidence must be between 0 and 1",
		},
		{
			name: "negative ML max",
			opts: &CLIOptions{
				MLSuggest:        true,
				MLMaxSuggestions: -1,
			},
			wantErr: true,
			errMsg:  "ml-max must be >= 0",
		},
		{
			name: "ml patch min score too high",
			opts: &CLIOptions{
				Target:          "./app",
				Profile:         ProfileBalanced,
				Workers:         2,
				Timeout:         120,
				MLPatch:         true,
				MLPatchMinScore: 150,
			},
			wantErr: true,
			errMsg:  "ml-patch-min-score",
		},
		{
			name: "mark-relevant and mark-noise conflict",
			opts: &CLIOptions{
				MarkRelevant: "path",
				MarkNoise:    "path",
			},
			wantErr: true,
			errMsg:  "mutually exclusive",
		},

		{
			name: "deobf iterations negative",
			opts: &CLIOptions{
				Target:          "./app",
				Profile:         ProfileBalanced,
				DeobfIterations: -1,
			},
			wantErr: true,
			errMsg:  "deobf-iterations must be >= 0",
		},
		{
			name: "deobf confidence out of range",
			opts: &CLIOptions{
				Target:             "./app",
				Profile:            ProfileBalanced,
				DeobfMinConfidence: 150,
			},
			wantErr: true,
			errMsg:  "deobf-min-confidence must be between 0 and 100",
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

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS PROFILE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestAnalysisProfile_IsValid(t *testing.T) {
	tests := []struct {
		profile AnalysisProfile
		valid   bool
	}{
		{ProfileQuick, true},
		{ProfileBalanced, true},
		{ProfileDeep, true},
		{ProfileParanoid, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.profile), func(t *testing.T) {
			if tt.profile.IsValid() != tt.valid {
				t.Errorf("IsValid() = %v, want %v", tt.profile.IsValid(), tt.valid)
			}
		})
	}
}

func TestAnalysisProfile_Description(t *testing.T) {
	profiles := []AnalysisProfile{
		ProfileQuick,
		ProfileBalanced,
		ProfileDeep,
		ProfileParanoid,
	}

	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			desc := p.Description()
			if desc == "" {
				t.Error("Description should not be empty")
			}
			if desc == "Unknown profile" {
				t.Error("Should have description for valid profile")
			}
		})
	}

	t.Run("invalid profile", func(t *testing.T) {
		p := AnalysisProfile("invalid")
		desc := p.Description()
		if desc != "Unknown profile" {
			t.Errorf("Description() = %q, want %q", desc, "Unknown profile")
		}
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// IS ML COMMAND TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCLIOptions_IsMLCommand(t *testing.T) {
	tests := []struct {
		name   string
		opts   *CLIOptions
		expect bool
	}{
		{
			name:   "suggest command",
			opts:   &CLIOptions{MLSuggest: true},
			expect: true,
		},
		{
			name:   "history command",
			opts:   &CLIOptions{MLHistory: true},
			expect: true,
		},
		{
			name:   "stats command",
			opts:   &CLIOptions{MLStats: true},
			expect: true,
		},
		{
			name:   "export command",
			opts:   &CLIOptions{MLExport: "file.json"},
			expect: true,
		},
		{
			name:   "mark relevant",
			opts:   &CLIOptions{MarkRelevant: "path"},
			expect: true,
		},
		{
			name:   "mark noise",
			opts:   &CLIOptions{MarkNoise: "path"},
			expect: true,
		},
		{
			name:   "regular analysis",
			opts:   &CLIOptions{Target: "./app"},
			expect: false,
		},
		{
			name:   "empty options",
			opts:   &CLIOptions{},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts.IsMLCommand() != tt.expect {
				t.Errorf("IsMLCommand() = %v, want %v", tt.opts.IsMLCommand(), tt.expect)
			}
		})
	}
}

func TestCLIOptions_IsSandboxCommand(t *testing.T) {
	tests := []struct {
		name   string
		opts   *CLIOptions
		expect bool
	}{
		{
			name:   "sandbox enabled",
			opts:   &CLIOptions{Sandbox: true},
			expect: true,
		},
		{
			name:   "regular analysis",
			opts:   &CLIOptions{Target: "./app"},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts.IsSandboxCommand() != tt.expect {
				t.Errorf("IsSandboxCommand() = %v, want %v", tt.opts.IsSandboxCommand(), tt.expect)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// NORMALIZE ARGS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNormalizeArgs(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name:   "flags before positional",
			input:  []string{"-p", "deep", "./app"},
			expect: []string{"-p", "deep", "./app"},
		},
		{
			name:   "positional before flags",
			input:  []string{"./app", "-p", "deep"},
			expect: []string{"-p", "deep", "./app"},
		},
		{
			name:   "mixed order",
			input:  []string{"-t", "./app", "-p", "deep", "./result"},
			expect: []string{"-t", "./app", "-p", "deep", "./result"},
		},
		{
			name:   "flag with equals",
			input:  []string{"--profile=deep", "./app"},
			expect: []string{"--profile=deep", "./app"},
		},
		{
			name:   "boolean flags",
			input:  []string{"--debug", "./app", "--quiet"},
			expect: []string{"--debug", "--quiet", "./app"},
		},
	}

	fs := referenceFlagSet(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeArgs(tt.input, fs)
			if len(result) != len(tt.expect) {
				t.Fatalf("length mismatch: got %d, want %d", len(result), len(tt.expect))
			}
			for i := range result {
				if result[i] != tt.expect[i] {
					t.Errorf("arg[%d] = %q, want %q", i, result[i], tt.expect[i])
				}
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkCLIParser_Parse(b *testing.B) {
	args := []string{
		"-t", "./app",
		"-o", "./results",
		"-p", "deep",
		"--callgraph",
		"--correlations",
		"-w", "16",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser := NewCLIParser()
		_, _ = parser.Parse(args)
	}
}

func BenchmarkNormalizeArgs(b *testing.B) {
	args := []string{"./app", "-p", "deep", "-w", "8", "--callgraph"}
	p := NewCLIParser()
	_, _ = p.Parse(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizeArgs(args, p.fs)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE LOADING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCLIParser_ProfileLoading(t *testing.T) {
	// Save existing mocks
	oldExists := fsExists
	oldReadFile := fsReadFile
	defer func() {
		fsExists = oldExists
		fsReadFile = oldReadFile
	}()

	// Mock file system map
	mockFiles := map[string]string{
		"analyzer.flags.txt":        "-p quick\n--callgraph",
		"analyzer.flags.deep.txt":   "-p deep\n--correlations",
		"analyzer.flags.custom.txt": "-p paranoid\n-w 32",
	}

	fsExists = func(path string) bool {
		_, ok := mockFiles[path]
		return ok
	}
	fsReadFile = func(path string) (string, error) {
		content, ok := mockFiles[path]
		if !ok {
			return "", os.ErrNotExist
		}
		return content, nil
	}

	t.Run("default profile file auto loaded", func(t *testing.T) {
		parser := NewCLIParser()
		opts, err := parser.Parse([]string{"-t", "./app"})
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if opts.Profile != ProfileQuick {
			t.Errorf("Expected profile %s, got %s", ProfileQuick, opts.Profile)
		}
		if !opts.EnableCallGraph {
			t.Error("Expected call graph enabled from profile")
		}
	})

	t.Run("explicit deep profile loads deep flags", func(t *testing.T) {
		parser := NewCLIParser()
		opts, err := parser.Parse([]string{"-t", "./app", "-profile", "deep"})
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if opts.Profile != ProfileDeep {
			t.Errorf("Expected profile %s, got %s", ProfileDeep, opts.Profile)
		}
		if !opts.EnableCorrelations {
			t.Error("Expected correlations enabled from deep profile")
		}
	})

	t.Run("no-profile bypasses loading", func(t *testing.T) {
		parser := NewCLIParser()
		opts, err := parser.Parse([]string{"-t", "./app", "-no-profile"})
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		// Default without profile file should be ProfileBalanced (from defaultCLIOptions)
		if opts.Profile != ProfileBalanced {
			t.Errorf("Expected profile %s, got %s", ProfileBalanced, opts.Profile)
		}
		if opts.EnableCallGraph {
			t.Error("Callgraph should not be enabled when bypassed")
		}
	})

	t.Run("custom profile successfully loaded", func(t *testing.T) {
		parser := NewCLIParser()
		opts, err := parser.Parse([]string{"-t", "./app", "-profile", "custom"})
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if opts.Profile != ProfileParanoid {
			t.Errorf("Expected profile %s, got %s", ProfileParanoid, opts.Profile)
		}
		if opts.Workers != 32 {
			t.Errorf("Expected workers %d, got %d", 32, opts.Workers)
		}
	})

	t.Run("missing custom profile file returns error", func(t *testing.T) {
		parser := NewCLIParser()
		_, err := parser.Parse([]string{"-t", "./app", "-profile", "nonexistent"})
		if err == nil {
			t.Fatal("Expected error for missing custom profile file")
		}
		if !strings.Contains(err.Error(), "profile configuration file not found") {
			t.Errorf("Unexpected error message: %v", err)
		}
	})
}

func TestCLIParserSARIFAndFPTuning(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{
		"--target", "app",
		"--sarif",
		"--fp-strict",
		"--fp-show-suppressed",
		"--fp-min-score=2.5",
		"--fp-suppressed-limit=0",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.SARIF || !opts.FPStrict || !opts.FPShowSuppressed {
		t.Fatalf("SARIF/FP bool flags were not parsed: %#v", opts)
	}
	if opts.FPMinScore != 2.5 || opts.FPSuppressedLimit != 0 {
		t.Fatalf("FP tuning flags = %.1f/%d", opts.FPMinScore, opts.FPSuppressedLimit)
	}
}

func TestCLIParser_Helpers(t *testing.T) {
	// isTruthy
	if !isTruthy("yes") || !isTruthy("TRUE") || !isTruthy("1") {
		t.Error("isTruthy expected true")
	}
	if isTruthy("false") || isTruthy("0") || isTruthy("no") {
		t.Error("isTruthy expected false")
	}

	// normalizeArgs
	args := normalizeArgs([]string{"-target=foo", "--output", "bar", "--ml-train"}, referenceFlagSet(t))
	if len(args) != 4 {
		t.Errorf("normalizeArgs failed, got %v", args)
	}

	// splitArgs
	split, err := splitArgs(`--test "foo bar" -v`)
	if err != nil || len(split) != 3 {
		t.Errorf("splitArgs failed: %v", err)
	}
}
