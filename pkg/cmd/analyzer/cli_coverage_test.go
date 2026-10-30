package main

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ADDITIONAL CLI PARSER TESTS FOR COVERAGE
// ═══════════════════════════════════════════════════════════════════════════════

func TestCLIParser_MaxFileSize(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"-t", "./app", "--max-file-size", "16"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if opts.MaxFileSizeMB != 16 {
		t.Errorf("MaxFileSizeMB = %d, want 16", opts.MaxFileSizeMB)
	}
	if !opts.MaxFileSizeExplicit {
		t.Error("MaxFileSizeExplicit should be true")
	}
}

func TestCLIParser_MaxResourceSize(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"-t", "./app", "--max-resource-size", "32"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if opts.MaxResourceSizeMB != 32 {
		t.Errorf("MaxResourceSizeMB = %d, want 32", opts.MaxResourceSizeMB)
	}
	if !opts.MaxResourceSizeExplicit {
		t.Error("MaxResourceSizeExplicit should be true")
	}
}

func TestCLIParser_RebuildFlags(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"--rebuild", "-t", "./src", "-o", "output.apk", "--no-sign", "--no-align"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.Rebuild {
		t.Error("Rebuild should be true")
	}
	if !opts.NoSign {
		t.Error("NoSign should be true")
	}
	if !opts.NoAlign {
		t.Error("NoAlign should be true")
	}
}

func TestCLIParser_WindowsSandboxFlags(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{
		"--sandbox", "-t", "./sample.exe",
		"--win-sandbox",
		"--sandbox-vss-revert",
		"--sandbox-time-scale", "5.0",
		"--sandbox-output", "./artifacts",
		"--enable-kernel-monitor",
		"--enable-vss",
		"--enable-wfp",
		"--enable-api-tracing",
		"--enable-time-manip",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.WinSandbox {
		t.Error("WinSandbox should be true")
	}
	if !opts.SandboxVSSRevert {
		t.Error("SandboxVSSRevert should be true")
	}
	if opts.SandboxTimeScale != 5.0 {
		t.Errorf("SandboxTimeScale = %f, want 5.0", opts.SandboxTimeScale)
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
}

func TestCLIParser_MLPatchExportFlags(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{
		"-t", "./app",
		"--ml-patch",

		"--explain",
		"--export-format", "md,json",
		"--confidence-threshold", "0.5",
		"--export-output", "patches",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.MLPatchExplain {
		t.Error("MLPatchExplain should be true")
	}
	if len(opts.MLPatchExportFormat) != 2 {
		t.Errorf("MLPatchExportFormat length = %d, want 2", len(opts.MLPatchExportFormat))
	}
	if opts.MLPatchExportFormat[0] != "md" || opts.MLPatchExportFormat[1] != "json" {
		t.Errorf("MLPatchExportFormat = %v, want [md, json]", opts.MLPatchExportFormat)
	}
	if opts.MLPatchConfidenceThresh != 0.5 {
		t.Errorf("MLPatchConfidenceThresh = %f, want 0.5", opts.MLPatchConfidenceThresh)
	}
	if opts.MLPatchExportOutput != "patches" {
		t.Errorf("MLPatchExportOutput = %q, want %q", opts.MLPatchExportOutput, "patches")
	}
}

func TestCLIParser_PatternStatsFlags(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{
		"--pattern-stats",
		"--export-pattern-stats", "stats.json",
		"--feedback-file", "feedback.json",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.PatternStats {
		t.Error("PatternStats should be true")
	}
	if opts.ExportPatternStats != "stats.json" {
		t.Errorf("ExportPatternStats = %q, want %q", opts.ExportPatternStats, "stats.json")
	}
	if opts.FeedbackFile != "feedback.json" {
		t.Errorf("FeedbackFile = %q, want %q", opts.FeedbackFile, "feedback.json")
	}
}

func TestCLIParser_MLPatchTierFlags(t *testing.T) {
	// Test that MLPatchMinTier and related flags are stored in CLIOptions
	opts := &CLIOptions{
		Target:                   "./app",
		MLPatch:                  true,
		MLPatchMinTier:           "elite",
		MLPatchEnableDeprecated:  true,
		MLPatchEnableSDK:         true,
		MLPatchEnableCombination: true,
	}

	if opts.Target != "./app" {
		t.Errorf("Target = %q, want %q", opts.Target, "./app")
	}
	if !opts.MLPatch {
		t.Error("MLPatch should be true")
	}
	if opts.MLPatchMinTier != "elite" {
		t.Errorf("MLPatchMinTier = %q, want %q", opts.MLPatchMinTier, "elite")
	}
	if !opts.MLPatchEnableDeprecated {
		t.Error("MLPatchEnableDeprecated should be true")
	}
	if !opts.MLPatchEnableSDK {
		t.Error("MLPatchEnableSDK should be true")
	}
	if !opts.MLPatchEnableCombination {
		t.Error("MLPatchEnableCombination should be true")
	}
}

func TestCLIParser_GameModeFlags(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{
		"-gamemode",
		"-gamemode-output", "markdown",
		"-gamemode-persist",
		"-decoy-detection",
		"-interesting-score",
		"-ml-patch-confidence-min", "0.55",
		"-ml-patch-priority-sort=false",
		"-ml-patch-cross-language=false",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if !opts.GameMode {
		t.Error("GameMode should be true")
	}
	if opts.GameModeOutput != "markdown" {
		t.Errorf("GameModeOutput = %q, want %q", opts.GameModeOutput, "markdown")
	}
	if !opts.GameModePersist {
		t.Error("GameModePersist should be true")
	}
	if !opts.DecoyDetection {
		t.Error("DecoyDetection should be true")
	}
	if !opts.InterestingScore {
		t.Error("InterestingScore should be true")
	}
	if opts.MLPatchConfidenceMin != 0.55 {
		t.Errorf("MLPatchConfidenceMin = %f, want 0.55", opts.MLPatchConfidenceMin)
	}
	if opts.MLPatchPrioritySort {
		t.Error("MLPatchPrioritySort should be false")
	}
	if opts.MLPatchCrossLanguage {
		t.Error("MLPatchCrossLanguage should be false")
	}
}

func TestCLIParser_ShowFeedback(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"--show-feedback"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.ShowFeedback {
		t.Error("ShowFeedback should be true")
	}
}

func TestCLIParser_MLApply(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"--ml-apply", "1,3,5"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if opts.MLApply != "1,3,5" {
		t.Errorf("MLApply = %q, want %q", opts.MLApply, "1,3,5")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// VALIDATION EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

func TestCLIOptions_Validate_Rebuild(t *testing.T) {
	tests := []struct {
		name    string
		opts    *CLIOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid rebuild",
			opts: &CLIOptions{
				Rebuild: true,
				Target:  "./src",
				Output:  "output.apk",
			},
			wantErr: false,
		},
		{
			name: "rebuild missing target",
			opts: &CLIOptions{
				Rebuild: true,
				Output:  "output.apk",
			},
			wantErr: true,
			errMsg:  "rebuild requires target directory",
		},
		{
			name: "rebuild missing output",
			opts: &CLIOptions{
				Rebuild: true,
				Target:  "./src",
				Output:  "analysis_output",
			},
			wantErr: true,
			errMsg:  "rebuild requires output APK path",
		},
		{
			name: "rebuild with empty output",
			opts: &CLIOptions{
				Rebuild: true,
				Target:  "./src",
				Output:  "",
			},
			wantErr: true,
			errMsg:  "rebuild requires output APK path",
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

func TestCLIOptions_Validate_SandboxEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		opts    *CLIOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "sandbox with ML command",
			opts: &CLIOptions{
				Sandbox:         true,
				Target:          "./sample.exe",
				MLSuggest:       true,
				SandboxDuration: 60,
				SandboxMemoryMB: 512,
			},
			wantErr: true,
			errMsg:  "cannot be combined with ML assistant",
		},
		{
			name: "sandbox with rebuild",
			opts: &CLIOptions{
				Sandbox:         true,
				Rebuild:         true,
				Target:          "./sample.exe",
				SandboxDuration: 60,
				SandboxMemoryMB: 512,
			},
			wantErr: true,
			errMsg:  "cannot be combined with --rebuild",
		},
		{
			name: "sandbox time scale too low",
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
			name: "sandbox time scale too high",
			opts: &CLIOptions{
				Sandbox:          true,
				Target:           "./sample.exe",
				SandboxDuration:  60,
				SandboxMemoryMB:  512,
				SandboxTimeScale: 2000.0,
			},
			wantErr: true,
			errMsg:  "sandbox-time-scale must be between 0.1 and 1000.0",
		},
		{
			name: "sandbox with debug and quiet",
			opts: &CLIOptions{
				Sandbox:         true,
				Target:          "./sample.exe",
				SandboxDuration: 60,
				SandboxMemoryMB: 512,
				DebugVerbose:    true,
				Quiet:           true,
			},
			wantErr: true,
			errMsg:  "mutually exclusive",
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

func TestCLIOptions_Validate_MLPatchExport(t *testing.T) {
	tests := []struct {
		name    string
		opts    *CLIOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "invalid export format",
			opts: &CLIOptions{
				Target:              "./app",
				Profile:             ProfileBalanced,
				MLPatch:             true,
				MLPatchExportFormat: []string{"invalid"},
			},
			wantErr: true,
			errMsg:  "invalid export format",
		},
		{
			name: "confidence threshold too low",
			opts: &CLIOptions{
				Target:                  "./app",
				Profile:                 ProfileBalanced,
				MLPatch:                 true,
				MLPatchConfidenceThresh: -0.5,
			},
			wantErr: true,
			errMsg:  "confidence-threshold must be between 0.0 and 1.0",
		},
		{
			name: "confidence threshold too high",
			opts: &CLIOptions{
				Target:                  "./app",
				Profile:                 ProfileBalanced,
				MLPatch:                 true,
				MLPatchConfidenceThresh: 1.5,
			},
			wantErr: true,
			errMsg:  "confidence-threshold must be between 0.0 and 1.0",
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

func TestCLIOptions_Validate_MaxFileSize(t *testing.T) {
	opts := &CLIOptions{
		Target:        "./app",
		Profile:       ProfileBalanced,
		MaxFileSizeMB: -5,
	}
	err := opts.Validate()
	if err == nil {
		t.Error("Validate() should error for negative MaxFileSizeMB")
	}
	if !strings.Contains(err.Error(), "max-file-size must be >= 0") {
		t.Errorf("Validate() error = %v, should contain 'max-file-size must be >= 0'", err)
	}
}

func TestCLIOptions_Validate_MaxResourceSize(t *testing.T) {
	opts := &CLIOptions{
		Target:            "./app",
		Profile:           ProfileBalanced,
		MaxResourceSizeMB: -5,
	}
	err := opts.Validate()
	if err == nil {
		t.Error("Validate() should error for negative MaxResourceSizeMB")
	}
	if !strings.Contains(err.Error(), "max-resource-size must be >= 0") {
		t.Errorf("Validate() error = %v, should contain 'max-resource-size must be >= 0'", err)
	}
}

func TestCLIOptions_IsRebuildCommand(t *testing.T) {
	tests := []struct {
		name   string
		opts   *CLIOptions
		expect bool
	}{
		{"rebuild enabled", &CLIOptions{Rebuild: true}, true},
		{"rebuild disabled", &CLIOptions{Rebuild: false}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts.IsRebuildCommand() != tt.expect {
				t.Errorf("IsRebuildCommand() = %v, want %v", tt.opts.IsRebuildCommand(), tt.expect)
			}
		})
	}
}

func TestCLIParser_ExportFormatParsing(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected []string
	}{
		{
			name:     "single format",
			args:     []string{"-t", "./app", "--ml-patch", "--export-format", "json"},
			expected: []string{"json"},
		},
		{
			name:     "multiple formats",
			args:     []string{"-t", "./app", "--ml-patch", "--export-format", "md,json,csv"},
			expected: []string{"md", "json", "csv"},
		},
		{
			name:     "formats with spaces",
			args:     []string{"-t", "./app", "--ml-patch", "--export-format", " md , json "},
			expected: []string{"md", "json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCLIParser()
			opts, err := parser.Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(opts.MLPatchExportFormat) != len(tt.expected) {
				t.Errorf("MLPatchExportFormat length = %d, want %d", len(opts.MLPatchExportFormat), len(tt.expected))
				return
			}
			for i, f := range opts.MLPatchExportFormat {
				if f != tt.expected[i] {
					t.Errorf("MLPatchExportFormat[%d] = %q, want %q", i, f, tt.expected[i])
				}
			}
		})
	}
}

func TestCLIParser_FlagShorthands(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"-t", "./app", "-o", "./out", "-p", "quick", "-w", "4", "-d", "-q"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if opts.Target != "./app" {
		t.Errorf("Target = %q, want %q", opts.Target, "./app")
	}
	if opts.Output != "./out" {
		t.Errorf("Output = %q, want %q", opts.Output, "./out")
	}
	if opts.Profile != ProfileQuick {
		t.Errorf("Profile = %v, want %v", opts.Profile, ProfileQuick)
	}
	if opts.Workers != 4 {
		t.Errorf("Workers = %d, want 4", opts.Workers)
	}
	if !opts.DebugVerbose {
		t.Error("Debug should be true")
	}
	if !opts.Quiet {
		t.Error("Quiet should be true")
	}
}

func TestCLIParser_NoJSONFlag(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"-t", "./app", "--no-json"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.NoJSON {
		t.Error("NoJSON should be true")
	}
}

func TestCLIParser_PositionalTarget(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"./my_app_directory"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if opts.Target != "./my_app_directory" {
		t.Errorf("Target = %q, want %q", opts.Target, "./my_app_directory")
	}
}

func TestCLIParser_EqualsSyntax(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{
		"--target=./app",
		"--output=./results",
		"--profile=deep",
		"--workers=8",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if opts.Target != "./app" {
		t.Errorf("Target = %q, want %q", opts.Target, "./app")
	}
	if opts.Output != "./results" {
		t.Errorf("Output = %q, want %q", opts.Output, "./results")
	}
	if opts.Profile != ProfileDeep {
		t.Errorf("Profile = %v, want %v", opts.Profile, ProfileDeep)
	}
	if opts.Workers != 8 {
		t.Errorf("Workers = %d, want 8", opts.Workers)
	}
}

func TestCLIParser_Defaults(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"-t", "./app"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if opts.Output != "analysis_output" {
		t.Errorf("Output default = %q, want %q", opts.Output, "analysis_output")
	}
	if opts.Profile != ProfileBalanced {
		t.Errorf("Profile default = %v, want %v", opts.Profile, ProfileBalanced)
	}
	if opts.Timeout != 300 {
		t.Errorf("Timeout default = %d, want 300", opts.Timeout)
	}
	if opts.MLConfidence != 0.5 {
		t.Errorf("MLConfidence default = %f, want 0.5", opts.MLConfidence)
	}
	if opts.MLMaxSuggestions != 10 {
		t.Errorf("MLMaxSuggestions default = %d, want 10", opts.MLMaxSuggestions)
	}
}
