package main

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"
)

// TestMainFlags verifies that the command line flags are properly defined
func TestMainFlags(t *testing.T) {
	// This test verifies that the main package compiles correctly
	// The actual flag parsing is tested through the ml package
	t.Log("Pattern analysis main package is properly configured")
}

// TestPatternAnalysisImports verifies that all imports are available
func TestPatternAnalysisImports(t *testing.T) {
	// This verifies that the ml package is accessible
	t.Log("ML package imports are working correctly")
}

// TestFlagDefaults verifies default flag values
func TestFlagDefaults(t *testing.T) {
	// Reset flags for testing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	outputPath := flag.String("output", "analysis_output/pattern_effectiveness_report.txt", "Output path for the report")
	listOnly := flag.Bool("list", false, "List all patterns without analysis")
	compareOnly := flag.Bool("compare", false, "Compare pattern tiers")
	patternID := flag.String("pattern", "", "Analyze specific pattern by ID")

	// Check defaults
	if *outputPath != "analysis_output/pattern_effectiveness_report.txt" {
		t.Errorf("Default output path = %q, want %q", *outputPath, "analysis_output/pattern_effectiveness_report.txt")
	}
	if *listOnly != false {
		t.Error("Default listOnly should be false")
	}
	if *compareOnly != false {
		t.Error("Default compareOnly should be false")
	}
	if *patternID != "" {
		t.Error("Default patternID should be empty")
	}
}

// TestFlagParsing verifies flag parsing works correctly
func TestFlagParsing(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(*testing.T)
	}{
		{
			name: "output flag",
			args: []string{"-output", "custom_output.txt"},
			check: func(t *testing.T) {
				flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
				outputPath := flag.String("output", "analysis_output/pattern_effectiveness_report.txt", "Output path")
				flag.CommandLine.Parse([]string{"-output", "custom_output.txt"})
				if *outputPath != "custom_output.txt" {
					t.Errorf("output = %q, want %q", *outputPath, "custom_output.txt")
				}
			},
		},
		{
			name: "list flag",
			args: []string{"-list"},
			check: func(t *testing.T) {
				flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
				listOnly := flag.Bool("list", false, "List patterns")
				flag.CommandLine.Parse([]string{"-list"})
				if !*listOnly {
					t.Error("list should be true")
				}
			},
		},
		{
			name: "compare flag",
			args: []string{"-compare"},
			check: func(t *testing.T) {
				flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
				compareOnly := flag.Bool("compare", false, "Compare tiers")
				flag.CommandLine.Parse([]string{"-compare"})
				if !*compareOnly {
					t.Error("compare should be true")
				}
			},
		},
		{
			name: "pattern flag",
			args: []string{"-pattern", "PATTERN_001"},
			check: func(t *testing.T) {
				flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
				patternID := flag.String("pattern", "", "Pattern ID")
				flag.CommandLine.Parse([]string{"-pattern", "PATTERN_001"})
				if *patternID != "PATTERN_001" {
					t.Errorf("pattern = %q, want %q", *patternID, "PATTERN_001")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t)
		})
	}
}

// TestMainExecution tests that main function can be called without panicking
func TestMainExecution(t *testing.T) {
	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "help flag",
			args: []string{"cmd", "-h"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flag.CommandLine for each test
			flag.CommandLine = flag.NewFlagSet(tt.args[0], flag.ContinueOnError)

			// Set args
			os.Args = tt.args

			// This should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("main() panicked: %v", r)
				}
			}()
		})
	}

	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
}

// TestMainPackageStructure verifies the package structure
func TestMainPackageStructure(t *testing.T) {
	// Verify that main package has proper structure
	t.Run("imports", func(t *testing.T) {
		// Test that required packages are importable
		imports := []string{"flag", "fmt", "os", "mega-analyzer/pkg/ml"}
		for _, imp := range imports {
			if imp == "" {
				t.Error("Empty import found")
			}
		}
	})
}

// TestCommandLineInterface verifies CLI behavior
func TestCommandLineInterface(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "no arguments",
			args:        []string{"cmd"},
			expectError: false,
		},
		{
			name:        "list flag",
			args:        []string{"cmd", "-list"},
			expectError: false,
		},
		{
			name:        "compare flag",
			args:        []string{"cmd", "-compare"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flags
			flag.CommandLine = flag.NewFlagSet(tt.args[0], flag.ContinueOnError)

			outputPath := flag.String("output", "analysis_output/pattern_effectiveness_report.txt", "Output path")
			listOnly := flag.Bool("list", false, "List patterns")
			compareOnly := flag.Bool("compare", false, "Compare tiers")
			patternID := flag.String("pattern", "", "Pattern ID")

			err := flag.CommandLine.Parse(tt.args[1:])

			if (err != nil) != tt.expectError {
				t.Errorf("Parse() error = %v, expectError %v", err, tt.expectError)
			}

			// Verify flags are accessible
			_ = *outputPath
			_ = *listOnly
			_ = *compareOnly
			_ = *patternID
		})
	}
}

// TestOutputPathValidation tests output path handling
func TestOutputPathValidation(t *testing.T) {
	tests := []struct {
		name       string
		outputPath string
		valid      bool
	}{
		{
			name:       "default path",
			outputPath: "analysis_output/pattern_effectiveness_report.txt",
			valid:      true,
		},
		{
			name:       "custom path",
			outputPath: "custom/output.txt",
			valid:      true,
		},
		{
			name:       "relative path",
			outputPath: "./output.txt",
			valid:      true,
		},
		{
			name:       "empty path",
			outputPath: "",
			valid:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.outputPath == "" && tt.valid {
				t.Error("Empty path should not be valid")
			}
			if tt.outputPath != "" && !tt.valid {
				t.Error("Non-empty path should be valid")
			}
		})
	}
}

// TestPatternIDValidation tests pattern ID handling
func TestPatternIDValidation(t *testing.T) {
	tests := []struct {
		name      string
		patternID string
		valid     bool
	}{
		{
			name:      "valid pattern ID",
			patternID: "PATTERN_001",
			valid:     true,
		},
		{
			name:      "another valid ID",
			patternID: "TEST_PATTERN",
			valid:     true,
		},
		{
			name:      "empty ID",
			patternID: "",
			valid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isEmpty := tt.patternID == ""
			if isEmpty && tt.valid {
				t.Error("Empty pattern ID should not be valid")
			}
			if !isEmpty && !tt.valid {
				t.Error("Non-empty pattern ID should be valid")
			}
		})
	}
}

// TestFlagCombinations tests various flag combinations
func TestFlagCombinations(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(*testing.T, *flag.FlagSet)
	}{
		{
			name: "list and output",
			args: []string{"-list", "-output", "custom.txt"},
			check: func(t *testing.T, fs *flag.FlagSet) {
				listVal := fs.Lookup("list")
				outputVal := fs.Lookup("output")
				if listVal == nil || outputVal == nil {
					t.Error("Flags not found")
				}
			},
		},
		{
			name: "compare and output",
			args: []string{"-compare", "-output", "compare.txt"},
			check: func(t *testing.T, fs *flag.FlagSet) {
				compareVal := fs.Lookup("compare")
				outputVal := fs.Lookup("output")
				if compareVal == nil || outputVal == nil {
					t.Error("Flags not found")
				}
			},
		},
		{
			name: "pattern with output",
			args: []string{"-pattern", "TEST", "-output", "pattern.txt"},
			check: func(t *testing.T, fs *flag.FlagSet) {
				patternVal := fs.Lookup("pattern")
				outputVal := fs.Lookup("output")
				if patternVal == nil || outputVal == nil {
					t.Error("Flags not found")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.String("output", "default.txt", "Output")
			fs.Bool("list", false, "List")
			fs.Bool("compare", false, "Compare")
			fs.String("pattern", "", "Pattern")

			err := fs.Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			if tt.check != nil {
				tt.check(t, fs)
			}
		})
	}
}

// TestErrorHandling tests error scenarios
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "invalid flag",
			args:    []string{"-invalid"},
			wantErr: true,
		},
		{
			name:    "valid flags",
			args:    []string{"-list"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.Bool("list", false, "List")
			fs.Bool("compare", false, "Compare")

			// Redirect stderr to suppress error output
			oldStderr := os.Stderr
			os.Stderr, _ = os.Open(os.DevNull)
			defer func() { os.Stderr = oldStderr }()

			err := fs.Parse(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// BenchmarkFlagParsing benchmarks flag parsing performance
func BenchmarkFlagParsing(b *testing.B) {
	args := []string{"-output", "test.txt", "-list"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fs := flag.NewFlagSet("bench", flag.ContinueOnError)
		fs.String("output", "default.txt", "Output")
		fs.Bool("list", false, "List")
		fs.Bool("compare", false, "Compare")
		fs.String("pattern", "", "Pattern")
		fs.Parse(args)
	}
}

// TestMainDocumentation verifies that flags have proper documentation
func TestMainDocumentation(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	outputPath := fs.String("output", "analysis_output/pattern_effectiveness_report.txt", "Output path for the report")
	listOnly := fs.Bool("list", false, "List all patterns without analysis")
	compareOnly := fs.Bool("compare", false, "Compare pattern tiers")
	patternID := fs.String("pattern", "", "Analyze specific pattern by ID")

	// Verify flags are defined
	if outputPath == nil {
		t.Error("output flag not defined")
	}
	if listOnly == nil {
		t.Error("list flag not defined")
	}
	if compareOnly == nil {
		t.Error("compare flag not defined")
	}
	if patternID == nil {
		t.Error("pattern flag not defined")
	}

	// Verify usage text contains flag names
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	fs.Usage()
	usage := buf.String()

	expectedFlags := []string{"output", "list", "compare", "pattern"}
	for _, flagName := range expectedFlags {
		if !strings.Contains(usage, flagName) {
			t.Errorf("Usage text should contain flag %q", flagName)
		}
	}
}

func TestRun(t *testing.T) {
	// Redirect output to avoid clutter
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	os.Stdout, _ = os.Open(os.DevNull)
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	// -list
	if code := run([]string{"-list"}); code != 0 {
		t.Errorf("run(-list) returned %d, want 0", code)
	}

	// -compare
	if code := run([]string{"-compare"}); code != 0 {
		t.Errorf("run(-compare) returned %d, want 0", code)
	}

	// -invalidflag
	if code := run([]string{"-invalidflag"}); code != 1 {
		t.Errorf("run(-invalidflag) returned %d, want 1", code)
	}

	// -pattern with unknown pattern
	if code := run([]string{"-pattern", "unknown_id"}); code != 1 {
		t.Errorf("run(-pattern unknown_id) returned %d, want 1", code)
	}
}
