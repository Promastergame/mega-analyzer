package main

import (
	"testing"
)

// TestExportFlagParsing tests the new export-related flags
func TestExportFlagParsing(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		validate func(*testing.T, *CLIOptions)
	}{
		{
			name: "export-format single format",
			args: []string{"-t", "./app", "--export-format", "json"},
			validate: func(t *testing.T, opts *CLIOptions) {
				if len(opts.MLPatchExportFormat) != 1 {
					t.Errorf("expected 1 export format, got %d", len(opts.MLPatchExportFormat))
				}
				if opts.MLPatchExportFormat[0] != "json" {
					t.Errorf("expected json format, got %s", opts.MLPatchExportFormat[0])
				}
				if !opts.MLPatch {
					t.Error("expected MLPatch to be auto-enabled")
				}
			},
		},
		{
			name: "export-format multiple formats",
			args: []string{"-t", "./app", "--export-format", "json,md,csv"},
			validate: func(t *testing.T, opts *CLIOptions) {
				if len(opts.MLPatchExportFormat) != 3 {
					t.Errorf("expected 3 export formats, got %d", len(opts.MLPatchExportFormat))
				}
				expected := []string{"json", "md", "csv"}
				for i, format := range expected {
					if opts.MLPatchExportFormat[i] != format {
						t.Errorf("expected format %s at index %d, got %s", format, i, opts.MLPatchExportFormat[i])
					}
				}
			},
		},
		{
			name: "export-format with spaces",
			args: []string{"-t", "./app", "--export-format", "json, md, csv"},
			validate: func(t *testing.T, opts *CLIOptions) {
				if len(opts.MLPatchExportFormat) != 3 {
					t.Errorf("expected 3 export formats, got %d", len(opts.MLPatchExportFormat))
				}
			},
		},
		{
			name:    "export-format invalid format",
			args:    []string{"-t", "./app", "--export-format", "xml"},
			wantErr: true,
		},
		{
			name: "confidence-threshold valid",
			args: []string{"-t", "./app", "--confidence-threshold", "0.8"},
			validate: func(t *testing.T, opts *CLIOptions) {
				if opts.MLPatchConfidenceThresh != 0.8 {
					t.Errorf("expected confidence threshold 0.8, got %.2f", opts.MLPatchConfidenceThresh)
				}
			},
		},
		{
			name:    "confidence-threshold too high",
			args:    []string{"-t", "./app", "--confidence-threshold", "1.5"},
			wantErr: true,
		},
		{
			name:    "confidence-threshold negative",
			args:    []string{"-t", "./app", "--confidence-threshold", "-0.1"},
			wantErr: true,
		},
		{
			name: "export-output custom path",
			args: []string{"-t", "./app", "--export-output", "./custom/path"},
			validate: func(t *testing.T, opts *CLIOptions) {
				if opts.MLPatchExportOutput != "./custom/path" {
					t.Errorf("expected export output './custom/path', got %s", opts.MLPatchExportOutput)
				}
			},
		},
		{
			name: "explain flag",
			args: []string{"-t", "./app", "--explain"},
			validate: func(t *testing.T, opts *CLIOptions) {
				if !opts.MLPatchExplain {
					t.Error("expected MLPatchExplain to be true")
				}
			},
		},
		{
			name: "all export flags combined",
			args: []string{
				"-t", "./app",

				"--explain",
				"--export-format", "json,md",
				"--confidence-threshold", "0.7",
				"--export-output", "./patches",
			},
			validate: func(t *testing.T, opts *CLIOptions) {
				if !opts.MLPatchExplain {
					t.Error("expected MLPatchExplain to be true")
				}
				if len(opts.MLPatchExportFormat) != 2 {
					t.Errorf("expected 2 export formats, got %d", len(opts.MLPatchExportFormat))
				}
				if opts.MLPatchConfidenceThresh != 0.7 {
					t.Errorf("expected confidence threshold 0.7, got %.2f", opts.MLPatchConfidenceThresh)
				}
				if opts.MLPatchExportOutput != "./patches" {
					t.Errorf("expected export output './patches', got %s", opts.MLPatchExportOutput)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCLIParser()
			opts, err := parser.Parse(tt.args)

			if err != nil {
				if !tt.wantErr {
					t.Errorf("unexpected parse error: %v", err)
				}
				return
			}

			// Validate options
			err = opts.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected validation error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected validation error: %v", err)
				return
			}

			if tt.validate != nil {
				tt.validate(t, opts)
			}
		})
	}
}

// TestExportFlagsAutoEnablement tests that export flags auto-enable ML patch
func TestExportFlagsAutoEnablement(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "export-format auto-enables ml-patch",
			args: []string{"-t", "./app", "--export-format", "json"},
		},
		{
			name: "export-output auto-enables ml-patch",
			args: []string{"-t", "./app", "--export-output", "./patches"},
		},
		{
			name: "explain auto-enables ml-patch",
			args: []string{"-t", "./app", "--explain"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCLIParser()
			opts, err := parser.Parse(tt.args)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			err = opts.Validate()
			if err != nil {
				t.Fatalf("validation error: %v", err)
			}

			if !opts.MLPatch {
				t.Error("expected MLPatch to be auto-enabled")
			}
		})
	}
}
