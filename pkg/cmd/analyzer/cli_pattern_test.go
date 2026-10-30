package main

import (
	"testing"
)

func TestCLIPatternEffectivenessFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		validate func(*testing.T, *CLIOptions)
	}{
		{
			name: "pattern-stats flag",
			args: []string{"--pattern-stats"},
			validate: func(t *testing.T, opts *CLIOptions) {
				if !opts.PatternStats {
					t.Error("PatternStats should be true")
				}
				if !opts.IsMLCommand() {
					t.Error("Should be recognized as ML command")
				}
			},
		},
		{
			name: "export-pattern-stats flag",
			args: []string{"--export-pattern-stats", "metrics.json"},
			validate: func(t *testing.T, opts *CLIOptions) {
				if opts.ExportPatternStats != "metrics.json" {
					t.Errorf("ExportPatternStats = %q, want %q", opts.ExportPatternStats, "metrics.json")
				}
				if !opts.IsMLCommand() {
					t.Error("Should be recognized as ML command")
				}
			},
		},
		{
			name: "feedback-file flag",
			args: []string{"--feedback-file", "feedback.json"},
			validate: func(t *testing.T, opts *CLIOptions) {
				if opts.FeedbackFile != "feedback.json" {
					t.Errorf("FeedbackFile = %q, want %q", opts.FeedbackFile, "feedback.json")
				}
				if !opts.IsMLCommand() {
					t.Error("Should be recognized as ML command")
				}
			},
		},
		{
			name: "combined pattern flags",
			args: []string{"--pattern-stats", "--export-pattern-stats", "output.json"},
			validate: func(t *testing.T, opts *CLIOptions) {
				if !opts.PatternStats {
					t.Error("PatternStats should be true")
				}
				if opts.ExportPatternStats != "output.json" {
					t.Errorf("ExportPatternStats = %q, want %q", opts.ExportPatternStats, "output.json")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCLIParser()
			opts, err := parser.Parse(tt.args)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && tt.validate != nil {
				tt.validate(t, opts)
			}
		})
	}
}

func TestCLIPatternEffectivenessValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    *CLIOptions
		wantErr bool
	}{
		{
			name: "pattern-stats without target is valid",
			opts: &CLIOptions{
				PatternStats: true,
			},
			wantErr: false,
		},
		{
			name: "feedback-file without target is valid",
			opts: &CLIOptions{
				FeedbackFile: "feedback.json",
			},
			wantErr: false,
		},
		{
			name: "export-pattern-stats without target is valid",
			opts: &CLIOptions{
				ExportPatternStats: "metrics.json",
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
		})
	}
}
