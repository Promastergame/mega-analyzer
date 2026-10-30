package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/ml"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CLI PARSER
// ═══════════════════════════════════════════════════════════════════════════════

type CLIParser struct {
	fs *flag.FlagSet
}

func NewCLIParser() *CLIParser {
	return &CLIParser{
		fs: flag.NewFlagSet("analyzer", flag.ContinueOnError),
	}
}

// applyEnvDefaults applies environment variables as defaults (CLI flags override these)
func (p *CLIParser) applyEnvDefaults(opts *CLIOptions) {
	opts.DecisionAIURL = strings.TrimSpace(os.Getenv("MEGA_DECISION_AI_URL"))
	// Output directory
	if v := os.Getenv(config.EnvOutputDir); v != "" {
		opts.Output = v
	}

	// Workers
	if v := os.Getenv(config.EnvWorkers); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			opts.Workers = n
		}
	}

	// Timeout
	if v := os.Getenv(config.EnvTimeout); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			opts.Timeout = n
		}
	}

	// Max files
	if v := os.Getenv(config.EnvMaxFiles); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			opts.MaxFiles = n
		}
	}

	// Max file size MB
	if v := os.Getenv(config.EnvMaxFileSizeMB); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			opts.MaxFileSizeMB = n
		}
	}

	// Max resource size MB
	if v := os.Getenv(config.EnvMaxResourceSizeMB); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			opts.MaxResourceSizeMB = n
		}
	}

	// Profile
	if v := os.Getenv(config.EnvProfile); v != "" {
		profile := AnalysisProfile(strings.ToLower(v))
		if profile.IsValid() {
			opts.Profile = profile
		}
	}

	// Debug mode
	if v := os.Getenv(config.EnvDebug); v != "" {
		opts.DebugVerbose = isTruthy(v)
	}

	// Quiet mode
	if v := os.Getenv(config.EnvQuiet); v != "" {
		opts.Quiet = isTruthy(v)
	}

	// No color
	if v := os.Getenv(config.EnvNoColor); v != "" {
		opts.NoColor = isTruthy(v)
	}

	// Artifacts opt-in section.
	if v := os.Getenv(config.EnvArtifacts); v != "" {
		opts.EnableArtifacts = isTruthy(v)
	}
	if v := os.Getenv(config.EnvArtifactsBudgetMB); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			opts.ArtifactsBudgetMB = n
		}
	}
	if v := os.Getenv(config.EnvArtifactsMaxMB); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			opts.ArtifactsMaxMB = n
		}
	}
	if v := os.Getenv(config.EnvAllowExport); v != "" {
		opts.AllowExport = isTruthy(v)
	}
	if v := os.Getenv(config.EnvNoImageBlur); v != "" {
		opts.NoImageBlur = isTruthy(v)
	}
}

// isTruthy returns true for truthy string values
func isTruthy(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILESYSTEM HELPERS (MOCKED FOR TESTING)
// ═══════════════════════════════════════════════════════════════════════════════

var (
	fsExists = func(path string) bool {
		// Safeguard: do not load real filesystem profile files during test runs to prevent test failures.
		// Tests can still override fsExists to test loading.
		if flag.Lookup("test.v") != nil {
			return false
		}
		info, err := os.Stat(path)
		return err == nil && !info.IsDir()
	}
	fsReadFile = func(path string) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
)

func parseFlagsFile(content string) ([]string, error) {
	if !utf8.ValidString(content) {
		return nil, fmt.Errorf("flags file must be UTF-8, not UTF-16/ANSI")
	}
	content = strings.TrimPrefix(content, "\uFEFF") // Windows UTF-8 BOM
	var args []string
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts, err := splitArgs(line)
		if err != nil {
			return nil, err
		}
		args = append(args, parts...)
	}
	return args, nil
}

func splitArgs(s string) ([]string, error) {
	var args []string
	var current strings.Builder
	inDoubleQuotes := false
	inSingleQuotes := false

	for i := 0; i < len(s); i++ {
		r := s[i]
		switch r {
		case '"':
			if !inSingleQuotes {
				inDoubleQuotes = !inDoubleQuotes
			} else {
				current.WriteByte(r)
			}
		case '\'':
			if !inDoubleQuotes {
				inSingleQuotes = !inSingleQuotes
			} else {
				current.WriteByte(r)
			}
		case ' ', '\t':
			if inDoubleQuotes || inSingleQuotes {
				current.WriteByte(r)
			} else if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(r)
		}
	}
	if inDoubleQuotes || inSingleQuotes {
		return nil, fmt.Errorf("unclosed quote in flags file")
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args, nil
}

func defaultCLIOptions() *CLIOptions {
	return &CLIOptions{
		SandboxDuration:   0,
		SandboxMemoryMB:   512,
		SandboxTimeScale:  1.0, // default: real-time (no acceleration)
		Workers:           runtime.NumCPU(),
		Profile:           ProfileBalanced,
		Output:            "analysis_output",
		Timeout:           300,
		MLConfidence:      0.5, // default threshold
		MLMaxSuggestions:  10,
		MLPatchMinScore:   ml.MinPatchScore,
		FPMinScore:        -1,
		FPSuppressedLimit: -1,
		GNNModelPath:      "",
		NoTUI:             true,  // Default to CLI mode (no TUI)
		SaveLogFormat:     "txt", // default format for --save_log
	}
}
