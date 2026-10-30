package config

import (
	"os"
	"strconv"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Environment Variables Configuration
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// EnvPrefix is the prefix for all analyzer environment variables
	EnvPrefix = "ANALYZER_"

	// Environment variable names
	EnvConfigPath        = EnvPrefix + "CONFIG_PATH"
	EnvCacheDir          = EnvPrefix + "CACHE_DIR"
	EnvOutputDir         = EnvPrefix + "OUTPUT_DIR"
	EnvWorkers           = EnvPrefix + "WORKERS"
	EnvTimeout           = EnvPrefix + "TIMEOUT"
	EnvMaxFiles          = EnvPrefix + "MAX_FILES"
	EnvMaxFileSizeMB     = EnvPrefix + "MAX_FILE_SIZE_MB"
	EnvMaxResourceSizeMB = EnvPrefix + "MAX_RESOURCE_SIZE_MB"
	EnvLogLevel          = EnvPrefix + "LOG_LEVEL"
	EnvLogFile           = EnvPrefix + "LOG_FILE"
	EnvProfile           = EnvPrefix + "PROFILE"
	EnvDebug             = EnvPrefix + "DEBUG"
	EnvQuiet             = EnvPrefix + "QUIET"
	EnvNoColor           = EnvPrefix + "NO_COLOR"

	// Artifacts opt-in section.
	EnvArtifacts         = EnvPrefix + "ARTIFACTS"
	EnvArtifactsBudgetMB = EnvPrefix + "ARTIFACTS_BUDGET_MB"
	EnvArtifactsMaxMB    = EnvPrefix + "ARTIFACTS_MAX_MB"
	EnvAllowExport       = EnvPrefix + "ALLOW_EXPORT"
	EnvNoImageBlur       = EnvPrefix + "NO_IMAGE_BLUR"
)

// EnvConfig holds configuration loaded from environment variables
type EnvConfig struct {
	ConfigPath        string
	CacheDir          string
	OutputDir         string
	Workers           int
	Timeout           int
	MaxFiles          int
	MaxFileSizeMB     int
	MaxResourceSizeMB int
	LogLevel          string
	LogFile           string
	Profile           string
	Debug             bool
	Quiet             bool
	NoColor           bool
}

// LoadEnvConfig loads configuration from environment variables
// Returns nil if no env vars are set (allowing CLI to take precedence)
func LoadEnvConfig() *EnvConfig {
	cfg := &EnvConfig{}

	// Only set fields if env vars exist
	if v := os.Getenv(EnvConfigPath); v != "" {
		cfg.ConfigPath = v
	}
	if v := os.Getenv(EnvCacheDir); v != "" {
		cfg.CacheDir = v
	}
	if v := os.Getenv(EnvOutputDir); v != "" {
		cfg.OutputDir = v
	}
	if v := os.Getenv(EnvWorkers); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Workers = n
		}
	}
	if v := os.Getenv(EnvTimeout); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.Timeout = n
		}
	}
	if v := os.Getenv(EnvMaxFiles); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxFiles = n
		}
	}
	if v := os.Getenv(EnvMaxFileSizeMB); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxFileSizeMB = n
		}
	}
	if v := os.Getenv(EnvMaxResourceSizeMB); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxResourceSizeMB = n
		}
	}
	if v := os.Getenv(EnvLogLevel); v != "" {
		cfg.LogLevel = strings.ToLower(v)
	}
	if v := os.Getenv(EnvLogFile); v != "" {
		cfg.LogFile = v
	}
	if v := os.Getenv(EnvProfile); v != "" {
		cfg.Profile = strings.ToLower(v)
	}
	if v := os.Getenv(EnvDebug); v != "" {
		cfg.Debug = isTruthy(v)
	}
	if v := os.Getenv(EnvQuiet); v != "" {
		cfg.Quiet = isTruthy(v)
	}
	if v := os.Getenv(EnvNoColor); v != "" {
		cfg.NoColor = isTruthy(v)
	}

	// Return nil if nothing was set
	if cfg.IsEmpty() {
		return nil
	}
	return cfg
}

// IsEmpty returns true if no environment variables were set
func (c *EnvConfig) IsEmpty() bool {
	return c.ConfigPath == "" &&
		c.CacheDir == "" &&
		c.OutputDir == "" &&
		c.Workers == 0 &&
		c.Timeout == 0 &&
		c.MaxFiles == 0 &&
		c.MaxFileSizeMB == 0 &&
		c.MaxResourceSizeMB == 0 &&
		c.LogLevel == "" &&
		c.LogFile == "" &&
		c.Profile == "" &&
		!c.Debug &&
		!c.Quiet &&
		!c.NoColor
}

// isTruthy returns true for truthy string values
func isTruthy(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// ApplyToCLIOptions applies env config to CLI options (with lower priority)
func (c *EnvConfig) ApplyToCLIOptions(opts interface{}) {
	// This would be implemented if we had a struct to apply to
	// For now, the CLI parser can read env vars directly
}

// GetEnvHelp returns help text for environment variables
func GetEnvHelp() string {
	return `
Environment Variables (optional, override defaults):
  ` + EnvConfigPath + `=<path>       Path to config file
  ` + EnvCacheDir + `=<dir>          Cache directory
  ` + EnvOutputDir + `=<dir>         Default output directory
  ` + EnvWorkers + `=<N>             Number of workers (default: CPU cores)
  ` + EnvTimeout + `=<seconds>       Analysis timeout (0 = unlimited)
  ` + EnvMaxFiles + `=<N>            Max files to analyze (0 = unlimited)
  ` + EnvMaxFileSizeMB + `=<MB>      Max code file size in MB (0 = unlimited)
  ` + EnvMaxResourceSizeMB + `=<MB>  Max resource file size in MB (0 = unlimited)
  ` + EnvLogLevel + `=<level>        Log level: debug|info|warn|error
  ` + EnvLogFile + `=<path>          Log file path
  ` + EnvProfile + `=<profile>       Default profile: quick|balanced|deep|paranoid
  ` + EnvDebug + `=<bool>            Enable debug mode (1|true|yes|on)
  ` + EnvQuiet + `=<bool>            Enable quiet mode (1|true|yes|on)
  ` + EnvNoColor + `=<bool>          Disable colors (1|true|yes|on)
  ` + EnvArtifacts + `=<bool>        Enable Artifacts panel (off by default)
  ` + EnvArtifactsMaxMB + `=<MB>     Per-file embed cap for Artifacts (default: 10)
  ` + EnvArtifactsBudgetMB + `=<MB>  Total embed cap in MB (default: 200)
  ` + EnvAllowExport + `=<bool>      Show Export buttons in HTML (off by default)
  ` + EnvNoImageBlur + `=<bool>      Disable blur for sensitive image cards

Example:
  export ANALYZER_OUTPUT_DIR=/tmp/analysis
  export ANALYZER_WORKERS=8
  export ANALYZER_PROFILE=deep
  analyzer -t ./app.apk
`
}
