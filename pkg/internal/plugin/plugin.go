package plugin

import (
	"context"
	"fmt"
	"regexp"
	"sync"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════
// PLUGIN SYSTEM — interface для кастомных детекторов
// ═══════════════════════════════════════════════════════════════════════════

// PluginContext provides context to plugins during execution
type PluginContext struct {
	TargetDir  string                 // Directory being analyzed
	Config     map[string]string      // Plugin-specific configuration
	SharedData map[string]interface{} // Shared data between plugins
	mu         sync.RWMutex
}

// GetShared retrieves shared data safely
func (pc *PluginContext) GetShared(key string) (interface{}, bool) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	if pc.SharedData == nil {
		return nil, false
	}
	val, ok := pc.SharedData[key]
	return val, ok
}

// SetShared stores shared data safely
func (pc *PluginContext) SetShared(key string, value interface{}) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.SharedData == nil {
		pc.SharedData = make(map[string]interface{})
	}
	pc.SharedData[key] = value
}

// Plugin is the main interface that all custom detectors must implement
type Plugin interface {
	// Name returns the plugin name (used in logs and reports)
	Name() string

	// Version returns the plugin version
	Version() string

	// Description returns a human-readable description
	Description() string

	// Initialize is called once before analysis starts
	Initialize(ctx *PluginContext) error

	// Detect runs the plugin's detection logic and returns findings
	Detect(ctx context.Context, file FileInfo, content []byte) []PluginFinding

	// Finalize is called after all files are processed (cleanup, aggregation)
	Finalize() []PluginFinding
}

// PluginFinding represents a single finding from a plugin
type PluginFinding struct {
	PluginName    string                 `json:"plugin_name"`
	PluginVersion string                 `json:"plugin_version"`
	Type          string                 `json:"type"`
	Severity      types.Severity         `json:"severity"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	File          string                 `json:"file"`
	Line          int                    `json:"line,omitempty"`
	Column        int                    `json:"column,omitempty"`
	Snippet       string                 `json:"snippet,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// FileInfo provides information about a file being analyzed
type FileInfo struct {
	Path  string
	Name  string
	Size  int64
	IsDir bool
	Ext   string
}

// ToMatch converts PluginFinding к types.Match для интеграции
func (f PluginFinding) ToMatch() types.Match {
	match := types.Match{
		Text:       f.Title,
		Pattern:    f.Type,
		Context:    f.Snippet,
		IsCritical: f.Severity == types.SeverityCritical,
		SourceLocation: types.SourceLocation{
			File: f.File,
			Line: f.Line,
		},
		Scored: types.Scored{
			Score: severityToScore(f.Severity),
		},
	}

	// Set category based on tags
	if len(f.Tags) > 0 {
		match.Categorized = types.Categorized{
			Category: types.Category(f.Tags[0]),
		}
	}

	return match
}

func severityToScore(s types.Severity) float64 {
	switch s {
	case types.SeverityCritical:
		return 10.0
	case types.SeverityHigh:
		return 8.0
	case types.SeverityMedium:
		return 5.0
	case types.SeverityLow:
		return 2.0
	default:
		return 1.0
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// PLUGIN REGISTRY — управление плагинами
// ═══════════════════════════════════════════════════════════════════════════

// PluginRegistry manages loaded plugins
type PluginRegistry struct {
	plugins []Plugin
	mu      sync.RWMutex
}

// NewPluginRegistry creates a new registry
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		plugins: make([]Plugin, 0),
	}
}

// Register adds a plugin to the registry
func (pr *PluginRegistry) Register(plugin Plugin) error {
	if plugin == nil {
		return fmt.Errorf("plugin cannot be nil")
	}
	if plugin.Name() == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	// Check for duplicates
	for _, p := range pr.plugins {
		if p.Name() == plugin.Name() {
			return fmt.Errorf("plugin with name '%s' already registered", plugin.Name())
		}
	}

	pr.plugins = append(pr.plugins, plugin)
	return nil
}

// Unregister removes a plugin by name
func (pr *PluginRegistry) Unregister(name string) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for i, p := range pr.plugins {
		if p.Name() == name {
			pr.plugins = append(pr.plugins[:i], pr.plugins[i+1:]...)
			return true
		}
	}
	return false
}

// List returns all registered plugins
func (pr *PluginRegistry) List() []Plugin {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	result := make([]Plugin, len(pr.plugins))
	copy(result, pr.plugins)
	return result
}

// Count returns the number of registered plugins
func (pr *PluginRegistry) Count() int {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return len(pr.plugins)
}

// InitializeAll calls Initialize on all plugins
func (pr *PluginRegistry) InitializeAll(ctx *PluginContext) []error {
	var errs []error

	for _, plugin := range pr.List() {
		if err := plugin.Initialize(ctx); err != nil {
			errs = append(errs, fmt.Errorf("plugin %s init failed: %w", plugin.Name(), err))
		}
	}

	return errs
}

// RunAll runs Detect on all plugins for a given file concurrently
func (pr *PluginRegistry) RunAll(ctx context.Context, file FileInfo, content []byte) []PluginFinding {
	plugins := pr.List()
	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		allFindings []PluginFinding
	)
	for _, plugin := range plugins {
		wg.Add(1)
		go func(p Plugin) {
			defer wg.Done()
			findings := p.Detect(ctx, file, content)
			for i := range findings {
				findings[i].PluginName = p.Name()
				findings[i].PluginVersion = p.Version()
			}
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(plugin)
	}
	wg.Wait()
	return allFindings
}

// FinalizeAll calls Finalize on all plugins
func (pr *PluginRegistry) FinalizeAll() []PluginFinding {
	var allFindings []PluginFinding

	for _, plugin := range pr.List() {
		findings := plugin.Finalize()
		for i := range findings {
			findings[i].PluginName = plugin.Name()
			findings[i].PluginVersion = plugin.Version()
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

// ═══════════════════════════════════════════════════════════════════════════
// BASE PLUGIN — helper для создания плагинов
// ═══════════════════════════════════════════════════════════════════════════

// BasePlugin provides a default implementation for optional methods
type BasePlugin struct {
	PluginName        string
	PluginVersion     string
	PluginDescription string
}

// Name returns the plugin name
func (bp *BasePlugin) Name() string {
	return bp.PluginName
}

// Version returns the plugin version
func (bp *BasePlugin) Version() string {
	return bp.PluginVersion
}

// Description returns the plugin description
func (bp *BasePlugin) Description() string {
	return bp.PluginDescription
}

// Initialize is a no-op by default
func (bp *BasePlugin) Initialize(ctx *PluginContext) error {
	return nil
}

// Finalize is a no-op by default
func (bp *BasePlugin) Finalize() []PluginFinding {
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════
// EXAMPLE PLUGIN
// ═══════════════════════════════════════════════════════════════════════════

// HardcodedSecretDetector — detects hardcoded secrets using regex patterns
type HardcodedSecretDetector struct {
	BasePlugin
	patterns []*regexp.Regexp
}

// NewHardcodedSecretDetector creates the example plugin with regex-based detection
func NewHardcodedSecretDetector() *HardcodedSecretDetector {
	rawPatterns := []string{
		`(?i)(api[_-]?key|api[_-]?secret|access[_-]?token)\s*[=:]\s*["']?[A-Za-z0-9+/]{20,}["']?`,
		`(?i)(password|passwd|pwd)\s*[=:]\s*["'][^"']{6,}["']`,
		`AKIA[0-9A-Z]{16}`,
		`(?i)secret[_-]?key\s*[=:]\s*["']?[A-Za-z0-9+/]{20,}`,
		`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`,
		`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`,
	}
	var compiled []*regexp.Regexp
	for _, p := range rawPatterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}
	return &HardcodedSecretDetector{
		BasePlugin: BasePlugin{
			PluginName:        "hardcoded-secret-detector",
			PluginVersion:     "1.1.0",
			PluginDescription: "Detects hardcoded secrets, API keys and credentials using regex patterns",
		},
		patterns: compiled,
	}
}

// Detect searches for hardcoded secrets using compiled regex patterns
func (p *HardcodedSecretDetector) Detect(ctx context.Context, file FileInfo, content []byte) []PluginFinding {
	var findings []PluginFinding
	contentStr := string(content)
	for _, re := range p.patterns {
		matches := re.FindAllString(contentStr, -1)
		for _, match := range matches {
			truncated := match
			if len(truncated) > 60 {
				truncated = truncated[:60] + "..."
			}
			findings = append(findings, PluginFinding{
				Type:        "hardcoded_secret",
				Severity:    types.SeverityHigh,
				Title:       "Potential hardcoded secret detected",
				Description: fmt.Sprintf("File contains a potential hardcoded credential: %s", truncated),
				File:        file.Path,
				Tags:        []string{"security", "secrets", "credentials"},
			})
		}
	}
	return findings
}
