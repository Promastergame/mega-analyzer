package androidruntime

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/labdns"
)

// SessionReport is the final aggregated report for one emulator analysis session.
type SessionReport struct {
	SessionID     string                  `json:"session_id"`
	Profile       Profile                 `json:"profile"`
	StartedAt     time.Time               `json:"started_at"`
	FinishedAt    time.Time               `json:"finished_at"`
	DurationMs    int64                   `json:"duration_ms"`
	EmulatorPID   int                     `json:"emulator_pid"`
	ConsolePort   int                     `json:"console_port"`
	DNSLog        []labdns.DNSQueryRecord `json:"dns_log"`
	DNSStats      labdns.DNSStats         `json:"dns_stats"`
	SnapshotOps   []SnapshotOp            `json:"snapshot_ops"`
	AntiVMApplied interface{}             `json:"anti_vm"`
	EmulatorLog   string                  `json:"emulator_log_path"`
	Warnings      []string                `json:"warnings,omitempty"`
}

// SessionAggregator collects artifacts during a session and produces
// the final report.
type SessionAggregator struct {
	profile   Profile
	warnings  []string
	startedAt time.Time
}

// NewSessionAggregator creates a new report aggregator.
func NewSessionAggregator(profile Profile) *SessionAggregator {
	return &SessionAggregator{
		profile:   profile,
		warnings:  make([]string, 0),
		startedAt: time.Now().UTC(),
	}
}

// ExportJSON writes the session report as formatted JSON to a file.
func ExportJSON(report *SessionReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write session report: %w", err)
	}
	return nil
}

// ExportMarkdown writes the session report as a readable Markdown file.
func ExportMarkdown(report *SessionReport, path string) error {
	md := RenderMarkdownReport(report)
	if err := os.WriteFile(path, []byte(md), 0o644); err != nil {
		return fmt.Errorf("write session markdown report: %w", err)
	}
	return nil
}

// RenderMarkdownReport generates a Markdown summary of the session.
func RenderMarkdownReport(report *SessionReport) string {
	var b strings.Builder
	duration := time.Duration(report.DurationMs) * time.Millisecond

	b.WriteString("# Android Sandbox Session Report\n\n")
	b.WriteString(fmt.Sprintf("- **Session ID**: `%s`\n", report.SessionID))
	b.WriteString(fmt.Sprintf("- **AVD**: `%s`\n", report.Profile.AVDName))
	b.WriteString(fmt.Sprintf("- **Device**: `%s`\n", report.Profile.Device))
	b.WriteString(fmt.Sprintf("- **Started**: `%s`\n", report.StartedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- **Finished**: `%s`\n", report.FinishedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- **Duration**: `%s`\n", duration))
	b.WriteString(fmt.Sprintf("- **Emulator PID**: `%d`\n", report.EmulatorPID))
	b.WriteString(fmt.Sprintf("- **Console Port**: `%d`\n", report.ConsolePort))

	// Anti-VM Section.
	b.WriteString("\n## Anti-VM Evasion\n\n")
	if report.AntiVMApplied != nil {
		renderAntiVMSection(&b, report.AntiVMApplied)
	} else {
		b.WriteString("Anti-VM evasion was not applied.\n")
	}

	// DNS Section.
	b.WriteString("\n## DNS Activity\n\n")
	b.WriteString(fmt.Sprintf("- **Total Queries**: `%d`\n", report.DNSStats.TotalQueries))
	b.WriteString(fmt.Sprintf("- **Forwarded**: `%d`\n", report.DNSStats.ForwardedCount))
	b.WriteString(fmt.Sprintf("- **Sinkholed**: `%d`\n", report.DNSStats.SinkholeCount))
	b.WriteString(fmt.Sprintf("- **Blocked**: `%d`\n", report.DNSStats.BlockedCount))
	b.WriteString(fmt.Sprintf("- **NXDOMAIN**: `%d`\n", report.DNSStats.NXDomainCount))
	b.WriteString(fmt.Sprintf("- **Errors**: `%d`\n", report.DNSStats.ErrorCount))
	b.WriteString(fmt.Sprintf("- **Unique Names**: `%d`\n", report.DNSStats.UniqueNames))

	if len(report.DNSStats.TopDomains) > 0 {
		b.WriteString("\n### Top Queried Domains\n\n")
		b.WriteString("| Domain | Count |\n|--------|-------|\n")
		for _, d := range report.DNSStats.TopDomains {
			b.WriteString(fmt.Sprintf("| `%s` | %d |\n", d.Name, d.Count))
		}
	}

	if len(report.DNSStats.SinkholedNames) > 0 {
		b.WriteString("\n### Sinkholed Domains\n\n")
		for _, name := range report.DNSStats.SinkholedNames {
			b.WriteString(fmt.Sprintf("- `%s`\n", name))
		}
	}

	if len(report.DNSStats.C2Candidates) > 0 {
		b.WriteString("\n### ⚠️ Potential C2/DGA Domains\n\n")
		for _, name := range report.DNSStats.C2Candidates {
			b.WriteString(fmt.Sprintf("- `%s`\n", name))
		}
	}

	// DNS Full Log (first 50 entries).
	if len(report.DNSLog) > 0 {
		b.WriteString("\n### DNS Query Log (excerpt)\n\n")
		b.WriteString("| Time | Domain | Type | Action | Answer | Rule |\n")
		b.WriteString("|------|--------|------|--------|--------|------|\n")
		limit := len(report.DNSLog)
		if limit > 50 {
			limit = 50
		}
		for i := 0; i < limit; i++ {
			r := report.DNSLog[i]
			answer := r.AnswerIP
			if answer == "" {
				answer = "-"
			}
			rule := r.RuleName
			if rule == "" {
				rule = "-"
			}
			b.WriteString(fmt.Sprintf("| %s | `%s` | %s | %s | %s | %s |\n",
				r.Timestamp.Format("15:04:05.000"),
				r.QueryName, r.QueryType, r.Action, answer, rule))
		}
		if len(report.DNSLog) > 50 {
			b.WriteString(fmt.Sprintf("\n*... and %d more queries in the JSON report.*\n",
				len(report.DNSLog)-50))
		}
	}

	// Snapshot operations.
	if len(report.SnapshotOps) > 0 {
		b.WriteString("\n## Snapshot Operations\n\n")
		for _, op := range report.SnapshotOps {
			status := "✅"
			if op.Error != "" {
				status = "❌ " + op.Error
			}
			b.WriteString(fmt.Sprintf("- `%s` %s (%dms) %s\n",
				op.Action, op.Name, op.Duration, status))
		}
	}

	// Warnings.
	if len(report.Warnings) > 0 {
		b.WriteString("\n## Warnings\n\n")
		sorted := make([]string, len(report.Warnings))
		copy(sorted, report.Warnings)
		sort.Strings(sorted)
		for _, w := range sorted {
			b.WriteString("- " + w + "\n")
		}
	}

	return b.String()
}

// renderAntiVMSection renders the anti-VM evasion data from the generic
// interface{} report. We use JSON round-tripping to extract fields without
// importing the antivm package, keeping the dependency graph clean.
func renderAntiVMSection(b *strings.Builder, data interface{}) {
	// Marshal to JSON then back to a generic map.
	raw, err := json.Marshal(data)
	if err != nil {
		b.WriteString("Anti-VM data unavailable.\n")
		return
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		b.WriteString("Anti-VM data unavailable.\n")
		return
	}

	applied, _ := m["applied"].(bool)
	if !applied {
		b.WriteString("Anti-VM evasion was not applied.\n")
		return
	}

	// Device profile.
	if dp, ok := m["device_profile"].(map[string]interface{}); ok {
		b.WriteString(fmt.Sprintf("- **Device Identity**: `%s` (%s)\n",
			mapStr(dp, "model"), mapStr(dp, "brand")))
	}

	b.WriteString(fmt.Sprintf("- **IMEI**: `%s`\n", mapStr(m, "imei")))
	b.WriteString(fmt.Sprintf("- **Serial**: `%s`\n", mapStr(m, "serial_number")))
	b.WriteString(fmt.Sprintf("- **MAC**: `%s`\n", mapStr(m, "mac_address")))
	b.WriteString(fmt.Sprintf("- **WiFi SSID**: `%s`\n", mapStr(m, "wifi_ssid")))
	b.WriteString(fmt.Sprintf("- **Operator**: `%s` (`%s`)\n",
		mapStr(m, "operator_name"), mapStr(m, "operator_numeric")))

	if bl, ok := m["battery_level"].(float64); ok {
		b.WriteString(fmt.Sprintf("- **Battery**: `%d%%`\n", int(bl)))
	}
	if sn, ok := m["sensor_noise_active"].(bool); ok {
		b.WriteString(fmt.Sprintf("- **Sensor Noise**: `%t`\n", sn))
	}
	if ps, ok := m["properties_set"].([]interface{}); ok {
		b.WriteString(fmt.Sprintf("- **Properties Patched**: `%d`\n", len(ps)))
	}

	if ws, ok := m["warnings"].([]interface{}); ok && len(ws) > 0 {
		b.WriteString("\n### Evasion Warnings\n\n")
		for _, w := range ws {
			if s, ok := w.(string); ok {
				b.WriteString("- " + s + "\n")
			}
		}
	}
}

// mapStr safely extracts a string from a map[string]interface{}.
func mapStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
