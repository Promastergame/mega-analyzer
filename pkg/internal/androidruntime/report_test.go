package androidruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/labdns"
)

// evasionReportFixture is a stand-in for antivm.EvasionReport in tests,
// matching the same JSON shape without importing the package.
type evasionReportFixture struct {
	Applied           bool                  `json:"applied"`
	DeviceProfile     deviceProfileFixture  `json:"device_profile"`
	IMEI              string                `json:"imei"`
	SerialNumber      string                `json:"serial_number"`
	MACAddress        string                `json:"mac_address"`
	WiFiSSID          string                `json:"wifi_ssid"`
	OperatorName      string                `json:"operator_name"`
	OperatorNumeric   string                `json:"operator_numeric"`
	BatteryLevel      int                   `json:"battery_level"`
	SensorNoiseActive bool                  `json:"sensor_noise_active"`
	PropertiesSet     []propertyPairFixture `json:"properties_set"`
	Warnings          []string              `json:"warnings,omitempty"`
}

type deviceProfileFixture struct {
	Model    string `json:"model"`
	Brand    string `json:"brand"`
	Hardware string `json:"hardware"`
}

type propertyPairFixture struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func TestExportJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	report := &SessionReport{
		SessionID:   "test_session_001",
		Profile:     DefaultProfile(),
		StartedAt:   time.Now().UTC(),
		FinishedAt:  time.Now().UTC().Add(5 * time.Minute),
		DurationMs:  300000,
		EmulatorPID: 12345,
		ConsolePort: 5554,
		DNSLog: []labdns.DNSQueryRecord{
			{
				Timestamp: time.Now().UTC(),
				QueryName: "evil.com",
				QueryType: "A",
				Action:    "sinked",
				AnswerIP:  "127.0.0.1",
				RuleName:  "evil-rule",
				LatencyMs: 1,
			},
			{
				Timestamp: time.Now().UTC(),
				QueryName: "google.com",
				QueryType: "A",
				Action:    "forwarded",
				AnswerIP:  "142.250.80.46",
				Upstream:  "8.8.8.8:53",
				LatencyMs: 15,
			},
		},
		DNSStats: labdns.DNSStats{
			TotalQueries:   2,
			ForwardedCount: 1,
			SinkholeCount:  1,
			UniqueNames:    2,
			TopDomains: []labdns.DomainCount{
				{Name: "evil.com", Count: 1},
				{Name: "google.com", Count: 1},
			},
			SinkholedNames: []string{"evil.com"},
		},
		SnapshotOps: []SnapshotOp{
			{Action: "load", Name: "clean", Timestamp: time.Now().UTC(), Duration: 500},
		},
		AntiVMApplied: evasionReportFixture{
			Applied: true,
			DeviceProfile: deviceProfileFixture{
				Model:    "Pixel 7",
				Brand:    "google",
				Hardware: "tensor",
			},
			IMEI:              "354652061234567",
			SerialNumber:      "ABCD1234EF",
			MACAddress:        "3C:5A:B4:12:34:56",
			WiFiSSID:          "NETGEAR_A5B2_5G",
			OperatorName:      "T-Mobile",
			OperatorNumeric:   "310260",
			BatteryLevel:      67,
			SensorNoiseActive: true,
		},
		Warnings: []string{"test warning"},
	}

	if err := ExportJSON(report, path); err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)

	// Verify key fields are present.
	checks := []string{
		`"session_id": "test_session_001"`,
		`"query_name": "evil.com"`,
		`"action": "sinked"`,
		`"action": "forwarded"`,
		`"model": "Pixel 7"`,
		`"imei": "354652061234567"`,
		`"mac_address": "3C:5A:B4:12:34:56"`,
		`"battery_level": 67`,
		`"test warning"`,
	}
	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("JSON report missing %q", check)
		}
	}
}

func TestExportMarkdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.md")

	report := &SessionReport{
		SessionID:   "test_session_002",
		Profile:     DefaultProfile(),
		StartedAt:   time.Now().UTC(),
		FinishedAt:  time.Now().UTC().Add(2 * time.Minute),
		DurationMs:  120000,
		EmulatorPID: 9999,
		ConsolePort: 5554,
		DNSLog: []labdns.DNSQueryRecord{
			{
				Timestamp: time.Now().UTC(),
				QueryName: "tracker.io",
				QueryType: "A",
				Action:    "sinked",
				AnswerIP:  "127.0.0.1",
				LatencyMs: 0,
			},
		},
		DNSStats: labdns.DNSStats{
			TotalQueries:   1,
			SinkholeCount:  1,
			UniqueNames:    1,
			TopDomains:     []labdns.DomainCount{{Name: "tracker.io", Count: 1}},
			SinkholedNames: []string{"tracker.io"},
			C2Candidates:   []string{"xnrghtklm.xyz"},
		},
		AntiVMApplied: evasionReportFixture{
			Applied: true,
			DeviceProfile: deviceProfileFixture{
				Model: "SM-S928U",
				Brand: "samsung",
			},
			IMEI:         "353916101234560",
			BatteryLevel: 55,
		},
	}

	if err := ExportMarkdown(report, path); err != nil {
		t.Fatalf("ExportMarkdown: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	md := string(data)

	checks := []string{
		"# Android Sandbox Session Report",
		"test_session_002",
		"Anti-VM Evasion",
		"SM-S928U",
		"DNS Activity",
		"tracker.io",
		"Sinkholed Domains",
		"C2/DGA Domains",
		"xnrghtklm.xyz",
	}
	for _, check := range checks {
		if !strings.Contains(md, check) {
			t.Errorf("markdown report missing %q", check)
		}
	}
}

func TestRenderMarkdownReport_Empty(t *testing.T) {
	report := &SessionReport{
		SessionID: "empty",
		Profile:   DefaultProfile(),
		StartedAt: time.Now().UTC(),
	}
	md := RenderMarkdownReport(report)
	if !strings.Contains(md, "# Android Sandbox Session Report") {
		t.Error("missing header")
	}
	if !strings.Contains(md, "empty") {
		t.Error("missing session ID")
	}
}

func TestRenderMarkdownReport_LargeDNSLog(t *testing.T) {
	records := make([]labdns.DNSQueryRecord, 100)
	for i := 0; i < 100; i++ {
		records[i] = labdns.DNSQueryRecord{
			Timestamp: time.Now().UTC(),
			QueryName: "test.com",
			QueryType: "A",
			Action:    "forwarded",
		}
	}

	report := &SessionReport{
		SessionID: "large",
		Profile:   DefaultProfile(),
		StartedAt: time.Now().UTC(),
		DNSLog:    records,
		DNSStats:  labdns.DNSStats{TotalQueries: 100},
	}

	md := RenderMarkdownReport(report)
	if !strings.Contains(md, "and 50 more queries") {
		t.Error("should truncate DNS log to 50 entries")
	}
}

func TestSessionAggregatorCreation(t *testing.T) {
	p := DefaultProfile()
	agg := NewSessionAggregator(p)
	if agg == nil {
		t.Fatal("nil aggregator")
	}
	if agg.profile.AVDName != p.AVDName {
		t.Errorf("profile mismatch: %q vs %q", agg.profile.AVDName, p.AVDName)
	}
}
