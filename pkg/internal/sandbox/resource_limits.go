package sandbox

import "fmt"

// Resource limits for sandbox components to prevent memory exhaustion.
//
// Validates: Requirements 10.1, 10.3
const (
	// MaxKernelEvents limits kernel event collection to 100K events (~50 MB)
	MaxKernelEvents = 100000

	// MaxAPICalls limits API call collection to 50K calls (~50 MB)
	MaxAPICalls = 50000

	// MaxNetworkConnections limits network connection tracking
	MaxNetworkConnections = 10000

	// MaxDNSQueries limits DNS query tracking
	MaxDNSQueries = 5000

	// MaxTLSRecords limits TLS metadata tracking
	MaxTLSRecords = 1000

	// MaxPCAPSize limits PCAP file size to 100 MB
	MaxPCAPSize = 100 * 1024 * 1024

	// MaxCPUCores limits CPU usage to 2 logical cores
	MaxCPUCores = 2

	// TotalMemoryBudget is the total memory budget per session (~500 MB)
	TotalMemoryBudget = 500 * 1024 * 1024
)

// ResourceUsage tracks resource consumption during sandbox execution.
type ResourceUsage struct {
	KernelEventCount       int
	APICallCount           int
	NetworkConnectionCount int
	DNSQueryCount          int
	TLSRecordCount         int
	PCAPSize               int64
	MemoryUsageMB          int
}

// ResourcePressure summarizes how close a sandbox run came to hard collection limits.
type ResourcePressure struct {
	Score                 int      `json:"score"`
	Level                 string   `json:"level"`
	KernelEventPercent    int      `json:"kernel_event_percent"`
	APICallPercent        int      `json:"api_call_percent"`
	NetworkPercent        int      `json:"network_percent"`
	DNSPercent            int      `json:"dns_percent"`
	TLSPercent            int      `json:"tls_percent"`
	PCAPPercent           int      `json:"pcap_percent"`
	MemoryPercent         int      `json:"memory_percent"`
	ExhaustedResources    []string `json:"exhausted_resources,omitempty"`
	HighPressureResources []string `json:"high_pressure_resources,omitempty"`
	RecommendedAction     string   `json:"recommended_action,omitempty"`
}

// CheckResourceLimits checks if resource limits have been exceeded.
func CheckResourceLimits(usage ResourceUsage) []string {
	pressure := AnalyzeResourcePressure(usage)
	warnings := make([]string, 0, len(pressure.ExhaustedResources)+len(pressure.HighPressureResources))

	if usage.KernelEventCount >= MaxKernelEvents {
		warnings = append(warnings, "Kernel event limit reached (100K events)")
	}
	if usage.APICallCount >= MaxAPICalls {
		warnings = append(warnings, "API call limit reached (50K calls)")
	}
	if usage.NetworkConnectionCount >= MaxNetworkConnections {
		warnings = append(warnings, "Network connection limit reached (10K connections)")
	}
	if usage.DNSQueryCount >= MaxDNSQueries {
		warnings = append(warnings, "DNS query limit reached (5K queries)")
	}
	if usage.TLSRecordCount >= MaxTLSRecords {
		warnings = append(warnings, "TLS record limit reached (1K records)")
	}
	if usage.PCAPSize >= MaxPCAPSize {
		warnings = append(warnings, "PCAP size limit reached (100 MB)")
	}
	if memoryLimitMB := TotalMemoryBudget / (1024 * 1024); usage.MemoryUsageMB >= memoryLimitMB {
		warnings = append(warnings, fmt.Sprintf("Sandbox memory budget reached (%d MB)", memoryLimitMB))
	}

	for _, resource := range pressure.HighPressureResources {
		warnings = append(warnings, fmt.Sprintf("Sandbox resource pressure high: %s is above 80%% of its cap", resource))
	}
	return warnings
}

// AnalyzeResourcePressure returns a stable, JSON-friendly pressure summary for dashboards.
func AnalyzeResourcePressure(usage ResourceUsage) *ResourcePressure {
	p := &ResourcePressure{
		KernelEventPercent: percent(usage.KernelEventCount, MaxKernelEvents),
		APICallPercent:     percent(usage.APICallCount, MaxAPICalls),
		NetworkPercent:     percent(usage.NetworkConnectionCount, MaxNetworkConnections),
		DNSPercent:         percent(usage.DNSQueryCount, MaxDNSQueries),
		TLSPercent:         percent(usage.TLSRecordCount, MaxTLSRecords),
		PCAPPercent:        percent64(usage.PCAPSize, MaxPCAPSize),
		MemoryPercent:      percent(usage.MemoryUsageMB, TotalMemoryBudget/(1024*1024)),
	}

	metrics := []struct {
		name  string
		value int
	}{
		{"kernel_events", p.KernelEventPercent},
		{"api_calls", p.APICallPercent},
		{"network_connections", p.NetworkPercent},
		{"dns_queries", p.DNSPercent},
		{"tls_records", p.TLSPercent},
		{"pcap_size", p.PCAPPercent},
		{"memory", p.MemoryPercent},
	}
	for _, metric := range metrics {
		if metric.value > p.Score {
			p.Score = metric.value
		}
		if metric.value >= 100 {
			p.ExhaustedResources = append(p.ExhaustedResources, metric.name)
		} else if metric.value >= 80 {
			p.HighPressureResources = append(p.HighPressureResources, metric.name)
		}
	}

	switch {
	case p.Score >= 100:
		p.Level = "exhausted"
		p.RecommendedAction = "raise sandbox limits or reduce capture volume before rerunning"
	case p.Score >= 80:
		p.Level = "high"
		p.RecommendedAction = "consider raising sandbox limits for longer or noisier samples"
	case p.Score >= 50:
		p.Level = "medium"
	case p.Score > 0:
		p.Level = "low"
	default:
		p.Level = "idle"
	}
	return p
}

func percent(value, limit int) int {
	if value <= 0 || limit <= 0 {
		return 0
	}
	pct := value * 100 / limit
	if pct > 100 {
		return 100
	}
	return pct
}

func percent64(value, limit int64) int {
	if value <= 0 || limit <= 0 {
		return 0
	}
	pct := value * 100 / limit
	if pct > 100 {
		return 100
	}
	return int(pct)
}
