package vulnscan

import (
	"time"
)

// ScannerConfig defines safety gates and advanced engine settings
type ScannerConfig struct {
	IOwnThisTarget  bool
	LabMode         bool
	MaxWorkers      int
	MaxRPS          int
	TargetAllowlist []string
	UserAgent       string
	// Timeout configuration
	Timeout time.Duration
	// OAST
	OASTBindAddrDNS  string
	OASTBindAddrHTTP string
	OASTDomain       string
	// FSM Config path
	FSMConfigPath string
	// JWT Wordlist path
	JWTWordlist string

	// --- Elite engine settings (additive; safe zero-value defaults) ---
	// MaxBodyBytes bounds response body reads (memory-safety vs adversarial targets).
	MaxBodyBytes int
	// ConfidenceThreshold filters findings below this confidence from reports (0..1).
	ConfidenceThreshold float64
	// Authenticated-scanning credentials (optional).
	AuthCookie string
	AuthBearer string
	// Secondary identity for differential access checks (IDOR/BOLA) and FSM
	// role "B". Empty means single-identity scanning: cross-role checks fall
	// back to weaker heuristics instead of claiming proof.
	AuthCookie2 string
	AuthBearer2 string
	// EnableAIMD switches concurrency control from the PID controller to AIMD.
	EnableAIMD bool
	// frozen marks the config immutable after Freeze().
	frozen bool
}

func DefaultScannerConfig() ScannerConfig {
	return ScannerConfig{
		MaxWorkers:       4,
		MaxRPS:           50, // default safe RPS
		UserAgent:        "MegaAnalyzer-WebScan/11.1",
		Timeout:          15 * time.Second,
		OASTBindAddrDNS:  "127.0.0.1:8053", // High port by default as requested
		OASTBindAddrHTTP: "127.0.0.1:8081",
		OASTDomain:       "127.0.0.1",
		MaxBodyBytes:     5 * 1024 * 1024,
	}
}
