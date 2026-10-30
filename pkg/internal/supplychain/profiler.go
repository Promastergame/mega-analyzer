package supplychain

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SDKProfile defines known characteristics and risks for standard third-party libraries.
type SDKProfile struct {
	Name             string   `json:"name"`
	Namespace        string   `json:"namespace"`
	Category         string   `json:"category"`
	KnownRisks       []string `json:"known_risks,omitempty"`
	PullsPermissions []string `json:"pulls_permissions,omitempty"`
	Description      string   `json:"description"`
}

// Known SDK signatures database
var KnownSDKs = []SDKProfile{
	{
		Name:             "Google Firebase Analytics",
		Namespace:        "com/google/firebase/analytics",
		Category:         "analytics",
		KnownRisks:       []string{"User tracking", "ADID identifier collection"},
		PullsPermissions: []string{"android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"},
		Description:      "Google telemetry SDK designed to collect usage data.",
	},
	{
		Name:             "Facebook SDK",
		Namespace:        "com/facebook",
		Category:         "social/analytics",
		KnownRisks:       []string{"Deep link tracking", "Device fingerprinting", "Silent graph logins"},
		PullsPermissions: []string{"android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"},
		Description:      "Social sharing and ads tracking library with aggressive background logging.",
	},
	{
		Name:             "Yandex Metrica",
		Namespace:        "com/yandex/metrica",
		Category:         "telemetry/ads",
		KnownRisks:       []string{"Location tracking in background", "Non-resettable device id hash logging"},
		PullsPermissions: []string{"android.permission.INTERNET", "android.permission.ACCESS_COARSE_LOCATION"},
		Description:      "AppMetrica telemetry and crash logging suite.",
	},
	{
		Name:             "Adjust SDK",
		Namespace:        "com/adjust/sdk",
		Category:         "attribution/marketing",
		KnownRisks:       []string{"Device installation fingerprint tracking", "Background referrer sniffing"},
		PullsPermissions: []string{"android.permission.INTERNET", "android.permission.ACCESS_WIFI_STATE"},
		Description:      "Attribution and marketing performance measurement framework.",
	},
}

// SDKFinding is an identified SDK inside the analyzed application.
type SDKFinding struct {
	Profile    SDKProfile `json:"profile"`
	Version    string     `json:"version,omitempty"`
	PathFound  string     `json:"path_found"`
	RiskScore  int        `json:"risk_score"`
	Mitigation string     `json:"mitigation,omitempty"`
}

// Report aggregates supply chain intelligence results.
type Report struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Target      string       `json:"target"`
	Identified  []SDKFinding `json:"identified_sdks"`
	Score       int          `json:"score"`
	Verdict     string       `json:"verdict"`
}

// ProfileWalk scans the app's extracted directory to match package structures against known SDKs.
func ProfileWalk(appDir string) (*Report, error) {
	rep := &Report{
		GeneratedAt: time.Now().UTC(),
		Target:      appDir,
		Identified:  make([]SDKFinding, 0),
	}

	seen := make(map[string]bool)

	// A decoded APK can have smali, smali_classes2, smali_classes3, etc.
	smaliDir := appDir

	err := filepath.WalkDir(smaliDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(smaliDir, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		for _, sdk := range KnownSDKs {
			if seen[sdk.Name] {
				continue
			}

			// Match Smali package suffix or folder path
			if strings.HasSuffix(rel, ".smali") && strings.Contains("/"+rel, "/"+sdk.Namespace+"/") {
				seen[sdk.Name] = true
				riskScore := len(sdk.KnownRisks) * 15

				mitigation := ""
				if riskScore > 20 {
					mitigation = fmt.Sprintf("Restrict background permissions and verify compliance terms for %s.", sdk.Name)
				}

				rep.Identified = append(rep.Identified, SDKFinding{
					Profile:    sdk,
					PathFound:  rel,
					RiskScore:  riskScore,
					Mitigation: mitigation,
				})
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Score aggregated risk
	score := 0
	for _, f := range rep.Identified {
		score += f.RiskScore
	}
	if score > 100 {
		score = 100
	}
	rep.Score = score

	rep.Verdict = "secure"
	if score >= 50 {
		rep.Verdict = "suspicious_sdk_activity"
	} else if score >= 20 {
		rep.Verdict = "warnings"
	}

	return rep, nil
}
