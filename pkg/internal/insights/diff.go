package insights

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func AnalyzeDiff(oldPath, newPath string) (*DiffReport, error) {
	oldDigest, err := digestTarget(oldPath)
	if err != nil {
		return nil, err
	}
	newDigest, err := digestTarget(newPath)
	if err != nil {
		return nil, err
	}
	report := &DiffReport{GeneratedAt: time.Now(), OldPath: oldPath, NewPath: newPath, Old: oldDigest, New: newDigest}
	report.Added = DiffChanges{
		Permissions:  setDiff(newDigest.Permissions, oldDigest.Permissions),
		Endpoints:    setDiff(newDigest.Endpoints, oldDigest.Endpoints),
		Trackers:     setDiff(newDigest.Trackers, oldDigest.Trackers),
		Secrets:      setDiff(newDigest.Secrets, oldDigest.Secrets),
		NativeLibs:   mapAddedKeys(newDigest.NativeLibs, oldDigest.NativeLibs),
		Certificates: mapAddedKeys(newDigest.Certificates, oldDigest.Certificates),
	}
	report.Removed = DiffChanges{
		Permissions:  setDiff(oldDigest.Permissions, newDigest.Permissions),
		Endpoints:    setDiff(oldDigest.Endpoints, newDigest.Endpoints),
		Trackers:     setDiff(oldDigest.Trackers, newDigest.Trackers),
		Secrets:      setDiff(oldDigest.Secrets, newDigest.Secrets),
		NativeLibs:   mapAddedKeys(oldDigest.NativeLibs, newDigest.NativeLibs),
		Certificates: mapAddedKeys(oldDigest.Certificates, newDigest.Certificates),
	}
	report.Changed = DiffChanges{
		NativeLibs:   mapChangedKeys(oldDigest.NativeLibs, newDigest.NativeLibs),
		Certificates: mapChangedKeys(oldDigest.Certificates, newDigest.Certificates),
	}
	report.RiskOld = digestRisk(oldDigest)
	report.RiskNew = digestRisk(newDigest)
	report.RiskDelta = report.RiskNew - report.RiskOld
	report.Findings = buildDiffFindings(report)
	return report, nil
}

func digestTarget(path string) (TargetDigest, error) {
	files, err := LoadFiles(path, LoadOptions{MaxBytesPerFile: 16 << 20, IncludeBinary: true, RequireComplete: true})
	if err != nil {
		return TargetDigest{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return TargetDigest{}, err
	}
	d := TargetDigest{Path: path, Kind: "file", NativeLibs: map[string]string{}, Certificates: map[string]string{}}
	if info.IsDir() {
		d.Kind = "directory"
	}
	var perms, endpoints, trackers, secrets []string
	for _, f := range files {
		d.FileCount++
		d.TotalSize += f.Size
		lowerPath := strings.ToLower(f.Path)
		perms = append(perms, extractPermissions(f.Data)...)
		endpoints = append(endpoints, extractURLs(f.Data)...)
		trackers = append(trackers, detectTrackerNames(f.Data)...)
		secrets = append(secrets, detectSecretKinds(f.Data)...)
		if strings.HasSuffix(lowerPath, ".so") || strings.HasSuffix(lowerPath, ".dll") || strings.HasSuffix(lowerPath, ".dylib") {
			d.NativeLibs[f.Path] = sha256Hex(f.Data)
		}
		if strings.HasPrefix(lowerPath, "meta-inf/") && (strings.HasSuffix(lowerPath, ".rsa") || strings.HasSuffix(lowerPath, ".dsa") || strings.HasSuffix(lowerPath, ".ec") || strings.HasSuffix(lowerPath, ".sf")) {
			d.Certificates[f.Path] = sha256Hex(f.Data)
		}
	}
	d.Permissions = dedupStrings(perms)
	d.Endpoints = dedupStrings(endpoints)
	d.Trackers = dedupStrings(trackers)
	d.Secrets = dedupStrings(secrets)
	if !info.IsDir() {
		f, err := os.Open(path)
		if err != nil {
			return TargetDigest{}, err
		}
		defer f.Close()
		hash := sha256.New()
		if _, err := io.Copy(hash, f); err != nil {
			return TargetDigest{}, fmt.Errorf("hash diff input: %w", err)
		}
		d.SHA256 = hex.EncodeToString(hash.Sum(nil))
	}
	return d, nil
}

func detectTrackerNames(data []byte) []string {
	lower := strings.ToLower(string(data))
	var out []string
	for _, p := range trackerPatterns {
		for _, n := range p.Needles {
			if strings.Contains(lower, strings.ToLower(n)) {
				out = append(out, p.Name)
				break
			}
		}
	}
	return out
}

func detectSecretKinds(data []byte) []string {
	lower := strings.ToLower(string(data))
	var out []string
	patterns := []struct{ token, kind string }{
		{"api_key", "api_key"}, {"apikey", "api_key"}, {"client_secret", "oauth_secret"},
		{"private_key", "private_key_marker"}, {"firebase_database_url", "firebase_config"},
		{"aws_access_key_id", "aws_key_marker"}, {"secret_key", "secret_key_marker"},
	}
	for _, p := range patterns {
		if strings.Contains(lower, p.token) {
			out = append(out, p.kind)
		}
	}
	return out
}

func mapAddedKeys(a, b map[string]string) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func mapChangedKeys(oldMap, newMap map[string]string) []string {
	var out []string
	for k, oldHash := range oldMap {
		if newHash, ok := newMap[k]; ok && newHash != oldHash {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func digestRisk(d TargetDigest) int {
	score := 0
	for _, p := range d.Permissions {
		if isSensitivePermission(p) {
			score += 6
		}
	}
	score += len(d.Trackers) * 4
	score += len(d.Secrets) * 8
	score += len(d.NativeLibs) * 2
	if len(d.Endpoints) > 5 {
		score += 10
	} else {
		score += len(d.Endpoints) * 2
	}
	if score > 100 {
		return 100
	}
	return score
}

func buildDiffFindings(r *DiffReport) []Finding {
	var out []Finding
	if r.RiskDelta >= 15 {
		out = append(out, Finding{Severity: "high", Category: "version_diff", Title: "Risk increased between versions", Detail: intString(r.RiskOld) + " -> " + intString(r.RiskNew)})
	} else if r.RiskDelta <= -15 {
		out = append(out, Finding{Severity: "low", Category: "version_diff", Title: "Risk decreased between versions", Detail: intString(r.RiskOld) + " -> " + intString(r.RiskNew)})
	}
	if len(r.Added.Permissions) > 0 {
		out = append(out, Finding{Severity: "medium", Category: "version_diff", Title: "New permissions", Detail: strings.Join(limitStrings(r.Added.Permissions, 8), ", ")})
	}
	if len(r.Added.NativeLibs) > 0 {
		out = append(out, Finding{Severity: "medium", Category: "version_diff", Title: "New native libraries", Detail: strings.Join(limitStrings(r.Added.NativeLibs, 8), ", ")})
	}
	if len(r.Changed.Certificates) > 0 {
		out = append(out, Finding{Severity: "high", Category: "version_diff", Title: "Signing metadata changed", Detail: strings.Join(r.Changed.Certificates, ", ")})
	}
	return out
}

func defaultDiffOutputName(oldPath, newPath string) string {
	oldName := strings.TrimSuffix(filepath.Base(oldPath), filepath.Ext(oldPath))
	newName := strings.TrimSuffix(filepath.Base(newPath), filepath.Ext(newPath))
	if oldName == "" || newName == "" {
		return "VERSION_DIFF"
	}
	return oldName + "_vs_" + newName
}
