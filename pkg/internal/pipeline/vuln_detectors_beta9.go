// pkg/internal/pipeline/vuln_detectors_beta9.go
//
// beta.9 - detectors born from runtime data/ directory forensics (Unity games).
package pipeline

import (
	"bytes"
	"fmt"
	"math"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

func weakSaveEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	e := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

func weakSavePrintableRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	printable := 0
	for _, b := range data {
		if b == 0x09 || b == 0x0a || b == 0x0d || (b >= 0x20 && b <= 0x7e) {
			printable++
		}
	}
	return float64(printable) / float64(len(data))
}

type VulnIl2cppMetadataDetector struct{}

func NewVulnIl2cppMetadataDetector() *VulnIl2cppMetadataDetector {
	return &VulnIl2cppMetadataDetector{}
}

func (d *VulnIl2cppMetadataDetector) Name() string { return "vuln_il2cpp_metadata" }

func (d *VulnIl2cppMetadataDetector) SupportsFile(_ types.FileType, path string) bool {
	return strings.HasSuffix(strings.ToLower(path), "global-metadata.dat")
}

func (d *VulnIl2cppMetadataDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	c := ctx.Content
	if len(c) < 256 {
		return
	}
	if !(c[0] == 0xAF && c[1] == 0x1B && c[2] == 0xB1 && c[3] == 0xFA) {
		return
	}
	limit := len(c)
	if limit > 1<<20 {
		limit = 1 << 20
	}
	runs, run := 0, 0
	for i := 0; i < limit; i++ {
		b := c[i]
		if b >= 0x20 && b <= 0x7e {
			run++
			if run == 4 {
				runs++
			}
		} else {
			run = 0
		}
	}
	if runs < 50 {
		return
	}
	m := newMatch(
		types.CategoryIl2cppMetadata, analysis.Path, 1,
		fmt.Sprintf("Unencrypted IL2CPP global-metadata.dat (%d bytes, %d cleartext string runs): Unity type/method/field names and string literals are stored in cleartext, enabling trivial reverse engineering, cheating and asset extraction. No IL2CPP metadata encryption applied.", len(c), runs),
		"global-metadata.dat", false,
	)
	m.Severity = types.SeverityMedium
	analysis.Matches = append(analysis.Matches, m)
}

type VulnWeakSaveIntegrityDetector struct{}

func NewVulnWeakSaveIntegrityDetector() *VulnWeakSaveIntegrityDetector {
	return &VulnWeakSaveIntegrityDetector{}
}

func (d *VulnWeakSaveIntegrityDetector) Name() string { return "vuln_weak_save_integrity" }

func (d *VulnWeakSaveIntegrityDetector) SupportsFile(_ types.FileType, path string) bool {
	lp := strings.ToLower(path)
	base := lp
	if i := strings.LastIndex(lp, "/"); i >= 0 {
		base = lp[i+1:]
	}
	if base == "save.dat" {
		return true
	}
	return strings.HasSuffix(base, ".sav") || strings.HasSuffix(base, ".save")
}

func (d *VulnWeakSaveIntegrityDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	c := ctx.Content
	if len(c) < 8 {
		return
	}
	ratio := weakSavePrintableRatio(c)
	ent := weakSaveEntropy(c)
	if ratio > 0.85 && (bytes.IndexByte(c, '{') >= 0 || bytes.IndexByte(c, '=') >= 0 || bytes.IndexByte(c, 0x22) >= 0) {
		m := newMatch(
			types.CategoryWeakSaveIntegrity, analysis.Path, 1,
			fmt.Sprintf("Save file stored in plaintext (%.0f%% printable, entropy %.2f bits/byte): state is directly readable and editable, no integrity protection (CWE-312).", ratio*100, ent),
			"save-file", false,
		)
		m.Severity = types.SeverityHigh
		analysis.Matches = append(analysis.Matches, m)
		return
	}
	if ent < 7.0 {
		m := newMatch(
			types.CategoryWeakSaveIntegrity, analysis.Path, 1,
			fmt.Sprintf("Save file uses weak reversible obfuscation (entropy %.2f bits/byte): not real encryption, can be reversed and tampered (CWE-311).", ent),
			"save-file", false,
		)
		m.Severity = types.SeverityMedium
		analysis.Matches = append(analysis.Matches, m)
	}
}

type VulnDataPlaintextIDDetector struct{}

func NewVulnDataPlaintextIDDetector() *VulnDataPlaintextIDDetector {
	return &VulnDataPlaintextIDDetector{}
}

func (d *VulnDataPlaintextIDDetector) Name() string { return "vuln_data_plaintext_id" }

func (d *VulnDataPlaintextIDDetector) SupportsFile(fileType types.FileType, path string) bool {
	switch fileType {
	case types.FileTypeJSON, types.FileTypeText, types.FileTypeProperties:
		return true
	case types.FileTypeUnknown:
		lp := strings.ToLower(path)
		base := lp
		if i := strings.LastIndex(lp, "/"); i >= 0 {
			base = lp[i+1:]
		}
		return strings.Contains(lp, "analytics") || base == "config" || base == "values"
	}
	return false
}

func dataBoolAfter(c []byte, key string) (bool, bool) {
	i := bytes.Index(c, []byte(key))
	if i < 0 {
		return false, false
	}
	j := i + len(key)
	end := j + 24
	if end > len(c) {
		end = len(c)
	}
	w := c[j:end]
	if bytes.Contains(w, []byte("false")) {
		return false, true
	}
	if bytes.Contains(w, []byte("true")) {
		return true, true
	}
	return false, false
}

func (d *VulnDataPlaintextIDDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	c := ctx.ContentLower
	if len(c) == 0 {
		return
	}
	for _, key := range []string{"\"$userid\"", "\"cloudid\"", "\"deviceid\""} {
		if i := bytes.Index(c, []byte(key)); i >= 0 {
			m := newMatch(
				types.CategoryDataPlaintextId, analysis.Path, lineAt(ctx.LineOffsets, i),
				"Persistent identifier stored in cleartext in app data ("+strings.Trim(key, "\"")+"): device/user-linked ID readable without protection, enables cross-session tracking (CWE-359).",
				strings.Trim(key, "\""), false,
			)
			m.Severity = types.SeverityLow
			analysis.Matches = append(analysis.Matches, m)
			break
		}
	}
	ltVal, ltFound := dataBoolAfter(c, "limit_user_tracking")
	poVal, poFound := dataBoolAfter(c, "player_opted_out")
	if (ltFound && !ltVal) || (poFound && !poVal) {
		m := newMatch(
			types.CategoryDataPlaintextId, analysis.Path, 1,
			"Analytics active with tracking opt-outs disabled by default (limit_user_tracking=false / player_opted_out=false): collection is on unless the user opts out.",
			"analytics-tracking", false,
		)
		m.Severity = types.SeverityLow
		analysis.Matches = append(analysis.Matches, m)
	}
}

// isForensicDataFile reports whether an otherwise-Unknown app data file should
// still be admitted to the pipeline so the beta.9 data/ forensics detectors can
// inspect it (IL2CPP metadata, save files, analytics/identifier stores).
func isForensicDataFile(path string) bool {
	lp := strings.ToLower(path)
	base := lp
	if i := strings.LastIndex(lp, "/"); i >= 0 {
		base = lp[i+1:]
	}
	if strings.HasSuffix(base, ".dat") || strings.HasSuffix(base, ".sav") || strings.HasSuffix(base, ".save") {
		return true
	}
	if base == "config" || base == "values" {
		return true
	}
	return strings.Contains(lp, "analytics")
}
