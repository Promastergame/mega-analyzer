package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/sbom"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/internal/verdict"
	"mega-analyzer/pkg/knownset"
	"mega-analyzer/pkg/logger"
)

// ─────────────────────────────────────────────────────────────────────────────
// KNOWN-SET — префильтр «известно хорошее / известно плохое» (см. pkg/knownset).
//
// Безопасная схема, зафиксированная здесь намеренно:
//
//   - Попадание в «плохое» (точный список, без ложных срабатываний по
//     построению) даёт ГРОМКУЮ находку: Kind=malware, Severity=critical.
//     Через verdict.Assess она участвует в CI-гейте -exit-codes.
//   - Попадание в «хорошее» (bloom, возможен ложный «да») даёт только
//     ИНФОРМАЦИОННУЮ заметку: Kind=inventory, Severity=info. На гейт не влияет.
//   - Анализ НИКОГДА не пропускается и находки никогда не скрываются:
//     функции только ДОБАВЛЯЮТ находки к готовому результату.
//   - Bad всегда старше Good: при конфликте ключей побеждает Bad
//     (гарантия pkg/knownset.Builder.Build, дублируется Lookup).
// ─────────────────────────────────────────────────────────────────────────────

// openKnownSet открывает набор по пути из -known-set. При сбое пишет warning,
// помечает интеллект деградировавшим (verdict 4 при -exit-codes: «чисто» по
// скану без заявленного intel ничего не доказывает) и возвращает nil.
func openKnownSet(path string) *knownset.Bundle {
	b, err := knownset.Open(path)
	if err != nil {
		logger.Warn("Known-set unavailable", "path", path, "error", err)
		verdict.MarkDegraded("knownset", "bundle unreadable: "+err.Error())
		return nil
	}
	return b
}

// warn пишет предупреждение, если вывод инициализирован (в тестах App
// собирается без Output — там предупреждение не нужно).
func (a *App) warn(format string, args ...interface{}) {
	if a != nil && a.output != nil {
		a.output.Warning(format, args...)
	}
}

// sha256OfFile считает sha256 файла потоково (без загрузки целиком в память).
func sha256OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// appendKnownFinding добавляет типизированную находку и поддерживает счётчик
// FindingsByKind (контракт buildTypedFindings из pkg/internal/pipeline).
func appendKnownFinding(result *types.AnalysisResult, f finding.Finding) {
	result.Findings = append(result.Findings, f)
	if result.FindingsByKind == nil {
		result.FindingsByKind = make(map[finding.Kind]int)
	}
	result.FindingsByKind[f.Kind]++
}

// applyKnownSetFileHash ищет sha256 входного файла в наборе. Вызывается после
// пайплайна: filePath — оригинальный APK/файл (не распакованная копия).
// Каталоги пропускаются (хеш каталога не определён), анализ продолжается.
func (a *App) applyKnownSetFileHash(result *types.AnalysisResult, filePath string) {
	if a == nil || a.opts == nil || a.opts.KnownSet == "" || result == nil {
		return
	}
	st, err := os.Stat(filePath)
	if err != nil || st.IsDir() {
		return
	}
	b := openKnownSet(a.opts.KnownSet)
	if b == nil {
		return
	}
	sum, err := sha256OfFile(filePath)
	if err != nil {
		logger.Warn("Known-set: cannot hash target", "path", filePath, "error", err)
		return
	}
	switch b.LookupSHA256(sum) {
	case knownset.KnownBad:
		appendKnownFinding(result, finding.Finding{
			SchemaVersion: 1,
			ID:            "known-bad-sha256",
			Fingerprint:   "knownset:bad:sha256:" + sum,
			RuleID:        "known-bad-sha256",
			Kind:          finding.KindMalware,
			Category:      "known_bad",
			Title:         "Known-bad artifact (knownset exact match)",
			Description:   fmt.Sprintf("sha256 %s exactly matches the known-bad list (%s). The match is exact; false positives are impossible by construction.", sum, a.opts.KnownSet),
			Severity:      "critical",
			Confidence:    1.0,
			Provenance: []finding.Provenance{{
				Engine:         "knownset",
				Detector:       "knownset",
				RuleID:         "known-bad-sha256",
				SourceArtifact: filePath,
				ArtifactSHA256: sum,
			}},
			Occurrences: 1,
		})
		a.warn("Known-set: target is KNOWN-BAD (exact sha256 match)")
	case knownset.KnownGood:
		appendKnownFinding(result, finding.Finding{
			SchemaVersion: 1,
			ID:            "known-good-sha256",
			Fingerprint:   "knownset:good:sha256:" + sum,
			RuleID:        "known-good-sha256",
			Kind:          finding.KindInventory,
			Category:      "known_good",
			Title:         "Probably known-good artifact (knownset bloom hint)",
			Description:   fmt.Sprintf("sha256 %s is probably in the known-good set (%s). This is a bloom-filter hint (a false yes is possible), not a verdict: the analysis ran in full.", sum, a.opts.KnownSet),
			Severity:      "info",
			Confidence:    0.9,
			Provenance: []finding.Provenance{{
				Engine:         "knownset",
				Detector:       "knownset",
				RuleID:         "known-good-sha256",
				SourceArtifact: filePath,
				ArtifactSHA256: sum,
			}},
			Occurrences: 1,
		})
	}
}

// applyKnownSetSBOM ищет PURL каждой SBOM-зависимости в наборе. Вызывается из
// medium-модуля после извлечения SBOM. Плохое даёт критическую находку
// (участвует в -exit-codes гейте), хорошее — info-заметку.
func (a *App) applyKnownSetSBOM(result *types.AnalysisResult, deps []sbom.Dependency) {
	if a == nil || a.opts == nil || a.opts.KnownSet == "" || result == nil || len(deps) == 0 {
		return
	}
	b := openKnownSet(a.opts.KnownSet)
	if b == nil {
		return
	}
	for _, d := range deps {
		if d.PURL == "" {
			continue
		}
		switch b.LookupPURL(d.PURL) {
		case knownset.KnownBad:
			appendKnownFinding(result, finding.Finding{
				SchemaVersion: 1,
				ID:            "known-bad-purl",
				Fingerprint:   "knownset:bad:purl:" + d.PURL,
				RuleID:        "known-bad-purl",
				Kind:          finding.KindMalware,
				Category:      "known_bad",
				Title:         fmt.Sprintf("Known-bad dependency (knownset): %s", d.Raw),
				Description:   fmt.Sprintf("PURL %s exactly matches the known-bad list (%s).", d.PURL, a.opts.KnownSet),
				Severity:      "critical",
				Confidence:    1.0,
				Provenance: []finding.Provenance{{
					Engine:   "knownset",
					Detector: "knownset",
					RuleID:   "known-bad-purl",
				}},
				Occurrences: 1,
			})
			a.warn("Known-set: dependency is KNOWN-BAD: %s", d.Raw)
		case knownset.KnownGood:
			appendKnownFinding(result, finding.Finding{
				SchemaVersion: 1,
				ID:            "known-good-purl",
				Fingerprint:   "knownset:good:purl:" + d.PURL,
				RuleID:        "known-good-purl",
				Kind:          finding.KindInventory,
				Category:      "known_good",
				Title:         fmt.Sprintf("Probably known-good dependency (knownset): %s", d.Raw),
				Description:   fmt.Sprintf("PURL %s is probably in the known-good set (%s). Bloom-filter hint; the analysis ran in full.", d.PURL, a.opts.KnownSet),
				Severity:      "info",
				Confidence:    0.9,
				Provenance: []finding.Provenance{{
					Engine:   "knownset",
					Detector: "knownset",
					RuleID:   "known-good-purl",
				}},
				Occurrences: 1,
			})
		}
	}
}
