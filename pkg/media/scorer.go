package media

import (
	"fmt"
	"math"
	"strings"
)

type Scorer struct{}

func NewScorer() *Scorer {
	return &Scorer{}
}

// compressedMediaFormats lists formats whose payload is compressed by
// design, so uniformly high entropy (~7.8+) is expected there and is NOT a
// steganography indicator on its own.
var compressedMediaFormats = map[MediaType]bool{
	TypePNG: true, TypeJPEG: true, TypeGIF: true, TypeWEBP: true,
	TypeMP4: true, TypeMP3: true, TypeOGG: true, TypeICO: true,
	TypeHEIC: true, TypeAVIF: true, TypeJXL: true,
}

// AnnotateRegions post-processes fused regions once the file has been
// classified. It has two jobs:
//
//  1. Kill the classic false positive: a file's OWN magic signature at
//     offset 0 plus the high entropy of its normal compressed payload is
//     what every legitimate PNG/JPEG looks like. Such regions get
//     FusedSeverity 0 and are marked Benign, so a clean image no longer
//     produces a bogus "Score 69/100".
//  2. Attach a human-readable Reason to every region explaining WHY it is
//     considered suspicious (or why it is not), so reports can show the
//     rationale instead of a bare severity number.
func (s *Scorer) AnnotateRegions(regions []Region, class Classification) []Region {
	for i := range regions {
		r := &regions[i]
		if reason, benign := s.explainBenign(*r, class); benign {
			r.Benign = true
			r.Reason = reason
			r.FusedSeverity = 0
			continue
		}
		r.Reason = s.explainSuspicious(*r, class)
	}
	return regions
}

// explainBenign reports whether the region carries no real risk for the
// classified format, and why. A region is benign when every signal in it is
// either the file's own format signature at offset 0 or high entropy that
// is normal for a compressed format. Any foreign magic, payload signature,
// privacy leak or ZIP/APK structure keeps the region suspicious.
func (s *Scorer) explainBenign(r Region, class Classification) (string, bool) {
	if len(r.Signals) == 0 {
		return "", false
	}
	ownMagic := false
	entropy := false
	for _, sig := range r.Signals {
		switch sig.Type {
		case SignalMagic:
			if MediaType(sig.Value) != class.PrimaryFormat || sig.Offset != 0 {
				return "", false
			}
			ownMagic = true
		case SignalHighEntropy:
			if !compressedMediaFormats[class.PrimaryFormat] {
				return "", false
			}
			entropy = true
		default:
			return "", false
		}
	}
	name := strings.ToUpper(string(class.PrimaryFormat))
	switch {
	case ownMagic && entropy:
		return fmt.Sprintf("Not suspicious: this is the file's own %s signature at offset 0x0 plus normal compression entropy (%.2f) - exactly what every valid %s looks like.", name, r.MaxEntropy, name), true
	case ownMagic:
		return fmt.Sprintf("Not suspicious: the file's own %s signature at offset 0x0.", name), true
	default:
		return fmt.Sprintf("Not suspicious: high entropy (%.2f) is expected inside compressed %s data.", r.MaxEntropy, name), true
	}
}

// explainSuspicious builds a short human-readable rationale from the
// signals present in a suspicious region.
func (s *Scorer) explainSuspicious(r Region, class Classification) string {
	name := strings.ToUpper(string(class.PrimaryFormat))
	var parts []string
	seen := make(map[string]bool)
	add := func(msg string) {
		if !seen[msg] {
			seen[msg] = true
			parts = append(parts, msg)
		}
	}
	for _, sig := range r.Signals {
		switch sig.Type {
		case SignalMagic:
			if MediaType(sig.Value) != class.PrimaryFormat {
				add(fmt.Sprintf("embedded %s signature at 0x%x inside a %s file (possible hidden payload / polyglot)", strings.ToUpper(sig.Value), sig.Offset, name))
			} else if sig.Offset != 0 {
				add(fmt.Sprintf("duplicate %s signature at 0x%x (a second file may be appended)", strings.ToUpper(sig.Value), sig.Offset))
			}
		case SignalZIPEOCD:
			add(fmt.Sprintf("ZIP archive structure at 0x%x (data can be hidden in an appended archive)", sig.Offset))
		case SignalAPKStruct:
			add(fmt.Sprintf("APK package structure at 0x%x (embedded installable app)", sig.Offset))
		case SignalPayload:
			add(fmt.Sprintf("payload pattern %q at 0x%x", sig.Value, sig.Offset))
		case SignalPrivacyLeak:
			add(fmt.Sprintf("privacy-sensitive data (%s) at 0x%x", sig.Value, sig.Offset))
		case SignalHighEntropy:
			if !compressedMediaFormats[class.PrimaryFormat] {
				add(fmt.Sprintf("unusually high entropy %.2f for this format (possible encrypted or hidden data)", sig.Metadata.EntropyScore))
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "Suspicious because: " + strings.Join(parts, "; ")
}

// Score computes a risk score from 0 (clean) to 100 (maximum risk).
// The scoring is format-aware: certain format+anomaly combinations carry
// higher risk than others (e.g. PDF with shellcode is extremely dangerous).
func (s *Scorer) Score(class Classification, regions []Region, globalStats GlobalStats) float64 {
	score, _ := s.ScoreWithBreakdown(class, regions, globalStats)
	return score
}

// ScoreWithBreakdown computes the risk score together with a per-category
// breakdown. Both are derived from exactly the same risk components and the
// same combination model, so the returned values are always mutually
// consistent: RiskBreakdown.TotalScore equals the returned score, and each
// category field reports that category's own risk on the same 0-100 scale.
func (s *Scorer) ScoreWithBreakdown(class Classification, regions []Region, globalStats GlobalStats) (float64, RiskBreakdown) {
	var polyglotRisks, regionRisks, entropyRisks []float64

	// Polyglot risk: file claims to be one format but contains another
	if class.IsPolyglot {
		polyglotRisks = append(polyglotRisks, 0.2)
		for _, hidden := range class.HiddenFormats {
			polyglotRisks = append(polyglotRisks, s.polyglotRisk(class.PrimaryFormat, hidden))
		}
	}

	// Per-region risk: format-aware spatial weighting
	for _, r := range regions {
		if r.FusedSeverity > 0 {
			spatialWeight := s.spatialWeight(r, class.PrimaryFormat)
			actualRisk := r.FusedSeverity * r.FusedConfidence * spatialWeight
			regionRisks = append(regionRisks, Clamp(actualRisk))
		}
	}

	// Global entropy anomaly: uniform very-high-entropy unknown format
	if globalStats.MeanEntropy > 7.9 && globalStats.Variance < 0.1 && class.PrimaryFormat == TypeUnknown {
		entropyRisks = append(entropyRisks, 0.5)
	}

	// Metadata consistency check: creation date after modification = suspicious
	if class.MediaExtra != nil && class.MediaExtra.Fields != nil {
		if _, hasCreation := class.MediaExtra.Fields["Date_Taken"]; hasCreation {
			// Could add timeline-based risk here if timeline is available
		}
	}

	// Combine each category on its own, then combine everything for the final
	// score, all using the same probabilistic complement model.
	allRisks := make([]float64, 0, len(polyglotRisks)+len(regionRisks)+len(entropyRisks))
	allRisks = append(allRisks, polyglotRisks...)
	allRisks = append(allRisks, regionRisks...)
	allRisks = append(allRisks, entropyRisks...)

	finalScore := combineRisks(allRisks)
	rb := RiskBreakdown{
		PolyglotRisk: combineRisks(polyglotRisks),
		RegionRisk:   combineRisks(regionRisks),
		EntropyRisk:  combineRisks(entropyRisks),
		TotalScore:   finalScore,
	}
	return finalScore, rb
}

// combineRisks folds independent risk probabilities into a single 0-100
// score using the probabilistic complement model (1 - product(1-r)).
func combineRisks(risks []float64) float64 {
	safeProb := 1.0
	for _, r := range risks {
		if r >= 1.0 {
			r = 0.99
		}
		safeProb *= (1.0 - r)
	}
	finalScore := Clamp(1.0 - safeProb)
	score100 := finalScore * 100.0
	return math.Round(score100*100) / 100
}

// combinePercentages folds two independent 0-100 risk scores into one using
// the same probabilistic-complement model. Adding a new risk source (e.g.
// IOC risk) through this helper can never *lower* the overall score.
func combinePercentages(a, b float64) float64 {
	return combineRisks([]float64{a / 100.0, b / 100.0})
}

// polyglotRisk returns the risk multiplier for a hidden format inside a
// given primary format. Certain combinations are more dangerous than others.
func (s *Scorer) polyglotRisk(primary, hidden MediaType) float64 {
	// APK/DEX inside any format: high risk (executable payload)
	if hidden == TypeAPK || hidden == TypeDEX {
		return 0.6
	}

	// Shellcode/executable inside documents: extreme risk
	if primary == TypePDF && (hidden == TypeZIP || hidden == TypeDEX) {
		return 0.8
	}

	// ZIP inside images: moderate-high risk (common polyglot attack)
	if (primary == TypeJPEG || primary == TypePNG) && hidden == TypeZIP {
		return 0.5
	}

	// Default polyglot risk
	return 0.4
}

// spatialWeight returns a risk multiplier based on where in the file a
// signal appears. Data in suspicious locations gets higher weight.
func (s *Scorer) spatialWeight(r Region, format MediaType) float64 {
	weight := 1.0

	switch format {
	case TypeJPEG:
		// Trailing data after EOI is the classic polyglot/stego vector
		if r.StartOffset > 0 {
			// Approximate: regions far into the file are more suspicious
			// (real JPEG markers are in the first few KB)
			if r.StartOffset > 64*1024 {
				weight = 1.5
			}
		}
	case TypePNG:
		// Data after IEND is trailing data
		if r.StartOffset > 0 {
			if r.StartOffset > 64*1024 {
				weight = 1.5
			}
		}
	case TypeUnknown, "":
		// Unknown format: all regions are equally suspicious
		weight = 1.0
	}

	return weight
}

// IsExpectedHighEntropy reports whether uniformly high entropy is normal
// (expected) for the given format because its payload is compressed by
// design. High entropy on such formats is NOT an anomaly.
func IsExpectedHighEntropy(mt MediaType) bool {
	return compressedMediaFormats[mt]
}
