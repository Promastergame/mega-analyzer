package media

import (
	"fmt"
	"math"
)

// StegoSignal describes a detected steganographic anomaly.
type StegoSignal struct {
	Method     string  `json:"method"` // "lsb_frequency", "dct_chi2", "dct_entropy_anomaly", "palette_lsb"
	Confidence float64 `json:"confidence"`
	Offset     int     `json:"offset"`   // byte offset in file (approximate)
	Length     int     `json:"length"`   // estimated payload size
	Evidence   string  `json:"evidence"` // human-readable description
}

// DetectSteganography runs all applicable steganography detectors for the
// given format and returns any signals found. This is a format-aware
// dispatcher — not all methods apply to every format.
func DetectSteganography(data []byte, format MediaType) []StegoSignal {
	if len(data) == 0 {
		return nil
	}

	var signals []StegoSignal

	switch format {
	case TypePNG, TypeBMP, TypeTIFF, TypeDNG, TypeRAW:
		signals = append(signals, detectLSBFrequency(data)...)
	case TypeGIF:
		signals = append(signals, detectPaletteLSB(data)...)
	case TypeJPEG:
		signals = append(signals, detectDCTChiSquared(data)...)
	}

	return signals
}

// TypeBMP lives in signals.go with the other MediaTypes; TIFF/DNG/RAW reuse
// the same whole-file LSB frequency check (uncompressed rasters).

// detectLSBFrequency performs frequency analysis on the least-significant
// bits of all bytes. In natural images, LSBs are approximately uniform
// (50/50 split of 0s and 1s). Steganographic payloads shift this balance.
func detectLSBFrequency(data []byte) []StegoSignal {
	if len(data) < 1024 {
		return nil
	}

	// Count LSB=1 bits
	var ones int
	for _, b := range data {
		ones += int(b & 1)
	}
	ratio := float64(ones) / float64(len(data))

	// Natural images: ratio should be close to 0.5
	// Chi-squared threshold: |ratio - 0.5| > 0.05 suggests stego
	deviation := ratio - 0.5
	if deviation < 0 {
		deviation = -deviation
	}

	if deviation > 0.05 {
		conf := Clamp(deviation * 4) // scale to 0-1
		return []StegoSignal{{
			Method:     "lsb_frequency",
			Confidence: conf,
			Offset:     0,
			Length:     len(data),
			Evidence:   formatLSBFrequencyEvidence(ratio, ones, len(data)),
		}}
	}
	return nil
}

func formatLSBFrequencyEvidence(ratio float64, ones, total int) string {
	pct := ratio * 100
	return fmt.Sprintf("LSB distribution: %.2f%% ones (%d/%d) — deviation from 50%% suggests hidden data", pct, ones, total)
}

// detectDCTChiSquared runs the Westfeld–Pfitzmann chi-squared attack on the
// quantized DCT coefficients of a JPEG.
//
// The attack exploits what LSB embedding does to "pairs of values" (PoVs) —
// value pairs that differ only in their least-significant bit, such as 4 and 5.
// Embedding a uniformly random payload moves coefficients freely within their
// pair, so the two members converge on equal frequency. Natural JPEG
// coefficient histograms are strongly monotone: the smaller magnitude of a pair
// is much more common than the larger. A histogram where PoV members are
// suspiciously balanced is therefore evidence of embedding, and the chi-squared
// goodness-of-fit test against the "equal frequency" hypothesis quantifies it.
//
// Note the inverted reading: a *high* p-value means the observed histogram fits
// the embedding hypothesis, so a high p-value is the incriminating result.
//
// Coefficients 0, 1 and -1 are excluded because JSteg-family embedders skip
// them (changing them would visibly damage the image and cost too much rate),
// so their PoVs carry no payload signal.
//
// If the file is not a Huffman-coded sequential JPEG (progressive, arithmetic
// coded, truncated), coefficients cannot be recovered and the function falls
// back to the coarse whole-file entropy heuristic rather than reporting
// nothing.
func detectDCTChiSquared(data []byte) []StegoSignal {
	if len(data) < 1024 {
		return nil
	}

	hist, ok := extractJPEGACHistogram(data)
	if !ok {
		return detectJPEGEntropyAnomaly(data)
	}

	chi2, df, used := jpegPoVChiSquared(hist)
	if df < minPoVDegreesOfFreedom {
		// Too few populated pairs for the test to mean anything (tiny or
		// very flat image). Fall back rather than reporting a bogus p-value.
		return detectJPEGEntropyAnomaly(data)
	}

	// p = P(X2 > chi2) under "PoV members are equally frequent".
	p := chiSquaredUpperTail(chi2, df)
	if p < povEmbeddingPValue {
		return nil
	}

	// Payload estimate: one bit per usable coefficient, so capacity in bytes.
	estBytes := used / 8

	return []StegoSignal{{
		Method:     "dct_chi2",
		Confidence: Clamp(p),
		Offset:     0,
		Length:     estBytes,
		Evidence: fmt.Sprintf(
			"JPEG DCT pairs-of-values are near-equal in frequency: chi2=%.2f, df=%d, p=%.4f "+
				"over %d AC coefficients in %d blocks — consistent with LSB embedding (JSteg-family); "+
				"estimated payload up to %d bytes",
			chi2, df, p, used, hist.blocks, estBytes),
	}}
}

const (
	// minPoVExpected is the minimum combined count of a value pair before it
	// is admitted to the test. The chi-squared approximation needs an expected
	// cell count of at least ~5, and the expected count is half the pair total.
	minPoVExpected = 10

	// minPoVDegreesOfFreedom guards against declaring a result from a handful
	// of pairs, where the statistic is dominated by noise.
	minPoVDegreesOfFreedom = 5

	// povEmbeddingPValue is the p-value above which the equal-frequency
	// (embedding) hypothesis is considered a match. Natural images sit far
	// below this because their coefficient histograms are steeply monotone.
	povEmbeddingPValue = 0.95
)

// jpegPoVChiSquared computes the chi-squared statistic for the pairs-of-values
// hypothesis over an AC coefficient histogram.
//
// Pairing is done by magnitude and applied to each sign independently: (2m,
// 2m+1) and (-2m, -(2m+1)) for m >= 1. This matches how JSteg-family tools
// alter a coefficient's LSB while leaving its sign alone.
//
// Returns the statistic, the degrees of freedom (pairs used minus one) and the
// total number of coefficients that took part.
func jpegPoVChiSquared(h *jpegACHistogram) (chi2 float64, df, used int) {
	pairs := 0
	for m := 1; m*2+1 < jpegACHistOffset; m++ {
		for _, sign := range [2]int{1, -1} {
			lo := sign * (2 * m)
			hi := sign * (2*m + 1)

			a := int(h.at(lo))
			b := int(h.at(hi))
			total := a + b
			if total < minPoVExpected {
				continue
			}

			// Under the embedding hypothesis both members are equally likely,
			// so each expects half the pair's mass. With two cells summing to a
			// fixed total the statistic reduces to a single term.
			expected := float64(total) / 2
			d := float64(a) - expected
			chi2 += 2 * d * d / expected

			pairs++
			used += total
		}
	}
	if pairs == 0 {
		return 0, 0, 0
	}
	return chi2, pairs - 1, used
}

// detectJPEGEntropyAnomaly is the fallback for JPEGs whose DCT coefficients
// cannot be recovered. It only flags entropy above what lossy compression
// normally yields, which is weak evidence — hence the low fixed confidence.
func detectJPEGEntropyAnomaly(data []byte) []StegoSignal {
	e := calcShannonEntropy(data)
	if e > 7.95 {
		return []StegoSignal{{
			Method:     "dct_entropy_anomaly",
			Confidence: 0.4,
			Offset:     0,
			Length:     len(data),
			Evidence:   fmt.Sprintf("Overall entropy %.4f exceeds typical JPEG ceiling", e),
		}}
	}
	return nil
}

// ─── chi-squared upper tail ───────────────────────────────────────────────────
//
// P(X2 > x) for df degrees of freedom is the regularized upper incomplete gamma
// function Q(df/2, x/2). Implemented with the standard pair of expansions:
// the series for P(a,x) when x is small relative to a, and the Lentz continued
// fraction for Q(a,x) otherwise, which is where each converges quickly.

func chiSquaredUpperTail(chi2 float64, df int) float64 {
	if df <= 0 {
		return 1
	}
	if chi2 <= 0 {
		return 1
	}
	return gammaQ(float64(df)/2, chi2/2)
}

func gammaQ(a, x float64) float64 {
	if x < 0 || a <= 0 {
		return 0
	}
	if x < a+1 {
		return 1 - gammaPSeries(a, x)
	}
	return gammaQContinuedFraction(a, x)
}

func gammaPSeries(a, x float64) float64 {
	const (
		maxIter = 300
		eps     = 3e-14
	)
	if x <= 0 {
		return 0
	}
	ap := a
	sum := 1.0 / a
	del := sum
	for i := 0; i < maxIter; i++ {
		ap++
		del *= x / ap
		sum += del
		if math.Abs(del) < math.Abs(sum)*eps {
			break
		}
	}
	lg, _ := math.Lgamma(a)
	return sum * math.Exp(-x+a*math.Log(x)-lg)
}

func gammaQContinuedFraction(a, x float64) float64 {
	const (
		maxIter = 300
		eps     = 3e-14
		tiny    = 1e-300
	)
	b := x + 1 - a
	c := 1 / tiny
	d := 1 / b
	h := d
	for i := 1; i <= maxIter; i++ {
		an := -float64(i) * (float64(i) - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = b + an/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		del := d * c
		h *= del
		if math.Abs(del-1) < eps {
			break
		}
	}
	lg, _ := math.Lgamma(a)
	return math.Exp(-x+a*math.Log(x)-lg) * h
}

// detectPaletteLSB checks for suspicious LSB patterns in palette-based
// image formats (GIF, BMP, 8-bit PNG).
func detectPaletteLSB(data []byte) []StegoSignal {
	if len(data) < 512 {
		return nil
	}

	// Simple heuristic: count LSB=1 in the first 4096 bytes after any header
	start := 0
	if len(data) > 13 {
		start = 13 // skip GIF header
	}
	end := start + 4096
	if end > len(data) {
		end = len(data)
	}

	region := data[start:end]
	var ones int
	for _, b := range region {
		ones += int(b & 1)
	}
	ratio := float64(ones) / float64(len(region))
	deviation := ratio - 0.5
	if deviation < 0 {
		deviation = -deviation
	}

	if deviation > 0.08 {
		return []StegoSignal{{
			Method:     "palette_lsb",
			Confidence: Clamp(deviation * 3),
			Offset:     start,
			Length:     len(region),
			Evidence:   fmt.Sprintf("Palette pixel LSB ratio %.2f%% deviates from expected 50%%", ratio*100),
		}}
	}
	return nil
}
