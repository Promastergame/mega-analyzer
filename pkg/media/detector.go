package media

import (
	"archive/zip"
	"bytes"
	"math"
	"strings"
	"unicode/utf8"
)

type Detector struct {
	magicWindowSize   int
	entropyWindowSize int
}

func NewDetector() *Detector {
	return &Detector{
		magicWindowSize:   64 * 1024,
		entropyWindowSize: 4 * 1024,
	}
}

func (d *Detector) Detect(data []byte) ([]Signal, GlobalStats) {
	var signals []Signal
	var stats GlobalStats

	if len(data) == 0 {
		return signals, stats
	}

	signals = append(signals, d.detectMagic(data)...)
	signals = append(signals, d.detectZipEOCD(data)...)

	entropySigs, globalStats := d.detectEntropy(data)
	signals = append(signals, entropySigs...)
	stats = globalStats

	signals = append(signals, d.detectPayloads(data)...)

	return signals, stats
}

func (d *Detector) detectMagic(data []byte) []Signal {
	var sigs []Signal

	searchLimit := d.magicWindowSize
	if len(data) < searchLimit {
		searchLimit = len(data)
	}
	window := data[:searchLimit]

	riffIdx := bytes.Index(window, []byte("RIFF"))
	if riffIdx != -1 && len(window) >= riffIdx+12 {
		subType := string(window[riffIdx+8 : riffIdx+12])
		if subType == "WAVE" {
			sigs = append(sigs, Signal{Type: SignalMagic, Value: string(TypeWAV), Offset: riffIdx, Length: 12, Confidence: 1.0, Metadata: SignalMetadata{Priority: 60}})
		} else if subType == "WEBP" {
			sigs = append(sigs, Signal{Type: SignalMagic, Value: string(TypeWEBP), Offset: riffIdx, Length: 12, Confidence: 1.0, Metadata: SignalMetadata{Priority: 60}})
		}
	}

	dexIdx := bytes.Index(window, []byte("dex\n03"))
	if dexIdx != -1 && len(window) >= dexIdx+8 {
		ver := window[dexIdx+6]
		nullByte := window[dexIdx+7]
		if (ver >= '5' && ver <= '9') && nullByte == 0x00 {
			sigs = append(sigs, Signal{Type: SignalMagic, Value: string(TypeDEX), Offset: dexIdx, Length: 8, Confidence: 1.0, Severity: 0.8, Metadata: SignalMetadata{Priority: 80}})
		}
	}

	for _, mt := range PrecompiledMagic {
		idx := bytes.Index(window, mt.Magic)
		if idx != -1 {
			sigs = append(sigs, Signal{
				Type:       SignalMagic,
				Value:      string(mt.Type),
				Offset:     idx,
				Length:     len(mt.Magic),
				Confidence: mt.Confidence,
				Severity:   0.0,
				Metadata:   SignalMetadata{Priority: mt.Priority},
			})
		}
	}

	// MP4/ISO base media: "ftyp" must appear at offset 4 per ISO 14496-12.
	// Searching generically would cause false positives on any file containing
	// the ASCII string "ftyp" in its data.
	// The major brand decides the type: HEIC/AVIF stills, Canon CR3 RAW and
	// JXL share the ftyp box with MP4 video, so a blanket "mp4" used to
	// misclassify every still in a BMFF container as video.
	if len(window) >= 12 && string(window[4:8]) == "ftyp" {
		bt := dispatchBMFFBrand(string(window[8:12]))
		sigs = append(sigs, Signal{
			Type:       SignalMagic,
			Value:      string(bt),
			Offset:     4,
			Length:     4,
			Confidence: 0.9,
			Severity:   0.0,
			Metadata:   SignalMetadata{Priority: 50},
		})
	}

	// Offset-0 still-image magics. These patterns ("BM", "II*\0", "8BPS",
	// "FUJIFILMCCD-RAW ") are far too generic to search mid-buffer, so —
	// like ICO — they are only meaningful at offset 0.
	if len(window) >= 4 {
		switch {
		case isTIFFHeader(window):
			sigs = append(sigs, Signal{
				Type:       SignalMagic,
				Value:      string(TypeTIFF),
				Offset:     0,
				Length:     4,
				Confidence: 0.95,
				Severity:   0.0,
				Metadata:   SignalMetadata{Priority: 50},
			})
		case window[0] == 'B' && window[1] == 'M':
			sigs = append(sigs, Signal{
				Type:       SignalMagic,
				Value:      string(TypeBMP),
				Offset:     0,
				Length:     2,
				Confidence: 0.9,
				Severity:   0.0,
				Metadata:   SignalMetadata{Priority: 50},
			})
		case string(window[0:4]) == "8BPS":
			sigs = append(sigs, Signal{
				Type:       SignalMagic,
				Value:      string(TypePSD),
				Offset:     0,
				Length:     4,
				Confidence: 0.95,
				Severity:   0.0,
				Metadata:   SignalMetadata{Priority: 50},
			})
		}
	}
	if len(window) >= 2 && window[0] == 0xFF && window[1] == 0x0A {
		sigs = append(sigs, Signal{
			Type:       SignalMagic,
			Value:      string(TypeJXL),
			Offset:     0,
			Length:     2,
			Confidence: 0.8,
			Severity:   0.0,
			Metadata:   SignalMetadata{Priority: 50},
		})
	}
	if len(window) >= 16 && string(window[0:16]) == "FUJIFILMCCD-RAW " {
		sigs = append(sigs, Signal{
			Type:       SignalMagic,
			Value:      string(TypeRAW),
			Offset:     0,
			Length:     16,
			Confidence: 0.95,
			Severity:   0.0,
			Metadata:   SignalMetadata{Priority: 55},
		})
	}
	// GIF87a at offset 0 (PrecompiledMagic searches it mid-buffer; the
	// offset-0 occurrence is the authoritative one for classification).
	if len(window) >= 6 && string(window[0:6]) == "GIF87a" {
		sigs = append(sigs, Signal{
			Type:       SignalMagic,
			Value:      string(TypeGIF),
			Offset:     0,
			Length:     6,
			Confidence: 0.95,
			Severity:   0.0,
			Metadata:   SignalMetadata{Priority: 50},
		})
	}

	gif89Idx := bytes.Index(window, []byte("GIF89a"))
	if gif89Idx != -1 {
		sigs = append(sigs, Signal{
			Type:       SignalMagic,
			Value:      string(TypeGIF),
			Offset:     gif89Idx,
			Length:     6,
			Confidence: 0.9,
			Severity:   0.0,
			Metadata:   SignalMetadata{Priority: 50},
		})
	}

	// ICO/CUR: "00 00 01 00" / "00 00 02 00" is only meaningful at offset 0 -
	// it's too generic a 4-byte pattern to search for mid-buffer.
	if len(window) >= 4 && window[0] == 0x00 && window[1] == 0x00 && (window[2] == 0x01 || window[2] == 0x02) && window[3] == 0x00 {
		sigs = append(sigs, Signal{
			Type:       SignalMagic,
			Value:      string(TypeICO),
			Offset:     0,
			Length:     4,
			Confidence: 0.9,
			Severity:   0.0,
			Metadata:   SignalMetadata{Priority: 50},
		})
	}

	if idx, length, ok := detectSVGStart(window); ok {
		sigs = append(sigs, Signal{
			Type:       SignalMagic,
			Value:      string(TypeSVG),
			Offset:     idx,
			Length:     length,
			Confidence: 0.7,
			Severity:   0.0,
			Metadata:   SignalMetadata{Priority: 45},
		})
	}

	return sigs
}

// detectSVGStart looks for "<?xml" or "<svg" (case-insensitive) among the
// leading bytes of the file. SVG has no binary magic number, so this is a
// conservative text heuristic rather than a byte-signature match: false
// positives on stray XML cost little here since the JPEG/PNG/etc. parsers
// downstream simply won't find anything to parse in non-image data anyway.
func detectSVGStart(window []byte) (offset, length int, ok bool) {
	limit := 512
	if len(window) < limit {
		limit = len(window)
	}
	head := bytes.ToLower(window[:limit])
	if idx := bytes.Index(head, []byte("<?xml")); idx != -1 {
		return idx, 5, true
	}
	if idx := bytes.Index(head, []byte("<svg")); idx != -1 {
		return idx, 4, true
	}
	return 0, 0, false
}

func (d *Detector) detectZipEOCD(data []byte) []Signal {
	var sigs []Signal

	tailLimit := 64 * 1024
	if len(data) < tailLimit {
		tailLimit = len(data)
	}
	tail := data[len(data)-tailLimit:]

	eocdIdx := bytes.LastIndex(tail, []byte("PK\x05\x06"))
	if eocdIdx == -1 {
		return sigs
	}

	reader := bytes.NewReader(data)
	zipReader, err := zip.NewReader(reader, int64(len(data)))
	if err == nil {
		sigs = append(sigs, Signal{Type: SignalZIPEOCD, Value: "Valid", Offset: 0, Length: len(data), Confidence: 1.0, Severity: 0.3})

		apkIndicators := 0
		maxFilesToCheck := 200
		filesChecked := 0
		for _, f := range zipReader.File {
			if filesChecked >= maxFilesToCheck {
				break
			}
			name := strings.ToLower(f.Name)
			if name == "classes.dex" || name == "androidmanifest.xml" || strings.HasPrefix(name, "meta-inf/") {
				apkIndicators++
			}
			filesChecked++
		}

		if apkIndicators >= 2 {
			sigs = append(sigs, Signal{Type: SignalAPKStruct, Value: "APK Indicators", Offset: 0, Length: len(data), Confidence: 0.9, Severity: 0.6})
		}
	}

	return sigs
}

func (d *Detector) detectEntropy(data []byte) ([]Signal, GlobalStats) {
	var sigs []Signal
	var stats GlobalStats
	dataLen := len(data)

	if dataLen < 256 {
		return sigs, stats
	}

	windowSize := d.entropyWindowSize
	if windowSize > dataLen {
		windowSize = dataLen
	}

	step := windowSize / 2
	if step == 0 {
		step = 1
	}

	var allScores []float64
	var sum float64
	var maxEnt float64

	// Downsample for very large files to prevent CPU DoS
	maxWindows := 10000
	currentWindow := 0

	for offset := 0; offset <= dataLen-windowSize; offset += step {
		if currentWindow >= maxWindows {
			break
		}

		entropy := calcShannonEntropy(data[offset : offset+windowSize])
		allScores = append(allScores, entropy)
		sum += entropy
		if entropy > maxEnt {
			maxEnt = entropy
		}
		currentWindow++
	}

	if len(allScores) == 0 {
		return sigs, stats
	}

	n := float64(len(allScores))
	mean := sum / n

	var sumSqDiff float64
	for _, s := range allScores {
		diff := s - mean
		sumSqDiff += diff * diff
	}
	variance := sumSqDiff / n
	stddev := math.Sqrt(variance)

	stats.MeanEntropy = mean
	stats.Variance = variance
	stats.MaxEntropy = maxEnt

	for i, ent := range allScores {
		var zScore float64
		if stddev > 0 {
			zScore = (ent - mean) / stddev
		}

		if zScore >= 3.0 || ent >= 7.8 {
			stats.Peaks++

			sev := 0.5
			if ent > 7.5 {
				sev = 0.7
			}
			if ent > 7.9 {
				sev = 0.9
			}

			sigs = append(sigs, Signal{
				Type:       SignalHighEntropy,
				Value:      "Anomalous Segment",
				Offset:     i * step,
				Length:     windowSize,
				Confidence: 0.8,
				Severity:   sev,
				Metadata:   SignalMetadata{EntropyScore: ent, ZScore: zScore},
			})
		}
	}

	return sigs, stats
}

func calcShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var frequencies [256]int
	for _, b := range data {
		frequencies[b]++
	}

	entropy := 0.0
	dataLen := float64(len(data))
	for _, count := range frequencies {
		if count > 0 {
			p := float64(count) / dataLen
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

type ExtractedString struct {
	Value  string
	Offset int
}

func extractUTF8Strings(data []byte, minLen int) []ExtractedString {
	var stringsFound []ExtractedString
	var sb strings.Builder

	offset := 0
	startOffset := 0
	maxLength := 1024

	for offset < len(data) {
		r, size := utf8.DecodeRune(data[offset:])
		if size == 0 {
			break
		}

		if r != utf8.RuneError && (r >= 32 && r != 127) {
			if sb.Len() == 0 {
				startOffset = offset
			}
			if sb.Len() < maxLength {
				sb.WriteRune(r)
			}
		} else {
			if sb.Len() >= minLen {
				stringsFound = append(stringsFound, ExtractedString{Value: sb.String(), Offset: startOffset})
			}
			sb.Reset()
		}
		offset += size
	}
	if sb.Len() >= minLen {
		stringsFound = append(stringsFound, ExtractedString{Value: sb.String(), Offset: startOffset})
	}

	return stringsFound
}

func (d *Detector) detectPayloads(data []byte) []Signal {
	var sigs []Signal

	extractedStrings := extractUTF8Strings(data, 7)

	for _, es := range extractedStrings {
		for _, ps := range PrecompiledPayloads {
			if len(es.Value) < ps.MinLength {
				continue
			}
			if ps.Regexp.MatchString(es.Value) {
				sigs = append(sigs, Signal{
					Type:       SignalPayload,
					Value:      ps.Name,
					Offset:     es.Offset,
					Length:     len(es.Value),
					Confidence: ps.Confidence,
					Severity:   ps.Severity,
					Metadata:   SignalMetadata{Evidence: es.Value},
				})
			}
		}

		for _, priv := range PrecompiledPrivacy {
			match := priv.Regexp.FindStringSubmatch(es.Value)
			if match != nil {
				sigs = append(sigs, Signal{
					Type:       SignalPrivacyLeak,
					Value:      priv.Field,
					Offset:     es.Offset,
					Length:     len(es.Value),
					Confidence: 0.9,
					Severity:   0.2,
					Metadata:   SignalMetadata{Field: priv.Field, Evidence: match[0]},
				})
			}
		}
	}

	return sigs
}
