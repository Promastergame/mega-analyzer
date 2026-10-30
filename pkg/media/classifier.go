package media

import "strings"

type Classification struct {
	PrimaryFormat MediaType         `json:"primary_format"`
	HiddenFormats []MediaType       `json:"hidden_formats"`
	IsPolyglot    bool              `json:"is_polyglot"`
	Confidence    float64           `json:"confidence"`
	RecoveredData map[string]string `json:"recovered_data"`
	MediaExtra    *MediaMetadata    `json:"media_extra,omitempty"`
}

type Classifier struct{}

func NewClassifier() *Classifier {
	return &Classifier{}
}

func (c *Classifier) Classify(globalStats GlobalStats, regions []Region, filename string) Classification {
	class := Classification{
		PrimaryFormat: TypeUnknown,
		HiddenFormats: []MediaType{},
		Confidence:    1.0,
		RecoveredData: make(map[string]string),
	}

	var primaryRegion *Region
	var hasValidZip bool
	var hasApkStruct bool

	for i := range regions {
		r := &regions[i]

		for _, sig := range r.Signals {
			if sig.Type == SignalMagic {
				if primaryRegion == nil {
					primaryRegion = r
				} else {
					oldSig := c.getPrimaryMagic(*primaryRegion)

					newPriority := sig.Metadata.Priority
					oldPriority := oldSig.Metadata.Priority

					if newPriority > oldPriority {
						primaryRegion = r
					} else if newPriority == oldPriority && r.StartOffset < primaryRegion.StartOffset {
						primaryRegion = r
					}
				}
			} else if sig.Type == SignalZIPEOCD {
				hasValidZip = true
			} else if sig.Type == SignalAPKStruct {
				hasApkStruct = true
			}
		}
	}

	if primaryRegion != nil {
		pm := c.getPrimaryMagic(*primaryRegion)
		class.PrimaryFormat = MediaType(pm.Value)
		class.Confidence = Clamp(pm.Confidence)
	}

	if class.PrimaryFormat == TypeZIP && hasApkStruct {
		class.PrimaryFormat = TypeAPK
	}

	if class.PrimaryFormat == TypeUnknown && globalStats.MeanEntropy > 7.9 {
		class.Confidence = 0.8
	}

	lowerName := strings.ToLower(filename)
	extMismatch := false
	if class.PrimaryFormat != TypeUnknown {
		switch class.PrimaryFormat {
		case TypeJPEG:
			extMismatch = !strings.HasSuffix(lowerName, ".jpg") && !strings.HasSuffix(lowerName, ".jpeg")
		case TypePNG:
			extMismatch = !strings.HasSuffix(lowerName, ".png")
		case TypeGIF:
			extMismatch = !strings.HasSuffix(lowerName, ".gif")
		case TypeMP4:
			extMismatch = !strings.HasSuffix(lowerName, ".mp4")
		case TypeMP3:
			extMismatch = !strings.HasSuffix(lowerName, ".mp3")
		case TypeWAV:
			extMismatch = !strings.HasSuffix(lowerName, ".wav")
		case TypeOGG:
			extMismatch = !strings.HasSuffix(lowerName, ".ogg")
		case TypeWEBP:
			extMismatch = !strings.HasSuffix(lowerName, ".webp")
		case TypePDF:
			extMismatch = !strings.HasSuffix(lowerName, ".pdf")
		case TypeAPK:
			extMismatch = !strings.HasSuffix(lowerName, ".apk") && !strings.HasSuffix(lowerName, ".jar")
		case TypeICO:
			extMismatch = !strings.HasSuffix(lowerName, ".ico") && !strings.HasSuffix(lowerName, ".cur")
		case TypeSVG:
			extMismatch = !strings.HasSuffix(lowerName, ".svg")
		case TypeTIFF:
			extMismatch = !strings.HasSuffix(lowerName, ".tif") && !strings.HasSuffix(lowerName, ".tiff")
		case TypeDNG:
			extMismatch = !strings.HasSuffix(lowerName, ".dng")
		case TypeRAW:
			extMismatch = !isRAWFilename(lowerName)
		case TypeBMP:
			extMismatch = !strings.HasSuffix(lowerName, ".bmp") && !strings.HasSuffix(lowerName, ".dib")
		case TypeHEIC:
			extMismatch = !strings.HasSuffix(lowerName, ".heic") && !strings.HasSuffix(lowerName, ".heif") && !strings.HasSuffix(lowerName, ".hif")
		case TypeAVIF:
			extMismatch = !strings.HasSuffix(lowerName, ".avif")
		case TypePSD:
			extMismatch = !strings.HasSuffix(lowerName, ".psd") && !strings.HasSuffix(lowerName, ".psb")
		case TypeJXL:
			extMismatch = !strings.HasSuffix(lowerName, ".jxl")
		}
	}

	if extMismatch {
		class.IsPolyglot = true
		class.Confidence = Clamp(class.Confidence * 0.8)
	}

	if class.PrimaryFormat != TypeUnknown {
		if class.PrimaryFormat != TypeZIP && class.PrimaryFormat != TypeAPK {
			if hasApkStruct {
				class.HiddenFormats = append(class.HiddenFormats, TypeAPK)
				class.IsPolyglot = true
			} else if hasValidZip {
				class.HiddenFormats = append(class.HiddenFormats, TypeZIP)
				class.IsPolyglot = true
			}
		}

		for _, r := range regions {
			for _, s := range r.Signals {
				if s.Type == SignalMagic && MediaType(s.Value) == TypeDEX {
					exists := false
					for _, h := range class.HiddenFormats {
						if h == TypeDEX {
							exists = true
							break
						}
					}
					if !exists {
						class.HiddenFormats = append(class.HiddenFormats, TypeDEX)
						class.IsPolyglot = true
					}
				}
			}
		}
	}

	return class
}

func (c *Classifier) getPrimaryMagic(r Region) Signal {
	for _, s := range r.Signals {
		if s.Type == SignalMagic {
			return s
		}
	}
	return Signal{}
}
