package vision

// PreviewAssessment is an advisory display policy, separate from malware risk.
// A color match does not identify the depicted object. Scores are similarities,
// not calibrated probabilities; a reader can reveal the original preview.
type PreviewAssessment struct {
	PolicyVersion int             `json:"policy_version"`
	Status        string          `json:"status"`
	Blur          bool            `json:"blur"`
	Classes       []string        `json:"classes,omitempty"`
	Score         int             `json:"score"`
	Source        string          `json:"source"`
	Reason        string          `json:"reason"`
	Calibrated    bool            `json:"calibrated"`
	Regions       []PreviewRegion `json:"regions,omitempty"`
}

type PreviewRegion struct {
	Class string `json:"class"`
	X     int    `json:"x"`
	Y     int    `json:"y"`
	W     int    `json:"w"`
	H     int    `json:"h"`
}

func IsPreviewClass(class string) bool {
	return class == "blood_dark" || class == "blood_bright"
}

func AssessPreview(analysis Analysis) PreviewAssessment {
	out := PreviewAssessment{PolicyVersion: 2, Status: "checked", Source: "local_color_heuristic", Reason: "no_selected_color_match"}
	// Мелкие изображения (иконки 16×16 и т.п.) — элементы интерфейса, а не
	// фотографии: цветовой блюр для них не включаем. Однотонные заливки
	// отсекаются флагом Solid из скоринга.
	tiny := analysis.Width < 64 || analysis.Height < 64
	for _, class := range []string{"blood_dark", "blood_bright"} {
		value := analysis.Sensitive[class]
		if value.Solid || tiny {
			continue
		}
		// Реальные фото дают скор 15–30 даже при заметной крови (скор
		// размазывается по всей площади), поэтому кроме скора смотрим долю:
		// 8% тёмной крови на фото — однозначный кандидат на блюр.
		threshold, areaThreshold := 25, 8.0
		if class == "blood_bright" {
			threshold, areaThreshold = 15, 10
		}
		globalMatch := value.AreaPct >= 1 && (value.Score >= threshold || value.AreaPct >= areaThreshold)
		localMatch, hasBoxes := false, false
		var regions []PreviewRegion
		for _, box := range analysis.Boxes {
			if box.Class != class {
				continue
			}
			hasBoxes = true
			if box.Solid {
				continue
			}
			minimum := 2.0
			if class == "blood_bright" {
				minimum = 3.0
			}
			localMatch = localMatch || box.AreaPct >= minimum
			if box.AreaPct >= .1 {
				region, ok := paddedPreviewRegion(box, analysis.Width, analysis.Height)
				if ok {
					regions = append(regions, region)
				}
			}
		}
		if (!globalMatch && !localMatch) || (hasBoxes && len(regions) == 0) {
			continue
		}
		out.Classes = append(out.Classes, class)
		out.Score = max(out.Score, value.Score)
		out.Blur, out.Reason = true, "possible_sensitive_color_match"
		for _, region := range regions {
			if len(out.Regions) < 16 {
				out.Regions = append(out.Regions, region)
			}
		}
	}
	return out
}

// Padding includes the sample-grid boundary without revealing a thin edge of
// the selected patch. Returned coordinates always stay inside the original.
func paddedPreviewRegion(box SensitiveBox, width, height int) (PreviewRegion, bool) {
	if width <= 0 || height <= 0 || box.W <= 0 || box.H <= 0 || box.X < 0 || box.Y < 0 || box.X >= width || box.Y >= height {
		return PreviewRegion{}, false
	}
	padding := max(2, min(box.W, box.H)/16)
	x, y := max(0, box.X-padding), max(0, box.Y-padding)
	right := min(width, box.X+min(box.W, width-box.X)+padding)
	bottom := min(height, box.Y+min(box.H, height-box.Y)+padding)
	return PreviewRegion{Class: box.Class, X: x, Y: y, W: right - x, H: bottom - y}, true
}

// AddFeedbackMatch uses a trained region descriptor only for selected classes.
// Unknown labels and negative labels do not certify a picture as safe.
func (p *PreviewAssessment) AddFeedbackMatch(class string, score int, region PreviewRegion) {
	if !IsPreviewClass(class) || score < 60 || score > 100 || region.X < 0 || region.Y < 0 || region.W <= 0 || region.H <= 0 {
		return
	}
	p.Blur = true
	p.Score = max(p.Score, score)
	p.Source = "local_color_and_feedback"
	p.Reason = "possible_sensitive_feedback_match"
	found := false
	for _, previous := range p.Classes {
		found = found || previous == class
	}
	if !found {
		p.Classes = append(p.Classes, class)
	}
	if len(p.Regions) < 16 && region.W > 0 && region.H > 0 {
		region.Class = class
		for _, previous := range p.Regions {
			if previous == region {
				return
			}
		}
		p.Regions = append(p.Regions, region)
	}
}
