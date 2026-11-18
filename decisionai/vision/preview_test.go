package vision

import (
	"context"
	"testing"
)

func TestPreviewFilterUsesPixelsAndSelectedClasses(t *testing.T) {
	for _, tc := range []struct {
		name, color string
		blur        bool
	}{
		// Однотонные заливки — фон/иконка, не сцена: блюр не включается.
		{"solid_dark_fill", "821418", false},
		{"solid_bright_fill", "DF2F26", false},
		{"red_shirt_negative", "DB2927", false},
		{"tomato_negative", "FA2C06", false},
		{"skin_is_not_selected", "E9D0C3", false},
		{"yellow_negative", "FCD348", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			analysis, err := (Local{}).Analyze(context.Background(), encodeImage(solidImage(tc.color, 64, 64)))
			if err != nil {
				t.Fatal(err)
			}
			if analysis.Preview.Blur != tc.blur || analysis.Preview.Calibrated || analysis.Preview.Status != "checked" {
				t.Fatalf("wrong preview assessment: %+v", analysis.Preview)
			}
		})
	}
}

// TestPreviewTexturedPhotoBlurs — настоящее фото с кровью (вариативное,
// не однотонное) включают блюр по площади, даже когда скор размазан.
func TestPreviewTexturedPhotoBlurs(t *testing.T) {
	analysis, err := (Local{}).Analyze(context.Background(), encodeImage(texturedBloodImage(128, 128)))
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.Preview.Blur || analysis.Preview.Reason != "possible_sensitive_color_match" {
		t.Fatalf("textured blood photo must blur: %+v", analysis.Preview)
	}
}

// TestPreviewTinyImageDoesNotBlur — иконки 16×16 не фото: цветовой блюр
// для них не включается, что бы там ни совпало по палитре.
func TestPreviewTinyImageDoesNotBlur(t *testing.T) {
	analysis, err := (Local{}).Analyze(context.Background(), encodeImage(solidImage("821418", 16, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Preview.Blur {
		t.Fatalf("tiny icon must not blur: %+v", analysis.Preview)
	}
}

func TestFeedbackUnknownDoesNotClearSensitivePreview(t *testing.T) {
	p := AssessPreview(Analysis{Width: 320, Height: 240, Sensitive: SensitiveReport{"blood_dark": {Score: 80, AreaPct: 30}}})
	p.AddFeedbackMatch("skin", 100, PreviewRegion{W: 64, H: 64})
	p.AddFeedbackMatch("", 0, PreviewRegion{})
	if !p.Blur || p.Source != "local_color_heuristic" || p.Score != 80 {
		t.Fatalf("unrelated/unknown class certified safety: %+v", p)
	}
	p.AddFeedbackMatch("blood_bright", 90, PreviewRegion{X: 3, Y: 4, W: 10, H: 20})
	if !p.Blur || p.Source != "local_color_and_feedback" || len(p.Regions) != 1 || p.Regions[0].X != 3 {
		t.Fatalf("feedback region was lost: %+v", p)
	}
}
