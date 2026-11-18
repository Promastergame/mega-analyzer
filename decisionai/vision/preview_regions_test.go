package vision

import (
	"context"
	"image"
	"image/color"
	"image/draw"
	"testing"
)

func grayTexture(bounds image.Rectangle) *image.RGBA {
	im := image.NewRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			v := uint8(50 + (x*17+y*31)%180)
			im.SetRGBA(x, y, color.RGBA{v, v, v, 255})
		}
	}
	return im
}

func TestPreviewLocalizedTexturedPatchBelowGlobalThreshold(t *testing.T) {
	im := grayTexture(image.Rect(0, 0, 512, 512))
	draw.Draw(im, image.Rect(180, 160, 308, 288), texturedBloodImage(128, 128), image.Point{}, draw.Src)
	a, err := (Local{}).Analyze(context.Background(), encodeImage(im))
	if err != nil {
		t.Fatal(err)
	}
	score := a.Sensitive["blood_dark"]
	if score.AreaPct >= 8 || score.Score >= 25 {
		t.Fatalf("fixture already meets old global gate: %+v", score)
	}
	if !a.Preview.Blur || len(a.Preview.Regions) == 0 {
		t.Fatalf("localized patch missed: %+v / %+v", score, a.Preview)
	}
	for _, region := range a.Preview.Regions {
		if region.Class != "blood_dark" || region.X < 0 || region.Y < 0 || region.X+region.W > a.Width || region.Y+region.H > a.Height {
			t.Fatal(region)
		}
		if region.W > 160 || region.H > 160 {
			t.Fatal("localized match hid the whole image", region)
		}
	}
}

func TestPreviewFlatLogoDoesNotBorrowBackgroundTexture(t *testing.T) {
	im := grayTexture(image.Rect(0, 0, 256, 256))
	draw.Draw(im, image.Rect(40, 40, 180, 180), solidImage("821418", 140, 140), image.Point{}, draw.Src)
	a, err := (Local{}).Analyze(context.Background(), encodeImage(im))
	if err != nil {
		t.Fatal(err)
	}
	if a.Sensitive["blood_dark"].AreaPct < 20 || !a.Sensitive["blood_dark"].Solid || a.Preview.Blur {
		t.Fatalf("flat logo misclassified: %+v / %+v", a.Sensitive, a.Preview)
	}
}

func TestPreviewSkipsFlatComponentWhenAnotherComponentIsTextured(t *testing.T) {
	im := grayTexture(image.Rect(0, 0, 320, 240))
	draw.Draw(im, image.Rect(10, 20, 110, 120), solidImage("821418", 100, 100), image.Point{}, draw.Src)
	draw.Draw(im, image.Rect(190, 80, 290, 180), texturedBloodImage(100, 100), image.Point{}, draw.Src)
	a, err := (Local{}).Analyze(context.Background(), encodeImage(im))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Preview.Blur || len(a.Preview.Regions) == 0 {
		t.Fatal(a.Preview)
	}
	for _, region := range a.Preview.Regions {
		if region.X < 170 {
			t.Fatal("flat component selected for blur", region)
		}
	}
}

func TestPreviewPaddingClipsAtImageEdges(t *testing.T) {
	for _, box := range []SensitiveBox{
		{Class: "blood_dark", X: 0, Y: 0, W: 20, H: 20},
		{Class: "blood_dark", X: 90, Y: 70, W: 10, H: 10},
		{Class: "blood_dark", X: 30, Y: 20, W: 20, H: 20},
	} {
		r, ok := paddedPreviewRegion(box, 100, 80)
		if !ok || r.X < 0 || r.Y < 0 || r.W <= 0 || r.H <= 0 || r.X+r.W > 100 || r.Y+r.H > 80 || r.X > box.X || r.Y > box.Y || r.X+r.W < box.X+box.W || r.Y+r.H < box.Y+box.H {
			t.Fatal(box, r, ok)
		}
	}
	if _, ok := paddedPreviewRegion(SensitiveBox{X: -1, W: 10, H: 10}, 100, 80); ok {
		t.Fatal("negative region accepted")
	}
}

func TestSensitiveAnalysisSharesScoresOnOffsetImages(t *testing.T) {
	im := grayTexture(image.Rect(20, 30, 276, 286))
	draw.Draw(im, image.Rect(60, 70, 160, 170), texturedBloodImage(100, 100), image.Point{}, draw.Src)
	standalone := ScoreSensitive(im)
	combined, boxes := SensitiveAnalyze(im)
	for _, class := range SensitiveOrder() {
		a, b := standalone[class], combined[class]
		if a.Score != b.Score || a.Solid != b.Solid || a.AreaPct != b.AreaPct {
			t.Fatalf("score drift for %s: %+v / %+v", class, a, b)
		}
	}
	for _, box := range boxes {
		if box.X < 0 || box.Y < 0 || box.X+box.W > im.Bounds().Dx() || box.Y+box.H > im.Bounds().Dy() {
			t.Fatal("coordinates not relative to original", box)
		}
	}
}

func TestPreviewFeedbackRejectsInvalidAndDeduplicatesRegions(t *testing.T) {
	p := AssessPreview(Analysis{Width: 100, Height: 100})
	p.AddFeedbackMatch("blood_dark", 90, PreviewRegion{X: -1, W: 10, H: 10})
	if p.Blur {
		t.Fatal("invalid feedback changed display policy")
	}
	region := PreviewRegion{X: 10, Y: 10, W: 20, H: 20}
	for i := 0; i < 20; i++ {
		p.AddFeedbackMatch("blood_dark", 90, region)
	}
	if !p.Blur || len(p.Regions) != 1 || len(p.Classes) != 1 {
		t.Fatal(p)
	}
}
