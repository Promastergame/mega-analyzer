package imagesensitive

import (
	"image"
	"image/color"
	"testing"
)

func solidImg(c color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, c)
		}
	}
	return img
}

func TestScoreNil(t *testing.T) {
	score, label := Score(nil, "")
	if score != 0 || label != "" {
		t.Fatalf("expected zero empty, got %f %q", score, label)
	}
}

func TestScoreBoundedZeroToOne(t *testing.T) {
	cases := []*image.RGBA{
		solidImg(color.RGBA{0, 0, 0, 255}),
		solidImg(color.RGBA{255, 255, 255, 255}),
		solidImg(color.RGBA{200, 150, 120, 255}), // skin-toned
		solidImg(color.RGBA{50, 200, 50, 255}),   // green
	}
	for i, img := range cases {
		score, _ := Score(img, "")
		if score < 0 || score > 1 {
			t.Fatalf("case %d score out of range: %f", i, score)
		}
	}
}

func TestNeutralLandscape(t *testing.T) {
	score, label := Score(solidImg(color.RGBA{50, 200, 50, 255}), "landscape.png")
	if label != "" {
		t.Fatalf("expected no label for green landscape, got %q", label)
	}
	if score >= thumbnailScoreThreshold {
		t.Fatalf("expected low score, got %f", score)
	}
}

func TestSolidSkinToneNoFalsePositive(t *testing.T) {
	// A solid beige square should NOT trigger the label because
	// ColorVariance suppresses the signal.
	_, label := Score(solidImg(color.RGBA{200, 150, 120, 255}), "")
	if label != "" {
		t.Fatalf("solid skin-toned image should not trigger label, got %q", label)
	}
}

func TestHintsScoreCapped(t *testing.T) {
	v := HintsScore("private_selfie_passport_id_card.jpg")
	if v < 0 || v > 1 {
		t.Fatalf("hint score out of range: %f", v)
	}
}

func TestHintsTokenized(t *testing.T) {
	// "adult" is no longer a keyword — should not match.
	v := HintsScore("adult_content.png")
	if v != 0 {
		t.Fatalf("expected 0 for removed keyword 'adult', got %f", v)
	}
	// "xxx" is no longer a keyword.
	v = HintsScore("xxx_file.png")
	if v != 0 {
		t.Fatalf("expected 0 for removed keyword 'xxx', got %f", v)
	}
}

func TestHintsBigramIDCard(t *testing.T) {
	v := HintsScore("my_id_card_scan.jpg")
	if v == 0 {
		t.Fatal("expected non-zero for 'id_card' bigram")
	}
}

func TestHintsNoSubstringMatch(t *testing.T) {
	// "privately" contains "private" as substring but tokenization should
	// produce "privately" which is NOT in the keyword list.
	v := HintsScore("privately_owned.png")
	if v != 0 {
		t.Fatalf("expected 0 for non-exact match 'privately', got %f", v)
	}
}

func TestNeverEmitsExplicitVerdict(t *testing.T) {
	// Sweep variants — label may only be empty or SensitiveLabel.
	imgs := []*image.RGBA{
		solidImg(color.RGBA{200, 150, 120, 255}),
		solidImg(color.RGBA{210, 160, 130, 255}),
		solidImg(color.RGBA{220, 170, 140, 255}),
	}
	for i, img := range imgs {
		_, label := Score(img, "")
		if label != "" && label != SensitiveLabel {
			t.Fatalf("case %d emitted forbidden label: %q", i, label)
		}
	}
}

func TestScoreBytesInvalid(t *testing.T) {
	score, label := ScoreBytes([]byte("not image"), "x.png")
	if score != 0 || label != "" {
		t.Fatalf("expected zero empty, got %f %q", score, label)
	}
}

func TestScoreResultReasons(t *testing.T) {
	// A varied skin-toned image with a personal hint should produce reasons.
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			// Vary the colour slightly to avoid ColorVariance suppression.
			r := uint8(180 + (x+y)%40)
			g := uint8(130 + (x+y)%30)
			b := uint8(100 + (x+y)%20)
			img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}
	res := ScoreResult(img, "private_selfie.jpg")
	if res.Score < 0 || res.Score > 1 {
		t.Fatalf("score out of range: %f", res.Score)
	}
	if len(res.Reasons) == 0 {
		t.Fatal("expected non-empty reasons for skin-toned image with hints")
	}
	if res.Label != "" && res.Label != SensitiveLabel {
		t.Fatalf("bad label: %q", res.Label)
	}
}

func TestColorVarianceSolid(t *testing.T) {
	v := ColorVariance(solidImg(color.RGBA{128, 128, 128, 255}))
	if v > 0.001 {
		t.Fatalf("expected near-zero variance for solid image, got %f", v)
	}
}

func FuzzScoreBytes(f *testing.F) {
	f.Add([]byte("not an image"), "file.png")
	f.Add([]byte{0x89, 0x50, 0x4E, 0x47}, "test.png")
	f.Fuzz(func(t *testing.T, data []byte, hint string) {
		score, label := ScoreBytes(data, hint)
		if score < 0 || score > 1 {
			t.Fatalf("score out of range: %f", score)
		}
		if label != "" && label != SensitiveLabel {
			t.Fatalf("bad label: %q", label)
		}
	})
}
