package media

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"testing"
)

// makePNG encodes a noisy (high-entropy) image, like real game sprites.
func makePNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	rnd := rand.New(rand.NewSource(1))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, color.RGBA{uint8(rnd.Intn(256)), uint8(rnd.Intn(256)), uint8(rnd.Intn(256)), 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func analyze(t *testing.T, data []byte, name string) (float64, []Region) {
	t.Helper()
	det := NewDetector()
	signals, stats := det.Detect(data)
	fus := NewFusionLayer()
	regions := fus.Fuse(signals)
	cls := NewClassifier()
	class := cls.Classify(stats, regions, name)
	sc := NewScorer()
	regions = sc.AnnotateRegions(regions, class)
	return sc.Score(class, regions, stats), regions
}

// A clean PNG (own magic + normal compression entropy) must not be scored
// as a threat anymore (previously every such file got ~69/100).
func TestCleanPNGScoresZero(t *testing.T) {
	score, regions := analyze(t, makePNG(t), "clean.png")
	if score >= 5 {
		t.Fatalf("clean PNG scored %.2f, want < 5; regions: %+v", score, regions)
	}
	for _, r := range regions {
		if r.Benign && r.Reason == "" {
			t.Fatalf("benign region missing Reason")
		}
	}
}

// A PNG with an appended ZIP archive must still be flagged, with a reason.
func TestPNGWithAppendedZIPStillFlagged(t *testing.T) {
	data := makePNG(t)
	// Minimal ZIP: local file header + EOCD magic bytes appended after IEND.
	zipStub := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x41}, 64)...)
	zipStub = append(zipStub, []byte("PK\x05\x06")...)
	zipStub = append(zipStub, make([]byte, 18)...)
	data = append(data, zipStub...)
	score, regions := analyze(t, data, "polyglot.png")
	if score < 20 {
		t.Fatalf("PNG+ZIP polyglot scored only %.2f, want >= 20; regions: %+v", score, regions)
	}
	hasReason := false
	for _, r := range regions {
		if !r.Benign && r.Reason != "" {
			hasReason = true
		}
	}
	if !hasReason {
		t.Fatalf("suspicious regions have no Reason; regions: %+v", regions)
	}
}
