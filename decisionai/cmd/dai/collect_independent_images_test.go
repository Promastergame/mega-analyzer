package main

import (
	"fmt"
	"testing"

	"decisionai/vision"
)

func independentFeedback(image, region, vote int) collectFeedback {
	f := sampleFeedback(region)
	f.ImgSHA256 = fmt.Sprintf("%064x", image)
	f.Box.Class = "blood_dark"
	f.Vote = vote
	v := vision.VectorV1{}
	if vote < 0 {
		for i := range v {
			v[i] = 255
		}
	}
	f.Vector = &v
	return f
}

func TestCollectCropsOfOneImageDoNotUnlockPredictions(t *testing.T) {
	m := newCollectVectorModel()
	for region := 0; region < 5; region++ {
		m.add(independentFeedback(1, region, 1))
	}
	for image := 2; image < 5; image++ {
		m.add(independentFeedback(image, 0, -1))
	}
	if got := m.predict(vision.VectorV1{}); got.Class != "" || got.Reason != "insufficient_distinct_images" {
		t.Fatalf("correlated labels unlocked a prediction: %+v", got)
	}
	if p := m.Classes["blood_dark"].Positive; p.N != 5 || p.Images != 1 {
		t.Fatalf("region/image accounting lost: %+v", p)
	}
	m.add(independentFeedback(5, 0, 1))
	m.add(independentFeedback(6, 0, 1))
	if got := m.predict(vision.VectorV1{}); got.Class != "blood_dark" || got.Score < 60 {
		t.Fatalf("independent labels did not enable matching: %+v", got)
	}
	// Correcting the last label on a distinct image removes its support,
	// even though enough positive regions remain on the first image.
	m.add(independentFeedback(6, 0, -1))
	if got := m.predict(vision.VectorV1{}); got.Class != "" || m.Classes["blood_dark"].Positive.Images != 2 {
		t.Fatalf("correction retained stale independent support: %+v", got)
	}
}

func TestCollectIndependentCountsSurviveReplay(t *testing.T) {
	path := t.TempDir() + "/labels.jsonl"
	for image := 1; image <= 3; image++ {
		for _, vote := range []int{1, -1} {
			f := independentFeedback(image+10*(1-vote), 0, vote)
			if err := appendCollectFeedback(path, f); err != nil {
				t.Fatal(err)
			}
		}
	}
	collectModelCache.Path, collectModelCache.Model = "", nil
	m, err := loadCollectModel(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.predict(vision.VectorV1{}); got.Class != "blood_dark" || m.Classes["blood_dark"].Positive.Images != 3 || m.Classes["blood_dark"].Negative.Images != 3 {
		t.Fatalf("replay changed independent support: %+v", got)
	}
}
