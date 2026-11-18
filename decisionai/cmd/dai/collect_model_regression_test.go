package main

import (
	"fmt"
	"decisionai/vision"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleFeedback(x int) collectFeedback {
	v := vision.VectorV1{100, 120, 140}
	return collectFeedback{ImgSHA256: strings.Repeat("ab", 32), Width: 100, Height: 100, Box: collectBox{Class: "skin", X: x, Y: 0, W: 1, H: 1}, Vote: 1, Src: "auto", Vector: &v, VectorVersion: vision.VectorVersion}
}
func TestCollectDistinctRegionsAndCorrection(t *testing.T) {
	m := newCollectVectorModel()
	a, b := sampleFeedback(0), sampleFeedback(1)
	if !m.add(a) || !m.add(b) || m.Samples != 2 || m.Classes["skin"].Positive.N != 2 {
		t.Fatalf("regions merged: %+v", m)
	}
	if m.add(a) || m.Samples != 2 {
		t.Fatal("duplicate added")
	}
	a.Vote = -1
	if !m.add(a) || m.Samples != 2 || m.Classes["skin"].Positive.N != 1 || m.Classes["skin"].Negative.N != 1 {
		t.Fatal("correction did not replace label")
	}
	a.Vector = nil
	a.VectorVersion = 0
	m.add(a)
	if m.Samples != 1 || m.Classes["skin"].Negative.N != 0 {
		t.Fatal("vectorless correction retained stale training label")
	}
}
func TestCollectCorrectionAtCapacityAndOwnsVector(t *testing.T) {
	m := newCollectVectorModel()
	for i := 0; i < collectModelMaxSamples; i++ {
		f := sampleFeedback(0)
		f.ImgSHA256 = fmt.Sprintf("%064x", i)
		if !m.add(f) {
			t.Fatal(i)
		}
	}
	f := sampleFeedback(0)
	f.ImgSHA256 = fmt.Sprintf("%064x", 0)
	f.Vote = -1
	if !m.add(f) || m.Samples != collectModelMaxSamples || m.Classes["skin"].Negative.N != 1 {
		t.Fatal("correction blocked at capacity")
	}
	f.ImgSHA256 = fmt.Sprintf("%064x", collectModelMaxSamples)
	if m.add(f) || !m.Limited {
		t.Fatal("capacity not enforced")
	}
	n := newCollectVectorModel()
	f = sampleFeedback(0)
	n.add(f)
	f.Vector[0] = 0
	if n.Records[collectSampleKey(f)].Feedback.Vector[0] != 100 {
		t.Fatal("retained caller-owned vector")
	}
}
func TestCollectAgeCorrectionAndReplay(t *testing.T) {
	m := newCollectVectorModel()
	f := sampleFeedback(0)
	adult := true
	f.Adult = &adult
	m.add(f)
	adult = false
	m.add(f)
	if m.Adult.N != 0 || m.Safe.N != 1 {
		t.Fatal("age correction counted both labels")
	}
	f.Vote = -1
	f.Adult = nil
	m.add(f)
	if m.Safe.N != 0 || m.Adult.N != 0 {
		t.Fatal("rejected region retained age label")
	}
	path := filepath.Join(t.TempDir(), "feedback.jsonl")
	collectModelCache.Path = ""
	collectModelCache.Model = nil
	f = sampleFeedback(0)
	if err := appendCollectFeedback(path, f); err != nil {
		t.Fatal(err)
	}
	f.Vote = -1
	if err := appendCollectFeedback(path, f); err != nil {
		t.Fatal(err)
	}
	f = sampleFeedback(1)
	if err := appendCollectFeedback(path, f); err != nil {
		t.Fatal(err)
	}
	collectModelCache.Path = ""
	collectModelCache.Model = nil
	replay, err := loadCollectModel(path)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Samples != 2 || replay.Classes["skin"].Positive.N != 1 || replay.Classes["skin"].Negative.N != 1 {
		t.Fatal("replay did not apply latest labels")
	}
	if n, err := collectLikes(path, f.ImgSHA256); err != nil || n != 1 {
		t.Fatalf("active budget %d: %v", n, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
func BenchmarkCollectNewSamples(b *testing.B) {
	for i := 0; i < b.N; i++ {
		m := newCollectVectorModel()
		for j := 0; j < 100; j++ {
			f := sampleFeedback(j)
			m.add(f)
		}
	}
}
