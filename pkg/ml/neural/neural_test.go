package neural

import (
	"math"
	"testing"
	"time"
)

func TestTimelineEncoder_Encode(t *testing.T) {
	// Case 1: Buckets <= 0 (defaults to 8)
	encDefault := TimelineEncoder{Buckets: 0}
	emptyVec := encDefault.Encode(nil)
	if len(emptyVec) != 12 { // 8 buckets + 4 extra
		t.Fatalf("Expected default vector length 12, got %d", len(emptyVec))
	}
	for _, val := range emptyVec {
		if val != 0.0 {
			t.Errorf("Expected 0.0, got %f", val)
		}
	}

	// Case 2: events with length 0
	enc5 := TimelineEncoder{Buckets: 5}
	if len(enc5.Encode([]Event{})) != 9 {
		t.Fatal("Expected vector length 9 for 5 buckets")
	}

	// Case 3: single event (window <= 0 scenario)
	t0 := time.Now()
	evs1 := []Event{
		{At: t0, Kind: "NetworkEvent", Subject: "host.com", Value: 2.5},
	}
	vec1 := enc5.Encode(evs1)
	// For 1 event, scale is 1.0. Buckets=5. First=t0, Last=t0 -> window = 0 -> window = 1 second.
	// pos = (At - first)/window * (Buckets-1) = 0.
	// vec[0] = 1, vec[5] = 2.5 (value), vec[6] = 1 (count), vec[7] = 1 (network/dns matches), vec[8] = 0 (file/reg)
	// multiplied by scale = 1.0.
	expected1 := []float64{1.0, 0, 0, 0, 0, 2.5, 1.0, 1.0, 0.0}
	for i, v := range vec1 {
		if math.Abs(v-expected1[i]) > 1e-9 {
			t.Errorf("Expected vec[%d] = %f, got %f", i, expected1[i], v)
		}
	}

	// Case 4: multiple events, proper ordering, check position calculations and scaling
	// We want events to span some time. Let's make t0, t0+50s, t0+100s.
	// window = 100s. Buckets = 5.
	// event 0: t0 -> pos = 0. Kind = "dns", Value = 1
	// event 1: t0+50s -> pos = int(50/100 * 4) = 2. Kind = "file", Value = 3
	// event 2: t0+100s -> pos = int(100/100 * 4) = 4. Kind = "reg", Value = 5
	// total count = 3. scale = 1/3.
	// Buckets:
	// vec[0] = 1, vec[1] = 0, vec[2] = 1, vec[3] = 0, vec[4] = 1
	// vec[5] (Value sum) = 1 + 3 + 5 = 9
	// vec[6] (Count sum) = 3
	// vec[7] (Network/DNS match) = 1 (dns)
	// vec[8] (File/Reg match) = 2 (file, reg)
	// Scaled by 1/3:
	// vec = [1/3, 0, 1/3, 0, 1/3, 3, 1, 1/3, 2/3]
	evs2 := []Event{
		{At: t0, Kind: "dns", Subject: "google.com", Value: 1.0},
		{At: t0.Add(50 * time.Second), Kind: "file-write", Subject: "file.txt", Value: 3.0},
		{At: t0.Add(100 * time.Second), Kind: "reg-read", Subject: "key", Value: 5.0},
	}
	vec2 := enc5.Encode(evs2)
	expected2 := []float64{1.0 / 3.0, 0, 1.0 / 3.0, 0, 1.0 / 3.0, 3.0, 1.0, 1.0 / 3.0, 2.0 / 3.0}
	for i, v := range vec2 {
		if math.Abs(v-expected2[i]) > 1e-9 {
			t.Errorf("Expected vec2[%d] = %f, got %f", i, expected2[i], v)
		}
	}

	// Case 5: event ordering checks.
	// We pass out-of-order events to ensure first and last times are found correctly.
	// event 0: t0+50s
	// event 1: t0 (earliest)
	// event 2: t0+100s (latest)
	evs3 := []Event{
		{At: t0.Add(50 * time.Second), Kind: "other", Subject: "a", Value: 0},
		{At: t0, Kind: "other", Subject: "b", Value: 0},
		{At: t0.Add(100 * time.Second), Kind: "other", Subject: "c", Value: 0},
	}
	vec3 := enc5.Encode(evs3)
	// Scale = 1/3.
	// first = t0, last = t0+100s. window = 100s.
	// ev 0: pos = 2
	// ev 1: pos = 0
	// ev 2: pos = 4
	// vec = [1/3, 0, 1/3, 0, 1/3, 0, 1, 0, 0]
	expected3 := []float64{1.0 / 3.0, 0, 1.0 / 3.0, 0, 1.0 / 3.0, 0.0, 1.0, 0.0, 0.0}
	for i, v := range vec3 {
		if math.Abs(v-expected3[i]) > 1e-9 {
			t.Errorf("Expected vec3[%d] = %f, got %f", i, expected3[i], v)
		}
	}

	// Case 6: testing bounds clamping of pos
	// event outside window (negative diff or pos >= Buckets due to math precision, though usually pos is inside [0, Buckets-1])
	// Let's create an event where pos would be negative if At < first.
	// Actually, the code calculates:
	// first := events[0].At, last := events[0].At
	// and then scans events[1:] to find absolute first and last.
	// So first and last will always bound all events' At!
	// Therefore At - first is always >= 0, and At - first <= window.
	// But let's check what if pos gets clamped if we manually set some times.
	// Since the code logic ensures pos is between 0 and Buckets-1, it is safe.
	// Let's test a case where we have event Kind that doesn't match network/dns/file/reg
	evs4 := []Event{
		{At: t0, Kind: "process-start", Subject: "cmd.exe", Value: 10},
	}
	vec4 := enc5.Encode(evs4)
	if vec4[7] != 0 || vec4[8] != 0 {
		t.Errorf("Expected network and file matches to be 0, got net=%f, file=%f", vec4[7], vec4[8])
	}
}

func TestSimilarity(t *testing.T) {
	// Case 1: Empty or mismatched lengths
	if Similarity(nil, []float64{1}) != 0 {
		t.Error("Expected 0 similarity for nil")
	}
	if Similarity([]float64{1}, []float64{1, 2}) != 0 {
		t.Error("Expected 0 similarity for mismatched lengths")
	}

	// Case 2: Zero magnitudes
	if Similarity([]float64{0, 0}, []float64{1, 1}) != 0 {
		t.Error("Expected 0 similarity for zero vector")
	}
	if Similarity([]float64{1, 1}, []float64{0, 0}) != 0 {
		t.Error("Expected 0 similarity for zero vector")
	}

	// Case 3: Identical vectors
	sim1 := Similarity([]float64{3, 4}, []float64{3, 4})
	if math.Abs(sim1-1.0) > 1e-9 {
		t.Errorf("Expected similarity 1.0, got %f", sim1)
	}

	// Case 4: Orthogonal vectors
	sim2 := Similarity([]float64{1, 0}, []float64{0, 1})
	if math.Abs(sim2-0.0) > 1e-9 {
		t.Errorf("Expected similarity 0.0, got %f", sim2)
	}

	// Case 5: Opposite vectors
	sim3 := Similarity([]float64{1, 1}, []float64{-1, -1})
	if math.Abs(sim3+1.0) > 1e-9 {
		t.Errorf("Expected similarity -1.0, got %f", sim3)
	}
}

func TestAnomalyScore_Score(t *testing.T) {
	// Case 1: Mismatched lengths or empty
	as := AnomalyScore{Mean: []float64{1, 2}, StdDev: []float64{0.5, 0.5}}
	if as.Score([]float64{1}) != 0 {
		t.Error("Expected 0 for mismatched length")
	}
	if (AnomalyScore{}).Score([]float64{1}) != 0 {
		t.Error("Expected 0 for empty mean/stddev")
	}
	asMismatch := AnomalyScore{Mean: []float64{1, 2}, StdDev: []float64{0.5}}
	if asMismatch.Score([]float64{1, 2}) != 0 {
		t.Error("Expected 0 for mismatched mean and stddev lengths")
	}

	// Case 2: Normal scoring with positive stddev
	// mean = [1.0, 2.0], stddev = [0.5, 1.0]
	// x = [2.0, 2.0]
	// d[0] = (2 - 1) / 0.5 = 2 -> d[0]^2 = 4
	// d[1] = (2 - 2) / 1.0 = 0 -> d[1]^2 = 0
	// z = 4
	// Score = 1 - exp(-sqrt(4)/3) = 1 - exp(-2/3)
	score := as.Score([]float64{2.0, 2.0})
	expected := 1.0 - math.Exp(-2.0/3.0)
	if math.Abs(score-expected) > 1e-9 {
		t.Errorf("Expected score %f, got %f", expected, score)
	}

	// Case 3: StdDev <= 0 gets clamped to 1
	asZeroStd := AnomalyScore{Mean: []float64{1.0}, StdDev: []float64{0.0}}
	// x = [2.0]
	// stddev gets clamped to 1.0
	// d = (2 - 1) / 1.0 = 1 -> z = 1
	// Score = 1 - exp(-1/3)
	scoreZeroStd := asZeroStd.Score([]float64{2.0})
	expectedZeroStd := 1.0 - math.Exp(-1.0/3.0)
	if math.Abs(scoreZeroStd-expectedZeroStd) > 1e-9 {
		t.Errorf("Expected score %f, got %f", expectedZeroStd, scoreZeroStd)
	}
}

func TestFusion(t *testing.T) {
	// Case 1: DefaultFusion
	f := DefaultFusion()
	if f.WTimeline != 0.22 || f.WSimilarity != 0.18 || f.WAnomaly != 0.22 || f.WStatic != 0.20 || f.WSandbox != 0.18 {
		t.Error("DefaultFusion has incorrect weights")
	}

	// Case 2: Score within bounds
	// timeline=0.5, similarity=0.5, anomaly=0.5, static=0.5, sandbox=0.5
	// sum = 0.5 * (0.22 + 0.18 + 0.22 + 0.20 + 0.18) = 0.5 * 1.0 = 0.5
	// Score should be 0.5 * 100 = 50.0
	s := f.Score(0.5, 0.5, 0.5, 0.5, 0.5)
	if math.Abs(s-50.0) > 1e-9 {
		t.Errorf("Expected score 50.0, got %f", s)
	}

	// Case 3: Score clamping (underflow)
	fCustom := Fusion{WTimeline: -1.0}
	sUnder := fCustom.Score(1.0, 0, 0, 0, 0)
	if sUnder != 0 {
		t.Errorf("Expected score clamped to 0, got %f", sUnder)
	}

	// Case 4: Score clamping (overflow)
	fCustom2 := Fusion{WTimeline: 2.0}
	sOver := fCustom2.Score(1.0, 0, 0, 0, 0)
	if sOver != 100 {
		t.Errorf("Expected score clamped to 100, got %f", sOver)
	}
}

func TestFingerprint(t *testing.T) {
	// Case 1: normal fingerprinting
	events := []Event{
		{Kind: "DNS", Subject: "Google.com"},
		{Kind: "", Subject: ""}, // Should produce ":" which is ignored
		{Kind: "File", Subject: "secret.txt"},
	}
	fp := Fingerprint(events)
	if len(fp) != 2 {
		t.Fatalf("Expected fingerprint length 2, got %d", len(fp))
	}
	// Sort order: "dns:google.com" < "file:secret.txt"
	if fp[0] != "dns:google.com" {
		t.Errorf("Expected fp[0] to be dns:google.com, got %s", fp[0])
	}
	if fp[1] != "file:secret.txt" {
		t.Errorf("Expected fp[1] to be file:secret.txt, got %s", fp[1])
	}
}
