package ml

import (
	"encoding/json"
	"math"
	"testing"
)

func TestStandardScaler(t *testing.T) {
	X := [][]float64{
		{1.0, 10.0, 5.0},
		{2.0, 10.0, 15.0},
		{3.0, 10.0, 25.0},
	}

	scaler := NewStandardScaler()
	scaler.Fit(X)

	if len(scaler.Means) != 3 || len(scaler.StdDevs) != 3 {
		t.Fatalf("unexpected dimensions: means=%d stds=%d", len(scaler.Means), len(scaler.StdDevs))
	}

	// For col 1 (index 0): 1, 2, 3 -> mean 2, std sqrt((1+0+1)/3) = sqrt(2/3) ~ 0.81649658
	if math.Abs(scaler.Means[0]-2.0) > 1e-6 {
		t.Errorf("expected mean 2.0, got %v", scaler.Means[0])
	}
	// For col 2 (index 1): constant 10 -> zero variance -> std should be 1
	if scaler.Means[1] != 10.0 || scaler.StdDevs[1] != 1.0 {
		t.Errorf("zero variance column failed: mean=%v std=%v", scaler.Means[1], scaler.StdDevs[1])
	}

	res := scaler.Transform([]float64{2.0, 10.0, 15.0})
	if math.Abs(res[0]) > 1e-6 {
		t.Errorf("expected transformed value 0 for mean, got %v", res[0])
	}
	if res[1] != 0.0 {
		t.Errorf("expected 0 for constant column, got %v", res[1])
	}

	// JSON round-trip
	data, err := json.Marshal(scaler)
	if err != nil {
		t.Fatalf("failed to marshal scaler: %v", err)
	}

	var loaded StandardScaler
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal scaler: %v", err)
	}

	if len(loaded.Means) != len(scaler.Means) || len(loaded.StdDevs) != len(scaler.StdDevs) {
		t.Errorf("loaded dimensions mismatch")
	}
	for i := range scaler.Means {
		if loaded.Means[i] != scaler.Means[i] || loaded.StdDevs[i] != scaler.StdDevs[i] {
			t.Errorf("mismatch at index %d", i)
		}
	}
}
