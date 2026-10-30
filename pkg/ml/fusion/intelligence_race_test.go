package fusion

import (
	"fmt"
	"sync"
	"testing"
)

func TestIntelligenceRaceSafety(t *testing.T) {
	t.Parallel()
	cfg := IntelligenceConfig{
		Schema:           []string{"f1", "f2", "f3", "f4", "f5"},
		OnlineLR:         0.01,
		AnomalyWeight:    1.0,
		SimilarityWeight: 0.8,
		OnlineWeight:     1.0,
	}
	intel := NewIntelligence(cfg)

	const goroutines = 20
	const iters = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				s := Sample{
					ID:       fmt.Sprintf("sample-%d-%d", id, i),
					Features: []float64{float64(id), float64(i), 0.5, 0.3, 0.1},
				}
				_, _ = intel.Analyze(s)
				_ = intel.Learn(s, i%2, "label")
			}
		}(g)
	}
	wg.Wait()
}
