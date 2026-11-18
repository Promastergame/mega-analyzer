//go:build nim && cgo

package semai

import (
	"fmt"
	"math"
	"sync"
	"testing"
)

func TestNimConcurrentLoadAndForward(t *testing.T) {
	e := loadAcc(t)
	text := "Concurrent model registration must preserve forward results."
	want := e.Encode(text)
	data := wordShareFixture(t)
	start := make(chan struct{})
	errs := make(chan error, 5)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 12; j++ {
				got := e.Encode(text)
				for i, v := range got.Mean {
					if math.Abs(float64(v-want.Mean[i])) > 1e-6 {
						errs <- fmt.Errorf("concurrent forward differs at %d", i)
						return
					}
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 48; i++ {
			loaded, err := ParseEncoder(data)
			if err != nil {
				errs <- err
				return
			}
			if loaded.Native() != "nim" {
				errs <- fmt.Errorf("registered model has no accelerator")
				return
			}
			loaded.Encode("x")
		}
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
