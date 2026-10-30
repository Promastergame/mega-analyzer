package syncx

import (
	"testing"
	"time"
)

func TestSingleFlight_Do(t *testing.T) {
	var sf SingleFlight

	calls := 0
	fn := func() (any, error) {
		calls++
		time.Sleep(100 * time.Millisecond) // artificially delay
		return "result", nil
	}

	ch := make(chan struct{})

	for i := 0; i < 5; i++ {
		go func() {
			val, err, shared := sf.Do("key", fn)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if val != "result" {
				t.Errorf("unexpected value: %v", val)
			}
			_ = shared // ok
			ch <- struct{}{}
		}()
	}

	for i := 0; i < 5; i++ {
		<-ch
	}

	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestSingleFlight_Forget(t *testing.T) {
	var sf SingleFlight
	calls := 0

	sf.Do("foo", func() (any, error) {
		calls++
		return nil, nil
	})

	sf.Forget("foo")

	sf.Do("foo", func() (any, error) {
		calls++
		return nil, nil
	})

	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}
