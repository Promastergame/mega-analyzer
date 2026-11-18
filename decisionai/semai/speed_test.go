package semai

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestForwardSpeed prints encoder forward throughput (DAI_SPEED=1 go test [-tags nim] -run ForwardSpeed -v ./semai).
func TestForwardSpeed(t *testing.T) {
	if os.Getenv("DAI_SPEED") == "" {
		t.Skip("set DAI_SPEED=1")
	}
	e, err := LoadEncoder("../models/encoder-tiny.dte")
	if err != nil {
		t.Skip(err)
	}
	d, err := LoadCrossEncoderAny("../models/s1-distilled.dte", e)
	if err != nil {
		t.Fatal(err)
	}
	txt := strings.Repeat("Клиент пишет, что сервис не работает уже третий день и он требует вернуть деньги. ", 8)
	for _, n := range []int{16, 48, 128} {
		ids := d.Tokenize(txt, n)
		d.forward(ids, nil)
		t0 := time.Now()
		const R = 50
		for i := 0; i < R; i++ {
			d.forward(ids, nil)
		}
		dt := time.Since(t0) / R
		flop := 2.0 * float64(len(ids)) * float64(len(d.layers)) * float64(4*d.hidden*d.hidden+2*d.hidden*d.inter)
		t.Logf("tokens=%d accel=%v %v/forward  %.1f GFLOP/s (linear layers only)", len(ids), d.acc != nil, dt, flop/dt.Seconds()/1e9)
	}
}
