package labkit

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"
)

func BenchmarkMetricsObserve(b *testing.B) {
	m := NewMetrics()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Observe("lat", 1500*time.Microsecond)
		}
	})
}

func BenchmarkScenarioRoll(b *testing.B) {
	s := NewScenario(ScenarioConfig{ErrorRate: 0.1, TimeoutRate: 0.05, Seed: 99})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = s.Roll()
	}
}

func BenchmarkFrameRoundTrip(b *testing.B) {
	payload := bytes.Repeat([]byte("z"), 512)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		_ = writeFrame(bw, wsFrame{fin: true, opcode: opBinary, masked: true, maskKey: [4]byte{1, 2, 3, 4}, payload: payload})
		_ = bw.Flush()
		if _, err := readFrame(bufio.NewReader(&buf)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHTTPHealth(b *testing.B) {
	cfg := &Config{Servers: []ServerConfig{{Name: "web", Kind: "http", Addr: "127.0.0.1:0", HTTP: &HTTPConfig{}}}}
	mgr := startManager(b, cfg)
	url := "http://" + serviceAddr(b, mgr, "web") + "/_health"
	client := &http.Client{Timeout: 5 * time.Second}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
