package trackercollector

import (
	"bytes"
	"net/http"
	"testing"
	"time"
)

func TestBeaconRecordedAndListed(t *testing.T) {
	s := New()
	if err := s.StartBackground("127.0.0.1:0"); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Stop()

	resp, err := http.Post("http://"+s.Addr()+"/beacon", "application/json", bytes.NewBufferString(`{"user":"admin"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.Hits()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	hits := s.Hits()
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if hits[0].Path != "/beacon" || hits[0].Method != "POST" {
		t.Fatalf("unexpected hit: %+v", hits[0])
	}
	if hits[0].BodyLen == 0 {
		t.Fatalf("expected non-empty body length")
	}
}

func TestClear(t *testing.T) {
	s := New()
	if err := s.StartBackground("127.0.0.1:0"); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Stop()

	http.Get("http://" + s.Addr() + "/x")
	time.Sleep(50 * time.Millisecond)
	s.Clear()
	if len(s.Hits()) != 0 {
		t.Fatalf("expected empty after Clear")
	}
}
