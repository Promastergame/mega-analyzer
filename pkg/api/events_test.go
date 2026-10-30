package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventBroker_Singleton(t *testing.T) {
	b1 := GetBroker()
	b2 := GetBroker()
	if b1 != b2 {
		t.Error("expected singleton broker instance")
	}
}

func TestEventBroker_Broadcast(t *testing.T) {
	broker := GetBroker()

	// Clear existing clients if any
	broker.mu.Lock()
	for k := range broker.clients {
		delete(broker.clients, k)
	}
	broker.mu.Unlock()

	client := make(chan ScanEvent, 10)
	broker.register <- client
	time.Sleep(10 * time.Millisecond) // let run() loop process

	broker.Broadcast("info", "test broadcast", nil)

	select {
	case ev := <-client:
		if ev.Type != "info" || ev.Message != "test broadcast" {
			t.Errorf("unexpected event: %+v", ev)
		}
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for broadcast event")
	}

	broker.deregister <- client
	time.Sleep(10 * time.Millisecond) // let run() loop process
}

func TestEventBroker_ServeHTTP(t *testing.T) {
	broker := GetBroker()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	// This blocks until context is done or flusher error
	broker.ServeHTTP(rr, req)

	// In Go 1.20+, ResponseRecorder doesn't implement http.Flusher directly if you just check w.(http.Flusher)
	// Wait, httptest.ResponseRecorder DOES implement http.Flusher.
	body := rr.Body.String()
	if !strings.Contains(body, "Diagnostic Event Stream Established") {
		t.Errorf("expected initial event in body, got %s", body)
	}
}

func TestEventBroker_ServeHTTP_NoFlusher(t *testing.T) {
	broker := GetBroker()

	// Custom writer without Flusher
	rr := httptest.NewRecorder()
	w := &noFlusherWriter{rr}
	req := httptest.NewRequest(http.MethodGet, "/events", nil)

	broker.ServeHTTP(w, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 status for no flusher, got %d", rr.Code)
	}
}

type noFlusherWriter struct {
	http.ResponseWriter
}

// We override any potential Flusher interface
// The interface conversion w.(http.Flusher) fails for this struct because it doesn't declare it.
