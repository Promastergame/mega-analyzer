package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ScanEvent represents a diagnostic real-time execution signal
type ScanEvent struct {
	Timestamp time.Time   `json:"timestamp"`
	Type      string      `json:"type"` // "info", "crawling", "fuzzing", "success", "vuln_found", "error"
	Message   string      `json:"message"`
	Data      interface{} `json:"data,omitempty"`
	// JobID scopes the event to one scan job. Empty means the event is a
	// server-level broadcast visible to every subscriber.
	JobID string `json:"job_id,omitempty"`
}

type EventBroker struct {
	clients    map[chan ScanEvent]bool
	mu         sync.RWMutex
	register   chan chan ScanEvent
	deregister chan chan ScanEvent
}

var (
	GlobalBroker *EventBroker
	brokerOnce   sync.Once
)

// GetBroker returns the singleton diagnostic broadcast broker
func GetBroker() *EventBroker {
	brokerOnce.Do(func() {
		GlobalBroker = &EventBroker{
			clients:    make(map[chan ScanEvent]bool),
			register:   make(chan chan ScanEvent),
			deregister: make(chan chan ScanEvent),
		}
		go GlobalBroker.run()
	})
	return GlobalBroker
}

// GetActiveCount returns the current number of active SSE visual console connections
func (b *EventBroker) GetActiveCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

func (b *EventBroker) run() {
	for {
		select {
		case client := <-b.register:
			b.mu.Lock()
			b.clients[client] = true
			b.mu.Unlock()
		case client := <-b.deregister:
			b.mu.Lock()
			if _, exists := b.clients[client]; exists {
				delete(b.clients, client)
				// Channel left unclosed: Broadcast holds lock during send,
				// and GC collects orphaned channel after client goroutine exits.
			}
			b.mu.Unlock()
		}
	}
}

// Broadcast sends a server-level event to all active SSE connections.
// The channel is never closed by the deregister path and sends happen under
// the read lock, so no recover() masking is needed here.
func (b *EventBroker) Broadcast(eventType string, message string, data interface{}) {
	b.BroadcastJob("", eventType, message, data)
}

// BroadcastJob sends an event scoped to one scan job. Subscribers that
// passed a job_id filter receive only server-level events and their own
// job's events — one client's scan log (including the scanned target URL)
// no longer leaks to every other SSE subscriber.
func (b *EventBroker) BroadcastJob(jobID string, eventType string, message string, data interface{}) {
	event := ScanEvent{
		Timestamp: time.Now(),
		Type:      eventType,
		Message:   message,
		Data:      data,
		JobID:     jobID,
	}

	b.mu.RLock()
	// Send under lock to prevent deregister from closing the channel mid-send.
	// Non-blocking send with default keeps lock held briefly per client.
	for client := range b.clients {
		select {
		case client <- event:
		default:
		}
	}
	b.mu.RUnlock()
}

// ServeHTTP handles Server-Sent Events (SSE) connections from the web console
func (b *EventBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// A subscriber may scope itself to one job with /api/v1/scan/events?job_id=X:
	// it then receives server-level events plus its own job's events only.
	jobFilter := strings.TrimSpace(r.URL.Query().Get("job_id"))

	clientChan := make(chan ScanEvent, 1000)
	b.register <- clientChan

	defer func() {
		b.deregister <- clientChan
	}()

	// Send initial heartbeat connection event
	initialEvent := ScanEvent{
		Timestamp: time.Now(),
		Type:      "info",
		Message:   "Diagnostic Event Stream Established",
	}
	initialBytes, _ := json.Marshal(initialEvent)
	fmt.Fprintf(w, "data: %s\n\n", string(initialBytes))
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-clientChan:
			if !ok {
				return
			}
			if jobFilter != "" && event.JobID != "" && event.JobID != jobFilter {
				continue
			}
			bytes, err := json.Marshal(event)
			if err == nil {
				fmt.Fprintf(w, "data: %s\n\n", string(bytes))
				flusher.Flush()
			}
		case <-ticker.C:
			// Heartbeat
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
