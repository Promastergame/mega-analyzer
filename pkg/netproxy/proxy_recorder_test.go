package netproxy

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestPacketRecorder_RingKeepsNewestInOrder verifies the circular buffer keeps
// the most recent recorderRingCapacity packets, oldest-first, once it overflows.
func TestPacketRecorder_RingKeepsNewestInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rec.jsonl")
	r, err := NewPacketRecorder(path)
	if err != nil {
		t.Fatalf("NewPacketRecorder: %v", err)
	}
	defer r.Close()

	total := recorderRingCapacity + 500
	for i := 0; i < total; i++ {
		r.Record(Packet{Direction: DirectionClientToServer, Size: 1})
	}

	pkts := r.Packets()
	if len(pkts) != recorderRingCapacity {
		t.Fatalf("ring retained %d packets, want %d", len(pkts), recorderRingCapacity)
	}
	// IDs are auto-stamped 1..total; the retained window must be the newest
	// capacity of them, in ascending order.
	wantFirst := uint64(total - recorderRingCapacity + 1)
	if pkts[0].ID != wantFirst {
		t.Errorf("oldest retained ID = %d, want %d", pkts[0].ID, wantFirst)
	}
	for i := 1; i < len(pkts); i++ {
		if pkts[i].ID != pkts[i-1].ID+1 {
			t.Fatalf("ring not in ascending order at %d: %d after %d", i, pkts[i].ID, pkts[i-1].ID)
		}
	}
	if r.Count() != uint64(total) {
		t.Errorf("Count = %d, want %d", r.Count(), total)
	}
}

// TestPacketRecorder_CloseFlushesWrites checks that every queued write reaches
// disk before Close returns (up to any counted drops).
func TestPacketRecorder_CloseFlushesWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rec.jsonl")
	r, err := NewPacketRecorder(path)
	if err != nil {
		t.Fatalf("NewPacketRecorder: %v", err)
	}

	const n = 100
	for i := 0; i < n; i++ {
		r.Record(Packet{Direction: DirectionClientToServer, Size: 1})
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Count the JSONL lines actually written.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	lines := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var p Packet
		if err := json.Unmarshal(sc.Bytes(), &p); err != nil {
			t.Fatalf("bad JSONL line: %v", err)
		}
		lines++
	}
	// With a 4096-deep buffer and only 100 writes, nothing should have dropped.
	if uint64(lines)+r.DroppedWrites() != n {
		t.Errorf("written(%d) + dropped(%d) != recorded(%d)", lines, r.DroppedWrites(), n)
	}
	if r.DroppedWrites() != 0 {
		t.Errorf("unexpected drops for a small batch: %d", r.DroppedWrites())
	}
}

// TestPacketRecorder_RecordCloseRace exercises concurrent Record and Close to
// ensure no send-on-closed-channel panic under -race.
func TestPacketRecorder_RecordCloseRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rec.jsonl")
	r, err := NewPacketRecorder(path)
	if err != nil {
		t.Fatalf("NewPacketRecorder: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				r.Record(Packet{Direction: DirectionClientToServer, Size: 1})
			}
		}()
	}
	// Close while writers are still going.
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()
	// Extra records after Close must be safe no-ops (dropped, no panic).
	r.Record(Packet{Direction: DirectionClientToServer, Size: 1})
}
