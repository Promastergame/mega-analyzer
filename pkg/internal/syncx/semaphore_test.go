package syncx

import (
	"context"
	"testing"
)

func TestSemaphore(t *testing.T) {
	s := NewSemaphore(2)

	if s.Available() != 2 {
		t.Errorf("expected 2 available, got %d", s.Available())
	}

	if err := s.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}

	if s.Available() != 1 {
		t.Errorf("expected 1 available, got %d", s.Available())
	}

	if !s.TryAcquire() {
		t.Fatal("TryAcquire should succeed")
	}

	if s.Available() != 0 {
		t.Errorf("expected 0 available, got %d", s.Available())
	}

	if s.TryAcquire() {
		t.Fatal("TryAcquire should fail when semaphore is full")
	}

	s.Release()
	if s.Available() != 1 {
		t.Errorf("expected 1 available, got %d", s.Available())
	}
}

func TestSemaphore_ContextCancel(t *testing.T) {
	s := NewSemaphore(1)
	s.Acquire(context.Background()) // fill

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	if err := s.Acquire(ctx); err == nil {
		t.Fatal("expected error on cancelled context")
	}
}
