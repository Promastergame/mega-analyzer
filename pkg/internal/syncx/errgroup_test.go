package syncx

import (
	"context"
	"errors"
	"testing"
)

func TestGroup_Wait(t *testing.T) {
	g, _ := WithContext(context.Background())
	g.Go(func() error { return nil })
	g.Go(func() error { return nil })
	if err := g.Wait(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestGroup_ErrorCanceled(t *testing.T) {
	g, ctx := WithContext(context.Background())
	expectedErr := errors.New("test error")

	g.Go(func() error {
		return expectedErr
	})

	g.Go(func() error {
		<-ctx.Done()
		return ctx.Err()
	})

	err := g.Wait()
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestGroup_TryGo(t *testing.T) {
	g, _ := WithContext(context.Background())
	if !g.TryGo(func() error { return nil }) {
		t.Error("TryGo returned false")
	}
	g.Wait()
}

func TestGroup_SetLimitNegativeDisablesLimit(t *testing.T) {
	g, _ := WithContext(context.Background())
	g.SetLimit(-1)

	if !g.TryGo(func() error { return nil }) {
		t.Fatal("TryGo should succeed when the limit is disabled")
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("Wait returned unexpected error: %v", err)
	}
}

func TestGroup_SetLimitPanicsWhenActive(t *testing.T) {
	g, _ := WithContext(context.Background())
	g.SetLimit(1)
	block := make(chan struct{})
	started := make(chan struct{})
	g.Go(func() error {
		close(started)
		<-block
		return nil
	})
	<-started

	defer func() {
		close(block)
		if err := g.Wait(); err != nil {
			t.Errorf("Wait returned unexpected error: %v", err)
		}
		if recover() == nil {
			t.Error("expected SetLimit to panic while a goroutine is active")
		}
	}()
	g.SetLimit(2)
}

func TestGroup_TryGoReturnsFalseWhenLimitExhausted(t *testing.T) {
	g, _ := WithContext(context.Background())
	g.SetLimit(1)
	block := make(chan struct{})
	started := make(chan struct{})
	g.Go(func() error {
		close(started)
		<-block
		return nil
	})
	<-started

	if g.TryGo(func() error { return nil }) {
		t.Fatal("TryGo should return false when the concurrency limit is exhausted")
	}
	close(block)
	if err := g.Wait(); err != nil {
		t.Fatalf("Wait returned unexpected error: %v", err)
	}
}

func TestGroup_TryGoStoresErrorAndCancelsContext(t *testing.T) {
	g, ctx := WithContext(context.Background())
	expectedErr := errors.New("trygo failure")

	if !g.TryGo(func() error { return expectedErr }) {
		t.Fatal("TryGo returned false")
	}
	if err := g.Wait(); err != expectedErr {
		t.Fatalf("expected %v, got %v", expectedErr, err)
	}
	if cause := context.Cause(ctx); cause != expectedErr {
		t.Fatalf("expected cancellation cause %v, got %v", expectedErr, cause)
	}
}

func TestGroup_TryGoWithLimitReleasesSlot(t *testing.T) {
	g, _ := WithContext(context.Background())
	g.SetLimit(1)

	if !g.TryGo(func() error { return nil }) {
		t.Fatal("first TryGo returned false")
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("Wait returned unexpected error: %v", err)
	}
	if !g.TryGo(func() error { return nil }) {
		t.Fatal("second TryGo should succeed after the first task releases its slot")
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("second Wait returned unexpected error: %v", err)
	}
}
