package cdpconn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/testutil"
	"mega-analyzer/pkg/internal/wsx"
)

func TestExecuteCorrelatesConcurrentResponses(t *testing.T) {
	ws, server := testutil.WebSocketPair(t)
	c := NewConn(ws)
	t.Cleanup(func() { c.Close() })
	c.SetSessionID("session-42")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if FromContext(ctx) != nil || FromContext(WithConn(ctx, c)) != c {
		t.Fatal("connection context")
	}
	const count = 12
	serverDone := make(chan error, 1)
	go func() {
		requests := make([]wireMessage, 0, count)
		for i := 0; i < count; i++ {
			p, _, err := wsx.ReadClientData(server)
			if err != nil {
				serverDone <- err
				return
			}
			var req wireMessage
			if err := json.Unmarshal(p, &req); err != nil {
				serverDone <- err
				return
			}
			var params struct {
				Value int `json:"value"`
			}
			if err := json.Unmarshal(req.Params, &params); err != nil {
				serverDone <- err
				return
			}
			if req.Method != fmt.Sprintf("Test.%d", params.Value) || req.SessionID != "session-42" {
				serverDone <- fmt.Errorf("request=%s", p)
				return
			}
			requests = append(requests, req)
		}
		// Reply in reverse order, not goroutine order: each waiter must get its ID.
		for i := len(requests) - 1; i >= 0; i-- {
			req := requests[i]
			data, _ := json.Marshal(map[string]interface{}{"id": req.ID, "result": json.RawMessage(req.Params)})
			if err := wsx.WriteServerText(server, data); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var result struct {
				Value int `json:"value"`
			}
			err := c.Execute(ctx, fmt.Sprintf("Test.%d", i), map[string]int{"value": i}, &result)
			if err == nil && result.Value != i {
				err = fmt.Errorf("response %d got %d", i, result.Value)
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	for i := 0; i < count; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	if err := <-serverDone; err != nil {
		t.Error(err)
	}
	c.mu.Lock()
	remaining := len(c.pending)
	c.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("leaked %d requests", remaining)
	}
}

func TestExecuteErrorsAndEmptyParams(t *testing.T) {
	for _, tt := range []struct {
		name, response string
		result         interface{}
		want           string
	}{
		{"success", `"result":{}`, nil, ""},
		{"protocol", `"error":{"code":-32000,"message":"denied","data":"details"}`, nil, "cdp error -32000: denied (details)"},
		{"bad-result", `"result":"wrong"`, new(int), "cannot unmarshal"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ws, server := testutil.WebSocketPair(t)
			c := NewConn(ws)
			t.Cleanup(func() { c.Close() })
			done := make(chan error, 1)
			go func() {
				p, _, err := wsx.ReadClientData(server)
				if err != nil {
					done <- err
					return
				}
				var req wireMessage
				if err = json.Unmarshal(p, &req); err != nil {
					done <- err
					return
				}
				if string(req.Params) != "{}" || req.SessionID != "" {
					done <- fmt.Errorf("empty params/session: %s", p)
					return
				}
				done <- wsx.WriteServerText(server, []byte(fmt.Sprintf(`{"id":%d,%s}`, req.ID, tt.response)))
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := c.Execute(ctx, "Test.command", nil, tt.result)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !containsError(err, tt.want) {
				t.Fatalf("err=%v want %s", err, tt.want)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
	if got := (&ProtoError{Code: 1, Message: "bad"}).Error(); got != "cdp error 1: bad" {
		t.Fatal(got)
	}
}

func containsError(err error, s string) bool { return err != nil && strings.Contains(err.Error(), s) }

func TestExecuteCancellationAndClosedPeer(t *testing.T) {
	for _, closePeer := range []bool{false, true} {
		t.Run(fmt.Sprint(closePeer), func(t *testing.T) {
			ws, server := testutil.WebSocketPair(t)
			c := NewConn(ws)
			t.Cleanup(func() { c.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, _, err := wsx.ReadClientData(server)
				if err == nil {
					if closePeer {
						server.Close()
					} else {
						cancel()
					}
				}
				done <- err
			}()
			err := c.Execute(ctx, "Test.wait", nil, nil)
			if closePeer {
				if err == nil || !containsError(err, "closed") {
					t.Fatalf("peer close=%v", err)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel=%v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			n := len(c.pending)
			c.mu.Unlock()
			if n != 0 {
				t.Fatal("pending request retained")
			}
		})
	}
}

func TestMarshalAndWriteErrors(t *testing.T) {
	ws, server := testutil.WebSocketPair(t)
	c := NewConn(ws)
	t.Cleanup(func() { c.Close() })
	if err := c.Execute(context.Background(), "Bad", make(chan int), nil); err == nil {
		t.Fatal("unsupported JSON params accepted")
	}
	c.Close()
	server.Close()
	if err := c.Execute(context.Background(), "Closed", nil, nil); err == nil {
		t.Fatal("closed write succeeded")
	}
}

func TestEventDispatchAndMalformedInput(t *testing.T) {
	type event struct {
		Value int `json:"value"`
	}
	const method = "Coverage.testEvent"
	RegisterEvent(method, func() interface{} { return &event{} })
	t.Cleanup(func() { evMu.Lock(); delete(eventFactories, method); evMu.Unlock() })
	ws, server := testutil.WebSocketPair(t)
	c := NewConn(ws)
	t.Cleanup(func() { c.Close() })
	events := make(chan interface{}, 4)
	c.SetDispatch(func(ev interface{}) { events <- ev })
	done := make(chan error, 1)
	go func() {
		payloads := []string{`broken`, `{"id":9999,"result":{}}`, `{}`, `{"method":"Unknown.event","params":{}}`, `{"method":"Coverage.testEvent","params":{"value":"bad"}}`, `{"method":"Coverage.testEvent","params":{"value":7}}`, `{"method":"Coverage.testEvent"}`}
		if err := wsx.WriteServerBinary(server, []byte(`{"method":"Coverage.testEvent"}`)); err != nil {
			done <- err
			return
		}
		for _, p := range payloads {
			if err := wsx.WriteServerText(server, []byte(p)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for _, want := range []int{7, 0} {
		select {
		case raw := <-events:
			ev, ok := raw.(*event)
			if !ok || ev.Value != want {
				t.Fatalf("event=%#v want %d", raw, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("event not dispatched")
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case unexpected := <-events:
		t.Fatalf("unexpected event %#v", unexpected)
	default:
	}
}
