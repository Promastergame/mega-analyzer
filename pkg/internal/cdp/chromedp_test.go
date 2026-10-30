package chromedp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/cdp/cdpconn"
	"mega-analyzer/pkg/internal/testutil"
	"mega-analyzer/pkg/internal/wsx"
)

func TestAllocatorAndFlags(t *testing.T) {
	opts := append([]ExecAllocatorOption(nil), DefaultExecAllocatorOptions[:]...)
	opts = append(opts, ExecPath("custom-chrome"), Flag("headless", false), Flag("window-size", "800,600"))
	ctx, cancel := NewExecAllocator(context.Background(), opts...)
	defer cancel()
	child, closeChild := NewContext(ctx)
	defer closeChild()
	c := FromContext(child)
	if c == nil || c.alloc.path != "custom-chrome" || c.alloc.flags["headless"] != false || c.alloc.flags["mute-audio"] != true {
		t.Fatalf("allocator=%+v", c)
	}
	for _, tt := range []struct {
		value interface{}
		want  []string
	}{{true, []string{"--test"}}, {false, nil}, {"a b", []string{"--test=a b"}}, {42, []string{"--test=42"}}} {
		if got := flagToArgs("test", tt.value); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("flag %v=%v want %v", tt.value, got, tt.want)
		}
	}
	if FromContext(context.Background()) != nil {
		t.Fatal("unexpected browser context")
	}
	plain, closePlain := NewContext(context.Background())
	defer closePlain()
	if FromContext(plain).alloc.flags == nil {
		t.Fatal("default allocator missing")
	}
}

func TestRunOrderingAndListenerSnapshot(t *testing.T) {
	ctx, cancel := NewContext(context.Background())
	defer cancel()
	c := FromContext(ctx)
	c.startOnce.Do(func() {}) // No browser needed for pure action sequencing.
	called := []int{}
	stop := errors.New("stop")
	err := Run(ctx, nil, ActionFunc(func(context.Context) error { called = append(called, 1); return nil }), ActionFunc(func(context.Context) error { called = append(called, 2); return stop }), ActionFunc(func(context.Context) error { called = append(called, 3); return nil }))
	if !errors.Is(err, stop) || !reflect.DeepEqual(called, []int{1, 2}) {
		t.Fatalf("actions=%v err=%v", called, err)
	}
	if err := Run(context.Background()); err == nil {
		t.Fatal("missing context accepted")
	}
	if err := Run(ctx, nil); err != nil {
		t.Fatal(err)
	}
	ListenTarget(context.Background(), func(interface{}) { t.Error("listener should not be installed") })
	events := []string{}
	ListenTarget(ctx, func(ev interface{}) {
		events = append(events, "first:"+ev.(string))
		ListenTarget(ctx, func(ev interface{}) { events = append(events, "late:"+ev.(string)) })
	})
	c.dispatch("a")
	c.dispatch("b")
	if !reflect.DeepEqual(events, []string{"first:a", "first:b", "late:b"}) {
		t.Fatalf("listener snapshot=%v", events)
	}
}

func TestMissingExecutableAndCleanup(t *testing.T) {
	parent, cancel := NewExecAllocator(context.Background(), ExecPath(filepath.Join(t.TempDir(), "missing-chrome")), Flag("headless", true))
	defer cancel()
	ctx, closeBrowser := NewContext(parent)
	defer closeBrowser()
	first := Run(ctx)
	if first == nil {
		t.Fatal("missing executable succeeded")
	}
	if second := Run(ctx); second != first {
		t.Fatal("lazy startup was retried")
	}
	dir := FromContext(ctx).userDataDir
	if dir == "" {
		t.Fatal("temporary profile not recorded")
	}
	closeBrowser()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("profile retained: %v", err)
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestReadDevToolsEndpoint(t *testing.T) {
	url, err := readDevToolsURL(strings.NewReader("noise\nDevTools listening on ws://127.0.0.1:1234/devtools/browser/a\n"), time.Second)
	if err != nil || url != "ws://127.0.0.1:1234/devtools/browser/a" {
		t.Fatalf("endpoint=%q %v", url, err)
	}
	if _, err := readDevToolsURL(strings.NewReader("no endpoint\n"), time.Second); err == nil || !strings.Contains(err.Error(), "not announced") {
		t.Fatalf("EOF=%v", err)
	}
	if _, err := readDevToolsURL(brokenReader{}, time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reader error=%v", err)
	}
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	if _, err := readDevToolsURL(r, time.Millisecond); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout=%v", err)
	}
	// Close the pipe to release the scanner goroutine after a timeout.
	w.Close()
}

func TestSleepAndMissingConnections(t *testing.T) {
	if err := Sleep(0).Do(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Sleep(time.Hour).Do(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("sleep cancellation=%v", err)
	}
	for _, a := range []Action{Navigate("about:blank"), OuterHTML("html", nil), Evaluate("1", nil)} {
		if err := a.Do(context.Background()); err == nil {
			t.Fatal("command accepted missing connection")
		}
	}
}

func TestBrowserActionsOverCDP(t *testing.T) {
	for _, tt := range []struct {
		name, method, expression, response string
		out                                interface{}
		want                               interface{}
		wantErr                            string
		url                                string
		outer                              bool
	}{
		{name: "navigate", method: "Page.navigate", url: "https://example.test/", response: `"result":{}`},
		{name: "html", method: "Runtime.evaluate", expression: "document.documentElement.outerHTML", outer: true, out: new(string), want: "<html>ok</html>", response: `"result":{"result":{"value":"<html>ok</html>"}}`},
		{name: "html-nil", method: "Runtime.evaluate", expression: "document.documentElement.outerHTML", outer: true, response: `"result":{"result":{"value":"x"}}`},
		{name: "evaluate", method: "Runtime.evaluate", expression: "21*2", out: new(int), want: 42, response: `"result":{"result":{"value":42},"exceptionDetails":null}`},
		{name: "evaluate-nil", method: "Runtime.evaluate", expression: "void 0", response: `"result":{"result":{}}`},
		{name: "exception", method: "Runtime.evaluate", expression: "bad()", response: `"result":{"exceptionDetails":{"text":"ReferenceError"}}`, wantErr: "evaluate exception"},
		{name: "type-mismatch", method: "Runtime.evaluate", expression: "'text'", out: new(int), response: `"result":{"result":{"value":"text"}}`, wantErr: "cannot unmarshal"},
		{name: "protocol-error", method: "Runtime.evaluate", expression: "1", response: `"error":{"code":-1,"message":"denied"}`, wantErr: "denied"},
		{name: "html-error", method: "Runtime.evaluate", expression: "document.documentElement.outerHTML", outer: true, response: `"error":{"code":-1,"message":"denied"}`, wantErr: "denied"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ws, server := testutil.WebSocketPair(t)
			conn := cdpconn.NewConn(ws)
			t.Cleanup(func() { conn.Close() })
			done := make(chan error, 1)
			go func() {
				p, _, err := wsx.ReadClientData(server)
				if err != nil {
					done <- err
					return
				}
				var req struct {
					ID     int
					Method string
					Params struct {
						URL           string `json:"url"`
						Expression    string `json:"expression"`
						ReturnByValue bool   `json:"returnByValue"`
						AwaitPromise  bool   `json:"awaitPromise"`
					}
				}
				if err := json.Unmarshal(p, &req); err != nil {
					done <- err
					return
				}
				if req.Method != tt.method || req.Params.URL != tt.url || req.Params.Expression != tt.expression || (tt.expression != "" && !req.Params.ReturnByValue) || (tt.expression != "" && !tt.outer && !req.Params.AwaitPromise) {
					done <- fmt.Errorf("command=%s", p)
					return
				}
				done <- wsx.WriteServerText(server, []byte(fmt.Sprintf(`{"id":%d,%s}`, req.ID, tt.response)))
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx = cdpconn.WithConn(ctx, conn)
			var action Action
			if tt.url != "" {
				action = Navigate(tt.url)
			} else if tt.outer {
				var out *string
				if tt.out != nil {
					out = tt.out.(*string)
				}
				action = OuterHTML("html", out)
			} else {
				action = Evaluate(tt.expression, tt.out)
			}
			err := action.Do(ctx)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err=%v want %s", err, tt.wantErr)
			}
			if tt.want != nil && !reflect.DeepEqual(reflect.ValueOf(tt.out).Elem().Interface(), tt.want) {
				t.Fatalf("output=%v want %v", reflect.ValueOf(tt.out).Elem(), tt.want)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
