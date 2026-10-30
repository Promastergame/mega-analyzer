// Package chromedp is a minimal drop-in for github.com/chromedp/chromedp. It
// launches a real Chrome/Chromium process and drives it over the DevTools
// Protocol using our own WebSocket + CDP transport. Only the subset of the
// API used by this project is implemented: exec allocator + flags, a browser
// context, ListenTarget, Run, and the Navigate/Sleep/OuterHTML/Evaluate
// actions. Chrome itself is an external program discovered at runtime, not a
// Go module dependency.
package chromedp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/cdp/cdpconn"
	"mega-analyzer/pkg/internal/wsx"
)

// Action is a single step executed by Run. It is satisfied structurally by
// cdproto-style command params (e.g. network.Enable()).
type Action interface {
	Do(ctx context.Context) error
}

// ActionFunc adapts a function to an Action.
type ActionFunc func(context.Context) error

// Do calls f(ctx).
func (f ActionFunc) Do(ctx context.Context) error { return f(ctx) }

// ── Exec allocator ─────────────────────────────────────────

type allocConfig struct {
	flags map[string]interface{}
	path  string
}

// ExecAllocatorOption configures how Chrome is launched.
type ExecAllocatorOption func(*allocConfig)

// Flag sets a Chrome command-line flag. bool false omits the flag.
func Flag(name string, value interface{}) ExecAllocatorOption {
	return func(a *allocConfig) { a.flags[name] = value }
}

// ExecPath overrides the Chrome executable path.
func ExecPath(path string) ExecAllocatorOption {
	return func(a *allocConfig) { a.path = path }
}

// DefaultExecAllocatorOptions is a reasonable default flag set for headless
// automation. It is an array so callers can slice it with [:].
var DefaultExecAllocatorOptions = [...]ExecAllocatorOption{
	Flag("headless", true),
	Flag("disable-gpu", true),
	Flag("no-first-run", true),
	Flag("no-default-browser-check", true),
	Flag("disable-background-networking", true),
	Flag("disable-background-timer-throttling", true),
	Flag("disable-backgrounding-occluded-windows", true),
	Flag("disable-renderer-backgrounding", true),
	Flag("disable-dev-shm-usage", true),
	Flag("disable-sync", true),
	Flag("metrics-recording-only", true),
	Flag("mute-audio", true),
}

type allocKey struct{}

// NewExecAllocator returns a context carrying the allocator config. Cleanup of
// the launched browser is handled by the NewContext cancel func.
func NewExecAllocator(parent context.Context, opts ...ExecAllocatorOption) (context.Context, context.CancelFunc) {
	a := &allocConfig{flags: map[string]interface{}{}}
	for _, o := range opts {
		o(a)
	}
	return context.WithValue(parent, allocKey{}, a), func() {}
}

// ── Browser context ───────────────────────────────────────

// Context holds the browser process and CDP connection for a task.
type Context struct {
	alloc *allocConfig

	startOnce sync.Once
	startErr  error

	cmd           *exec.Cmd
	browserCancel context.CancelFunc
	userDataDir   string
	conn          *cdpconn.Conn

	lmu       sync.Mutex
	listeners []func(interface{})
}

type ctxKey struct{}

// NewContext creates a browser context. The browser is launched lazily on the
// first Run. The returned cancel func tears the browser down.
func NewContext(parent context.Context, _ ...func(*Context)) (context.Context, context.CancelFunc) {
	a, _ := parent.Value(allocKey{}).(*allocConfig)
	if a == nil {
		a = &allocConfig{flags: map[string]interface{}{}}
	}
	c := &Context{alloc: a}
	ctx := context.WithValue(parent, ctxKey{}, c)
	return ctx, func() { c.shutdown() }
}

// FromContext returns the Context stored by NewContext, or nil.
func FromContext(ctx context.Context) *Context {
	c, _ := ctx.Value(ctxKey{}).(*Context)
	return c
}

func (c *Context) shutdown() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	if c.browserCancel != nil {
		c.browserCancel()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		_, _ = c.cmd.Process.Wait()
	}
	if c.userDataDir != "" {
		_ = os.RemoveAll(c.userDataDir)
	}
}

func (c *Context) dispatch(ev interface{}) {
	c.lmu.Lock()
	ls := make([]func(interface{}), len(c.listeners))
	copy(ls, c.listeners)
	c.lmu.Unlock()
	for _, l := range ls {
		l(ev)
	}
}

// ListenTarget registers a listener for CDP events on this context.
func ListenTarget(ctx context.Context, fn func(ev interface{})) {
	c := FromContext(ctx)
	if c == nil {
		return
	}
	c.lmu.Lock()
	c.listeners = append(c.listeners, fn)
	c.lmu.Unlock()
}

var wsURLRe = regexp.MustCompile(`ws://[^\s]+`)

func flagToArgs(name string, val interface{}) []string {
	switch v := val.(type) {
	case bool:
		if v {
			return []string{"--" + name}
		}
		return nil
	case string:
		return []string{"--" + name + "=" + v}
	default:
		return []string{fmt.Sprintf("--%s=%v", name, v)}
	}
}

func findChrome() string {
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		candidates = []string{"chrome.exe", "chrome"}
		for _, base := range []string{
			os.Getenv("ProgramFiles"),
			os.Getenv("ProgramFiles(x86)"),
			os.Getenv("LocalAppData"),
		} {
			if base != "" {
				candidates = append(candidates, base+`\Google\Chrome\Application\chrome.exe`)
			}
		}
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"google-chrome", "chromium",
		}
	default:
		candidates = []string{
			"google-chrome", "google-chrome-stable", "chromium",
			"chromium-browser", "chrome", "headless-shell", "chrome-headless-shell",
			"/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
			"/snap/bin/chromium",
		}
	}
	for _, cand := range candidates {
		if p, err := exec.LookPath(cand); err == nil {
			return p
		}
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

func (c *Context) ensureStarted(ctx context.Context) error {
	c.startOnce.Do(func() { c.startErr = c.launch(ctx) })
	return c.startErr
}

func (c *Context) launch(ctx context.Context) error {
	path := c.alloc.path
	if path == "" {
		path = findChrome()
	}
	if path == "" {
		return errors.New("chromedp: no Chrome/Chromium executable found")
	}

	tmp, err := os.MkdirTemp("", "cdp-user-")
	if err != nil {
		return err
	}
	c.userDataDir = tmp

	flags := map[string]interface{}{}
	for k, v := range c.alloc.flags {
		flags[k] = v
	}
	if _, ok := flags["user-data-dir"]; !ok {
		flags["user-data-dir"] = tmp
	}
	// Force an ephemeral debugging port that we parse from stderr.
	flags["remote-debugging-port"] = "0"

	var args []string
	for name, val := range flags {
		args = append(args, flagToArgs(name, val)...)
	}
	args = append(args, "about:blank")

	bctx, bcancel := context.WithCancel(context.Background())
	c.browserCancel = bcancel
	cmd := exec.CommandContext(bctx, path, args...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		bcancel()
		return err
	}
	if err := cmd.Start(); err != nil {
		bcancel()
		return err
	}
	c.cmd = cmd

	wsURL, err := readDevToolsURL(stderr, 30*time.Second)
	if err != nil {
		c.shutdown()
		return err
	}

	ws, err := wsx.Dial(wsURL)
	if err != nil {
		c.shutdown()
		return err
	}
	conn := cdpconn.NewConn(ws)

	// Open a page target and attach to it (flatten -> sessionId on the wire).
	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := conn.Execute(ctx, "Target.createTarget", map[string]interface{}{"url": "about:blank"}, &created); err != nil {
		conn.Close()
		c.shutdown()
		return err
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := conn.Execute(ctx, "Target.attachToTarget", map[string]interface{}{"targetId": created.TargetID, "flatten": true}, &attached); err != nil {
		conn.Close()
		c.shutdown()
		return err
	}
	conn.SetSessionID(attached.SessionID)
	conn.SetDispatch(c.dispatch)
	c.conn = conn
	return nil
}

func readDevToolsURL(r interface{ Read([]byte) (int, error) }, timeout time.Duration) (string, error) {
	type result struct {
		url string
		err error
	}
	done := make(chan result, 1)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if m := wsURLRe.FindString(sc.Text()); m != "" {
				done <- result{url: m}
				return
			}
		}
		if err := sc.Err(); err != nil {
			done <- result{err: err}
			return
		}
		done <- result{err: errors.New("chromedp: DevTools endpoint not announced")}
	}()
	select {
	case <-time.After(timeout):
		return "", errors.New("chromedp: timed out waiting for DevTools endpoint")
	case res := <-done:
		return res.url, res.err
	}
}

// Run starts the browser if needed and executes actions sequentially.
func Run(ctx context.Context, actions ...Action) error {
	c := FromContext(ctx)
	if c == nil {
		return errors.New("chromedp: context not created with NewContext")
	}
	if err := c.ensureStarted(ctx); err != nil {
		return err
	}
	runCtx := cdpconn.WithConn(ctx, c.conn)
	for _, a := range actions {
		if a == nil {
			continue
		}
		if err := a.Do(runCtx); err != nil {
			return err
		}
	}
	return nil
}

// ── Actions ──────────────────────────────────────────────

// Navigate loads url in the current page.
func Navigate(url string) Action {
	return ActionFunc(func(ctx context.Context) error {
		c := cdpconn.FromContext(ctx)
		if c == nil {
			return errors.New("chromedp: no cdp connection")
		}
		return c.Execute(ctx, "Page.navigate", map[string]interface{}{"url": url}, nil)
	})
}

// Sleep pauses for d, or until ctx is done.
func Sleep(d time.Duration) Action {
	return ActionFunc(func(ctx context.Context) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}

// OuterHTML stores the serialized outer HTML of the document into res. The
// selector is accepted for API compatibility; the full document is returned.
func OuterHTML(_ string, res *string, _ ...interface{}) Action {
	return ActionFunc(func(ctx context.Context) error {
		c := cdpconn.FromContext(ctx)
		if c == nil {
			return errors.New("chromedp: no cdp connection")
		}
		var out struct {
			Result struct {
				Value string `json:"value"`
			} `json:"result"`
		}
		params := map[string]interface{}{
			"expression":    "document.documentElement.outerHTML",
			"returnByValue": true,
		}
		if err := c.Execute(ctx, "Runtime.evaluate", params, &out); err != nil {
			return err
		}
		if res != nil {
			*res = out.Result.Value
		}
		return nil
	})
}

// Evaluate runs a JS expression and, if res is non-nil, unmarshals the
// returned value into it.
func Evaluate(expression string, res interface{}, _ ...interface{}) Action {
	return ActionFunc(func(ctx context.Context) error {
		c := cdpconn.FromContext(ctx)
		if c == nil {
			return errors.New("chromedp: no cdp connection")
		}
		var out struct {
			Result struct {
				Value json.RawMessage `json:"value"`
			} `json:"result"`
			ExceptionDetails json.RawMessage `json:"exceptionDetails"`
		}
		params := map[string]interface{}{
			"expression":    expression,
			"returnByValue": true,
			"awaitPromise":  true,
		}
		if err := c.Execute(ctx, "Runtime.evaluate", params, &out); err != nil {
			return err
		}
		if len(out.ExceptionDetails) > 0 && string(out.ExceptionDetails) != "null" {
			return fmt.Errorf("chromedp: evaluate exception: %s", string(out.ExceptionDetails))
		}
		if res != nil && len(out.Result.Value) > 0 {
			return json.Unmarshal(out.Result.Value, res)
		}
		return nil
	})
}
