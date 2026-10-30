// Package cdpconn is a tiny Chrome DevTools Protocol transport: it frames
// JSON commands/responses over a WebSocket, correlates responses by id, and
// dispatches events to registered typed factories. It is shared by the
// chromedp and network shim packages.
package cdpconn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"mega-analyzer/pkg/internal/wsx"
)

// ProtoError is a CDP protocol-level error.
type ProtoError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func (e *ProtoError) Error() string {
	if e.Data != "" {
		return fmt.Sprintf("cdp error %d: %s (%s)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("cdp error %d: %s", e.Code, e.Message)
}

type wireMessage struct {
	ID        int64           `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *ProtoError     `json:"error,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

// Conn is a live CDP connection over a WebSocket.
type Conn struct {
	ws  *wsx.ClientConn
	idc int64

	mu        sync.Mutex
	pending   map[int64]chan *wireMessage
	sessionID string

	dispatch func(interface{})

	closed    chan struct{}
	closeOnce sync.Once
}

// NewConn wraps an established WebSocket and starts the read loop.
func NewConn(ws *wsx.ClientConn) *Conn {
	c := &Conn{
		ws:      ws,
		pending: make(map[int64]chan *wireMessage),
		closed:  make(chan struct{}),
	}
	go c.readLoop()
	return c
}

// SetSessionID pins a target session; all subsequent commands are routed to it.
func (c *Conn) SetSessionID(id string) {
	c.mu.Lock()
	c.sessionID = id
	c.mu.Unlock()
}

// SetDispatch installs the callback invoked for each decoded event.
func (c *Conn) SetDispatch(fn func(interface{})) {
	c.mu.Lock()
	c.dispatch = fn
	c.mu.Unlock()
}

// Close terminates the connection.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.ws.Close()
}

func (c *Conn) readLoop() {
	for {
		op, data, err := c.ws.ReadMessage()
		if err != nil {
			c.closeOnce.Do(func() { close(c.closed) })
			return
		}
		if op != wsx.OpText {
			continue
		}
		var m wireMessage
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.pending[m.ID]
			c.mu.Unlock()
			if ch != nil {
				mm := m
				select {
				case ch <- &mm:
				default:
				}
			}
			continue
		}
		if m.Method == "" {
			continue
		}
		c.mu.Lock()
		fn := c.dispatch
		c.mu.Unlock()
		if fn == nil {
			continue
		}
		if factory, ok := lookupEvent(m.Method); ok {
			ev := factory()
			if len(m.Params) > 0 {
				if err := json.Unmarshal(m.Params, ev); err != nil {
					continue
				}
			}
			fn(ev)
		}
	}
}

// Execute sends a command and waits for its response. params and res may be
// nil. If a session is pinned, the command is routed to that session.
func (c *Conn) Execute(ctx context.Context, method string, params, res interface{}) error {
	id := atomic.AddInt64(&c.idc, 1)

	c.mu.Lock()
	session := c.sessionID
	c.mu.Unlock()

	envelope := map[string]interface{}{"id": id, "method": method}
	if params != nil {
		envelope["params"] = params
	} else {
		envelope["params"] = map[string]interface{}{}
	}
	if session != "" {
		envelope["sessionId"] = session
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	ch := make(chan *wireMessage, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	if err := c.ws.WriteText(data); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return errors.New("cdp: connection closed")
	case m := <-ch:
		if m.Error != nil {
			return m.Error
		}
		if res != nil && len(m.Result) > 0 {
			return json.Unmarshal(m.Result, res)
		}
		return nil
	}
}

// ── Event registry ──────────────────────────────────────────

var (
	evMu           sync.RWMutex
	eventFactories = map[string]func() interface{}{}
)

// RegisterEvent maps a CDP event method to a factory producing a fresh typed
// value to unmarshal the event params into.
func RegisterEvent(method string, factory func() interface{}) {
	evMu.Lock()
	eventFactories[method] = factory
	evMu.Unlock()
}

func lookupEvent(method string) (func() interface{}, bool) {
	evMu.RLock()
	defer evMu.RUnlock()
	f, ok := eventFactories[method]
	return f, ok
}

// ── Context plumbing ───────────────────────────────────────

type ctxKey struct{}

// WithConn stores a Conn in the context for command actions to retrieve.
func WithConn(ctx context.Context, c *Conn) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// FromContext returns the Conn previously stored with WithConn, or nil.
func FromContext(ctx context.Context) *Conn {
	c, _ := ctx.Value(ctxKey{}).(*Conn)
	return c
}
