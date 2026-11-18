package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// An actual subprocess exercises framing, initialization, notifications and IDs.
func TestMCPHelper(t *testing.T) {
	mode := ""
	for _, a := range os.Args {
		if strings.HasPrefix(a, "mcp-helper=") {
			mode = strings.TrimPrefix(a, "mcp-helper=")
		}
	}
	if mode == "" {
		return
	}
	s := bufio.NewScanner(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	initialized := false
	for s.Scan() {
		var req struct {
			ID     json.RawMessage
			Method string
			Params json.RawMessage
		}
		_ = json.Unmarshal(s.Bytes(), &req)
		if req.Method == "notifications/initialized" {
			initialized = true
			continue
		}
		var result any
		switch req.Method {
		case "initialize":
			version := ProtocolVersion
			if mode == "version" {
				version = "unknown"
			}
			result = map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{}}}
		case "tools/list":
			if !initialized {
				os.Exit(12)
			}
			var p struct{ Cursor string }
			_ = json.Unmarshal(req.Params, &p)
			if p.Cursor == "" {
				result = map[string]any{"tools": []any{map[string]any{"name": "observe", "inputSchema": map[string]any{"type": "object"}}}, "nextCursor": "two"}
			} else {
				result = map[string]any{"tools": []any{map[string]any{"name": "move", "inputSchema": json.RawMessage(`{"type":"object","properties":{"cell":{"type":"integer"}},"required":["cell"],"additionalProperties":false}`)}}}
			}
		case "tools/call":
			if mode == "hang" {
				time.Sleep(5 * time.Second)
				os.Exit(0)
			}
			if mode == "wrong-id" {
				req.ID = json.RawMessage(`999`)
			}
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/message", "params": map[string]any{"level": "info", "data": "hello"}})
			result = map[string]any{"content": []any{map[string]string{"type": "text", "text": "done"}}, "structuredContent": map[string]any{"game": "maze", "grid": []string{"S.G"}}, "isError": mode == "error"}
		default:
			os.Exit(13)
		}
		_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
	os.Exit(0)
}

func testClient(t *testing.T, mode string) *Client {
	t.Helper()
	c, err := Start(context.Background(), Config{Command: os.Args[0], Args: []string{"-test.run=^TestMCPHelper$", "mcp-helper=" + mode}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	tools, err := c.ListTools(context.Background())
	if err != nil || len(tools) != 2 {
		t.Fatalf("tools: %v %v", tools, err)
	}
	return c
}
func TestMCPRoundTrip(t *testing.T) {
	c := testClient(t, "normal")
	for _, call := range []Call{{Name: "missing"}, {Name: "move"}, {Name: "move", Arguments: map[string]any{"cell": "2"}}, {Name: "move", Arguments: map[string]any{"cell": 1, "extra": true}}} {
		if _, err := c.CallTool(context.Background(), call); err == nil {
			t.Fatalf("accepted invalid %+v", call)
		}
	}
	r, err := c.CallTool(context.Background(), Call{Name: "move", Arguments: map[string]any{"cell": 2}})
	if err != nil || len(r.Content) != 1 || r.Content[0].Text != "done" || !strings.Contains(string(r.Structured), "maze") {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestMCPFailures(t *testing.T) {
	for _, mode := range []string{"error", "wrong-id", "hang"} {
		t.Run(mode, func(t *testing.T) {
			c := testClient(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			if _, err := c.CallTool(ctx, Call{Name: "observe"}); err == nil {
				t.Fatal("expected failure")
			}
		})
	}
	c, err := Start(context.Background(), Config{Command: os.Args[0], Args: []string{"-test.run=^TestMCPHelper$", "mcp-helper=version"}})
	if c != nil {
		c.Close()
	}
	if err == nil || !strings.Contains(fmt.Sprint(err), "protocol") {
		t.Fatalf("accepted protocol: %v", err)
	}
}
