// Package mcpclient implements the MCP 2025-06-18 stdio tool lifecycle.
// It launches only the operator-configured executable, without a shell.
package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"decisionai/vision"
)

const ProtocolVersion = "2025-06-18"
const maxMessage = 2 << 20

type Config struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Dir     string   `json:"cwd,omitempty"`
}
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}
type Call struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}
type Content struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MIMEType string `json:"mimeType,omitempty"`
}
type Result struct {
	Content    []Content       `json:"content"`
	Structured json.RawMessage `json:"structuredContent,omitempty"`
	IsError    bool            `json:"isError,omitempty"`
}

func (r Result) Images() []vision.Image {
	var out []vision.Image
	for _, c := range r.Content {
		if c.Type == "image" {
			out = append(out, vision.Image{Data: c.Data, MIMEType: c.MIMEType})
		}
	}
	return out
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
type received struct {
	msg message
	err error
}
type Client struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	inbox  chan received
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	next   int
	tools  map[string]Tool
}

func Start(ctx context.Context, config Config) (*Client, error) {
	if config.Command == "" {
		return nil, fmt.Errorf("MCP command is required")
	}
	cmd := exec.CommandContext(ctx, config.Command, config.Args...)
	cmd.Dir = config.Dir
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, err
	}
	c := &Client{cmd: cmd, stdin: stdin, stdout: stdout, inbox: make(chan received), done: make(chan struct{})}
	go c.read()
	var init struct {
		Protocol     string                     `json:"protocolVersion"`
		Capabilities map[string]json.RawMessage `json:"capabilities"`
	}
	err = c.request(ctx, "initialize", map[string]any{"protocolVersion": ProtocolVersion, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "decisionai", "version": "1"}}, &init)
	if err == nil && init.Protocol != ProtocolVersion {
		err = fmt.Errorf("unsupported MCP protocol %q", init.Protocol)
	}
	if err == nil {
		if _, ok := init.Capabilities["tools"]; !ok {
			err = fmt.Errorf("MCP server has no tools capability")
		}
	}
	if err == nil {
		err = c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) read() {
	s := bufio.NewScanner(c.stdout)
	s.Buffer(make([]byte, 64<<10), maxMessage)
	for s.Scan() {
		var m message
		err := json.Unmarshal(s.Bytes(), &m)
		if err == nil && m.JSONRPC != "2.0" {
			err = fmt.Errorf("invalid JSON-RPC version")
		}
		select {
		case c.inbox <- received{m, err}:
		case <-c.done:
			return
		}
		if err != nil {
			return
		}
	}
	err := s.Err()
	if err == nil {
		err = io.EOF
	}
	select {
	case c.inbox <- received{err: err}:
	case <-c.done:
	}
}

func (c *Client) Close() {
	c.once.Do(func() { close(c.done); c.stdin.Close(); c.stdout.Close(); _ = c.cmd.Process.Kill(); _ = c.cmd.Wait() })
}

func (c *Client) send(v any) error { return json.NewEncoder(c.stdin).Encode(v) }

// Requests are serialized. A timeout closes the session: actions are never retried
// because the peer may already have applied a timed-out action.
func (c *Client) request(ctx context.Context, method string, params any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	c.next++
	id := strconv.Itoa(c.next)
	requestID := c.next
	written := make(chan error, 1)
	go func() {
		written <- c.send(map[string]any{"jsonrpc": "2.0", "id": requestID, "method": method, "params": params})
	}()
	select {
	case err := <-written:
		if err != nil {
			c.Close()
			return err
		}
	case <-ctx.Done():
		c.Close()
		return ctx.Err()
	case <-c.done:
		return fmt.Errorf("MCP session closed")
	}
	for {
		select {
		case <-ctx.Done():
			c.Close()
			return ctx.Err()
		case <-c.done:
			return fmt.Errorf("MCP session closed")
		case r := <-c.inbox:
			if r.err != nil {
				c.Close()
				return fmt.Errorf("MCP %s: %w", method, r.err)
			}
			m := r.msg
			if m.Method != "" {
				if len(m.ID) > 0 {
					response := map[string]any{"jsonrpc": "2.0", "id": m.ID}
					if m.Method == "ping" {
						response["result"] = map[string]any{}
					} else {
						response["error"] = map[string]any{"code": -32601, "message": "client capability not supported"}
					}
					// Bound writes to peers which stop reading after sending a request.
					ch := make(chan error, 1)
					go func() { ch <- c.send(response) }()
					select {
					case err := <-ch:
						if err != nil {
							c.Close()
							return err
						}
					case <-ctx.Done():
						c.Close()
						return ctx.Err()
					}
				}
				continue
			}
			if string(m.ID) != id {
				c.Close()
				return fmt.Errorf("MCP response ID mismatch")
			}
			if m.Error != nil {
				return fmt.Errorf("MCP %s error %d: %s", method, m.Error.Code, m.Error.Message)
			}
			if len(m.Result) == 0 {
				return fmt.Errorf("MCP response has no result")
			}
			return json.Unmarshal(m.Result, out)
		}
	}
}

func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	var all []Tool
	cursor := ""
	seen := map[string]bool{}
	registry := map[string]Tool{}
	for page := 0; page < 32; page++ {
		var r struct {
			Tools []Tool `json:"tools"`
			Next  string `json:"nextCursor"`
		}
		params := map[string]string{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		if err := c.request(ctx, "tools/list", params, &r); err != nil {
			return nil, err
		}
		for _, t := range r.Tools {
			if t.Name == "" {
				return nil, fmt.Errorf("MCP tool has no name")
			}
			if _, ok := registry[t.Name]; ok {
				return nil, fmt.Errorf("duplicate MCP tool %q", t.Name)
			}
			registry[t.Name] = t
			all = append(all, t)
			if len(all) > 1024 {
				return nil, fmt.Errorf("too many MCP tools")
			}
		}
		if r.Next == "" {
			c.mu.Lock()
			c.tools = registry
			c.mu.Unlock()
			return all, nil
		}
		if seen[r.Next] {
			return nil, fmt.Errorf("MCP tools pagination loop")
		}
		seen[r.Next] = true
		cursor = r.Next
	}
	return nil, fmt.Errorf("MCP tool pagination limit exceeded")
}

func (c *Client) CheckCall(call Call) error {
	c.mu.Lock()
	tool, ok := c.tools[call.Name]
	c.mu.Unlock()
	if !ok {
		return fmt.Errorf("tool %q was not discovered with tools/list", call.Name)
	}
	args := call.Arguments
	if args == nil {
		args = map[string]any{}
	}
	return validateArguments(tool.InputSchema, args)
}

func (c *Client) CallTool(ctx context.Context, call Call) (Result, error) {
	if err := c.CheckCall(call); err != nil {
		return Result{}, err
	}
	if call.Arguments == nil {
		call.Arguments = map[string]any{}
	}
	var r Result
	if err := c.request(ctx, "tools/call", call, &r); err != nil {
		return r, err
	}
	if r.IsError {
		return r, fmt.Errorf("MCP tool %q reported isError; no automatic retry", call.Name)
	}
	return r, nil
}
