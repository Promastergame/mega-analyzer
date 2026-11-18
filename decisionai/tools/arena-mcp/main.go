// arena-mcp exposes the same visible game as /games over stdio MCP.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"decisionai/mcpclient"
	"decisionai/vision"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	endpoint := flag.String("url", "http://127.0.0.1:7480", "local DecisionAI server")
	flag.Parse()
	u, err := url.Parse(*endpoint)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || u.User != nil {
		fmt.Fprintln(os.Stderr, "url must be a loopback HTTP server")
		os.Exit(1)
	}
	token := os.Getenv("DAI_API_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "DAI_API_TOKEN must match the local server")
		os.Exit(1)
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	revision := 0
	call := func(body any) (vision.Image, error) {
		b, _ := json.Marshal(body)
		req, err := http.NewRequest("POST", *endpoint+"/v1/arena", bytes.NewReader(b))
		if err != nil {
			return vision.Image{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := client.Do(req)
		if err != nil {
			return vision.Image{}, err
		}
		defer res.Body.Close()
		var frame struct {
			Image    vision.Image `json:"image"`
			Revision int          `json:"revision"`
			Error    string       `json:"error"`
		}
		if err = json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&frame); err != nil {
			return vision.Image{}, err
		}
		if res.StatusCode != 200 {
			return vision.Image{}, fmt.Errorf("arena: %s", frame.Error)
		}
		revision = frame.Revision
		return frame.Image, nil
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 128<<10)
	enc := json.NewEncoder(os.Stdout)
	initialized, ready := false, false
	for scan.Scan() {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(scan.Bytes(), &req) != nil {
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "invalid JSON"}})
			continue
		}
		if len(req.ID) == 0 {
			if req.Method == "notifications/initialized" && initialized {
				ready = true
			}
			continue
		}
		var result any
		var callErr error
		switch req.Method {
		case "initialize":
			initialized = true
			result = map[string]any{"protocolVersion": mcpclient.ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "decisionai-visual-arena", "version": "1"}}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			if !ready {
				callErr = fmt.Errorf("session not initialized")
				break
			}
			result = map[string]any{"tools": []mcpclient.Tool{
				{Name: "observe", Description: "Screenshot of the visible board, without hidden game state.", InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)},
				{Name: "apply", Description: "Apply controls or complete checker path to the last observed frame; stale frames are rejected.", InputSchema: json.RawMessage(`{"type":"object","properties":{"decision":{"type":"object"}},"required":["decision"],"additionalProperties":false}`)},
			}}
		case "tools/call":
			if !ready {
				callErr = fmt.Errorf("session not initialized")
				break
			}
			var c mcpclient.Call
			if err := json.Unmarshal(req.Params, &c); err != nil {
				callErr = err
				break
			}
			var im vision.Image
			switch c.Name {
			case "observe":
				im, callErr = call(map[string]any{"command": "frame"})
			case "apply":
				if revision == 0 {
					callErr = fmt.Errorf("observe before applying a move")
					break
				}
				_, callErr = call(map[string]any{"command": "apply", "revision": revision, "decision": c.Arguments["decision"]})
				revision = 0
			default:
				callErr = fmt.Errorf("unknown tool")
			}
			if callErr != nil {
				result = mcpclient.Result{IsError: true, Content: []mcpclient.Content{{Type: "text", Text: callErr.Error()}}}
				callErr = nil
			} else if c.Name == "observe" {
				result = mcpclient.Result{Content: []mcpclient.Content{{Type: "image", Data: im.Data, MIMEType: im.MIMEType}}}
			} else {
				result = mcpclient.Result{Content: []mcpclient.Content{{Type: "text", Text: "Move applied. Observe again."}}}
			}
		default:
			callErr = fmt.Errorf("method not found")
		}
		response := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if callErr != nil {
			response["error"] = map[string]any{"code": -32601, "message": callErr.Error()}
		} else {
			response["result"] = result
		}
		if enc.Encode(response) != nil {
			return
		}
	}
}
