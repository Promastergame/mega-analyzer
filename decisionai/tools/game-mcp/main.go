// game-mcp is a small local MCP fixture: a maze which can be observed and moved.
// stdout contains protocol messages only. It requires no game engine or browser.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"decisionai/games"
	"decisionai/mcpclient"
)

func main() {
	grid := []string{"S...#", ".##..", "...XG"}
	x, y := 0, 0
	initialized, ready := false, false
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 64<<10)
	enc := json.NewEncoder(os.Stdout)
	for s.Scan() {
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(s.Bytes(), &req); err != nil {
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "invalid JSON"}})
			continue
		}
		if len(req.ID) == 0 {
			if req.Method == "notifications/initialized" && initialized {
				ready = true
			}
			continue
		}
		response := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		var result any
		var callErr error
		switch req.Method {
		case "initialize":
			initialized = true
			result = map[string]any{"protocolVersion": mcpclient.ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "decisionai-maze-demo", "version": "1"}}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			if !ready {
				callErr = fmt.Errorf("session not initialized")
				break
			}
			result = map[string]any{"tools": []mcpclient.Tool{
				{Name: "observe", Description: "Read the current maze state.", InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)},
				{Name: "move", Description: "Move one cell, then observe again.", InputSchema: json.RawMessage(`{"type":"object","properties":{"direction":{"type":"string","enum":["up","right","down","left"]}},"required":["direction"],"additionalProperties":false}`)},
			}}
		case "tools/call":
			if !ready {
				callErr = fmt.Errorf("session not initialized")
				break
			}
			var call mcpclient.Call
			if err := json.Unmarshal(req.Params, &call); err != nil {
				callErr = err
				break
			}
			if call.Name == "move" {
				dx, dy := 0, 0
				switch call.Arguments["direction"] {
				case "up":
					dy = -1
				case "down":
					dy = 1
				case "left":
					dx = -1
				case "right":
					dx = 1
				default:
					callErr = fmt.Errorf("invalid direction")
				}
				nx, ny := x+dx, y+dy
				if callErr == nil && (nx < 0 || nx >= len(grid[0]) || ny < 0 || ny >= len(grid) || grid[ny][nx] == '#' || grid[ny][nx] == 'X' || grid[y][x] == '*') {
					callErr = fmt.Errorf("illegal move")
				}
				if callErr == nil {
					old := []byte(grid[y])
					old[x] = '.'
					grid[y] = string(old)
					next := []byte(grid[ny])
					if next[nx] == 'G' {
						next[nx] = '*'
					} else {
						next[nx] = 'S'
					}
					grid[ny] = string(next)
					x, y = nx, ny
				}
			} else if call.Name != "observe" {
				callErr = fmt.Errorf("unknown tool")
			}
			if callErr != nil {
				result = mcpclient.Result{IsError: true, Content: []mcpclient.Content{{Type: "text", Text: callErr.Error()}}}
				callErr = nil
			} else {
				state, _ := json.Marshal(games.State{Game: "maze", Grid: grid})
				result = mcpclient.Result{Structured: state, Content: []mcpclient.Content{{Type: "text", Text: string(state)}}}
			}
		default:
			callErr = fmt.Errorf("method not supported")
		}
		if callErr != nil {
			response["error"] = map[string]any{"code": -32601, "message": callErr.Error()}
		} else {
			response["result"] = result
		}
		if err := enc.Encode(response); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
}
