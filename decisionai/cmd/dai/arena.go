package main

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"decisionai/arena"
	"decisionai/games"
	"io"
	"net/http"
	"strings"
	"sync"
)

//go:embed arena.html
var arenaPage string

func registerArena(mux *http.ServeMux, token string) {
	var mu sync.Mutex
	w, _ := arena.New("tetris")
	revision := 1
	mux.HandleFunc("/games", func(out http.ResponseWriter, r *http.Request) {
		out.Header().Set("Content-Type", "text/html; charset=utf-8")
		out.Header().Set("Cache-Control", "no-store")
		out.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; frame-ancestors 'none'")
		// Quote as JSON so a user-supplied API token cannot escape a script string.
		quoted, _ := json.Marshal(token)
		_, _ = io.WriteString(out, strings.ReplaceAll(arenaPage, "__ARENA_TOKEN__", string(quoted)))
	})
	mux.HandleFunc("/v1/arena", func(out http.ResponseWriter, r *http.Request) {
		out.Header().Set("Content-Type", "application/json")
		out.Header().Set("Cache-Control", "no-store")
		fail := func(code int, err error) {
			out.WriteHeader(code)
			_ = json.NewEncoder(out).Encode(map[string]string{"error": err.Error()})
		}
		if r.Method != "POST" {
			fail(405, fmt.Errorf("POST required"))
			return
		}
		if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(token)) != 1 {
			fail(401, fmt.Errorf("invalid token"))
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			fail(415, fmt.Errorf("application/json required"))
			return
		}
		var req struct {
			Command  string         `json:"command"`
			Game     string         `json:"game"`
			Revision int            `json:"revision"`
			Control  string         `json:"control"`
			Point    games.Point    `json:"point"`
			Decision games.Decision `json:"decision"`
		}
		b, err := io.ReadAll(http.MaxBytesReader(out, r.Body, 64<<10))
		if err == nil {
			err = strict(b, &req)
		}
		if err != nil {
			fail(400, err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if req.Command != "frame" && req.Command != "new" && req.Revision != revision {
			fail(409, fmt.Errorf("board changed; observe again"))
			return
		}
		switch req.Command {
		case "frame":
		case "new":
			var next *arena.World
			next, err = arena.New(req.Game)
			if err == nil {
				w = next
			}
		case "control":
			err = w.Control([]string{req.Control}, false)
		case "click":
			err = w.Click(r.Context(), req.Point)
		case "apply":
			err = w.Apply(r.Context(), req.Decision)
		default:
			err = fmt.Errorf("unknown arena command")
		}
		if err != nil {
			fail(400, err)
			return
		}
		if req.Command != "frame" {
			revision++
		}
		im, err := w.Render()
		if err != nil {
			fail(500, err)
			return
		}
		_ = json.NewEncoder(out).Encode(map[string]any{"game": w.State.Game, "image": im, "revision": revision, "status": w.Status, "moves": w.Moves, "lines": w.Lines, "player": w.State.Player, "selected": len(w.Selected)})
	})
}
