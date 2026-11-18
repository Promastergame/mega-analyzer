package main

import (
	_ "embed"
	"io"
	"net/http"
	"strings"

	"decisionai/web"
)

//go:embed menu.html
var menuHTML string

// registerWebMenu exposes the root Web Menu dashboard, /menu, and routes to Text, Eval, and Rules.
func registerWebMenu(mux *http.ServeMux, token string) {
	serveHTML := func(w http.ResponseWriter, content string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		rendered := strings.ReplaceAll(content, "__TOKEN__", token)
		rendered = strings.ReplaceAll(rendered, "__SESSION_TOKEN__", token)
		_, _ = io.WriteString(w, rendered)
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/menu" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		serveHTML(w, menuHTML)
	})
	mux.HandleFunc("/menu", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		serveHTML(w, menuHTML)
	})
	mux.HandleFunc("/text", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		serveHTML(w, string(web.TextPage))
	})
	mux.HandleFunc("/eval", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		serveHTML(w, string(web.EvalPage))
	})
	mux.HandleFunc("/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		serveHTML(w, string(web.Page))
	})
	mux.HandleFunc("/api/eval-report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(web.EvalReport)
	})
}
