package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const tokenCookie = "ma_token"

// middleware is the one place every request passes through.
func (s *Server) middleware(next http.Handler) http.Handler {
	return s.recoverPanics(s.securityHeaders(s.guard(next)))
}

// recoverPanics keeps one bad request from tearing down the whole run.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil && rec != http.ErrAbortHandler {
				fmt.Printf("[webui] panic on %s %s: %v\n", r.Method, r.URL.Path, rec)
				httpError(w, r, http.StatusInternalServerError, "The server hit an internal error handling this request.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		// Phase 1 CSP: still allows inline handlers/styles that the current SPA
		// relies on. Tighten to script-src 'self' once the inline onclick=
		// attributes are replaced by delegated listeners.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; "+
				"style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "+
				"connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		next.ServeHTTP(w, r)
	})
}

// guard closes the hole that mattered most: the API had no authentication and
// no origin checks, so any web page the user happened to open could drive the
// local analyzer (spawn processes, control the attached phone, read reports)
// via DNS rebinding or a plain cross-site form post.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			httpError(w, r, http.StatusForbidden, "Unexpected Host header; refusing to serve (DNS-rebinding guard).")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				httpError(w, r, http.StatusForbidden, "Cross-site requests to the API are not allowed.")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(origin) {
				httpError(w, r, http.StatusForbidden, "Unexpected Origin header.")
				return
			}
			if !s.tokenOK(r) {
				httpError(w, r, http.StatusUnauthorized, "A session token is required. Open the paired URL printed by the web server.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(host string) bool {
	if host == "" {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if isLoopbackHost(h) || h == s.host || h == browserHost(s.host) {
		return true
	}
	// Off-loopback binds are token-gated, so any resolvable name is acceptable
	// there; loopback binds are not, so they stay strict.
	return !isLoopbackHost(s.host)
}

func (s *Server) originAllowed(origin string) bool {
	if s.opts.Privileged {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return false
		}
		port := u.Port()
		if port == "" {
			port = "80"
		}
		return u.Hostname() == s.host && port == strconv.Itoa(s.port)
	}
	for _, scheme := range []string{"http://", "https://"} {
		if !strings.HasPrefix(origin, scheme) {
			continue
		}
		return s.hostAllowed(strings.TrimPrefix(origin, scheme))
	}
	return false
}

func (s *Server) tokenOK(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	if eq(r.Header.Get("X-MA-Token"), s.token) || eq(r.URL.Query().Get("t"), s.token) {
		return true
	}
	if c, err := r.Cookie(tokenCookie); err == nil && eq(c.Value, s.token) {
		return true
	}
	return false
}

func eq(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func newToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// newJobID replaces time.Now().UnixNano(): job IDs are the only thing standing
// between a caller and someone else's scan output, so they must not be guessable.
func newJobID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(int64(len(b)), 10)
	}
	return strconv.FormatUint(binary.BigEndian.Uint64(b[:])>>1, 10)
}

// Tokens also enter an HttpOnly cookie; never truncate invalid values.
func validPrivilegedToken(token string) bool {
	if len(token) < 32 || len(token) > 256 {
		return false
	}
	for _, c := range token {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
