package api

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// hostGuard covers every route, including GETs, before auth and CORS.
// Request-controlled names must never be resolved (DNS rebinding).
func (s *APIServer) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		bind := strings.ToLower(strings.Trim(s.getBindHost(), "[]"))
		if h, port, err := net.SplitHostPort(host); err == nil {
			if isLoopbackBind(bind) && port != strconv.Itoa(s.Port) {
				writeProblem(w, r, 403, "ERR_HOST_FORBIDDEN", "Unexpected Host", "The request port does not match this API.", "Use the configured API address.", nil)
				return
			}
			host = h
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		allowed := host != "" && (isLoopbackBind(host) || host == bind && bind != "0.0.0.0" && bind != "::")
		if !isLoopbackBind(bind) {
			// Network binds require a token. Proxy names must be opted in.
			allowed = allowed || net.ParseIP(host) != nil
			for _, name := range strings.Split(os.Getenv("MEGA_ANALYZER_API_HOSTS"), ",") {
				allowed = allowed || host != "" && host == strings.ToLower(strings.TrimSpace(name))
			}
		}
		if !allowed {
			writeProblem(w, r, 403, "ERR_HOST_FORBIDDEN", "Unexpected Host", "The request host is not allowed by this API.", "Use the local API URL or configure MEGA_ANALYZER_API_HOSTS for a network deployment.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH / CSRF / CORS MIDDLEWARES
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) apiAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := s.getAPIToken()
		// The console shell contains no runtime data. Let users open it and
		// enter a token; the specification and all operational APIs stay gated.
		publicDocs := (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
			(r.URL.Path == "/api/docs" || r.URL.Path == "/api/docs/assets/openapi.js" || r.URL.Path == "/api/docs/assets/openapi.css")
		if token == "" || r.Method == http.MethodOptions || publicDocs {
			next.ServeHTTP(w, r)
			return
		}
		provided := r.Header.Get("X-Mega-Analyzer-Token")
		if provided == "" {
			provided = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			writeProblem(w, r, http.StatusUnauthorized, "ERR_UNAUTHORIZED", "Unauthorized", "Missing or invalid API token.", "Set X-Mega-Analyzer-Token or Authorization: Bearer <token>.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopbackBind(host string) bool {
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// csrfMiddleware hardens the tokenless loopback mode against browser-driven
// cross-site requests. Without a token any page in the user's browser can
// reach 127.0.0.1:<port>; a cross-site <form> (including enctype=text/plain,
// which the JSON parser used to accept) could otherwise launch scans, port
// scans, MITM proxies or rewrite rules on disk. For unsafe methods we
// require:
//
//  1. Sec-Fetch-Site, when the browser sent it, to not be "cross-site";
//  2. Origin, when present, to be in the CORS allowlist;
//  3. a JSON or multipart Content-Type on requests that carry a body —
//     cross-site forms can only send text/plain or urlencoded without a
//     CORS preflight, and both are rejected here.
func (s *APIServer) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
			writeProblem(w, r, http.StatusForbidden, "ERR_CROSS_SITE_FORBIDDEN", "Cross-site request forbidden",
				"Sec-Fetch-Site: cross-site requests are not accepted by this API.",
				"Call the API from the local dashboard or a same-origin client.", nil)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(origin) {
			writeProblem(w, r, http.StatusForbidden, "ERR_ORIGIN_FORBIDDEN", "Origin not allowed",
				fmt.Sprintf("Origin %q is not in the API allowlist.", origin),
				"Configure MEGA_ANALYZER_CORS_ORIGINS or call the API same-origin.", nil)
			return
		}
		if r.ContentLength > 0 {
			ct := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
			if ct != "application/json" && ct != "multipart/form-data" {
				writeProblem(w, r, http.StatusUnsupportedMediaType, "ERR_UNSUPPORTED_MEDIA_TYPE", "Unsupported Content-Type",
					fmt.Sprintf("Content-Type %q is not accepted; send application/json.", ct),
					"Set Content-Type: application/json (or multipart/form-data for uploads).", nil)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware enables CORS only for configured local/dashboard origins.
func (s *APIServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.originAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Mega-Analyzer-Token")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *APIServer) originAllowed(origin string) bool {
	return s.isOriginAllowedCached(origin)
}
