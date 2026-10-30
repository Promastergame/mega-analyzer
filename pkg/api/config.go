package api

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// ═══════════════════════════════════════════════════════════════════════════════
// APISERVER CONFIG — env vars are read once and cached, with auto-refresh
// when the underlying env value changes (keeps tests that mutate env green
// while avoiding per-request strings.Split / Sprintf on the hot path).
// ═══════════════════════════════════════════════════════════════════════════════

// cachedConfig holds parsed, request-hot values.
type cachedConfig struct {
	mu sync.RWMutex

	tokenRaw string
	token    string

	bindHostRaw string
	bindHost    string

	trustProxyRaw string
	trustProxy    bool

	corsRaw     string
	corsAllowed map[string]struct{}

	scanRootRaw string
	scanRoot    string
}

func (s *APIServer) ensureConfigInit() {
	s.cfgOnce.Do(func() {
		s.cfg = &cachedConfig{}
		s.refreshConfig(true)
	})
}

// refreshConfig re-reads env. When force is false it still re-reads — callers
// on the hot path should prefer the fast getters below which skip parsing
// when the raw value is unchanged.
func (s *APIServer) refreshConfig(force bool) {
	_ = force
	token := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_API_TOKEN"))

	bindHost := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_API_BIND"))
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}

	trustRaw := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_TRUST_PROXY"))
	trust := strings.EqualFold(trustRaw, "1") || strings.EqualFold(trustRaw, "true")

	corsRaw := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_CORS_ORIGINS"))
	allowed := parseCORSOrigins(corsRaw, s.Port)

	scanRoot := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_SCAN_ROOT"))

	s.cfg.mu.Lock()
	defer s.cfg.mu.Unlock()
	s.cfg.tokenRaw, s.cfg.token = token, token
	s.cfg.bindHostRaw, s.cfg.bindHost = bindHost, bindHost
	s.cfg.trustProxyRaw, s.cfg.trustProxy = trustRaw, trust
	s.cfg.corsRaw, s.cfg.corsAllowed = corsRaw, allowed
	s.cfg.scanRootRaw, s.cfg.scanRoot = scanRoot, scanRoot
}

func parseCORSOrigins(raw string, port int) map[string]struct{} {
	if raw == "" {
		raw = fmt.Sprintf("http://127.0.0.1:%d,http://localhost:%d", port, port)
	}
	out := make(map[string]struct{}, 8)
	for _, o := range strings.Split(raw, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out[o] = struct{}{}
		}
	}
	return out
}

// getAPIToken returns the cached API token, refreshing if env changed.
func (s *APIServer) getAPIToken() string {
	s.ensureConfigInit()
	raw := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_API_TOKEN"))
	s.cfg.mu.RLock()
	cached := s.cfg.token
	cachedRaw := s.cfg.tokenRaw
	s.cfg.mu.RUnlock()
	if raw == cachedRaw {
		return cached
	}
	s.cfg.mu.Lock()
	defer s.cfg.mu.Unlock()
	// Double-check after acquiring write lock.
	if raw == s.cfg.tokenRaw {
		return s.cfg.token
	}
	s.cfg.tokenRaw, s.cfg.token = raw, raw
	return raw
}

// getBindHost returns cached bind host, refreshing if env changed.
func (s *APIServer) getBindHost() string {
	s.ensureConfigInit()
	raw := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_API_BIND"))
	if raw == "" {
		raw = "127.0.0.1"
	}
	s.cfg.mu.RLock()
	cached := s.cfg.bindHost
	cachedRaw := s.cfg.bindHostRaw
	s.cfg.mu.RUnlock()
	if raw == cachedRaw {
		return cached
	}
	s.cfg.mu.Lock()
	defer s.cfg.mu.Unlock()
	if raw == s.cfg.bindHostRaw {
		return s.cfg.bindHost
	}
	s.cfg.bindHostRaw, s.cfg.bindHost = raw, raw
	return raw
}

// getTrustProxy reports whether X-Forwarded-For is trusted.
func (s *APIServer) getTrustProxy() bool {
	s.ensureConfigInit()
	raw := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_TRUST_PROXY"))
	s.cfg.mu.RLock()
	cached := s.cfg.trustProxy
	cachedRaw := s.cfg.trustProxyRaw
	s.cfg.mu.RUnlock()
	if raw == cachedRaw {
		return cached
	}
	v := strings.EqualFold(raw, "1") || strings.EqualFold(raw, "true")
	s.cfg.mu.Lock()
	defer s.cfg.mu.Unlock()
	s.cfg.trustProxyRaw, s.cfg.trustProxy = raw, v
	return v
}

// isOriginAllowedCached is the cached variant of originAllowed.
func (s *APIServer) isOriginAllowedCached(origin string) bool {
	s.ensureConfigInit()
	raw := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_CORS_ORIGINS"))
	s.cfg.mu.RLock()
	allowed := s.cfg.corsAllowed
	cachedRaw := s.cfg.corsRaw
	s.cfg.mu.RUnlock()
	if raw != cachedRaw {
		parsed := parseCORSOrigins(raw, s.Port)
		s.cfg.mu.Lock()
		s.cfg.corsRaw, s.cfg.corsAllowed = raw, parsed
		allowed = parsed
		s.cfg.mu.Unlock()
	}
	_, ok := allowed[origin]
	return ok
}

// getScanRoot returns cached scan root.
func (s *APIServer) getScanRoot() string {
	s.ensureConfigInit()
	raw := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_SCAN_ROOT"))
	s.cfg.mu.RLock()
	cached := s.cfg.scanRoot
	cachedRaw := s.cfg.scanRootRaw
	s.cfg.mu.RUnlock()
	if raw == cachedRaw {
		return cached
	}
	s.cfg.mu.Lock()
	defer s.cfg.mu.Unlock()
	s.cfg.scanRootRaw, s.cfg.scanRoot = raw, raw
	return raw
}
