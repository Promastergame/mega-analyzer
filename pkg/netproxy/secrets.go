package netproxy

import (
	"fmt"
	"regexp"
	"sync"
)

// SecretScanner сканирует захваченные данные на наличие секретов.
//
// Patterns are compiled once at construction (previously they were stored as
// raw strings and never compiled, so either the scanner did nothing or it
// recompiled the same regexps on every scan).
type SecretScanner struct {
	patterns map[string]*regexp.Regexp
	mu       sync.RWMutex
}

func newSecretScanner() (*SecretScanner, error) {
	raw := initializeSecretPatterns()
	compiled := make(map[string]*regexp.Regexp, len(raw))
	for name, expr := range raw {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("secret pattern %q invalid: %w", name, err)
		}
		compiled[name] = re
	}
	return &SecretScanner{patterns: compiled}, nil
}

// Scan returns the names of every pattern that matches data.
func (s *SecretScanner) Scan(data []byte) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var hits []string
	for name, re := range s.patterns {
		if re.Match(data) {
			hits = append(hits, name)
		}
	}
	return hits
}

// initializeSecretPatterns инициализирует паттерны для поиска секретов.
//
// Patterns are value-oriented rather than keyword-only: matching a bare word
// like "password" or "token" anywhere in a byte stream produces overwhelming
// false positives, so we require a key=value shape or a concrete token format.
func initializeSecretPatterns() map[string]string {
	return map[string]string{
		"api_key":      `(?i)api[_-]?key["'\s:=]+[A-Za-z0-9._\-]{16,}`,
		"private_key":  `-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`,
		"password":     `(?i)(?:password|passwd|pwd)["'\s:=]+[^\s"']{6,}`,
		"bearer_token": `(?i)bearer\s+[A-Za-z0-9._\-]{16,}`,
		"aws_key":      `AKIA[0-9A-Z]{16}`,
		"github_token": `ghp_[0-9a-zA-Z]{36}`,
		"jwt":          `\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`,
	}
}
