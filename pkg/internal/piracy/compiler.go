// Package piracy — compiler.go
// Компиляция паттернов
package piracy

import (
	"fmt"
	"regexp"
	"strings"
)

func isASCIIWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

// canUseWordBoundaries returns true when Go regexp \b-based matching is likely to work.
// Go's \b is ASCII-only, so we must not apply it to purely non-ASCII aliases (e.g. Cyrillic),
// otherwise we'd silently miss matches.
func canUseWordBoundaries(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}

	return isASCIIWordByte(s[0]) && isASCIIWordByte(s[len(s)-1])
}

// CompilePattern компилирует один паттерн
func CompilePattern(p WeightedPattern) (*CompiledPattern, error) {
	value := strings.TrimSpace(p.Value)
	if value == "" {
		return nil, fmt.Errorf("empty pattern value")
	}

	cp := &CompiledPattern{
		Original: value,
		Lower:    []byte(strings.ToLower(value)),
		Weight:   p.Weight,
		Mode:     p.Mode,
	}

	// Defaults
	if cp.Weight <= 0 {
		cp.Weight = 1.0
	}
	if cp.Mode == "" {
		cp.Mode = MatchSubstring
	}

	// Compile regex for word/regex modes
	switch cp.Mode {
	case MatchWord:
		// Word patterns are plain literals delimited by \b. They are matched by
		// wordIndex/matchPattern directly on lowercased input, so no regexp is
		// compiled here: the engine cost dominated the whole scan.

	case MatchRegex:
		re, err := regexp.Compile("(?i)" + value)
		if err != nil {
			return nil, fmt.Errorf("compile regex pattern %q: %w", value, err)
		}
		cp.Regex = re
	}

	return cp, nil
}

// CompileSite компилирует паттерны сайта
func CompileSite(s *Site) error {
	// Estimate capacity
	capacity := len(s.Patterns) + len(s.Aliases) + len(s.Domains) + len(s.HistoricalDomains)
	s.CompiledPatterns = make([]*CompiledPattern, 0, capacity)

	// Compile weighted patterns
	for _, p := range s.Patterns {
		cp, err := CompilePattern(p)
		if err != nil {
			return fmt.Errorf("pattern %q: %w", p.Value, err)
		}
		s.CompiledPatterns = append(s.CompiledPatterns, cp)
	}

	// Compile domains as substring patterns
	for _, domain := range s.Domains {
		s.CompiledPatterns = append(s.CompiledPatterns, &CompiledPattern{
			Original: domain,
			Lower:    []byte(strings.ToLower(domain)),
			Weight:   1.0,
			Mode:     MatchSubstring,
		})
	}

	// Compile aliases with lower weight
	for _, alias := range s.Aliases {
		cp := &CompiledPattern{
			Original: alias,
			Lower:    []byte(strings.ToLower(alias)),
			Weight:   0.8,
			Mode:     MatchSubstring,
		}

		// Aliases are typically short and often cause massive false positives when treated as substrings
		// (e.g. "lp" matches inside "alpha"). Prefer word-boundary matching for ASCII-like aliases.
		if canUseWordBoundaries(alias) {
			cp.Mode = MatchWord
		}

		s.CompiledPatterns = append(s.CompiledPatterns, cp)
	}

	// Compile historical domains with lower weight
	for _, domain := range s.HistoricalDomains {
		s.CompiledPatterns = append(s.CompiledPatterns, &CompiledPattern{
			Original: domain,
			Lower:    []byte(strings.ToLower(domain)),
			Weight:   0.7,
			Mode:     MatchSubstring,
		})
	}

	// Pre-lowercase false-positive words once, instead of per finding.
	if len(s.FalsePositiveWords) > 0 {
		s.FalsePositiveLower = make([]string, 0, len(s.FalsePositiveWords))
		for _, fp := range s.FalsePositiveWords {
			s.FalsePositiveLower = append(s.FalsePositiveLower, strings.ToLower(fp))
		}
	} else {
		s.FalsePositiveLower = nil
	}

	// Compile regex patterns
	s.CompiledRegex = make([]*regexp.Regexp, 0, len(s.PatternsRegex))
	for _, pattern := range s.PatternsRegex {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return fmt.Errorf("regex %q: %w", pattern, err)
		}
		s.CompiledRegex = append(s.CompiledRegex, re)
	}

	return nil
}

// CompileConfig компилирует всю конфигурацию
func CompileConfig(c *Config) error {
	if c.Compiled {
		return nil
	}

	// Compile sites
	for i := range c.Sites {
		if err := CompileSite(&c.Sites[i]); err != nil {
			return fmt.Errorf("site %q: %w", c.Sites[i].Name, err)
		}
	}

	// Compile mod patterns
	c.ModCompiled = make([]*CompiledPattern, 0, len(c.ModPatterns))
	for _, p := range c.ModPatterns {
		cp, err := CompilePattern(p)
		if err != nil {
			return fmt.Errorf("mod pattern %q: %w", p.Value, err)
		}
		c.ModCompiled = append(c.ModCompiled, cp)
	}

	// Compile crack patterns
	c.CrackCompiled = make([]*CompiledPattern, 0, len(c.CrackPatterns))
	for _, p := range c.CrackPatterns {
		cp, err := CompilePattern(p)
		if err != nil {
			return fmt.Errorf("crack pattern %q: %w", p.Value, err)
		}
		c.CrackCompiled = append(c.CrackCompiled, cp)
	}

	c.Compiled = true
	return nil
}

// NormalizeConfig нормализует конфигурацию (dedupe, lowercase, trim)
func NormalizeConfig(c *Config) {
	seen := make(map[string]struct{})

	for i := range c.Sites {
		site := &c.Sites[i]

		// Normalize patterns
		normalized := make([]WeightedPattern, 0, len(site.Patterns))
		for _, p := range site.Patterns {
			p.Value = strings.TrimSpace(strings.ToLower(p.Value))
			if p.Value == "" {
				continue
			}
			if _, exists := seen[p.Value]; exists {
				continue
			}
			seen[p.Value] = struct{}{}
			normalized = append(normalized, p)
		}
		site.Patterns = normalized

		// Normalize aliases
		normalizedAliases := make([]string, 0, len(site.Aliases))
		for _, a := range site.Aliases {
			a = strings.TrimSpace(strings.ToLower(a))
			if a == "" {
				continue
			}
			if _, exists := seen[a]; exists {
				continue
			}
			seen[a] = struct{}{}
			normalizedAliases = append(normalizedAliases, a)
		}
		site.Aliases = normalizedAliases

		// Normalize domains
		normalizedDomains := make([]string, 0, len(site.Domains))
		for _, d := range site.Domains {
			d = strings.TrimSpace(strings.ToLower(d))
			if d == "" {
				continue
			}
			normalizedDomains = append(normalizedDomains, d)
		}
		site.Domains = normalizedDomains
	}
}
