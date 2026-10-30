package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN — С THREAD-SAFE COMPILE (sync.Once) + DEDUPE
// ═══════════════════════════════════════════════════════════════════════════════

// MaxMatchesPerPattern — защита от pathological files (фикс #10).
const MaxMatchesPerPattern = 1000

// PatternGroup — группа паттернов по категории.
type PatternGroup struct {
	Category    Category   `json:"category"`
	Description string     `json:"description,omitempty"`
	Patterns    []*Pattern `json:"patterns,omitempty"`
}

// Pattern — паттерн поиска с поддержкой сериализации regex.
type Pattern struct {
	Expr          string         `json:"expr,omitempty"`
	Regex         *regexp.Regexp `json:"-"`
	Keywords      []string       `json:"keywords,omitempty"`
	KeywordsLower [][]byte       `json:"-"` // предвычисленные lowercase bytes
	Category      Category       `json:"category"`
	Description   string         `json:"description,omitempty"`
	MustBeAppCode bool           `json:"must_be_app_code,omitempty"`

	compileOnce sync.Once `json:"-"` // thread-safe compile (фикс #9)
	compileErr  error     `json:"-"`
}

// Compile компилирует regex и подготавливает keywords.
// Thread-safe через sync.Once (фикс #9).
func (p *Pattern) Compile() error {
	p.compileOnce.Do(func() {
		if p.Expr != "" && p.Regex == nil {
			re, err := regexp.Compile(p.Expr)
			if err != nil {
				p.compileErr = fmt.Errorf("invalid pattern expr %q: %w", p.Expr, err)
				return
			}
			p.Regex = re
		}
		// Предвычисляем lowercase keywords
		if len(p.Keywords) > 0 && len(p.KeywordsLower) == 0 {
			p.KeywordsLower = make([][]byte, len(p.Keywords))
			for i, kw := range p.Keywords {
				p.KeywordsLower[i] = []byte(strings.ToLower(kw))
			}
		}
	})
	return p.compileErr
}

// UnmarshalJSON с автокомпиляцией regex.
func (p *Pattern) UnmarshalJSON(data []byte) error {
	// Используем отдельный alias без sync.Once, чтобы избежать копирования lock
	type patternAlias struct {
		Expr          string   `json:"expr,omitempty"`
		Keywords      []string `json:"keywords,omitempty"`
		Category      Category `json:"category"`
		Description   string   `json:"description,omitempty"`
		MustBeAppCode bool     `json:"must_be_app_code,omitempty"`
	}

	var a patternAlias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	*p = Pattern{
		Expr:          a.Expr,
		Keywords:      a.Keywords,
		Category:      a.Category,
		Description:   a.Description,
		MustBeAppCode: a.MustBeAppCode,
	}

	// Reset sync.Once для нового паттерна
	p.compileOnce = sync.Once{}
	return p.Compile()
}

// MatchBytes проверяет совпадение паттерна с контентом.
// Возвращает (matched, deduplicated byte indices).
// contentLower должен быть предвычислен!
func (p *Pattern) MatchBytes(content, contentLower []byte) (bool, []int) {
	if err := p.Compile(); err != nil {
		return false, nil
	}

	// Используем map для дедупликации (фикс #2)
	seen := make(map[int]struct{}, 32)

	// Regex поиск
	if p.Regex != nil {
		locs := p.Regex.FindAllIndex(content, MaxMatchesPerPattern)
		for _, loc := range locs {
			seen[loc[0]] = struct{}{}
		}
	}

	// Keywords поиск (case-insensitive)
	for _, kwLower := range p.KeywordsLower {
		if len(seen) >= MaxMatchesPerPattern {
			break // защита от explosion (фикс #10)
		}
		idx := 0
		for {
			pos := bytes.Index(contentLower[idx:], kwLower)
			if pos < 0 {
				break
			}
			absPos := idx + pos
			seen[absPos] = struct{}{}
			idx = absPos + len(kwLower)

			if len(seen) >= MaxMatchesPerPattern {
				break
			}
		}
	}

	if len(seen) == 0 {
		return false, nil
	}

	// Конвертируем в sorted slice
	indices := make([]int, 0, len(seen))
	for idx := range seen {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	return true, indices
}

// ═══════════════════════════════════════════════════════════════════════════════
// DURATION
// ═══════════════════════════════════════════════════════════════════════════════

type Duration time.Duration

func (d Duration) String() string          { return time.Duration(d).String() }
func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		var ns int64
		if err2 := json.Unmarshal(data, &ns); err2 != nil {
			return err
		}
		*d = Duration(ns)
		return nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}
