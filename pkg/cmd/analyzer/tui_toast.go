package main

import (
	"fmt"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TOAST — transient notification overlay (OpenCode-style)
// ═══════════════════════════════════════════════════════════════════════════════

type toastKind string

const (
	toastOK    toastKind = "ok"
	toastWarn  toastKind = "warn"
	toastInfo  toastKind = "info"
	toastError toastKind = "error"
)

type toastEntry struct {
	text     string
	kind     toastKind
	at       time.Time
	duration time.Duration
}

// toastQueue holds active toasts.
type toastQueue struct {
	entries []toastEntry
}

func (q *toastQueue) add(kind toastKind, text string) {
	d := 4 * time.Second
	if kind == toastError {
		d = 6 * time.Second
	}
	q.entries = append(q.entries, toastEntry{
		text:     text,
		kind:     kind,
		at:       time.Now(),
		duration: d,
	})
	// prune old
	now := time.Now()
	alive := []toastEntry{}
	for _, e := range q.entries {
		if now.Sub(e.at) < e.duration {
			alive = append(alive, e)
		}
	}
	q.entries = alive
}

func (q *toastQueue) active() []toastEntry {
	now := time.Now()
	alive := []toastEntry{}
	for _, e := range q.entries {
		if now.Sub(e.at) < e.duration {
			alive = append(alive, e)
		}
	}
	q.entries = alive
	return alive
}

func (t *tuiState) toast(kind toastKind, text string) {
	t.toasts.add(kind, text)
	// also log to activity
	switch kind {
	case toastOK:
		t.log("ok", text)
	case toastWarn:
		t.log("warn", text)
	case toastError:
		t.log("warn", "error: "+text)
	default:
		t.log("info", text)
	}
}

// renderToasts draws up to 3 active toasts in the top-right corner.
func (t *tuiState) renderToasts(cols int) []string {
	th := t.theme
	active := t.toasts.active()
	if len(active) == 0 {
		return nil
	}
	out := []string{}
	maxW := 50
	if cols > 0 && maxW > cols-10 {
		maxW = cols - 10
	}

	for i, e := range active {
		if i >= 3 {
			break
		}
		var border, fg string
		switch e.kind {
		case toastOK:
			border = th.Success
			fg = th.Success
		case toastWarn:
			border = th.Warning
			fg = th.Warning
		case toastError:
			border = th.Error
			fg = th.Error
		default:
			border = th.Info
			fg = th.Info
		}
		// icon
		icon := "ℹ"
		switch e.kind {
		case toastOK:
			icon = "✓"
		case toastWarn:
			icon = "⚠"
		case toastError:
			icon = "✗"
		}

		msg := truncate(e.text, maxW-4)
		inner := visibleLen(msg) + 4
		pad := maxW - inner - 3
		if pad < 0 {
			pad = 0
		}
		line := fmt.Sprintf("%s%s %s %s",
			border+"┃ "+fg+icon+" "+th.Reset+th.Text,
			msg, th.Reset,
			border+strings.Repeat(" ", pad)+"┃"+th.Reset,
		)
		out = append(out, line)
	}
	return out
}
