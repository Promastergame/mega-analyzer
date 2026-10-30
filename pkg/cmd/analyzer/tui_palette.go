package main

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ACTIONS — OpenCode-style fuzzy command search overlay
// ═══════════════════════════════════════════════════════════════════════════════

// paletteItem describes one command shown in the overlay.
type paletteItem struct {
	label     string
	desc      string
	category  string
	keybind   string // shown as hint, not parsed
	slash     string // e.g. "artifacts"
	onSelect  func()
	suggested bool
	getBool   func() bool // for toggle items: current state
}

// paletteState is a transient overlay inside the TUI.
type paletteState struct {
	t        *tuiState
	filter   string
	items    []paletteItem
	selected int
	vpStart  int
	open     bool
}

func newPalette(t *tuiState) *paletteState {
	return &paletteState{t: t}
}

func (p *paletteState) show() {
	p.filter = ""
	p.selected = 0
	p.vpStart = 0
	p.open = true
	p.refresh()
}

func (p *paletteState) hide() {
	p.open = false
}

func (p *paletteState) toggle() {
	if p.open {
		p.hide()
	} else {
		p.show()
	}
}

// refresh rebuilds the filtered item list based on current rows + static commands.
func (p *paletteState) refresh() {
	rows := p.t.allRows()
	items := []paletteItem{}

	// dynamic toggles from current menu
	for _, r := range rows {
		if r.kind == "bool" && r.label != "" {
			items = append(items, paletteItem{
				label:    r.label,
				desc:     r.hint,
				category: "Settings",
				getBool:  r.getBool,
				onSelect: func(row menuRow) func() {
					return func() {
						if row.getBool != nil && row.setBool != nil {
							v := !row.getBool()
							row.setBool(v)
							if v {
								p.t.toast(toastOK, row.label+" enabled")
							} else {
								p.t.toast(toastWarn, row.label+" disabled")
							}
						}
					}
				}(r),
			})
		}
		if r.kind == "action" && r.run != nil {
			items = append(items, paletteItem{
				label:    r.label,
				desc:     "run action",
				category: "Actions",
				onSelect: func(row menuRow) func() {
					return func() {
						_ = row.run()
					}
				}(r),
			})
		}
	}

	// static commands
	items = append(items, []paletteItem{
		{label: "Start analysis", desc: "run full scan", category: "Actions", suggested: true, onSelect: func() {
			for _, r := range p.t.allRows() {
				if r.kind == "action" && r.label == "─ start analysis" {
					_ = r.run()
					return
				}
			}
		}},
		{label: "Open help", desc: "keybind reference", category: "Navigation", keybind: "?", onSelect: func() {
			p.t.screen = "help"
		}},
		{label: "Quit", desc: "exit wizard", category: "System", keybind: "Q", onSelect: func() {
			p.t.quit = true
		}},
	}...)

	// filter
	if p.filter != "" {
		f := strings.ToLower(p.filter)
		filtered := []paletteItem{}
		for _, it := range items {
			if fuzzyMatch(it.label, f) || fuzzyMatch(it.desc, f) || fuzzyMatch(it.category, f) {
				filtered = append(filtered, it)
			}
		}
		items = filtered
	}

	p.items = items
	if p.selected >= len(p.items) {
		p.selected = 0
	}
	if p.selected < 0 {
		p.selected = 0
	}
}

func fuzzyMatch(s, filter string) bool {
	s = strings.ToLower(s)
	fi := 0
	for _, r := range s {
		if fi < len(filter) && rune(filter[fi]) == r {
			fi++
		}
	}
	return fi == len(filter)
}

func (p *paletteState) handleKey(ev keyEvent) bool {
	if !p.open {
		return false
	}
	switch ev.kind {
	case keyEsc:
		p.hide()
		return true
	case keyEnter:
		if p.selected < len(p.items) {
			p.items[p.selected].onSelect()
			// overlay stays open so user can toggle multiple items
			p.refresh()
		}
		return true
	case keyUp:
		p.selected--
		if p.selected < 0 {
			p.selected = len(p.items) - 1
		}
		if p.selected < 0 {
			p.selected = 0
		}
		p.syncViewport(p.calcMaxVis())
		return true
	case keyDown:
		p.selected++
		if p.selected >= len(p.items) {
			p.selected = 0
		}
		p.syncViewport(p.calcMaxVis())
		return true
	case keyPgUp:
		p.selected -= 5
		if p.selected < 0 {
			p.selected = 0
		}
		p.syncViewport(p.calcMaxVis())
		return true
	case keyPgDn:
		p.selected += 5
		if p.selected >= len(p.items) {
			p.selected = len(p.items) - 1
		}
		if p.selected < 0 {
			p.selected = 0
		}
		p.syncViewport(p.calcMaxVis())
		return true
	case keyBackspace:
		if len(p.filter) > 0 {
			// remove last rune
			runes := []rune(p.filter)
			p.filter = string(runes[:len(runes)-1])
			p.refresh()
		} else {
			p.hide()
		}
		return true
	case keyChar:
		if ev.r == '/' && p.filter == "" {
			// slash prefix for commands, keep it as part of filter
		}
		p.filter += string(ev.r)
		p.refresh()
		return true
	case keyTab:
		// autocomplete to first match
		if len(p.items) > 0 {
			p.selected = 0
			p.items[0].onSelect()
			p.hide()
		}
		return true
	}
	return false
}

func (p *paletteState) calcMaxVis() int {
	windowed := termRows() < 46
	if !windowed {
		return 12
	}
	// For windowed mode, make the list of actions much smaller (max 6 items)
	// so that it fits beautifully in small/windowed terminal sizes without overflowing.
	v := termRows() - 10
	if v < 3 {
		v = 3
	}
	if v > 6 {
		v = 6
	}
	return v
}

func (p *paletteState) syncViewport(maxVis int) {
	// cursor-inside-viewport: scroll only when cursor hits an edge
	if p.selected < p.vpStart {
		p.vpStart = p.selected
	}
	if p.selected >= p.vpStart+maxVis {
		p.vpStart = p.selected - maxVis + 1
	}
	if p.vpStart < 0 {
		p.vpStart = 0
	}
	if p.vpStart > len(p.items)-maxVis && len(p.items) > 0 {
		p.vpStart = len(p.items) - maxVis
		if p.vpStart < 0 {
			p.vpStart = 0
		}
	}
}

func (p *paletteState) render(width, edge int, windowed bool) []string {
	if !p.open {
		return nil
	}
	th := p.t.theme
	out := []string{}

	// title bar
	out = append(out, fmt.Sprintf("%s%s Actions %s",
		th.Bold+th.Primary, strings.Repeat("─", width-11), th.Reset))

	// input line
	prompt := "> " + p.filter
	cursor := "_"
	if len(p.filter) > 0 {
		cursor = ""
	}
	out = append(out, fmt.Sprintf("%s%s%s%s%s",
		th.Bold+th.Primary, prompt, th.Reset, th.Bold+th.Accent, cursor+th.Reset))

	// separator
	out = append(out, th.Edge+strings.Repeat("─", width)+th.Reset)

	// viewport size depends on terminal height
	maxVis := p.calcMaxVis()
	p.syncViewport(maxVis)
	start := p.vpStart
	end := start + maxVis
	if end > len(p.items) {
		end = len(p.items)
	}
	if start > 0 {
		out = append(out, fmt.Sprintf("  %s▲ %d more%s", th.Muted, start, th.Reset))
	}
	for i := start; i < end; i++ {
		it := p.items[i]
		marker := "  "
		labelCol := th.Text
		descCol := th.Muted
		if i == p.selected {
			marker = th.Primary + "▶ " + th.Reset
			labelCol = th.Bold + th.Primary
			descCol = th.Reset
		}
		state := ""
		if it.getBool != nil {
			if it.getBool() {
				state = th.Success + "[on] " + th.Reset
			} else {
				state = th.Muted + "[off]" + th.Reset
			}
		}
		cat := fmt.Sprintf("%s[%s]%s ", th.Muted, it.category, th.Reset)
		labelW := 20
		if state != "" {
			labelW = 14
		}
		line := fmt.Sprintf("%s%s%s%s %s %s%s%s",
			marker, labelCol, padRight(it.label, labelW), th.Reset,
			state, descCol, truncate(it.desc, width-36-len(cat)), th.Reset)
		out = append(out, line)
	}
	if end < len(p.items) {
		out = append(out, fmt.Sprintf("  %s▼ %d more%s", th.Muted, len(p.items)-end, th.Reset))
	}
	if len(p.items) == 0 {
		out = append(out, th.Muted+"  no matches"+th.Reset)
	}

	// footer
	out = append(out, fmt.Sprintf("%s%s %s↑↓ navigate  ↵ select  esc close%s",
		th.Edge, strings.Repeat("─", width-35), th.Muted, th.Reset))

	return out
}
