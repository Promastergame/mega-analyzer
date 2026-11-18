package main

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DIALOG — modal confirmation overlay
// ═══════════════════════════════════════════════════════════════════════════════

type dialogState struct {
	t        *tuiState
	open     bool
	title    string
	body     string
	confirm  bool // true = yes, false = no (or cancelled)
	okCB     func()
	cancelCB func()
}

func newDialog(t *tuiState) *dialogState {
	return &dialogState{t: t}
}

func (d *dialogState) show(title, body string, onOK func()) {
	d.title = title
	d.body = body
	d.confirm = false
	d.okCB = onOK
	d.cancelCB = nil
	d.open = true
}

func (d *dialogState) hide() {
	d.open = false
}

func (d *dialogState) handleKey(ev keyEvent) bool {
	if !d.open {
		return false
	}
	switch ev.kind {
	case keyEsc:
		if d.cancelCB != nil {
			d.cancelCB()
		}
		d.hide()
		return true
	case keyEnter, keyChar:
		if ev.kind == keyChar && ev.r == 'y' || ev.r == 'Y' || ev.kind == keyEnter {
			d.confirm = true
			if d.okCB != nil {
				d.okCB()
			}
			d.hide()
			return true
		}
		if ev.kind == keyChar && ev.r == 'n' || ev.r == 'N' {
			if d.cancelCB != nil {
				d.cancelCB()
			}
			d.hide()
			return true
		}
	}
	return true // a modal must never pass keystrokes through to a text field
}

func (d *dialogState) render(width int) []string {
	if !d.open {
		return nil
	}
	th := d.t.theme
	out := []string{}

	// dim background line
	out = append(out, "")
	out = append(out, centerText(th.Muted+strings.Repeat("─", width)+th.Reset, width))

	titleLine := fmt.Sprintf("  %s%s%s", th.Bold+th.Warning, d.title, th.Reset)
	out = append(out, centerText(titleLine, width))
	out = append(out, "")

	for _, ln := range wrapText(d.body, width-8) {
		out = append(out, centerText("  "+th.Text+ln+th.Reset, width))
	}

	out = append(out, "")
	buttons := fmt.Sprintf("  %s[Y]es%s    %s[N]o%s",
		th.Bold+th.Success, th.Reset, th.Bold+th.Error, th.Reset)
	out = append(out, centerText(buttons, width))
	out = append(out, centerText(th.Muted+strings.Repeat("─", width)+th.Reset, width))
	return out
}
