package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func newTestTUI(t *testing.T) *tuiState {
	t.Helper()
	opts, err := NewCLIParser().Parse([]string{"-no-profile", "-tui"})
	if err != nil {
		t.Fatal(err)
	}
	ts := &tuiState{opts: opts, theme: NoColorTheme(), out: NewOutput(NoColorTheme(), false), screen: "home"}
	ts.out.writer = io.Discard
	ts.home, ts.palette, ts.dialog = newHomeScreen(ts), newPalette(ts), newDialog(ts)
	return ts
}

func TestTUIPathInputPreservesAllCharacters(t *testing.T) {
	for _, path := range []string{
		`"F:\PROJECTS\mega-analyzer\Button VPN(1).apk"`,
		`C:\Users\gQй\My App [release](2).apk`,
		`/home/games/query App.apk`,
		`"F:\Игры\Приложение с пробелами.apk"`,
	} {
		for _, pasted := range []bool{false, true} {
			ts := newTestTUI(t)
			if pasted {
				_ = ts.handleKey(keyEvent{kind: keyPaste, text: path})
			} else {
				for _, r := range path {
					if err := ts.handleKey(keyEvent{kind: keyChar, r: r}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if ts.screen != "home" || ts.dialog.open || ts.palette.open || ts.opts.Target != path {
				t.Fatalf("path %q paste=%v became %q, screen=%s", path, pasted, ts.opts.Target, ts.screen)
			}
			_ = ts.handleKey(keyEvent{kind: keyTab})
			_ = ts.handleKey(keyEvent{kind: keyEsc})
			if ts.home.prompt != path {
				t.Fatalf("navigation changed path: %q", ts.home.prompt)
			}
		}
	}
}

func TestTUIQuotedSpacePathStartsFromHomeAndPalette(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Button VPN(1).apk")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, palette := range []bool{false, true} {
		ts := newTestTUI(t)
		_ = ts.handleKey(keyEvent{kind: keyPaste, text: "  \"" + path + "\"  "})
		if palette {
			ts.palette.show()
			ts.palette.filter = "Start analysis"
			ts.palette.refresh()
		}
		err := ts.handleKey(keyEvent{kind: keyEnter})
		if !errors.Is(err, errStartAnalysis) || ts.opts.Target != path {
			t.Fatalf("palette=%v path=%q err=%v flash=%s", palette, ts.opts.Target, err, ts.flash)
		}
	}
}

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestTUIKeyboardDecodesFragmentedUnicodeAndPaste(t *testing.T) {
	path := `"F:\Игры\Button VPN(1).apk"`
	input := "\x1b[200~" + path + "\r\n\x1b[201~\x1b[3~\x1b[Z\x1b[H\x1b[F\x1bOPя\x03"
	reader := bufio.NewReader(oneByteReader{strings.NewReader(input)})
	wants := []keyEvent{{kind: keyPaste, text: path + "\r\n"}, {kind: keyDelete}, {kind: keyShiftTab}, {kind: keyHome}, {kind: keyEnd}, {kind: keyF1}, {kind: keyChar, r: 'я'}, {kind: keyInterrupt}}
	for _, want := range wants {
		got, err := decodeKey(reader, func() bool { return true })
		if err != nil || got != want {
			t.Fatalf("got %+v err=%v, want %+v", got, err, want)
		}
	}
	// Clipboard newlines and control keys are data, never actions.
	e := newTextEdit("")
	e.handleKey(keyEvent{kind: keyPaste, text: path + "\r\n\x03"}, false)
	if e.text != path {
		t.Fatalf("paste changed path: %q", e.text)
	}
	reader = bufio.NewReader(strings.NewReader("\x1b"))
	got, err := decodeKey(reader, func() bool { return false })
	if err != nil || got.kind != keyEsc {
		t.Fatalf("lone Escape: %+v %v", got, err)
	}
}

func TestTUIEditorConsumesSharedEvents(t *testing.T) {
	ts := newTestTUI(t)
	ts.keyCh = make(chan keyEvent, 8)
	ts.keyCh <- keyEvent{kind: keyChar, r: 0x15}
	ts.keyCh <- keyEvent{kind: keyPaste, text: `F:\PROJECTS\mega-analyzer\Button VPN(1).apk`}
	ts.keyCh <- keyEvent{kind: keyLeft}
	ts.keyCh <- keyEvent{kind: keyChar, r: 'я'}
	ts.keyCh <- keyEvent{kind: keyDelete}
	ts.keyCh <- keyEvent{kind: keyEnter}
	got, ok := ts.inlinePrompt("target", "old.apk", false)
	if !ok || got != `F:\PROJECTS\mega-analyzer\Button VPN(1).apя` {
		t.Fatalf("edit=%q ok=%v", got, ok)
	}
}

func TestTUISectionNavigationAndSearch(t *testing.T) {
	ts := newTestTUI(t)
	_ = ts.handleKey(keyEvent{kind: keyTab})
	for i, section := range tuiSections {
		_ = ts.handleKey(keyEvent{kind: keyChar, r: rune('1' + i)})
		rows := ts.sectionRows()
		if len(rows) == 0 {
			t.Fatalf("empty section %s", section)
		}
		for _, row := range rows {
			if row.section != section {
				t.Fatalf("wrong section for %s", row.label)
			}
		}
	}
	_ = ts.handleKey(keyEvent{kind: keyTab})
	if ts.section != 0 {
		t.Fatal("Tab did not wrap")
	}
	_ = ts.handleKey(keyEvent{kind: keyShiftTab})
	if ts.section != 8 {
		t.Fatal("Shift+Tab did not wrap")
	}
	ts.palette.show()
	ts.palette.filter = "--data-flow-max-methods"
	ts.palette.refresh()
	if len(ts.palette.items) != 1 {
		t.Fatalf("flag search returned %d entries", len(ts.palette.items))
	}
	_ = ts.handleKey(keyEvent{kind: keyEnter})
	rows := ts.sectionRows()
	if ts.palette.open || ts.screen != "settings" || rows[ts.cursor].flag != "data-flow-max-methods" {
		t.Fatal("search did not navigate to setting")
	}
	for _, row := range ts.allRows() {
		if row.flag == "callgraph" {
			row.setBool(false)
			if !ts.opts.CallGraphExplicit {
				t.Fatal("lost explicit setting")
			}
		}
	}
}

func TestTUIAllFlagNamesAreRegistered(t *testing.T) {
	p := NewCLIParser()
	opts, err := p.Parse([]string{"-no-profile"})
	if err != nil {
		t.Fatal(err)
	}
	ts := &tuiState{opts: opts}
	seen := make(map[string]bool)
	for _, row := range ts.allRows() {
		if row.kind == "action" {
			continue
		}
		if row.flag == "" || p.fs.Lookup(row.flag) == nil {
			t.Errorf("unregistered flag %q for %s", row.flag, row.label)
		}
		if seen[row.flag] {
			t.Errorf("duplicate flag %q", row.flag)
		}
		seen[row.flag] = true
	}
}

func TestTUIStartupFlagsPreserveOptions(t *testing.T) {
	for _, section := range tuiSections {
		opts, err := NewCLIParser().Parse([]string{"-no-profile", "-tui-section", section, "-sarif", "-workers", "3", "-timeout", "77", "-deep-scan", "-enable-data-flow=false"})
		if err != nil {
			t.Fatal(err)
		}
		if opts.NoTUI || opts.TUISection != section || !reflect.DeepEqual(opts, tuiOptions(opts)) {
			t.Fatal("TUI lost CLI settings")
		}
		copy := tuiOptions(opts)
		copy.Workers = 99
		if opts.Workers != 3 {
			t.Fatal("wizard modified caller options")
		}
	}
	if _, err := NewCLIParser().Parse([]string{"-tui-section", "invalid"}); err == nil {
		t.Fatal("invalid section accepted")
	}
	opts, err := NewCLIParser().Parse([]string{"-tui-search", "sarif", "-no-tui"})
	if err != nil || !opts.NoTUI {
		t.Fatal("no-tui must win")
	}
}

func TestTUIStartDoesNotDispatchStandaloneTools(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Button VPN(1).apk")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	ts := newTestTUI(t)
	ts.opts.Target = path
	// Loaded or previously selected standalone modes cannot change the meaning
	// of the primary Start command.
	ts.opts.Firmware, ts.opts.MakeServer = true, true
	for _, row := range ts.allRows() {
		if row.kind != "bool" {
			continue
		}
		if row.flag == "firmware" || row.flag == "make-server" {
			t.Fatalf("standalone mode exposed as a toggle: %s", row.flag)
		}
		if row.section == "toolkit" || row.section == "mobile" || row.section == "compliance" {
			row.setBool(true)
		}
	}
	if err := ts.startAnalysis(); !errors.Is(err, errStartAnalysis) {
		t.Fatalf("start=%v, flash=%s", err, ts.flash)
	}
	if ts.opts.IsFirmwareCommand() || ts.opts.IsMakeServerCommand() {
		t.Fatal("regular Start dispatched a standalone tool")
	}
	if !ts.opts.EnableJNI || !ts.opts.EnablePrivacy || !ts.opts.EnableManifestAudit {
		t.Fatal("regular analysis flags were lost")
	}
}

func TestFirmwareActionRejectsAppPackages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Button VPN(1).apk")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	ts := newTestTUI(t)
	ts.opts.Target = "  \"" + path + "\"  "
	found := false
	for _, row := range ts.allRows() {
		if row.label != "─ firmware analysis (run now)" {
			continue
		}
		found = true
		if err := row.run(); err != nil || ts.opts.Firmware || !strings.Contains(ts.flash, "app package") {
			t.Fatalf("APK dispatched to firmware: err=%v mode=%v flash=%q", err, ts.opts.Firmware, ts.flash)
		}
	}
	if !found {
		t.Fatal("firmware action missing")
	}
	for _, ext := range []string{".apk", ".APKS", ".xapk", ".aab", ".dex", ".ipa"} {
		opts, err := NewCLIParser().Parse([]string{"-no-profile", "-firmware", "-t", "app" + ext})
		if err != nil {
			t.Fatal(err)
		}
		if err := opts.Validate(); err == nil {
			t.Errorf("firmware accepted %s", ext)
		}
	}
	for _, path := range []string{"image.bin", "firmware.zip", "rootfs"} {
		if err := validateFirmwareTarget(path); err != nil {
			t.Errorf("firmware rejected %s: %v", path, err)
		}
	}
}

func TestTUILayoutFitsTerminal(t *testing.T) {
	for _, size := range [][2]int{{50, 14}, {60, 18}, {78, 24}, {98, 26}, {116, 30}, {156, 40}} {
		for _, section := range tuiSections {
			ts := newTestTUI(t)
			ts.selectSection(section)
			ts.cursor = len(ts.sectionRows()) - 1
			var output bytes.Buffer
			ts.out.writer = &output
			ts.renderSettings(size[0], 0, size[1])
			lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
			if len(lines) > size[1] {
				t.Errorf("%s %v: %d rows", section, size, len(lines))
			}
			for i, line := range lines {
				if visibleLen(line) > size[0] {
					t.Errorf("%s %v row %d width=%d: %s", section, size, i, visibleLen(line), line)
				}
			}
			if dir := os.Getenv("TUI_SNAPSHOT_DIR"); dir != "" && section == "analysis" {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("settings-%dx%d.txt", size[0], size[1])), output.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				ts.theme = DarkTheme()
				ts.out.theme = ts.theme
				output.Reset()
				ts.renderSettings(size[0], 0, size[1])
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("settings-%dx%d.ansi", size[0], size[1])), output.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				if size[0] == 116 {
					ts.home.setPrompt(`"F:\PROJECTS\mega-analyzer\Button VPN(1).apk"`)
					if err := os.WriteFile(filepath.Join(dir, "home.ansi"), []byte(strings.Join(ts.home.render(116, 0), "\n")), 0600); err != nil {
						t.Fatal(err)
					}
					ts.palette.show()
					ts.palette.filter = "data-flow"
					ts.palette.refresh()
					if err := os.WriteFile(filepath.Join(dir, "search.ansi"), []byte(strings.Join(ts.palette.render(116, 0, true), "\n")), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}
