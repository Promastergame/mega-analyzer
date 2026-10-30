package web

import (
	"regexp"
	"strings"
	"testing"
)

// The "Detonation Parameters" and "Target Environment" columns share a single
// #envRow container, and that container belongs to the sandbox tool alone.
//
// Three call sites used to restore it with a bare show("envRow",true) whenever a
// job ended. The visible symptom was backwards from the real defect: finishing a
// Full Static Analysis scan made a sandbox configuration panel appear beneath a
// static report, and reloading the page then made it "vanish" -- even though the
// hidden state was the correct one all along.
//
// These tests pin the invariant that #envRow visibility is derived from the
// active tool in exactly one place.

func TestEnvRowMarkupStartsHidden(t *testing.T) {
	if !strings.Contains(webUIHTML, `<div id="envRow" style="display:none; width:100%;">`) {
		t.Fatal(`#envRow must start hidden; the sandbox columns are not part of the default tool`)
	}
}

func TestSyncEnvRowHelperExists(t *testing.T) {
	const want = `function syncEnvRow(){var m=MODES[curMode];show("envRow",!!m&&m.panel==="sandbox");}`
	if !strings.Contains(webUIHTML, want) {
		t.Fatalf("syncEnvRow helper missing or reworded; expected:\n%s", want)
	}
}

// The regression itself: nothing may force the row visible.
func TestNoCallSiteForcesEnvRowVisible(t *testing.T) {
	re := regexp.MustCompile(`show\(\s*"envRow"\s*,\s*true\s*\)`)
	if hits := re.FindAllString(webUIHTML, -1); len(hits) != 0 {
		t.Fatalf("found %d unconditional show(\"envRow\",true) call(s): %q -- route them through syncEnvRow() instead", len(hits), hits)
	}
}

func TestSelToolDerivesEnvRowFromMode(t *testing.T) {
	if strings.Contains(webUIHTML, `show("envRow",p==="sandbox")`) {
		t.Error("selTool still gates envRow inline; it should call syncEnvRow()")
	}
	// selTool sets curMode before touching panels, so the helper is equivalent.
	idx := strings.Index(webUIHTML, `function selTool(k){`)
	if idx < 0 {
		t.Fatal("selTool not found")
	}
	body := webUIHTML[idx:]
	if end := strings.Index(body, "\nfunction "); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, `curMode=k`) {
		t.Fatal("selTool no longer assigns curMode; syncEnvRow would read a stale mode")
	}
	if !strings.Contains(body, `syncEnvRow();`) {
		t.Error("selTool must call syncEnvRow() so switching tools re-derives the row")
	}
	if strings.Index(body, `curMode=k`) > strings.Index(body, `syncEnvRow();`) {
		t.Error("selTool must assign curMode before calling syncEnvRow()")
	}
}

// syncEnvRow keys off MODES[curMode].panel, so exactly one tool may claim it.
func TestSandboxIsTheOnlyToolWithTheSandboxPanel(t *testing.T) {
	re := regexp.MustCompile(`"([a-z-]+)":\{t:"[^"]*",s:"[^"]*",panel:"([a-z]+)"`)
	ms := re.FindAllStringSubmatch(webUIHTML, -1)
	if len(ms) < 5 {
		t.Fatalf("expected the MODES table to parse; got %d entries", len(ms))
	}
	var owners []string
	for _, m := range ms {
		if m[2] == "sandbox" {
			owners = append(owners, m[1])
		}
	}
	if len(owners) != 1 || owners[0] != "sandbox" {
		t.Fatalf(`panel:"sandbox" must belong to the sandbox tool only, got %v`, owners)
	}
}

// A live detonation hides the configuration columns two ways: the CSS class and
// an explicit call on submit. Both must survive.
func TestSandboxRunStillHidesEnvRow(t *testing.T) {
	for _, want := range []string{
		"body.sbx-running #envRow",
		`if(curMode==="sandbox")show("envRow",false);`,
		`if(curMode==="sandbox"){show("envRow",false);}else{syncEnvRow();}`,
	} {
		if !strings.Contains(webUIHTML, want) {
			t.Errorf("missing sandbox hide path: %s", want)
		}
	}
}

// The finished-sandbox report also hides it before rendering.
func TestLoadSandboxHidesEnvRow(t *testing.T) {
	idx := strings.Index(webUIHTML, `function loadSandbox(id){`)
	if idx < 0 {
		t.Fatal("loadSandbox not found")
	}
	body := webUIHTML[idx:]
	if end := strings.Index(body, "\nfunction "); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, `show("envRow",false);`) {
		t.Error("loadSandbox must hide envRow before showing the report")
	}
}

// The dashboard's OS badge is driven by the selected target rather than the
// Windows placeholder that sits in the static markup.
func TestSandboxDashboardIconFollowsCurrentTarget(t *testing.T) {
	if !strings.Contains(webUIHTML, `var icoKey = (curTarget && curTarget.ico) || (curEnv === "android" ? "android" : "win");`) {
		t.Fatal("sandbox dashboard no longer derives its OS icon from the selected target")
	}
	if !strings.Contains(webUIHTML, `osIco.innerHTML = OS_ICONS[icoKey] || OS_ICONS.other;`) {
		t.Fatal("sandbox dashboard no longer applies the derived OS icon")
	}
}
