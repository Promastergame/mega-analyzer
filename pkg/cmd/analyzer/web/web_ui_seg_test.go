package web

import (
	"strings"
	"testing"
)

func TestSegmentedControlUsesSharedPalette(t *testing.T) {
	workbenchDeclaration(t, ".seg", "border-radius", "8px")
	workbenchDeclaration(t, ".seg-ind", "background", "var(--accent-soft)")
	workbenchDeclaration(t, ".seg-ind", "box-shadow", "none")
	if strings.Contains(workbenchRule(t, ".seg-ind"), "gradient") {
		t.Error("the report indicator should remain a flat surface")
	}
}

func TestSegmentedControlIsKeyboardVisible(t *testing.T) {
	workbenchDeclaration(t, ".sbtn", "min-height", "44px")
	workbenchDeclaration(t, ".sbtn.on", "text-shadow", "none")
	workbenchDeclaration(t, ".sbtn:focus-visible", "outline", "2px solid var(--focus)")
	workbenchDeclaration(t, ".sbtn:active", "transform", "none")
}

func TestSegmentedTravelIsShortButKept(t *testing.T) {
	workbenchDeclaration(t, ".seg-ind", "transition", "transform .2s var(--ease),width .2s var(--ease)")
}

func TestRangeControlsHaveLargeHitAreas(t *testing.T) {
	workbenchDeclaration(t, ".rng", "height", "44px")
	workbenchDeclaration(t, ".rng::-webkit-slider-thumb", "box-shadow", "none")
	workbenchDeclaration(t, ".rng::-moz-range-thumb", "box-shadow", "none")
}

func TestReducedMotionGuardFollowsComponents(t *testing.T) {
	css := mustAsset("assets/app.css")
	guard := strings.LastIndex(css, "@media(prefers-reduced-motion:reduce)")
	if guard < strings.Index(css, ".seg-ind{") || guard < strings.Index(css, ".rng{") {
		t.Error("reduced-motion overrides must follow the controls")
	}
	for _, marker := range []string{"transition:none!important", "animation-iteration-count:1!important", "preferredScrollBehavior"} {
		if !strings.Contains(spaHTML(), marker) {
			t.Errorf("reduced-motion support missing: %s", marker)
		}
	}
}

func TestProfileButtonsAndDisclosureRemainAccessible(t *testing.T) {
	h := mustAsset("assets/index.html")
	for _, marker := range []string{`class="prof-row" role="group"`, `class="pcard on"`, `aria-pressed="true"`, `id="settingsGrid"`, `id="tuning"`, `id="outRow"`, `class="settings-summary"`} {
		if !strings.Contains(h, marker) {
			t.Errorf("missing profile or disclosure contract: %s", marker)
		}
	}
}

func TestSegmentedControlJSIsUntouched(t *testing.T) {
	h := spaHTML()
	for _, want := range []string{
		"ind.style.width=on.offsetWidth+\"px\";",
		"ind.style.transform=\"translate3d(\"+on.offsetLeft+\"px,0,0)\";",
		"if(!_segReady)ind.style.transition=\"none\";",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("moveSeg was disturbed, missing: %q", want)
		}
	}
}

func TestReportFormatSegmentsAreUnchanged(t *testing.T) {
	h := spaHTML()
	for _, want := range []string{
		`data-v="" onclick="selSeg(this)" type="button" aria-pressed="false">auto</button>`,
		`data-v="short" onclick="selSeg(this)" type="button" aria-pressed="false">short</button>`,
		`data-v="default" onclick="selSeg(this)" type="button" aria-pressed="true">default</button>`,
		`data-v="full" onclick="selSeg(this)" type="button" aria-pressed="false">full</button>`,
		`data-v="all" onclick="selSeg(this)" type="button" aria-pressed="false">all</button>`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("report-format segment markup changed, missing: %q", want)
		}
	}
	if !strings.Contains(h, `<div class="seg" role="group" aria-label="Report format">`) {
		t.Error("the accessible group wrapper is missing")
	}
}
