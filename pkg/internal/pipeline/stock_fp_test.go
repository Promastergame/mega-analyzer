package pipeline

import (
	"context"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/configs"
	"mega-analyzer/pkg/internal/piracy"
	"mega-analyzer/pkg/internal/types"
)

func TestThreatDetector_RuntimeNamesDoNotSuppress(t *testing.T) {
	for _, name := range []string{"libunity.so", "libil2cpp.so", "libmonosgen-2.0.so", "libapp.so"} {
		t.Run(name, func(t *testing.T) {
			d := NewThreatIndicatorsDetector()
			content := []byte("\x7fELF checking for frida detection discord.com/api/webhooks")
			ctx := newTestContext("lib/arm64-v8a/"+name, content, types.FileTypeNative)
			a := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
			d.Detect(ctx, a)
			for _, m := range a.Matches {
				if m.Text == "ANTI_ANALYSIS+PAYLOAD" {
					return
				}
			}
			t.Fatal("renaming a payload must not suppress native correlation")
		})
	}
}

func TestRuntimeDataNamesDoNotSuppress(t *testing.T) {
	for _, path := range []string{"assets/bin/Data/Managed/etc/mono/browscap.ini", "assets/bin/Data/Managed/etc/mono/mconfig/config.xml"} {
		t.Run(path, func(t *testing.T) {
			ctx := makeKwCtx(path, `debug webminer/2.0 http://collector.badactor.net/payload`, types.FileTypeText)
			ctx.Ctx = context.Background()
			ctx.IsAppCode = true
			inner, err := piracy.NewDetectorFromBytes(configs.PiracySites())
			if err != nil {
				t.Fatal(err)
			}
			detectors := []FileDetector{NewEndpointDetector(), newTestDetector("debug"), NewVulnNetworkDetector(), NewPiracyDetectorAdapter(inner)}
			for _, d := range detectors {
				a := makeAnalysis(path)
				d.Detect(ctx, a)
				if len(a.Matches) == 0 {
					t.Errorf("%T suppressed findings based on path", d)
				}
			}
		})
	}
}

func TestDefaultKeywords_NoBareDebug(t *testing.T) {
	// Bare "debug" (word mode) fires on every APK's BuildConfig.DEBUG field
	// declaration and SDK internals (e.g. Swappy DEBUG:Z). Real debug risk is
	// covered by DEBUG_DETECTION patterns + manifest debuggable.
	d := NewCustomKeywordDetector()
	for _, kw := range d.Keywords() {
		if strings.ToLower(strings.TrimSpace(kw)) == "debug" {
			t.Error("default keywords must not contain bare \"debug\" (systematic false positive)")
		}
	}
}

func TestOverlayDetector_BareLayoutParamsNotOverlay(t *testing.T) {
	// Swappy frame-pacing touches its OWN Activity window attributes
	// (preferredDisplayModeId) — no overlay type, no addView, no overlay
	// permission. Must not score as an overlay attack (ultraf9.apk).
	d := NewAccessibilityAbuseDetector()
	swappy := `.method public final run()V
    invoke-virtual {v0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;
    invoke-virtual {v0}, Landroid/view/Window;->getAttributes()Landroid/view/WindowManager$LayoutParams;
    iput v2, v1, Landroid/view/WindowManager$LayoutParams;->preferredDisplayModeId:I
    invoke-virtual {v0, v1}, Landroid/view/Window;->setAttributes(Landroid/view/WindowManager$LayoutParams;)V
    return-void
.end method`
	ctx := makeKwCtx("smali/com/google/androidgamesdk/SwappyDisplayManager$1.smali", swappy, types.FileTypeSmali)
	a := makeAnalysis(ctx.Path)
	d.Detect(ctx, a)
	for _, m := range a.Matches {
		if m.Category == types.CategorySecurity && strings.Contains(m.Context, "Overlay pattern") {
			t.Errorf("bare LayoutParams must not be an overlay pattern, got: %s", m.Text)
		}
	}

	// Real overlay setup (TYPE_APPLICATION_OVERLAY) still fires (control).
	evil := `.method public show()V
    sget v0, Landroid/view/WindowManager$LayoutParams;->TYPE_APPLICATION_OVERLAY:I
    invoke-virtual {v1, v2}, Landroid/view/WindowManager;->addView(Landroid/view/View;Landroid/view/WindowManager$LayoutParams;)V
    return-void
.end method`
	ctx2 := makeKwCtx("smali/com/evil/Overlay.smali", evil, types.FileTypeSmali)
	a2 := makeAnalysis(ctx2.Path)
	d2 := NewAccessibilityAbuseDetector()
	d2.Detect(ctx2, a2)
	found := false
	for _, m := range a2.Matches {
		if m.Category == types.CategorySecurity && strings.Contains(m.Context, "Overlay pattern") {
			found = true
		}
	}
	if !found {
		t.Error("control: TYPE_APPLICATION_OVERLAY must still match as overlay pattern")
	}
}
