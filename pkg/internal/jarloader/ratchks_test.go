package jarloader

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestRatSignalsPaths(t *testing.T) {
	cf := &ClassFile{
		ThisClass: "com.evil.DiscordStealer",
		Strings: []string{
			"discord/Local Storage/leveldb",
			"Login Data",
			"Cookies",
			"exodus.wallet",
			"launcher_accounts.json",
			"Telegram Desktop/tdata",
			".ssh/id_rsa",
			"hello world",
		},
	}
	hits := ratSignals(cf)
	cats := map[string]bool{}
	for _, h := range hits {
		cats[h.subcat] = true
	}
	for _, want := range []string{"malware", "discord", "browser", "wallet", "minecraft", "telegram", "ssh"} {
		if !cats[want] {
			t.Errorf("missing subcat %q in %+v", want, hits)
		}
	}
	// Bare "Cookies" is LOW (HTTP client cookie jars share the word).
	for _, h := range hits {
		if h.subcat == "browser" && h.evidence == "Cookies" && h.sev != types.SeverityLow {
			t.Errorf("Cookies severity = %v, want Low", h.sev)
		}
	}
}

func TestRatSignalsAPIs(t *testing.T) {
	cf := &ClassFile{
		ThisClass: "com.evil.Spy",
		MethodRefs: []MethodRef{
			{Class: "com.sun.jna.platform.win32.User32", Name: "GetAsyncKeyState"},
			{Class: "java.awt.Robot", Name: "createScreenCapture"},
			{Class: "javax.sound.sampled.AudioSystem", Name: "getTargetDataLine"},
			{Class: "javax.sound.sampled.TargetDataLine", Name: "read"},
			{Class: "com.github.sarxos.webcam.Webcam", Name: "getDefault"},
			{Class: "com.sun.jna.platform.win32.Advapi32", Name: "CryptUnprotectData"},
			{Class: "java.net.ServerSocket", Name: "accept"},
			{Class: "java.awt.Toolkit", Name: "getSystemClipboard"},
			{Class: "java.lang.String", Name: "concat"},
		},
	}
	bySub := map[string]types.Severity{}
	for _, h := range ratSignals(cf) {
		bySub[h.subcat] = h.sev
	}
	want := map[string]types.Severity{
		"keylog":     types.SeverityHigh,
		"screen":     types.SeverityMedium,
		"microphone": types.SeverityMedium,
		"camera":     types.SeverityMedium,
		"dpapi":      types.SeverityHigh,
		"ratsock":    types.SeverityMedium,
		"clipboard":  types.SeverityLow,
	}
	for sub, sev := range want {
		if got, ok := bySub[sub]; !ok || got != sev {
			t.Errorf("subcat %q: got (%v,%v), want severity %v", sub, ok, got, sev)
		}
	}
}

func TestRatSignalsTrackerHost(t *testing.T) {
	cf := &ClassFile{
		ThisClass:       "com.evil.Beacon",
		StringConstants: []string{"https://api.ipify.org/"},
	}
	var tracker []types.Match
	for _, m := range analyzeClass(cf, "Beacon.class") {
		if m.Category == types.CategoryStealerIndicator {
			tracker = append(tracker, m)
		}
	}
	if len(tracker) != 1 {
		t.Fatalf("want 1 ip-tracker row, got %+v", tracker)
	}
	// Tracker hosts must not ALSO produce a generic URL inventory row.
	for _, m := range analyzeClass(cf, "Beacon.class") {
		if m.Category == types.CategoryNetworkEndpoint && m.Severity == types.SeverityInfo {
			t.Errorf("tracker host must skip URL inventory: %+v", m)
		}
	}
}

func TestEmitRatCombo(t *testing.T) {
	mk := func(sub string) types.Match {
		return types.Match{
			Categorized: types.Categorized{Category: types.CategoryStealerIndicator},
			Pattern:     "rat-indicator:" + sub,
		}
	}
	rep := &Report{Target: "x.jar", Findings: []types.Match{mk("browser"), mk("discord")}}
	if m := emitRatCombo(rep); m != nil {
		t.Errorf("2 subcats must not combo: %+v", m)
	}
	rep.Findings = append(rep.Findings, mk("keylog"), mk("wallet"))
	m := emitRatCombo(rep)
	if m == nil {
		t.Fatal("4 subcats must combo")
	}
	if m.Category != types.CategoryMalwareCombo || m.Severity != types.SeverityHigh {
		t.Errorf("got %v %v, want MALWARE_COMBO/High", m.Category, m.Severity)
	}
}

func TestRatFindingsInAnalyzeClass(t *testing.T) {
	cf := &ClassFile{
		ThisClass:       "com.evil.BrowserDataStealer",
		StringConstants: []string{"Login Data"},
		MethodRefs:      []MethodRef{{Class: "java.awt.Robot", Name: "createScreenCapture"}},
	}
	var rows []types.Match
	for _, m := range analyzeClass(cf, "evil.class") {
		if m.Category == types.CategoryStealerIndicator {
			rows = append(rows, m)
		}
	}
	if len(rows) < 3 {
		t.Fatalf("want >=3 stealer rows (name+browser+screen), got %+v", rows)
	}
}

func TestRatPlaybackSilent(t *testing.T) {
	// Pure sound playback (game UI sounds) must not read as microphone
	// capture: learned from wexside's CustomSoundLibrary (22 FP rows).
	cf := &ClassFile{
		ThisClass: "ru.wexside.util.CustomSoundLibrary",
		MethodRefs: []MethodRef{
			{Class: "javax.sound.sampled.AudioSystem", Name: "getAudioInputStream"},
			{Class: "javax.sound.sampled.AudioSystem", Name: "getClip"},
			{Class: "javax.sound.sampled.AudioSystem", Name: "getLine"},
			{Class: "javax.sound.sampled.Clip", Name: "open"},
			{Class: "javax.sound.sampled.Clip", Name: "start"},
			{Class: "javax.sound.sampled.SourceDataLine", Name: "write"},
		},
	}
	for _, h := range ratSignals(cf) {
		if h.subcat == "microphone" {
			t.Errorf("playback-only refs fired microphone: %+v", h)
		}
	}
	if hits := ratSignals(cf); len(hits) != 0 {
		t.Errorf("playback-only class must be fully silent, got %+v", hits)
	}
}

func TestRatNameNeedsCorroboration(t *testing.T) {
	// A gameplay "stealer" (chest looting) with no theft behavior around
	// it stays silent; with a credential store beside it, it counts.
	lonely := &ClassFile{ThisClass: "ru.wexside.module.player.ChestStealerModule"}
	if hits := ratSignals(lonely); len(hits) != 0 {
		t.Errorf("uncorroborated stealer name fired: %+v", hits)
	}
	backed := &ClassFile{
		ThisClass: "ru.wexside.module.player.ChestStealerModule",
		Strings:   []string{"Login Data"},
	}
	cats := map[string]bool{}
	for _, h := range ratSignals(backed) {
		cats[h.subcat] = true
	}
	if !cats["malware"] || !cats["browser"] {
		t.Errorf("corroborated stealer name must fire (malware+browser), got %+v", ratSignals(backed))
	}
}

func TestRatLibCallerPathsSilent(t *testing.T) {
	// A bundled HTTP client naming its own cookie jar is library
	// self-talk, not credential theft: learned from KeazClient's shaded
	// httpclient (a dozen browser-LOW rows from getCookies/CookieSpecs).
	cf := &ClassFile{
		ThisClass: "org.apache.http.client.CookieStore",
		Strings:   []string{"getCookies", "CookieSpecs", "cookieSpec", "setCookieSpec", "ignoreCookies"},
	}
	for _, h := range ratSignals(cf) {
		if h.subcat == "browser" {
			t.Errorf("library self-talk fired browser: %+v", h)
		}
	}
	if hits := ratSignals(cf); len(hits) != 0 {
		t.Errorf("httpclient internals must be fully silent, got %+v", hits)
	}
}

func TestRatWebserverRatsockSilent(t *testing.T) {
	// Javassist's bundled debug web server accept()s sockets by design;
	// shaded copies (com.viaversion...libs.javassist...) must hush too.
	for _, cls := range []string{
		"javassist.tools.web.Webserver",
		"com.viaversion.viaversion.libs.javassist.tools.web.Webserver",
	} {
		cf := &ClassFile{
			ThisClass: cls,
			MethodRefs: []MethodRef{
				{Class: "java.net.ServerSocket", Name: "accept"},
				{Class: "java.net.ServerSocket", Name: "close"},
			},
		}
		for _, h := range ratSignals(cf) {
			if h.subcat == "ratsock" {
				t.Errorf("webserver accept fired ratsock in %s: %+v", cls, h)
			}
		}
	}
	// A real listener elsewhere still fires.
	evil := &ClassFile{
		ThisClass:  "com.evil.Listener",
		MethodRefs: []MethodRef{{Class: "java.net.ServerSocket", Name: "accept"}},
	}
	found := false
	for _, h := range ratSignals(evil) {
		if h.subcat == "ratsock" && h.sev == types.SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Error("plain accept() outside a webserver must still fire ratsock/medium")
	}
}

func TestRatLibCallerAPISilent(t *testing.T) {
	// Library self-implementation is not a foreign use: LWJGL's own
	// keyboard binding, JNA's own DPAPI helpers, the JDK Robot class
	// itself, log4j's socket server. Learned from KeazClient's fat jar,
	// where these stacked into a bogus HIGH stealer-combo.
	for _, tc := range []struct {
		class string
		ref   MethodRef
	}{
		{"org.lwjgl.opengl.WindowsKeyboard", MethodRef{Class: "org.lwjgl.opengl.WindowsKeyboard", Name: "GetAsyncKeyState"}},
		{"com.sun.jna.platform.win32.Crypt32Util", MethodRef{Class: "com.sun.jna.platform.win32.Crypt32", Name: "CryptUnprotectData"}},
		{"java.awt.Robot", MethodRef{Class: "java.awt.Robot", Name: "createScreenCapture"}},
		{"javax.sound.sampled.AudioInputStream", MethodRef{Class: "javax.sound.sampled.TargetDataLine", Name: "read"}},
		{"org.apache.logging.log4j.core.net.server.TcpSocketServer", MethodRef{Class: "java.net.ServerSocket", Name: "accept"}},
	} {
		cf := &ClassFile{ThisClass: tc.class, MethodRefs: []MethodRef{tc.ref}}
		if hits := ratSignals(cf); len(hits) != 0 {
			t.Errorf("library self-impl must be silent in %s, got %+v", tc.class, hits)
		}
	}
	// Same references from mod code still fire.
	evil := &ClassFile{
		ThisClass: "com.evil.Stealer",
		Strings:   []string{"Login Data"},
		MethodRefs: []MethodRef{
			{Class: "com.sun.jna.platform.win32.User32", Name: "GetAsyncKeyState"},
			{Class: "java.awt.Robot", Name: "createScreenCapture"},
		},
	}
	cats := map[string]bool{}
	for _, h := range ratSignals(evil) {
		cats[h.subcat] = true
	}
	for _, want := range []string{"malware", "browser", "keylog", "screen"} {
		if !cats[want] {
			t.Errorf("mod caller must still fire %q, got %+v", want, ratSignals(evil))
		}
	}
}
