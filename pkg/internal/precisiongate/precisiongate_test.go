package precisiongate

import "testing"

// All fixtures are VERBATIM false positives from the mega-analyzer run on
// shattered-pixel-dungeon-3.3.8.apk, plus true-positive controls that MUST
// still fire so the gate does not over-suppress.
func TestEvaluate(t *testing.T) {
	cases := []struct {
		name     string
		c        Candidate
		wantKeep bool
	}{
		// --- FALSE POSITIVES that must be dropped ---
		{"swedish-magisk-prose", Candidate{
			Category: "Piracy Site", Keyword: "magisk", Context: AssetCtx,
			FilePath: "assets/messages/actors/actors_sv.properties",
			Line:     "actors.buffs.amok.desc=Amok orsakar ett tillstand av oerhort raseri och magisk forvirring",
		}, false},
		{"unlocked-game-vocab", Candidate{
			Category: "Mod Detection", Keyword: "unlocked", Context: AssetCtx,
			FilePath: "assets/messages/misc/misc.properties",
			Line:     "badges.new=Badge unlocked: %s.",
		}, false},
		{"cracked-game-vocab", Candidate{
			Category: "Mod Detection", Keyword: "cracked", Context: AssetCtx,
			FilePath: "assets/messages/items/items.properties",
			Line:     "items.trinkets.chaoticcenser.desc=a cracked censer spreads harmful gas",
		}, false},
		{"bundle-hit-without-window", Candidate{
			Category: "PIRACY_SITE", Keyword: "magisk", Context: AssetCtx,
			FilePath: "assets/messages/actors/actors_sv.properties",
			Line:     "magisk", // caller had no wider window: bundle alone decides
		}, false},
		{"semantic-window-inputdevice", Candidate{
			Category: "DEVICE_ID",
			Keyword:  "invoke-virtual {v0}, Landroid/view/InputDevice;->getDeviceId()I",
			Line:     "invoke-virtual {v0}, Landroid/view/InputDevice;->getDeviceId()I",
			Context:  CodeCtx, FilePath: "smali/com/badlogic/gdx/x.smali",
		}, false},
		{"semantic-window-telephony", Candidate{
			Category: "DEVICE_ID",
			Keyword:  "invoke-virtual {v0}, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;",
			Line:     "invoke-virtual {v0}, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;",
			Context:  CodeCtx, FilePath: "smali/evil/x.smali",
		}, true},
		{"des-in-descend", Candidate{
			Category: "Crypto", Keyword: "DES", Context: CodeCtx,
			FilePath: "smali/x.smali", Line: "const-string v0, \"DESCEND\"",
		}, false},
		{"getdeviceid-inputdevice", Candidate{
			Category: "Device", Keyword: "getDeviceId", Context: CodeCtx,
			FilePath: "smali/com/badlogic/gdx/controllers/a.smali",
			Line:     "invoke-virtual {v0}, Landroid/view/InputDevice;->getDeviceId()I",
		}, false},
		{"exec-as-freememory", Candidate{
			Category: "Command Exec", Keyword: "exec", Context: CodeCtx,
			FilePath: "smali/y.smali",
			Line:     "invoke-virtual {v0}, Ljava/lang/Runtime;->freeMemory()J",
		}, false},
		{"mp3-highentropy", Candidate{
			Category: "Media Anomaly", Keyword: "HighEntropy", Context: AssetCtx,
			FilePath: "assets/sounds/alert.mp3", ContainerFmt: "mp3", EntropyBits: 7.87,
		}, false},
		{"ogg-jpeg-polyglot-deep", Candidate{
			Category: "Media Anomaly", Keyword: "magic_signature:jpeg", Context: AssetCtx,
			FilePath: "assets/music/caves_tense.ogg", ContainerFmt: "ogg",
			EmbeddedMagic: "jpeg", ByteOffset: 0x6bbd, ContainerSize: 400000,
		}, false},

		// --- TRUE POSITIVES that must still fire ---
		{"real-des-cipher", Candidate{
			Category: "Crypto", Keyword: "DES", Context: CodeCtx,
			FilePath: "smali/evil.smali",
			Line:     "const-string v1, \"DES\" ... Ljavax/crypto/Cipher;->getInstance",
		}, true},
		{"real-imei", Candidate{
			Category: "Device", Keyword: "getDeviceId", Context: CodeCtx,
			FilePath: "smali/evil.smali",
			Line:     "invoke-virtual {v0}, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;",
		}, true},
		{"real-magisk-package", Candidate{
			Category: "Piracy Site", Keyword: "magisk", Context: CodeCtx,
			FilePath: "smali/root.smali",
			Line:     "const-string v0, \"com.topjohnwu.magisk\"",
		}, true},
		{"real-appended-zip-polyglot", Candidate{
			Category: "Media Anomaly", Keyword: "magic_signature:zip", Context: AssetCtx,
			FilePath: "assets/logo.png", ContainerFmt: "png",
			EmbeddedMagic: "zip", ByteOffset: 399980, ContainerSize: 400000,
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Evaluate(tc.c)
			if v.Keep != tc.wantKeep {
				t.Fatalf("keep=%v want=%v reason=%q", v.Keep, tc.wantKeep, v.Reason)
			}
		})
	}
}

func TestSignatureCheckIsReal(t *testing.T) {
	benign := "getPackageManager getPackageInfo versionName versionCode"
	if SignatureCheckIsReal(benign) {
		t.Fatal("benign version lookup wrongly treated as signature check")
	}
	real := "getPackageInfo GET_SIGNATURES apkContentsSigners MessageDigest"
	if !SignatureCheckIsReal(real) {
		t.Fatal("real signature verification not detected")
	}
}

func TestReviewSignatureLookupDropped(t *testing.T) {
	lookup := Candidate{
		Category: "Tamper", Keyword: "getPackageInfo", FilePath: "smali/App.smali",
		Context: CodeCtx,
		Line:    "info = pm.getPackageInfo(pkg, 0); v = info.versionName",
	}
	if v := Evaluate(lookup); v.Keep {
		t.Errorf("version lookup should drop, kept: %+v", v)
	}
	real := Candidate{
		Category: "Tamper", Keyword: "getPackageInfo", FilePath: "smali/App.smali",
		Context: CodeCtx,
		Line:    "info = pm.getPackageInfo(pkg, GET_SIGNATURES); s = info.signatures",
	}
	if v := Evaluate(real); !v.Keep {
		t.Errorf("real signature check should keep, dropped: %+v", v)
	}
	// Non-code context with the same keyword is unaffected by this rule
	// (other rules may still drop it for their own reasons).
	other := Candidate{
		Category: "Tamper", Keyword: "versionName", FilePath: "smali/App.smali",
		Context: CodeCtx,
		Line:    "v = info.versionName",
	}
	if v := Evaluate(other); !v.Keep {
		t.Errorf("unrelated keyword should keep, dropped: %+v", v)
	}
}

func TestReviewReasonDeterministic(t *testing.T) {
	// "unlock premium" hits two ambiguous tokens; map order must not leak
	// into the Reason.
	c := Candidate{
		Category: "Piracy", Keyword: "unlock premium",
		FilePath: "assets/messages/sv.properties", Context: AssetCtx,
		Line: "Badge unlock premium reward granted today",
	}
	first := Evaluate(c)
	if first.Keep {
		t.Fatalf("expected drop, kept: %+v", first)
	}
	for i := 0; i < 100; i++ {
		if got := Evaluate(c); got != first {
			t.Fatalf("nondeterministic verdict: %+v vs %+v", got, first)
		}
	}
}

func TestReviewRuneBoundaries(t *testing.T) {
	cases := []struct {
		text, keyword string
		want          bool
	}{
		{"DES DESCEND", "DES", true},         // classic: first occurrence standalone
		{"DESCEND", "DES", false},            // substring of a larger word
		{"премиумpremium", "premium", false}, // Cyrillic letter adjacent: not standalone
		{"премиум premium тест", "premium", true},
		{"", "premium", false},
		{"anything", "", false},
	}
	for _, tc := range cases {
		if got := IsStandaloneToken(tc.text, tc.keyword); got != tc.want {
			t.Errorf("IsStandaloneToken(%q, %q) = %v, want %v",
				tc.text, tc.keyword, got, tc.want)
		}
	}
}
