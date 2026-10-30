package matcher

import (
	"strings"
	"testing"
)

// gateCorpus holds representative lines from decompiled Android apps. It is the
// haystack for the necessary-condition property test below.
var gateCorpus = []string{
	`invoke-virtual {v0}, Lcom/android/vending/billing/IInAppBillingService;->getPurchases()`,
	`const-string v1, "isPremiumUser"`,
	`const-string v1, "IsPremiumUser"`,
	`.method public checkLicense()Z`,
	`.method private static a(Ljava/lang/String;)V`,
	`invoke-static {}, Lcom/google/android/gms/ads/MobileAds;->initialize()`,
	`const-string v2, "https://api.example.com/v1/subscription/verify"`,
	`const-string v3, "192.168.1.1"`,
	`invoke-virtual {p0}, Landroid/telephony/TelephonyManager;->getDeviceId()`,
	`if-eqz v0, :cond_premium_expired`,
	`const-string v4, "lucky patcher detected"`,
	`const-string v5, "com.chelpus.lackypatch"`,
	`invoke-static {v0, v1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)`,
	`const-string v6, "trial_expired_at"`,
	`invoke-virtual {v7}, Ldalvik/system/DexClassLoader;->loadClass()`,
	`const-string v8, "su"`,
	`const-string v9, "/system/xbin/su"`,
	`.field private mSubscriptionActive:Z`,
	`invoke-static {}, Lcom/appsflyer/AppsFlyerLib;->getInstance()`,
	`const-string v10, "BILLING_RESPONSE_RESULT_OK"`,
	`sget-object v11, Lcom/example/app/BuildConfig;->DEBUG:Z`,
	`const-string v12, "signature_mismatch"`,
	`<uses-permission android:name="android.permission.INTERNET" />`,
	`android:debuggable="true"`,
	`const-string v13, "purchaseToken"`,
	`invoke-interface {v14}, Ljava/util/Map;->get(Ljava/lang/Object;)`,
	`const-string v15, "ProGuard"`,
	`plain english sentence with no android tokens at all`,
	``,
	`   `,
}

// TestLiteralGateIsNecessaryCondition is the safety net for the scanLines
// optimization: skipping the regex when the gate literal is absent is only
// sound if every line the regex matches also contains the gate literal.
// Any pattern violating that would silently drop findings.
func TestLiteralGateIsNecessaryCondition(t *testing.T) {
	compiled, err := Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	gated := 0
	for gi := range compiled.Groups {
		for _, pat := range compiled.Groups[gi].Patterns {
			if pat.Regex == nil || pat.GateLiteral == "" {
				continue
			}
			gated++

			for _, line := range gateCorpus {
				if !pat.Regex.MatchString(line) {
					continue
				}
				haystack := line
				if pat.GateFold {
					haystack = strings.ToLower(line)
				}
				if !strings.Contains(haystack, pat.GateLiteral) {
					t.Errorf("pattern %q matched %q but gate literal %q (fold=%v) is absent: the gate would drop this finding",
						pat.Description, line, pat.GateLiteral, pat.GateFold)
				}
			}
		}
	}

	if gated == 0 {
		t.Fatal("no pattern got a literal gate; the optimization is not wired up")
	}
	t.Logf("%d gated patterns checked against %d corpus lines", gated, len(gateCorpus))
}

func TestBuildLiteralGate(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    string
		fold    bool
	}{
		{"plain literal", `checkLicense`, "checkLicense", false},
		{"case insensitive", `(?i)isPremium`, "ispremium", true},
		{"longest run in concat", `[a-z]+->getPurchases\(`, "->getPurchases(", false},
		{"too short", `ab`, "", false},
		{"alternation is not required", `(foo|barbaz)`, "", false},
		{"char class only", `[0-9]{4,}`, "", false},
		{"literal before alternation", `Lcom/android/(vending|billing)`, "Lcom/android/", false},
		{"invalid regex", `(unclosed`, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildLiteralGate(tc.pattern)
			if got.literal != tc.want || got.fold != tc.fold {
				t.Fatalf("buildLiteralGate(%q) = (%q, fold=%v), want (%q, fold=%v)",
					tc.pattern, got.literal, got.fold, tc.want, tc.fold)
			}
		})
	}
}

// TestCategoryIndexCoversAllPatterns guards the fast path in the hot loop: a
// pattern whose category is missing from the registry falls back to map lookups,
// which is correct but slow, and a wrong id would corrupt the per-file limits.
func TestCategoryIndexCoversAllPatterns(t *testing.T) {
	compiled, err := Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	for gi := range compiled.Groups {
		for _, pat := range compiled.Groups[gi].Patterns {
			if pat.CatIdx < 0 || int(pat.CatIdx) >= numCategories() {
				t.Fatalf("pattern %q has category %q with out-of-range id %d", pat.Description, pat.Category, pat.CatIdx)
			}
			if catNames[pat.CatIdx] != pat.Category {
				t.Fatalf("id %d maps to %q, want %q", pat.CatIdx, catNames[pat.CatIdx], pat.Category)
			}
		}
	}
}

// TestCatScratchLimits checks the per-file bookkeeping that replaced the two
// maps: one match per category per line, and the per-file limit is honoured.
func TestCatScratchLimits(t *testing.T) {
	compiled, err := Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var cat = compiled.Groups[0].Category
	id := categoryID(cat)
	if id < 0 {
		t.Fatalf("category %q is not registered", cat)
	}
	limit := int(catFileLimitByID[id])

	s := newCatScratch()
	s.nextLine()
	if s.blocked(id, cat) {
		t.Fatal("fresh scratch must not block")
	}
	s.record(id, cat)
	if !s.blocked(id, cat) {
		t.Fatal("same category must be blocked for the rest of the line")
	}

	for i := 1; i < limit; i++ {
		s.nextLine()
		if s.blocked(id, cat) {
			t.Fatalf("blocked after %d matches, limit is %d", i, limit)
		}
		s.record(id, cat)
	}

	s.nextLine()
	if !s.blocked(id, cat) {
		t.Fatalf("per-file limit %d was not enforced", limit)
	}
}
