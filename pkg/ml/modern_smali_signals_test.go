package ml

import "testing"

func TestModernSmaliSignals(t *testing.T) {
	tests := []struct {
		name     string
		detector func(*MethodInfo) *VulnSignal
		method   *MethodInfo
		wantKind VulnKind
		severity VulnSeverity
	}{
		{
			name:     "weak crypto with ECB mode",
			detector: detectWeakCrypto,
			method: &MethodInfo{
				Calls:        []CallInfo{{FullCall: "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;"}},
				StringConsts: []string{"AES/ECB/PKCS5Padding"},
			},
			wantKind: VulnWeakCrypto,
			severity: VulnSeverityHigh,
		},
		{
			name:     "unsafe deserialization",
			detector: detectUnsafeDeserialization,
			method: &MethodInfo{
				Calls: []CallInfo{{FullCall: "Ljava/io/ObjectInputStream;->readObject()Ljava/lang/Object;"}},
			},
			wantKind: VulnUnsafeDeserialization,
			severity: VulnSeverityHigh,
		},
		{
			name:     "webview bridge with file access",
			detector: detectUnsafeWebViewConfig,
			method: &MethodInfo{
				Calls: []CallInfo{
					{FullCall: "Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V"},
					{FullCall: "Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V"},
				},
			},
			wantKind: VulnWebViewConfig,
			severity: VulnSeverityHigh,
		},
		{
			name:     "mutable pending intent",
			detector: detectMutablePendingIntent,
			method: &MethodInfo{
				Calls:        []CallInfo{{FullCall: "Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;I)Landroid/app/PendingIntent;"}},
				StringConsts: []string{"FLAG_MUTABLE"},
			},
			wantKind: VulnMutablePendingIntent,
			severity: VulnSeverityMedium,
		},
		{
			name:     "raw SQL with string concatenation",
			detector: detectSQLInjection,
			method: &MethodInfo{
				Calls: []CallInfo{
					{FullCall: "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"},
					{FullCall: "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"},
				},
			},
			wantKind: VulnSQLInjection,
			severity: VulnSeverityHigh,
		},
		{
			name:     "path traversal indicator",
			detector: detectPathTraversal,
			method: &MethodInfo{
				Calls:        []CallInfo{{FullCall: "Ljava/io/File;-><init>(Ljava/lang/String;)V"}},
				StringConsts: []string{"../config.json"},
			},
			wantKind: VulnPathTraversal,
			severity: VulnSeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signal := tt.detector(tt.method)
			if signal == nil {
				t.Fatal("expected a signal")
			}
			if signal.Kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", signal.Kind, tt.wantKind)
			}
			if signal.Severity != tt.severity {
				t.Fatalf("severity = %q, want %q", signal.Severity, tt.severity)
			}
			if len(signal.Evidence) == 0 {
				t.Fatal("expected evidence")
			}
		})
	}
}

func TestAnalyzeVulnerabilitySignalsIncludesModernSignals(t *testing.T) {
	mi := &MethodInfo{
		Calls:        []CallInfo{{FullCall: "Ljava/security/SecureRandom;->nextBytes([B)V"}},
		StringConsts: []string{"http://api.example.com/v1"},
	}

	signals := AnalyzeVulnerabilitySignals(mi)
	if signals == nil || !signals.HasAny() {
		t.Fatal("expected aggregated vulnerability signals")
	}

	foundCleartext := false
	for _, signal := range signals.Signals {
		if signal.Kind == VulnCleartextHTTP {
			foundCleartext = true
			break
		}
	}
	if !foundCleartext {
		t.Fatalf("expected %q in aggregated signals, got %+v", VulnCleartextHTTP, signals.Signals)
	}
}

func TestDetectWeakCrypto_AlgorithmTokenBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		literals   []string
		wantSignal bool
		wantSevere bool
	}{
		{"ordinary word containing DES", []string{"description"}, false, false},
		{"destroy verb", []string{"destroy"}, false, false},
		{"desktop string", []string{"Desktop"}, false, false},
		{"transformation with DES", []string{"AES/DES/PKCS5Padding"}, true, true},
		{"bare DES literal", []string{"DES"}, true, true},
		{"triple DES name", []string{"DESede"}, true, true},
		{"3DES name", []string{"3DES"}, true, true},
		{"bare RC4 literal", []string{"RC4"}, true, true},
		{"SecureRandom SHA1PRNG is not a digest choice", []string{"SHA1PRNG"}, false, false},
		{"real MD5 choice", []string{"MD5"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := &MethodInfo{StringConsts: tt.literals}
			sig := detectWeakCrypto(mi)
			if !tt.wantSignal {
				if sig != nil {
					t.Fatalf("expected no signal for %q, got %+v", tt.literals, sig)
				}
				return
			}
			if sig == nil {
				t.Fatalf("expected signal for %q", tt.literals)
			}
			if tt.wantSevere && sig.Severity != VulnSeverityHigh {
				t.Fatalf("expected HIGH severity for %q, got %q", tt.literals, sig.Severity)
			}
		})
	}
}

func TestSmaliValidatorAllowsWideRegisterFormats(t *testing.T) {
	validator := NewSmaliValidator()
	code := `.method public static calculate()I
    .registers 300
    const/16 v16, 0x1
    move/from16 v17, v16
    add-int/lit8 v18, v17, 0x1
    return v18
.end method`

	if result := validator.Validate(code); !result.Valid {
		t.Fatalf("wide-register instructions must remain valid, got %+v", result.Errors)
	}
}

func TestSmaliValidatorRejectsNarrowRegisterOverflow(t *testing.T) {
	validator := NewSmaliValidator()
	code := `.method public static field()I
    .registers 17
    iget v16, v0, Lexample/Holder;->value:I
    return v0
.end method`

	result := validator.Validate(code)
	if result.Valid {
		t.Fatal("22c instruction with v16 must be rejected")
	}
	for _, err := range result.Errors {
		if err.Code == ErrRegisterOverflow {
			return
		}
	}
	t.Fatalf("expected %q, got %+v", ErrRegisterOverflow, result.Errors)
}
