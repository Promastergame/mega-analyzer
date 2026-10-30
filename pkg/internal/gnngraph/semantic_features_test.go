package gnngraph

import (
	"testing"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/dexir"
)

func semanticNode(t *testing.T, refs []cfg.InstructionRef) []float32 {
	t.Helper()
	return ExtractFeatures(&cfg.CFGNode{Instructions: refs}, 1)
}

func TestSemanticInvokeBuckets(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		slot int
	}{
		{"license", "invoke-virtual {v0}, Lcom/google/android/vending/licensing/LicenseChecker;->checkAccess()V", featAPILicense},
		{"billing", "invoke-static {v0}, Lcom/android/billingclient/api/BillingClient;->isReady()Z", featAPILicense},
		{"reflection", "invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;", featAPIReflection},
		{"dynload", "invoke-virtual {v0}, Ldalvik/system/DexFile;->loadDex(Ljava/lang/String;Ljava/lang/String;I)Ldalvik/system/DexFile;", featAPIDynLoad},
		{"crypto", "invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;", featAPICrypto},
		{"pkgsig", "invoke-virtual {v0, v1}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", featAPIPkgSig},
		{"native", "invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V", featAPINative},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Raw path (no IR): the method token is parsed from Raw text.
			f := semanticNode(t, []cfg.InstructionRef{{Opcode: "invoke-virtual", Raw: tc.raw}})
			if f[tc.slot] != 1 {
				t.Fatalf("%s: raw path slot %d = %v, want 1\n%v", tc.raw, tc.slot, f[tc.slot], f)
			}
			for s := 28; s < 36; s++ {
				if s != tc.slot && f[s] != 0 {
					t.Fatalf("%s: raw path slot %d = %v, want 0 (only %d set)", tc.raw, s, f[s], tc.slot)
				}
			}
		})
	}
}

func TestSemanticInvokeTypedIR(t *testing.T) {
	// Typed path: IR.Method drives classification even when Raw is empty.
	f := semanticNode(t, []cfg.InstructionRef{{
		Opcode: "invoke-static",
		IR:     &dexir.Instruction{Op: dexir.OpInvokeStatic, Method: &dexir.MethodRef{Class: "Lcom/pairip/licensecheck/LicenseClient;", Name: "check"}},
	}})
	if f[featAPILicense] != 1 {
		t.Fatalf("typed license invoke: slot 28 = %v, want 1\n%v", f[featAPILicense], f)
	}

	f = semanticNode(t, []cfg.InstructionRef{{
		Opcode: "invoke-virtual",
		IR:     &dexir.Instruction{Op: dexir.OpInvokeVirtual, Method: &dexir.MethodRef{Class: "Ldalvik/system/DexClassLoader;", Name: "findClass"}},
	}})
	if f[featAPIDynLoad] != 1 {
		t.Fatalf("typed classloader invoke: slot 30 = %v, want 1\n%v", f[featAPIDynLoad], f)
	}
}

func TestSemanticStrings(t *testing.T) {
	f := semanticNode(t, []cfg.InstructionRef{{Opcode: "const-string", Raw: `const-string v0, "https://license.example.com/check"`}})
	if f[featStrURL] != 1 {
		t.Fatalf("url string: slot 34 = %v, want 1", f[featStrURL])
	}

	f = semanticNode(t, []cfg.InstructionRef{{
		Opcode: "const-string",
		IR:     &dexir.Instruction{Op: dexir.OpConstString, Dst: 0, HasStr: true, Str: "premium_subscription_trial"},
	}})
	if f[featStrLicenseKw] != 1 {
		t.Fatalf("license keyword: slot 35 = %v, want 1", f[featStrLicenseKw])
	}
	if f[featStrURL] != 0 {
		t.Fatalf("license keyword must not set url slot: %v", f[featStrURL])
	}

	// Plain strings stay silent on all semantic slots.
	f = semanticNode(t, []cfg.InstructionRef{{Opcode: "const-string", Raw: `const-string v0, "hello world"`}})
	for s := 28; s < 36; s++ {
		if f[s] != 0 {
			t.Fatalf("plain string set slot %d", s)
		}
	}
}

func TestSemanticFieldSig(t *testing.T) {
	f := semanticNode(t, []cfg.InstructionRef{{
		Opcode: "iget-object",
		Raw:    "iget-object v0, v1, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;",
	}})
	if f[featAPIPkgSig] != 1 {
		t.Fatalf("signatures field: slot 32 = %v, want 1\n%v", f[featAPIPkgSig], f)
	}
}

func TestSemanticPlainInvokeSilent(t *testing.T) {
	f := semanticNode(t, []cfg.InstructionRef{{Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I"}})
	for s := 28; s < 36; s++ {
		if f[s] != 0 {
			t.Fatalf("plain invoke set semantic slot %d", s)
		}
	}
	// Structural flags still work.
	if f[18] != 1 {
		t.Fatalf("isCall lost: %v", f)
	}
}
