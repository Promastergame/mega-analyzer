package ml

import "testing"

func TestSafeRecommendationDecision(t *testing.T) {
	tests := []struct {
		name        string
		method      MethodInfo
		wantAllowed bool
		wantReason  string
	}{
		{
			name: "first party simple method remains eligible for review",
			method: MethodInfo{
				ClassName:        "Lcom/example/app/FeatureFlags;",
				FilePath:         "smali_classes2/com/example/app/FeatureFlags.smali",
				IsAppCode:        true,
				InstructionCount: 8,
				RawBody: []string{
					".method public isFeatureEnabled()Z",
					"    const/4 v0, 0x1",
					"    return v0",
					".end method",
				},
			},
			wantAllowed: true,
		},
		{
			name: "google mobile services descriptor is rejected",
			method: MethodInfo{
				ClassName:        "Lcom/google/android/gms/internal/ads/zzalq;",
				IsAppCode:        true,
				InstructionCount: 8,
			},
			wantReason: "framework_or_library_code",
		},
		{
			name: "androidx path is rejected",
			method: MethodInfo{
				ClassName:        "Lcom/example/app/Wrapper;",
				FilePath:         "smali_classes3/androidx/viewpager/widget/ViewPager.smali",
				IsAppCode:        true,
				InstructionCount: 8,
			},
			wantReason: "framework_or_library_code",
		},
		{
			name: "compose coroutine is rejected",
			method: MethodInfo{
				ClassName:        "Landroidx/compose/ui/text/font/AsyncFontListLoader;",
				IsAppCode:        true,
				InstructionCount: 12,
				RawBody: []string{
					"invoke-interface {p1}, Lkotlin/coroutines/Continuation;->getContext()Lkotlin/coroutines/CoroutineContext;",
				},
			},
			wantReason: "framework_or_library_code",
		},
		{
			name: "non application code is rejected",
			method: MethodInfo{
				ClassName:        "Lcom/example/dependency/Helper;",
				InstructionCount: 8,
			},
			wantReason: "non_app_code",
		},
		{
			name: "complex control flow is rejected",
			method: MethodInfo{
				ClassName:        "Lcom/example/app/Parser;",
				IsAppCode:        true,
				InstructionCount: 16,
				RawBody: []string{
					":try_start_0",
					"invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;",
					".catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0",
				},
			},
			wantReason: "complex_control_flow",
		},
		{
			name: "large first party method is rejected",
			method: MethodInfo{
				ClassName:        "Lcom/example/app/LargeMethod;",
				IsAppCode:        true,
				InstructionCount: maxSafeRecommendationInstructions + 1,
			},
			wantReason: "complex_method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := safeRecommendationDecision(&ScoredMethod{Method: tt.method})
			if allowed != tt.wantAllowed {
				t.Fatalf("allowed = %v, want %v (reason = %q)", allowed, tt.wantAllowed, reason)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestNormalizeSafetyReference(t *testing.T) {
	tests := map[string]string{
		"Lcom/google/android/gms/internal/ads/zzalq;":              "com/google/android/gms/internal/ads/zzalq",
		"smali_classes4/androidx/viewpager/widget/ViewPager.smali": "androidx/viewpager/widget/viewpager.smali",
		"smali\\kotlin\\coroutines\\Continuation.smali":            "kotlin/coroutines/continuation.smali",
	}

	for input, want := range tests {
		if got := normalizeSafetyReference(input); got != want {
			t.Errorf("normalizeSafetyReference(%q) = %q, want %q", input, got, want)
		}
	}
}
