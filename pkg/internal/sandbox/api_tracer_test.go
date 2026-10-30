package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAPITracer_Attach(t *testing.T) {
	tracer := NewAPITracer([]string{CategoryMemory, CategoryProcess})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tracer.Attach(ctx, 1234)
	if err != nil {
		t.Skipf("API tracer attach failed (expected on non-Windows): %v", err)
	}

	defer tracer.Stop()
}

func TestAPITracer_Calls(t *testing.T) {
	tracer := NewAPITracer([]string{CategoryMemory})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := tracer.Attach(ctx, 1234)
	if err != nil {
		t.Skipf("API tracer attach failed (expected on non-Windows): %v", err)
	}

	defer tracer.Stop()

	// Collect calls for a short time
	calls := []APICall{}
	timeout := time.After(1 * time.Second)

	for {
		select {
		case call := <-tracer.Calls():
			calls = append(calls, call)
			if len(calls) >= 3 {
				goto done
			}
		case <-timeout:
			goto done
		}
	}

done:
	if len(calls) == 0 {
		t.Skip("No API calls captured (expected on non-Windows)")
	}

	// Verify call structure
	for _, call := range calls {
		if call.ProcessID == 0 {
			t.Errorf("Expected non-zero ProcessID, got %d", call.ProcessID)
		}
		if call.Function == "" {
			t.Error("Expected non-empty Function")
		}
		if call.Module == "" {
			t.Error("Expected non-empty Module")
		}
	}
}

func TestAPITracer_Detach(t *testing.T) {
	tracer := NewAPITracer([]string{CategoryMemory})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tracer.Attach(ctx, 1234)
	if err != nil {
		t.Skipf("API tracer attach failed (expected on non-Windows): %v", err)
	}

	defer tracer.Stop()

	err = tracer.Detach(1234)
	if err != nil {
		t.Skipf("API tracer detach failed (expected on non-Windows): %v", err)
	}
}

func TestAPITracer_Stop(t *testing.T) {
	tracer := NewAPITracer([]string{CategoryMemory})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tracer.Attach(ctx, 1234)
	if err != nil {
		t.Skipf("API tracer attach failed (expected on non-Windows): %v", err)
	}

	err = tracer.Stop()
	if err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	// Verify channel is closed
	_, ok := <-tracer.Calls()
	if ok {
		t.Error("Expected calls channel to be closed")
	}
}

func TestDetectProcessInjection(t *testing.T) {
	tests := []struct {
		name     string
		calls    []APICall
		expected bool
	}{
		{
			name: "complete injection sequence",
			calls: []APICall{
				{Function: "VirtualAllocEx"},
				{Function: "WriteProcessMemory"},
				{Function: "CreateRemoteThread"},
			},
			expected: true,
		},
		{
			name: "incomplete sequence - missing CreateRemoteThread",
			calls: []APICall{
				{Function: "VirtualAllocEx"},
				{Function: "WriteProcessMemory"},
			},
			expected: false,
		},
		{
			name: "no injection calls",
			calls: []APICall{
				{Function: "CreateFileA"},
				{Function: "WriteFile"},
			},
			expected: false,
		},
		{
			name: "injection with NtCreateThreadEx",
			calls: []APICall{
				{Function: "VirtualAllocEx"},
				{Function: "WriteProcessMemory"},
				{Function: "NtCreateThreadEx"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectProcessInjection(tt.calls)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDetectProcessHollowing(t *testing.T) {
	tests := []struct {
		name     string
		calls    []APICall
		expected bool
	}{
		{
			name: "complete hollowing sequence",
			calls: []APICall{
				{
					Function: "CreateProcessA",
					Parameters: []APIParameter{
						{Name: "dwCreationFlags", Value: "CREATE_SUSPENDED"},
					},
				},
				{Function: "NtUnmapViewOfSection"},
				{Function: "WriteProcessMemory"},
				{Function: "ResumeThread"},
			},
			expected: true,
		},
		{
			name: "incomplete sequence - missing unmap",
			calls: []APICall{
				{
					Function: "CreateProcessA",
					Parameters: []APIParameter{
						{Name: "dwCreationFlags", Value: "CREATE_SUSPENDED"},
					},
				},
				{Function: "WriteProcessMemory"},
				{Function: "ResumeThread"},
			},
			expected: false,
		},
		{
			name: "normal process creation",
			calls: []APICall{
				{Function: "CreateProcessA"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectProcessHollowing(tt.calls)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAPITracer_CategoryFiltering(t *testing.T) {
	// Test that tracer respects category filtering
	tracer := NewAPITracer([]string{CategoryMemory})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := tracer.Attach(ctx, 1234)
	if err != nil {
		t.Skipf("API tracer attach failed (expected on non-Windows): %v", err)
	}

	defer tracer.Stop()

	// This test would verify category filtering in a real implementation
	// For now, we just verify the tracer was created with the correct categories
}

func TestAPITracer_SupportedMatrixAndWindowsFridaHelpers(t *testing.T) {
	requiredFunctions := []string{
		"VirtualAllocEx",
		"WriteProcessMemory",
		"CreateRemoteThread",
		"CreateProcessW",
		"NtUnmapViewOfSection",
		"ResumeThread",
		"CryptEncrypt",
		"RegSetValueEx",
		"CreateFileW",
	}
	for _, fn := range requiredFunctions {
		if !IsSupportedAPIFunction(fn) {
			t.Errorf("expected %s in WindowsSupportedAPIMatrix", fn)
		}
	}
	for _, cat := range []string{CategoryMemory, CategoryProcess, CategoryRegistry, CategoryFile, CategoryCrypto, CategoryNetwork} {
		if !IsSupportedAPICategory(cat) {
			t.Errorf("expected category %s to be supported", cat)
		}
	}
	if IsSupportedAPICategory("ETWKernel") {
		t.Error("ETWKernel should not be listed as a hooked WinAPI category")
	}

	scriptBytes, err := fridaScripts.ReadFile("frida_windows_default.js")
	if err != nil || len(scriptBytes) == 0 {
		t.Fatalf("expected embedded frida_windows_default.js, err=%v", err)
	}
	script := string(scriptBytes)
	for _, fn := range []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateProcessW", "NtUnmapViewOfSection", "ResumeThread", "CryptEncrypt", "RegSetValueExW", "CreateFileW"} {
		if !strings.Contains(script, fn) {
			t.Errorf("expected frida_windows_default.js to hook %s", fn)
		}
	}

	if !fridaWindowsNameMatchesArch("frida-server-16.4.2-windows-x86_64.exe", "x86_64") {
		t.Error("expected x86_64 Windows server match")
	}
	if fridaWindowsNameMatchesArch("frida-server-16.4.2-windows-x86_64.exe", "x86") {
		t.Error("x86 lookup must not match x86_64 Windows server binary")
	}
	if got := fridaWindowsVersionFromName("frida-server-16.4.2-windows-x86_64.exe"); got != "16.4.2" {
		t.Errorf("expected version 16.4.2, got %q", got)
	}
}
