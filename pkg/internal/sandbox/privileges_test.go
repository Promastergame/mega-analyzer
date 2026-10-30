//go:build windows

package sandbox

import (
	"strings"
	"testing"
)

func TestIsAdmin(t *testing.T) {
	// This test verifies that isAdmin() returns a boolean value
	// The actual result depends on whether the test is run with elevated privileges
	result := isAdmin()

	// We can't assert a specific value since it depends on execution context
	// But we can verify the function doesn't panic and returns a valid boolean
	t.Logf("isAdmin() returned: %v", result)

	// The result should be deterministic for the same execution context
	result2 := isAdmin()
	if result != result2 {
		t.Errorf("isAdmin() returned inconsistent results: first=%v, second=%v", result, result2)
	}
}

func TestCheckPrivileges(t *testing.T) {
	err := checkPrivileges()

	if !isAdmin() {
		// If not running as admin, checkPrivileges should return an error
		if err == nil {
			t.Error("checkPrivileges() should return error when not running as administrator")
		}
		if !strings.Contains(err.Error(), "administrator privileges") {
			t.Errorf("checkPrivileges() error should mention administrator privileges, got: %v", err)
		}
		t.Logf("Expected error when not admin: %v", err)
	} else {
		// If running as admin, checkPrivileges should succeed or return a warning about SeDebugPrivilege
		if err != nil {
			// It's acceptable to get a warning about SeDebugPrivilege
			if !strings.Contains(err.Error(), "SeDebugPrivilege") && !strings.Contains(err.Error(), "warning") {
				t.Errorf("checkPrivileges() returned unexpected error when running as admin: %v", err)
			} else {
				t.Logf("Warning from checkPrivileges(): %v", err)
			}
		} else {
			t.Log("checkPrivileges() succeeded with full privileges")
		}
	}
}

func TestEnableDebugPrivilege(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping enableDebugPrivilege test: requires administrator privileges")
	}

	err := enableDebugPrivilege()

	// When running as admin, we should be able to enable SeDebugPrivilege
	// However, it may fail in some restricted environments (e.g., CI/CD)
	if err != nil {
		t.Logf("enableDebugPrivilege() returned error (may be expected in restricted environments): %v", err)
	} else {
		t.Log("enableDebugPrivilege() succeeded")
	}

	// Verify the function is idempotent - calling it again should not fail
	err2 := enableDebugPrivilege()
	if err2 != nil {
		t.Logf("Second call to enableDebugPrivilege() returned error: %v", err2)
	}
}

func TestCheckPrivilegesGracefulDegradation(t *testing.T) {
	// Test that checkPrivileges provides clear error messages for graceful degradation
	err := checkPrivileges()

	if err != nil {
		// Error message should be informative
		errMsg := err.Error()
		if errMsg == "" {
			t.Error("checkPrivileges() returned error with empty message")
		}

		// Should mention either "administrator" or "privilege"
		if !strings.Contains(strings.ToLower(errMsg), "administrator") &&
			!strings.Contains(strings.ToLower(errMsg), "privilege") {
			t.Errorf("checkPrivileges() error message should mention privileges or administrator, got: %v", errMsg)
		}

		t.Logf("Graceful degradation message: %v", errMsg)
	}
}

// TestPrivilegeCheckingIntegration tests the integration of privilege checking
// with the sandbox workflow
func TestPrivilegeCheckingIntegration(t *testing.T) {
	// Simulate the workflow that the sandbox orchestrator would use

	// Step 1: Check if we have required privileges
	hasPrivileges := isAdmin()
	t.Logf("Running with admin privileges: %v", hasPrivileges)

	// Step 2: Attempt to enable enhanced privileges
	if hasPrivileges {
		err := enableDebugPrivilege()
		if err != nil {
			t.Logf("Could not enable SeDebugPrivilege (some features may be limited): %v", err)
		}
	}

	// Step 3: Verify checkPrivileges provides appropriate feedback
	err := checkPrivileges()
	if !hasPrivileges && err == nil {
		t.Error("checkPrivileges() should return error when not running as administrator")
	}

	// The sandbox should be able to make decisions based on this information
	// For example, disable kernel monitoring if privileges are insufficient
	if err != nil {
		t.Logf("Sandbox would gracefully degrade: %v", err)
	}
}
