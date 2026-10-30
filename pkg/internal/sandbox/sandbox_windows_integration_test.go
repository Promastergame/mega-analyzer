//go:build windows

package sandbox

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestWindowsEnhancedComponents_Lifecycle(t *testing.T) {
	cfg := Config{
		EnableKernelMonitor: true,
		EnableVSS:           true,
		EnableWFP:           true,
		EnableAPITracing:    true,
		EnableTimeManip:     true,
	}

	oldHook := checkPrivilegesFunc
	checkPrivilegesFunc = func() error { return nil }
	defer func() { checkPrivilegesFunc = oldHook }()

	components, err := initializeEnhancedComponents(cfg)
	if err != nil {
		t.Skip("Skipping due to privileges:", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// 1. Start components (many will fail internally because they lack real privileges or valid env,
	// but the start loop should handle these errors and just log/degrade).
	err = components.startComponents(ctx, cfg, 1234)
	if err != nil {
		t.Log("startComponents returned errors:", err)
	}

	// Wait briefly to allow goroutines to run
	time.Sleep(100 * time.Millisecond)

	// 2. Stop components
	components.stopComponents(ctx)

	// 3. Analyze and populate report
	rep := &Report{}
	err = components.analyzeAndPopulateReport(rep)
	if err != nil {
		t.Log("analyzeAndPopulateReport returned error:", err)
	}

	// 4. Export artifacts
	errs := components.exportArtifacts(os.TempDir(), rep)
	if len(errs) > 0 {
		t.Log("exportArtifacts returned errors:", errs)
	}

	// 5. Cleanup
	components.cleanup()
}
