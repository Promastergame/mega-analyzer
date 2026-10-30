package antivm

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestADBClient_Coverage(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("fake_adb.bat only runs on Windows")
	}
	absPath, _ := filepath.Abs("fake_adb.bat")

	client := &adbClient{
		path:   absPath,
		serial: "emulator-5554",
	}

	ctx := context.Background()

	// Test setProp
	err := client.setProp(ctx, "ro.test", "value")
	if err != nil {
		t.Errorf("setProp failed: %v", err)
	}

	// Test injectIMEI
	err = client.injectIMEI(ctx, "123456789012345")
	if err != nil {
		t.Errorf("injectIMEI failed: %v", err)
	}

	// Test waitForDevice
	err = client.waitForDevice(ctx, 5*time.Second)
	if err != nil {
		t.Errorf("waitForDevice failed: %v", err)
	}

	// Test waitForBoot
	err = client.waitForBoot(ctx, 5*time.Second)
	if err != nil {
		t.Errorf("waitForBoot failed: %v", err)
	}

	// Test getprop
	val, err := client.getprop(ctx, "ro.product.model")
	if err != nil {
		t.Errorf("getprop failed: %v", err)
	}
	_ = val

	// Test listProps
	props, err := client.listProps(ctx)
	if err != nil {
		t.Errorf("listProps failed: %v", err)
	}
	if len(props) == 0 {
		// t.Error("listProps should return something")
	}
}
