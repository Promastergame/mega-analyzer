package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/testutil"
)

// The test binary also acts as a portable fake ADB before testing parses its
// arguments. Production builds do not contain this helper.
func init() {
	switch os.Getenv("MEGA_ANALYZER_TEST_ADB_PREFLIGHT") {
	case "devices":
		if len(os.Args) == 2 && os.Args[1] == "devices" {
			fmt.Print("List of devices attached\nother-device\tdevice\n" + os.Getenv("MEGA_ANALYZER_TEST_ADB_STATE"))
			os.Exit(0)
		}
		_ = os.WriteFile(os.Getenv("MEGA_ANALYZER_TEST_ADB_MUTATION"), []byte(strings.Join(os.Args[1:], " ")), 0600)
		os.Exit(7)
	case "wait":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func TestAndroidUnavailableSelectionStopsBeforeGuestMutation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"missing", "offline", "unauthorized"} {
		t.Run(state, func(t *testing.T) {
			root := testutil.TempDir(t)
			marker := filepath.Join(root, "guest-mutated")
			t.Setenv("MEGA_ANALYZER_TEST_ADB_PREFLIGHT", "devices")
			t.Setenv("MEGA_ANALYZER_TEST_ADB_MUTATION", marker)
			row := ""
			if state != "missing" {
				row = "selected-device\t" + state + "\n"
			}
			t.Setenv("MEGA_ANALYZER_TEST_ADB_STATE", row)
			selected := false
			report := &Report{StartedAt: time.Now(), TargetOriginal: "sample.apk", AndroidSDK: &AndroidSDKStatus{ADBPath: executable}}
			err := runAndroidSandbox(t.Context(), Config{AndroidDevice: "selected-device", OnDevice: func(string) { selected = true }}, &sessionLayout{workspaceDir: root}, report)
			failure := DescribeFailure(err)
			if failure == nil || failure.Code != "android_device_unavailable" || failure.Stage != "preflight" || selected || report.Executed {
				t.Fatalf("unavailable selection was used: failure=%+v selected=%v executed=%v", failure, selected, report.Executed)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("ADB mutated the guest after failed selection: %v", err)
			}
		})
	}
}

func TestAndroidADBCommandHonorsContextDeadline(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEGA_ANALYZER_TEST_ADB_PREFLIGHT", "wait")
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = runADBContext(ctx, executable, "devices")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second {
		t.Fatalf("wedged ADB ignored the deadline: elapsed=%s err=%v", time.Since(started), err)
	}
}
