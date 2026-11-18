package sandbox

import (
	"context"
	"strings"
	"testing"
)

func TestAndroidOfflineRequestFailsBeforeDeviceAccess(t *testing.T) {
	deviceSelected := false
	// A nil layout deliberately proves that the preflight gate runs before
	// workspace/device setup, APK installation or guest settings mutations.
	err := runAndroidSandbox(context.Background(), Config{BlockNetwork: true,
		OnDevice: func(string) { deviceSelected = true }}, nil, &Report{})
	failure := DescribeFailure(err)
	if failure == nil || failure.Code != "android_network_isolation_unavailable" ||
		failure.Stage != "preflight" || deviceSelected {
		t.Fatalf("offline request bypassed the Android preflight gate: %+v selected=%v", failure, deviceSelected)
	}
}

func TestAndroidCrashEvidenceIsScopedToPackageAndPID(t *testing.T) {
	log := `10-31 17:06:32.567 3357 3357 E AndroidRuntime: FATAL EXCEPTION: main
10-31 17:06:32.567 9901 9901 E AndroidRuntime: FATAL EXCEPTION: main
10-31 17:06:32.567 9901 9901 E AndroidRuntime: Process: com.sample.other, PID: 9901
10-31 17:06:32.567 9901 9901 E AndroidRuntime: java.lang.RuntimeException: unrelated
10-31 17:06:32.567 3357 3357 E AndroidRuntime: Process: com.sample, PID: 3357
10-31 17:06:32.567 3357 3357 E AndroidRuntime: java.lang.RuntimeException: Unable to instantiate activity
10-31 17:06:32.567 3357 3357 E AndroidRuntime:     at android.app.ActivityThread.performLaunchActivity(ActivityThread.java:2843)
10-31 17:06:32.567 4457 4457 E AndroidRuntime: FATAL EXCEPTION: worker
10-31 17:06:32.567 4457 4457 E AndroidRuntime: Process: com.sample:worker, PID: 4457
10-31 17:06:32.567 4457 4457 E AndroidRuntime: java.lang.IllegalStateException: worker failed
10-31 17:06:32.567 5557 5557 E AndroidRuntime: FATAL EXCEPTION: main
10-31 17:06:32.567 5557 5557 E AndroidRuntime: Process: com.sample, PID: 1111
10-31 17:06:32.567 6667 6667 E AndroidRuntime: Process: com.sample, PID: 6667
`
	crashes, err := readAndroidAppCrashes(strings.NewReader(log), "com.sample")
	if err != nil || len(crashes) != 2 {
		t.Fatalf("crashes=%+v err=%v", crashes, err)
	}
	if crashes[0].PID != 3357 || !strings.Contains(crashes[0].Detail, "Unable to instantiate activity") ||
		strings.Contains(crashes[0].Detail, "ActivityThread.java") || crashes[1].Process != "com.sample:worker" {
		t.Fatalf("incorrect attribution or exception summary: %+v", crashes)
	}
}

func TestAndroidCrashEvidenceRequiresFatalAndProcessIdentity(t *testing.T) {
	for _, log := range []string{
		"10-31 17:06:32.567 3357 3357 E AndroidRuntime: FATAL EXCEPTION: main\n",
		"10-31 17:06:32.567 3357 3357 E AndroidRuntime: Process: com.sample, PID: 3357\n",
		"not a logcat header AndroidRuntime: Process: com.sample, PID: 3357\n",
	} {
		crashes, err := readAndroidAppCrashes(strings.NewReader(log), "com.sample")
		if err != nil || len(crashes) != 0 {
			t.Fatalf("unconfirmed crash became sample evidence: %+v %v", crashes, err)
		}
	}
}
