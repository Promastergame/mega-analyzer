package sandbox

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/androidsdk"
)

var (
	aaptPackageRe  = regexp.MustCompile(`package:\s+name='([^']+)'`)
	aaptActivityRe = regexp.MustCompile(`launchable-activity:\s+name='([^']+)'`)
)

// ResolveAPKPackage returns the package name of an APK using aapt2, or "" when
// it can't be determined statically. Exported for the streaming runner so it can
// scope live capture (e.g. PCAPdroid app_filter) to the target app.
func ResolveAPKPackage(apkPath string) string {
	pkg, _ := aaptResolvePackage(apkPath)
	return pkg
}

// aaptResolvePackage runs `aapt2 dump badging` on the APK and returns its
// package name and launchable-activity. Returns empty strings when aapt2 is
// not available or the file can't be parsed — callers fall back to a pm diff.
func aaptResolvePackage(apkPath string) (pkg, activity string) {
	tc := androidsdk.Detect()
	aapt := tc.AAPT2
	if aapt == "" {
		if p, err := exec.LookPath("aapt2"); err == nil {
			aapt = p
		} else if p, err := exec.LookPath("aapt"); err == nil {
			aapt = p
		}
	}
	if aapt == "" || apkPath == "" {
		return "", ""
	}
	if info, err := os.Stat(apkPath); err != nil || info.IsDir() {
		return "", "" // split/xapk dir — pm diff handles it
	}
	out, err := exec.Command(aapt, "dump", "badging", apkPath).Output()
	if err != nil {
		return "", ""
	}
	if m := aaptPackageRe.FindSubmatch(out); len(m) > 1 {
		pkg = string(m[1])
	}
	if m := aaptActivityRe.FindSubmatch(out); len(m) > 1 {
		activity = string(m[1])
	}
	return pkg, activity
}

// listInstalledPackages returns the set of package names currently installed on
// the device (third-party only, so we don't diff against hundreds of system
// packages). Needs nothing but adb.
func listInstalledPackages(adbPath, deviceID string) map[string]bool {
	set := map[string]bool{}
	out, err := runADB(adbPath, "-s", deviceID, "shell", "pm", "list", "packages", "-3")
	if err != nil {
		// Fall back to all packages if -3 isn't supported.
		out, err = runADB(adbPath, "-s", deviceID, "shell", "pm", "list", "packages")
		if err != nil {
			return set
		}
	}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		ln = strings.TrimPrefix(ln, "package:")
		if ln != "" {
			set[ln] = true
		}
	}
	return set
}

// resolveLauncherComponent asks the device for the launchable activity of a
// package via `cmd package resolve-activity`, returning "pkg/activity" or "".
func resolveLauncherComponent(adbPath, deviceID, pkg string) string {
	out, err := runADB(adbPath, "-s", deviceID, "shell",
		"cmd", "package", "resolve-activity", "--brief", pkg)
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		// The brief output's last line is "pkg/.Activity".
		if strings.HasPrefix(ln, pkg+"/") {
			return ln
		}
	}
	return ""
}

// ensureAndroidProfile guarantees report.AndroidProfile carries at least the
// resolved package name, so downstream reporting and the dashboard show it.
func ensureAndroidProfile(report *Report, pkg string) *AndroidProfile {
	if report.AndroidProfile == nil {
		return &AndroidProfile{PackageName: pkg}
	}
	if report.AndroidProfile.PackageName == "" {
		report.AndroidProfile.PackageName = pkg
	}
	return report.AndroidProfile
}

// runAndroidSandbox runs the APK on a connected Android device or emulator using ADB.
func runAndroidSandbox(parent context.Context, cfg Config, layout *sessionLayout, report *Report) error {
	// logf routes progress messages to the caller's LogSink when set (streaming
	// web UI path), or falls back to fmt.Printf (CLI / non-streaming path).
	logf := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if cfg.LogSink != nil {
			cfg.LogSink(msg)
		} else {
			fmt.Print(msg)
		}
	}

	adbPath := findADB(report)

	// Snapshot host workspace before any execution so diffSnapshots can detect
	// files written there during the run (e.g. pulled PCAP, logcat, reports).
	beforeSnap := beforeSnapshot(layout.workspaceDir)

	// 1. Detect active Android device/emulator
	deviceID, err := getActiveDevice(adbPath)
	if cfg.AndroidDevice != "" {
		// Explicit serial from -sandbox-device: use exactly this handset.
		// Never substitute another device and never launch an emulator
		// behind the user's back; a bad selection is a hard error.
		deviceID, err = requireExplicitDevice(adbPath, cfg.AndroidDevice)
	} else if err != nil {
		if cfg.AndroidAVD != "" || cfg.AndroidAutoAVD {
			logf("ℹ No active device found. Attempting to launch emulator...\n")
			launchedDeviceID, stopEmulator, launchErr := launchAndConnectEmulator(adbPath, cfg, layout, report, logf)
			if stopEmulator != nil {
				// Shut down an emulator we started ourselves. Leaving it running is
				// what used to exhaust console ports across repeated runs.
				defer stopEmulator()
			}
			if launchErr != nil {
				err = fmt.Errorf("%v (emulator launch failed: %v)", err, launchErr)
			} else {
				deviceID = launchedDeviceID
				err = nil
			}
		}

		if err != nil {
			logf("✗ Android dynamic execution skipped: %v\n", err)
			report.Executed = false
			report.ExecutionSkipReason = fmt.Sprintf("Android dynamic execution skipped: %v", err)
			report.FinishedAt = time.Now().UTC()
			report.DurationMS = report.FinishedAt.Sub(report.StartedAt).Milliseconds()
			report.FileChanges = diffSnapshots(beforeSnap, beforeSnapshot(layout.workspaceDir))
			report.Behavior = buildBehaviorSummary(report)
			report.NeuralAnalysis = buildNeuralAnalysis(report)
			sortReport(report)
			return writeReports(report)
		}
	}

	// Best-effort package name from static analysis. It is often empty when the
	// binary AndroidManifest.xml could not be decoded — that's fine, we resolve
	// it reliably from aapt2 and/or a pm-list diff after the install below, so we
	// must NOT abort here.
	packageName := ""
	if report.AndroidProfile != nil {
		packageName = report.AndroidProfile.PackageName
	}
	launchActivity := ""

	logf("ℹ Active Android device/emulator found: %s\n", deviceID)
	if cfg.OnDevice != nil {
		cfg.OnDevice(deviceID)
	}

	// Try aapt2 badging first — gives us both the package and its launchable
	// activity straight from the APK, no install needed.
	if pkg, act := aaptResolvePackage(report.TargetOriginal); pkg != "" {
		if packageName == "" {
			packageName = pkg
		}
		launchActivity = act
		logf("ℹ Resolved package from aapt2: %s\n", pkg)
	}

	// 1b. Apply requested guest environment tuning (resolution / orientation / locale / timezone).
	applyAndroidGuestTuning(adbPath, deviceID, cfg, logf)

	logf("ℹ Installing target APK: %s...\n", filepath.Base(report.TargetOriginal))

	// 2. Establish private server port forwarding if requested
	port := parsePort(cfg.PrivateServer)
	if cfg.PrivateServer != "" {
		logf("ℹ Private server connection: reverse port tcp:%s redirected to host\n", port)
		_, _ = runADB(adbPath, "-s", deviceID, "reverse", "tcp:"+port, "tcp:"+port)
	}

	// Force network isolation to be OFF so we act like PCAPdroid (always-on network capturing)
	logf("ℹ Network isolation is OFF (PCAPdroid Mode): enabling Wi-Fi and Mobile Data on device...\n")
	_, _ = runADB(adbPath, "-s", deviceID, "shell", "svc", "wifi", "enable")
	_, _ = runADB(adbPath, "-s", deviceID, "shell", "svc", "data", "enable")

	// 3. Clear logcat buffer and install APK
	_, _ = runADB(adbPath, "-s", deviceID, "logcat", "-c")

	// Disable install-time verification — this is what blocks adb install on
	// Infinix/Transsion and many other OEM ROMs even when USB debugging is on.
	// MobSF does the same thing. Best-effort: non-root devices may ignore it.
	logf("ℹ Disabling install verification...\n")
	_, _ = runADB(adbPath, "-s", deviceID, "shell", "settings", "put", "global", "verifier_verify_adb_installs", "0")
	_, _ = runADB(adbPath, "-s", deviceID, "shell", "settings", "put", "global", "package_verifier_enable", "0")

	// Snapshot device Download folder before install so we can pull only NEW
	// files after the app runs (i.e. files the app itself downloaded).
	deviceDownloadBefore := listDeviceDir(adbPath, deviceID, "/sdcard/Download")

	// Snapshot installed third-party packages so we can discover the newly
	// installed one by diffing after install — this is the bulletproof fallback
	// for when aapt2 isn't on PATH and the manifest couldn't be decoded.
	pkgsBefore := listInstalledPackages(adbPath, deviceID)

	targetPath := report.TargetOriginal
	lowerTarget := strings.ToLower(targetPath)
	if strings.HasSuffix(lowerTarget, ".xapk") || strings.HasSuffix(lowerTarget, ".apks") || strings.HasSuffix(lowerTarget, ".zip") {
		tmpDir := filepath.Join(layout.workspaceDir, "extracted_apks")
		_ = os.MkdirAll(tmpDir, 0755)
		logf("ℹ Extracting %s...\n", filepath.Base(targetPath))
		if err := unzipXAPK(targetPath, tmpDir); err == nil {
			targetPath = tmpDir
		} else {
			logf("⚠️ Failed to extract %s: %v\n", filepath.Base(targetPath), err)
		}
	}

	info, statErr := os.Stat(targetPath)
	if statErr == nil && info.IsDir() {
		var apks []string
		_ = filepath.Walk(targetPath, func(path string, d os.FileInfo, e error) error {
			if e == nil && !d.IsDir() && strings.HasSuffix(strings.ToLower(path), ".apk") {
				apks = append(apks, path)
			}
			return nil
		})
		if len(apks) == 0 {
			err = fmt.Errorf("no .apk files found in directory %s", targetPath)
		} else if len(apks) == 1 {
			_, err = runADB(adbPath, "-s", deviceID, "install", "-r", "-t", "-d", apks[0])
		} else {
			logf("ℹ Found %d APKs (Split APKs). Installing via install-multiple...\n", len(apks))
			args := []string{"-s", deviceID, "install-multiple", "-r", "-t", "-d"}
			args = append(args, apks...)
			_, err = runADB(adbPath, args...)
		}
	} else {
		_, err = runADB(adbPath, "-s", deviceID, "install", "-r", "-t", "-d", targetPath)
	}
	if err != nil {
		// Clean up reverse port forwarding if installation fails
		if cfg.PrivateServer != "" {
			_, _ = runADB(adbPath, "-s", deviceID, "reverse", "--remove", "tcp:"+port)
		}
		return fmt.Errorf("failed to install APK on device: %w%s", err, installFailureHint(err.Error()))
	}
	logf("✓ APK installed successfully\n")

	// Resolve the package name reliably now that the app is on the device:
	// diff the installed-package list against the pre-install snapshot. This
	// works with nothing but adb, even when aapt2 and manifest decoding fail.
	if packageName == "" {
		pkgsAfter := listInstalledPackages(adbPath, deviceID)
		for pkg := range pkgsAfter {
			if !pkgsBefore[pkg] {
				packageName = pkg
				logf("ℹ Discovered installed package via pm-list diff: %s\n", pkg)
				break
			}
		}
	}
	if packageName == "" {
		return fmt.Errorf("could not determine package name after install (aapt2 unavailable and pm-list diff empty)")
	}
	report.AndroidProfile = ensureAndroidProfile(report, packageName)

	// 3b. Start network capture if requested.
	var tcpdumpCmd *exec.Cmd
	var mitmCmd *exec.Cmd
	const devicePCAPPath = "/data/local/tmp/capture.pcap"
	if cfg.CaptureTraffic {
		tcpdumpCmd = startDeviceTcpdump(parent, adbPath, deviceID, devicePCAPPath)
		if tcpdumpCmd != nil {
			logf("ℹ Traffic capture started (tcpdump on device)\n")
		} else {
			logf("⚠ tcpdump not available on device — raw capture skipped\n")
		}
	}
	if cfg.MITMProxy {
		harPath := filepath.Join(layout.sessionDir, "intercept.har")
		hostIP := androidHostIP(adbPath, deviceID)
		var mitmPort int
		mitmCmd, mitmPort = startMitmProxyCapture(parent, harPath)
		if mitmCmd != nil && hostIP != "" {
			setAndroidWifiProxy(adbPath, deviceID, hostIP, mitmPort)
			// Remove the guest proxy on EVERY exit path. Any early return between
			// here and the end of the run used to leave the device pointing at a
			// dead proxy with no working networking, indefinitely.
			defer clearAndroidWifiProxy(adbPath, deviceID)
			logf("ℹ HTTPS interception started (mitmproxy → %s)\n", harPath)
		} else {
			logf("⚠ mitmproxy/host IP unavailable — HTTPS interception skipped\n")
		}
	}

	// 4. Start logcat capturing in the background
	logcatFile, err := os.Create(layout.stdoutPath)
	var logcatCmd *exec.Cmd
	if err == nil {
		// Close on every exit path. Previously the handle was only released
		// inside the teardown branch that required logcatCmd to be non-nil, so a
		// failed Start leaked the descriptor for the life of the process.
		defer func() { _ = logcatFile.Close() }()
		logcatCmd = exec.Command(adbPath, "-s", deviceID, "logcat", "-v", "threadtime")
		logcatCmd.Stdout = logcatFile
		logcatCmd.Stderr = logcatFile
		if serr := logcatCmd.Start(); serr != nil {
			logf("\u26a0 logcat capture unavailable: %v\n", serr)
			logcatCmd = nil
		}
	}

	// 5. Launch the application
	logf("ℹ Waking up device screen before launching...\n")
	_, _ = runADB(adbPath, "-s", deviceID, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
	time.Sleep(300 * time.Millisecond)
	_, _ = runADB(adbPath, "-s", deviceID, "shell", "input", "swipe", "500", "1800", "500", "1000")
	time.Sleep(500 * time.Millisecond)

	logf("ℹ Launching application: %s...\n", packageName)
	launched := false
	// Best path: explicit launcher activity from aapt2 (most reliable).
	if launchActivity != "" {
		comp := packageName + "/" + launchActivity
		if _, e := runADB(adbPath, "-s", deviceID, "shell", "am", "start", "-n", comp); e == nil {
			launched = true
			logf("✓ Launched %s\n", comp)
		} else {
			logf("⚠️ am start %s failed: %v\n", comp, e)
		}
	}
	// Fallback 1: resolve the launcher activity from the device itself.
	if !launched {
		if comp := resolveLauncherComponent(adbPath, deviceID, packageName); comp != "" {
			if _, e := runADB(adbPath, "-s", deviceID, "shell", "am", "start", "-n", comp); e == nil {
				launched = true
				logf("✓ Launched %s (resolved on device)\n", comp)
			}
		}
	}
	// Fallback 2: monkey with the LAUNCHER category.
	if !launched {
		if _, e := runADB(adbPath, "-s", deviceID, "shell", "monkey", "-p", packageName, "-c", "android.intent.category.LAUNCHER", "1"); e == nil {
			launched = true
			logf("✓ Launched %s via monkey\n", packageName)
		} else {
			logf("⚠️ monkey launch failed: %v\n", e)
		}
	}
	if !launched {
		logf("⚠️ Could not launch %s automatically — it is installed; you can open it manually in the live view.\n", packageName)
	}

	report.Executed = true
	report.ExecutionSkipReason = ""
	if cfg.OnObserving != nil {
		cfg.OnObserving()
	}

	// Frida instrumentation.
	//
	// Attach mode hooks the process that is already running. Spawn mode
	// force-stops the app and relaunches it under Frida so hooks are in place
	// before any application code executes, which is the only way to observe
	// packers and droppers that do their work in Application.onCreate.
	var stopFrida func()
	if cfg.Frida {
		fridaSess := &FridaSession{Requested: true}
		report.Frida = fridaSess
		if !fridaEnsureServer(adbPath, deviceID, fridaSess, logf) {
			logf("! frida requested but not available: %s\n", strings.Join(fridaSess.Warnings, "; "))
		} else {
			if cfg.FridaSpawn {
				_, _ = runADB(adbPath, "-s", deviceID, "shell", "am", "force-stop", packageName)
				time.Sleep(700 * time.Millisecond)
			}
			fridaConfig := cfg
			fridaConfig.AndroidDevice = deviceID
			stopFrida = fridaRun(parent, fridaConfig, layout.sessionDir, packageName, fridaSess, logf)
			if stopFrida != nil {
				defer stopFrida()
			}
		}
		for _, w := range fridaSess.Warnings {
			report.Warnings = append(report.Warnings, "frida: "+w)
		}
	}

	// 6. Monitoring loop
	runCtx, cancel := observationContext(parent, cfg.Duration)
	defer cancel()

	if cfg.Duration == 0 {
		logf("✓ Sandbox session running until stopped...\n")
	} else {
		logf("✓ Sandbox session running for %s...\n", cfg.Duration)
	}
	ticker := time.NewTicker(cfg.MonitorEvery)
	defer ticker.Stop()

	// Keep track of observed PIDs and connections
	observedPIDs := make(map[int]struct{})
	var allObservedProcesses []ObservedProcess
	var allObservedConnections []ObservedConnection

	monitorSample := func() {
		// Get PIDs for package
		pids := getAppPIDs(adbPath, deviceID, packageName)
		for _, pid := range pids {
			if _, ok := observedPIDs[pid]; !ok {
				observedPIDs[pid] = struct{}{}
				proc := ObservedProcess{PID: pid, ParentPID: 0, Name: packageName, FirstSeen: time.Now().UTC()}
				allObservedProcesses = append(allObservedProcesses, proc)
				if cfg.OnProcess != nil {
					cfg.OnProcess(proc)
				}
			}
		}

		// Get active connections
		conns := getAppConnections(adbPath, deviceID, pids)
		for _, conn := range conns {
			// Prevent duplicates
			exists := false
			for _, existing := range allObservedConnections {
				if existing.LocalAddr == conn.LocalAddr && existing.RemoteAddr == conn.RemoteAddr && existing.PID == conn.PID {
					exists = true
					break
				}
			}
			if !exists {
				conn.FirstSeen = time.Now().UTC()
				allObservedConnections = append(allObservedConnections, conn)
				if cfg.OnConnection != nil {
					cfg.OnConnection(conn)
				}
			}
		}
	}

	// First sample
	monitorSample()

OuterLoop:
	for {
		select {
		case <-runCtx.Done():
			if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
				report.TimedOut = true
			}
			break OuterLoop
		case <-ticker.C:
			monitorSample()
		}
	}

	// 7. Dynamic post-execution analysis & reports
	if stopFrida != nil {
		stopFrida() // Summarise keys before persisting the completed report.
	}
	report.FinishedAt = time.Now().UTC()
	report.DurationMS = report.FinishedAt.Sub(report.StartedAt).Milliseconds()
	report.Processes = allObservedProcesses
	report.Connections = allObservedConnections
	report.FileChanges = diffSnapshots(beforeSnap, beforeSnapshot(layout.workspaceDir))
	report.Behavior = buildBehaviorSummary(report)
	report.NeuralAnalysis = buildNeuralAnalysis(report)
	sortReport(report)

	// Write stdout/stderr reports
	if logcatCmd != nil && logcatCmd.Process != nil {
		_ = logcatCmd.Process.Kill()
		_ = logcatCmd.Wait()
	}

	// Stop network captures and pull artifacts to session dir.
	if tcpdumpCmd != nil && tcpdumpCmd.Process != nil {
		stopDeviceTcpdump(adbPath, deviceID, tcpdumpCmd)
		destPCAP := filepath.Join(layout.sessionDir, "capture.pcap")
		if _, err2 := runADB(adbPath, "-s", deviceID, "pull", devicePCAPPath, destPCAP); err2 == nil {
			logf("✓ Network capture saved → %s\n", destPCAP)
		}
		_, _ = runADB(adbPath, "-s", deviceID, "shell", "rm", "-f", devicePCAPPath)
	}
	if mitmCmd != nil {
		// Proxy removal is handled by the deferred clear registered at setup.
		_ = mitmCmd.Process.Kill()
		_ = mitmCmd.Wait()
		logf("✓ MITM proxy stopped\n")
	}

	// Pull files the app downloaded to /sdcard/Download during the run.
	pullNewDeviceFiles(adbPath, deviceID, deviceDownloadBefore, layout.sessionDir, logf)

	// Capture brief summary behaviors from connections/processes
	if len(report.Connections) > 0 {
		report.Behavior.Highlights = append(report.Behavior.Highlights,
			fmt.Sprintf("Android app initiated %d dynamic network connections during detention", len(report.Connections)))
	}
	if len(report.Processes) > 0 {
		report.Behavior.Highlights = append(report.Behavior.Highlights,
			fmt.Sprintf("Android app executed under PID %d", report.Processes[0].PID))
	}

	_ = writeReports(report)

	// 8. Cleanup — uninstall the app if the user requested it.
	if cfg.UninstallAfter {
		logf("ℹ Uninstalling %s from device...\n", packageName)
		if out, err := runADB(adbPath, "-s", deviceID, "uninstall", packageName); err != nil {
			logf("⚠ Uninstall failed: %v — %s\n", err, out)
		} else {
			logf("✓ Uninstalled %s\n", packageName)
		}
	} else {
		logf("ℹ App %s left installed on device.\n", packageName)
	}
	if cfg.PrivateServer != "" {
		_, _ = runADB(adbPath, "-s", deviceID, "reverse", "--remove", "tcp:"+port)
		logf("ℹ Removed private server reverse port tcp:%s from device.\n", port)
	}

	return nil
}

func beforeSnapshot(root string) map[string]fileFingerprint {
	snap, _ := captureFileSnapshot(root)
	return snap
}

func findADB(report *Report) string {
	if report.AndroidSDK != nil && report.AndroidSDK.ADBPath != "" {
		if _, err := os.Stat(report.AndroidSDK.ADBPath); err == nil {
			return report.AndroidSDK.ADBPath
		}
	}
	if path, err := exec.LookPath("adb"); err == nil {
		return path
	}
	// Fallback to common locations on Windows
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData != "" {
		path := filepath.Join(localAppData, "Android", "Sdk", "platform-tools", "adb.exe")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		path := filepath.Join(userProfile, "AppData", "Local", "Android", "Sdk", "platform-tools", "adb.exe")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return "adb"
}

func runADB(adbPath string, args ...string) (string, error) {
	cmd := exec.Command(adbPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// installFailureHint maps a raw adb/pm install error to a short, actionable hint
// appended to the engine log so the user knows exactly what to fix on the phone.
// Returns "" when nothing specific is recognised.
func installFailureHint(raw string) string {
	s := strings.ToLower(raw)
	switch {
	case strings.Contains(s, "user_restricted"):
		return " — enable 'Install via USB' in Developer Options (Infinix/Transsion blocks adb installs otherwise)"
	case strings.Contains(s, "device offline"), strings.Contains(s, "offline"):
		return " — phone went OFFLINE during transfer: use a known-good DATA USB cable (not charge-only), a rear USB 2.0 port, keep the screen unlocked"
	case strings.Contains(s, "unauthorized"):
		return " — tap 'Allow USB debugging' on the phone (check 'Always allow from this computer')"
	case strings.Contains(s, "version_downgrade"), strings.Contains(s, "update_incompatible"):
		return " — a newer version is already installed: uninstall it first or retry (the engine already passes -r)"
	case strings.Contains(s, "no_matching_abis"):
		return " — the APK's native code doesn't match this phone's CPU (wrong ABI)"
	case strings.Contains(s, "insufficient_storage"):
		return " — not enough free storage on the phone"
	case strings.Contains(s, "invalid_apk"), strings.Contains(s, "failed to parse"):
		return " — the file isn't a valid/complete APK"
	}
	return ""
}

func getActiveDevice(adbPath string) (string, error) {
	out, err := runADB(adbPath, "devices")
	if err != nil {
		return "", err
	}
	lines := strings.Split(out, "\n")
	var badState string // remember a connected-but-unusable device for a clearer error
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[1] {
		case "device":
			return fields[0], nil
		case "offline":
			badState = "device is OFFLINE — unlock the phone screen and keep it on, replug the USB cable (use a known-good DATA cable, not charge-only), then retry"
		case "unauthorized":
			badState = "device is UNAUTHORIZED — on the phone tap 'Allow USB debugging' (check 'Always allow from this computer')"
		case "no":
			// "no permissions" row.
			badState = "no USB permissions for the device — replug the cable / check the USB driver"
		}
	}
	if badState != "" {
		return "", errors.New(badState)
	}
	return "", fmt.Errorf("no active Android devices or emulators found")
}

// requireExplicitDevice binds the run to exactly the requested adb serial.
// It never substitutes another handset and never launches an emulator:
// a missing or unusable selection is a hard error, not a silent fallback.
func requireExplicitDevice(adbPath, serial string) (string, error) {
	out, err := runADB(adbPath, "devices")
	if err != nil {
		return "", err
	}
	found := false
	state := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != serial {
			continue
		}
		found = true
		state = fields[1]
		break
	}
	if !found {
		return "", fmt.Errorf("selected Android device %s is not connected; no other device was selected", serial)
	}
	if state != "device" {
		return "", fmt.Errorf("selected Android device %s is %s; authorize USB debugging or reconnect this device", serial, state)
	}
	return serial, nil
}

// applyAndroidGuestTuning applies the optional guest-environment settings
// (screen resolution, orientation, locale, timezone) to the connected device
// via adb. All operations are best-effort: failures are logged but never abort
// the run, since support varies across devices and Android versions.
func applyAndroidGuestTuning(adbPath, deviceID string, cfg Config, logf func(string, ...any)) {
	shell := func(args ...string) {
		full := append([]string{"-s", deviceID, "shell"}, args...)
		if _, err := runADB(adbPath, full...); err != nil {
			logf("⚠️ guest-tuning step failed (%v): %v\n", args, err)
		}
	}

	if cfg.Resolution != "" {
		// wm expects WxH in the device's natural (portrait) orientation.
		logf("ℹ Setting guest screen resolution to %s\n", cfg.Resolution)
		if isValidResolution(cfg.Resolution) {
			shell("wm", "size", cfg.Resolution)
		} else {
			// A malformed value here wedges the guest display until someone runs
			// wm size reset by hand, so refuse it instead of forwarding it.
			logf("! ignoring malformed resolution %q (expected WIDTHxHEIGHT, e.g. 1080x1920)\n", cfg.Resolution)
		}
	}

	if cfg.Orientation != "" {
		rot := "0" // portrait
		if strings.ToLower(cfg.Orientation) == "landscape" {
			rot = "1"
		}
		logf("ℹ Setting guest orientation to %s\n", cfg.Orientation)
		// Disable auto-rotate, then pin the user rotation.
		shell("settings", "put", "system", "accelerometer_rotation", "0")
		shell("settings", "put", "system", "user_rotation", rot)
	}

	if cfg.Locale != "" {
		// Best-effort: persists across the run; a full apply may require a reboot.
		logf("ℹ Setting guest locale to %s (best-effort)\n", cfg.Locale)
		shell("setprop", "persist.sys.locale", cfg.Locale)
	}

	if cfg.Timezone != "" {
		logf("ℹ Setting guest timezone to %s\n", cfg.Timezone)
		shell("setprop", "persist.sys.timezone", cfg.Timezone)
		// service call alarm 3 sets the timezone live on most builds.
		shell("service", "call", "alarm", "3", "s16", cfg.Timezone)
	}
}

// isValidResolution accepts only WIDTHxHEIGHT with plausible bounds.
func isValidResolution(s string) bool {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(s)), "x")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 160 || n > 8192 {
			return false
		}
	}
	return true
}

func parsePort(addr string) string {
	if addr == "" {
		return "9339"
	}
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[idx+1:]
	}
	if _, err := strconv.Atoi(addr); err == nil {
		return addr
	}
	return "9339"
}

// getAppPIDs returns the PIDs belonging to packageName.
//
// The old implementation used strings.Contains on the whole ps line, so it
// matched any process whose command line merely mentioned the package (and any
// package sharing a name prefix), attributing unrelated processes to the
// sample. pidof is exact and present on every modern Android build.
func getAppPIDs(adbPath, deviceID, packageName string) []int {
	if out, err := runADB(adbPath, "-s", deviceID, "shell", "pidof", packageName); err == nil {
		var pids []int
		for _, field := range strings.Fields(out) {
			if pid, cerr := strconv.Atoi(field); cerr == nil {
				pids = append(pids, pid)
			}
		}
		if len(pids) > 0 {
			return pids
		}
	}

	out, err := runADB(adbPath, "-s", deviceID, "shell", "ps", "-A")
	if err != nil {
		out, err = runADB(adbPath, "-s", deviceID, "shell", "ps")
		if err != nil {
			return nil
		}
	}

	var pids []int
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		// The process name is the last column; require an exact match or a
		// package-scoped subprocess such as com.foo.bar:remote.
		name := fields[len(fields)-1]
		if name != packageName && !strings.HasPrefix(name, packageName+":") {
			continue
		}
		if pid, cerr := strconv.Atoi(fields[1]); cerr == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

func getAppConnections(adbPath, deviceID string, pids []int) []ObservedConnection {
	if len(pids) == 0 {
		return nil
	}

	out, err := runADB(adbPath, "-s", deviceID, "shell", "netstat", "-an")
	if err != nil {
		return nil
	}

	pidSet := make(map[int]struct{})
	for _, pid := range pids {
		pidSet[pid] = struct{}{}
	}

	var conns []ObservedConnection
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto := strings.ToLower(fields[0])
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}

		local := fields[3]
		remote := ""
		state := ""
		if len(fields) >= 5 {
			remote = fields[4]
		}
		if len(fields) >= 6 {
			state = fields[5]
		}

		// Since netstat on Android might not show the PID unless run as root,
		// we assign the connection to the app's first PID for clarity
		conns = append(conns, ObservedConnection{
			Protocol:   proto,
			LocalAddr:  local,
			RemoteAddr: remote,
			State:      state,
			PID:        pids[0],
		})
	}
	return conns
}

// emulatorBootTimeout bounds a cold boot. A cold boot of a fresh AVD on a
// loaded host regularly needs more than three minutes, so the previous 3m
// ceiling was aborting boots that would have succeeded.
const emulatorBootTimeout = 6 * time.Minute

// listAdbSerials returns every serial adb currently knows about, whatever its
// state. Used to tell which serial a launch actually produced instead of
// trusting getActiveDevice, which returns the first ready device and therefore
// picks the wrong target on a host that already has a phone attached.
func listAdbSerials(adbPath string) map[string]bool {
	seen := make(map[string]bool)
	out, err := runADB(adbPath, "devices")
	if err != nil {
		return seen
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") {
			continue
		}
		if fields := strings.Fields(line); len(fields) >= 2 {
			seen[fields[0]] = true
		}
	}
	return seen
}

// deviceReady reports whether a serial is not just visible to adb but actually
// usable. sys.boot_completed flips to 1 well before the package manager and
// input system are up, which is why the install and am start immediately after
// boot used to fail intermittently. Requiring the boot animation to have
// stopped and package manager to answer a query removes that race.
func deviceReady(adbPath, serial string) bool {
	if out, err := runADB(adbPath, "-s", serial, "shell", "getprop", "sys.boot_completed"); err != nil || strings.TrimSpace(out) != "1" {
		return false
	}
	if out, err := runADB(adbPath, "-s", serial, "shell", "getprop", "init.svc.bootanim"); err == nil {
		if strings.TrimSpace(out) != "stopped" {
			return false
		}
	}
	out, err := runADB(adbPath, "-s", serial, "shell", "pm", "path", "android")
	return err == nil && strings.Contains(out, "package:")
}

// launchAndConnectEmulator cold-boots an AVD and waits until it is genuinely
// usable.
//
// It returns the serial plus a stop function. Callers MUST invoke the stop
// function: the previous implementation started the emulator, sent its stdout
// and stderr to nowhere and never killed it, so every failed run left an
// orphaned VM holding a console port. After a few attempts the host ran out of
// even-numbered console ports and all subsequent launches failed for reasons
// the log could not explain.
func launchAndConnectEmulator(adbPath string, cfg Config, layout *sessionLayout, report *Report, logf func(string, ...any)) (string, func(), error) {
	emulatorPath := findEmulator(report)
	if emulatorPath == "" {
		return "", nil, fmt.Errorf("emulator executable not found in SDK")
	}

	avdName := cfg.AndroidAVD
	if avdName == "" && cfg.AndroidAutoAVD {
		avdName = autoDiscoverAVD(emulatorPath, logf)
		if avdName == "" {
			return "", nil, fmt.Errorf("no AVDs found to auto-launch")
		}
		logf("\u2139 Auto-discovered AVD: %s\n", avdName)
	}
	if avdName == "" {
		return "", nil, fmt.Errorf("no AVD specified")
	}

	preexisting := listAdbSerials(adbPath)

	// Cold boot on purpose. Without -no-snapshot-load the emulator resumes its
	// Quick Boot snapshot, so the previous sample's installed packages, granted
	// permissions and dropped files are still on the device. For a malware
	// sandbox that is cross contamination between analyses, not a fast start.
	args := []string{"-avd", avdName, "-no-boot-anim", "-no-snapshot-load", "-no-audio"}
	if extra := strings.TrimSpace(os.Getenv("MEGA_EMULATOR_ARGS")); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}

	cmd := exec.Command(emulatorPath, args...)

	// Keep the emulator's own diagnostics. A failed boot is almost always
	// explained on stderr (no KVM permission, missing system image, corrupt AVD,
	// Vulkan ICD failure) and that output used to be discarded, leaving a bare
	// "timeout waiting for emulator to boot" with no cause.
	emuLogPath := filepath.Join(layout.sessionDir, "emulator.log")
	var emuLog *os.File
	if f, ferr := os.Create(emuLogPath); ferr == nil {
		emuLog = f
		cmd.Stdout = f
		cmd.Stderr = f
	}

	// Force the bundled SwiftShader Vulkan ICD so the emulator works on machines
	// with old GPU drivers, where the lavapipe fallback crashes.
	emuDir := filepath.Dir(emulatorPath)
	swiftICD := filepath.Join(emuDir, "lib64", "vulkan", "vk_swiftshader_icd.json")
	if _, statErr := os.Stat(swiftICD); statErr == nil {
		cmd.Env = append(os.Environ(), "VK_ICD_FILENAMES="+swiftICD)
	}

	if err := cmd.Start(); err != nil {
		if emuLog != nil {
			_ = emuLog.Close()
		}
		return "", nil, fmt.Errorf("failed to start emulator: %w", err)
	}

	serial := ""
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		// Ask the emulator to exit cleanly first so its disk image is flushed;
		// only then escalate to killing the process.
		if serial != "" {
			_, _ = runADB(adbPath, "-s", serial, "emu", "kill")
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				if !listAdbSerials(adbPath)[serial] {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		if emuLog != nil {
			_ = emuLog.Close()
		}
	}

	// Surface the emulator's own last words when a boot fails.
	bootDiag := func() string {
		data, rerr := os.ReadFile(emuLogPath)
		if rerr != nil || len(data) == 0 {
			return ""
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 6 {
			lines = lines[len(lines)-6:]
		}
		return " | emulator output: " + strings.Join(lines, " / ")
	}

	logf("\u2139 Cold-booting emulator AVD %q (log: %s)...\n", avdName, emuLogPath)
	_, _ = runADB(adbPath, "start-server")

	// Wait for a NEW serial to appear rather than calling the unbounded
	// `adb wait-for-device`, which blocks forever when the emulator dies during
	// startup and cannot distinguish this emulator from an attached handset.
	deadline := time.Now().Add(emulatorBootTimeout)
	for serial == "" {
		if time.Now().After(deadline) {
			stop()
			return "", nil, fmt.Errorf("emulator never registered with adb within %s%s", emulatorBootTimeout, bootDiag())
		}
		for s := range listAdbSerials(adbPath) {
			if !preexisting[s] {
				serial = s
				break
			}
		}
		if serial == "" {
			time.Sleep(time.Second)
		}
	}
	logf("\u2139 Emulator serial: %s. Waiting for the guest to become usable...\n", serial)

	for {
		if time.Now().After(deadline) {
			stop()
			return "", nil, fmt.Errorf("timeout waiting for emulator %s to finish booting%s", serial, bootDiag())
		}
		// If the emulator process died, stop waiting and say why.
		if !listAdbSerials(adbPath)[serial] {
			stop()
			return "", nil, fmt.Errorf("emulator %s disappeared during boot%s", serial, bootDiag())
		}
		if deviceReady(adbPath, serial) {
			logf("\u2713 Emulator ready (%s).\n", serial)
			return serial, stop, nil
		}
		time.Sleep(2 * time.Second)
	}
}

func findEmulator(report *Report) string {
	if report.AndroidSDK != nil && report.AndroidSDK.EmulatorPath != "" {
		if _, err := os.Stat(report.AndroidSDK.EmulatorPath); err == nil {
			return report.AndroidSDK.EmulatorPath
		}
	}
	if path, err := exec.LookPath("emulator"); err == nil {
		return path
	}
	// Fallback to common locations on Windows
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData != "" {
		path := filepath.Join(localAppData, "Android", "Sdk", "emulator", "emulator.exe")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		path := filepath.Join(userProfile, "AppData", "Local", "Android", "Sdk", "emulator", "emulator.exe")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func autoDiscoverAVD(emulatorPath string, logf func(string, ...any)) string {
	cmd := exec.Command(emulatorPath, "-list-avds")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		logf("⚠️ autoDiscoverAVD error: %v, stderr: %s\n", err, stderr.String())
		// Ignore error and still try to parse stdout, sometimes it returns exit code 1 but prints the avds
	}

	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Ignore lines that look like INFO or WARNING logs
		if line != "" && !strings.Contains(line, "INFO") && !strings.Contains(line, "WARNING") && !strings.Contains(line, "ERROR") {
			return line
		}
	}
	logf("⚠️ autoDiscoverAVD could not find AVD in stdout: %q\n", stdout.String())
	return ""
}

func unzipXAPK(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		outPath := filepath.Join(dest, f.Name)
		if !isWithinDir(dest, outPath) {
			return fmt.Errorf("unzipXAPK: illegal file path %q escapes destination", f.Name)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(outPath, 0755)
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		os.MkdirAll(filepath.Dir(outPath), 0755)
		outFile, err := os.Create(outPath)
		if err == nil {
			io.Copy(outFile, rc)
			outFile.Close()
		}
		rc.Close()
	}
	return nil
}

// isWithinDir reports whether target is dir itself or a descendant of dir.
func isWithinDir(dir, target string) bool {
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// startDeviceTcpdump starts tcpdump on the device and returns the running
// command, or nil when capture could not actually be started.
//
// The previous version returned a non-nil command whenever `adb shell` itself
// launched, which is always. adb happily reports success for a shell whose
// remote binary does not exist, so the caller logged "Traffic capture started"
// on devices with no tcpdump and produced an empty pcap. We now verify the
// binary exists first and confirm the capture file actually appears.
func startDeviceTcpdump(ctx context.Context, adbPath, deviceID, remotePath string) *exec.Cmd {
	bin := ""
	for _, candidate := range []string{"tcpdump", "/system/bin/tcpdump", "/system/xbin/tcpdump"} {
		if out, err := runADB(adbPath, "-s", deviceID, "shell", "command", "-v", candidate); err == nil && strings.TrimSpace(out) != "" {
			bin = candidate
			break
		}
	}
	if bin == "" {
		if out, err := runADB(adbPath, "-s", deviceID, "shell", "command", "-v", "busybox"); err == nil && strings.TrimSpace(out) != "" {
			bin = "busybox tcpdump"
		}
	}
	if bin == "" {
		return nil
	}

	_, _ = runADB(adbPath, "-s", deviceID, "shell", "rm", "-f", remotePath)

	shellArgs := []string{"-s", deviceID, "shell"}
	shellArgs = append(shellArgs, strings.Fields(bin)...)
	shellArgs = append(shellArgs, "-i", "any", "-w", remotePath, "-U")
	cmd := exec.CommandContext(ctx, adbPath, shellArgs...)
	if err := cmd.Start(); err != nil {
		return nil
	}

	// Confirm the capture file materialises. tcpdump exits immediately when it
	// lacks CAP_NET_RAW, which is the common case on an unrooted handset.
	for i := 0; i < 6; i++ {
		time.Sleep(400 * time.Millisecond)
		if out, err := runADB(adbPath, "-s", deviceID, "shell", "ls", remotePath); err == nil && strings.Contains(out, remotePath) {
			return cmd
		}
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	return nil
}

// stopDeviceTcpdump ends the capture without truncating it. tcpdump buffers
// packets, so SIGKILL (the old behaviour) regularly produced a pcap with a
// short final record that tools refuse to open. SIGINT lets it flush.
func stopDeviceTcpdump(adbPath, deviceID string, cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	_, _ = runADB(adbPath, "-s", deviceID, "shell", "pkill", "-INT", "-f", "tcpdump")
	time.Sleep(1200 * time.Millisecond)
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

// androidHostIP returns the IP address the Android device can use to reach the host.
// For emulators this is always 10.0.2.2; for USB-connected devices we return the
// host's primary LAN IP.
func androidHostIP(adbPath, deviceID string) string {
	if strings.HasPrefix(deviceID, "emulator-") {
		return "10.0.2.2"
	}
	// Find the host's LAN IP (first non-loopback IPv4).
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return ""
}

// startMitmProxyCapture starts mitmdump on a free port and returns the command
// plus the port it is listening on. Returns (nil, 0) when interception could
// not be established.
//
// The old version hardcoded port 8080 and, critically, the caller pointed the
// device's global proxy at 8080 whether or not mitmdump had actually bound it.
// When the port was already in use the device was left with a global proxy
// aimed at nothing, which silently broke ALL networking on that device and
// persisted after the run finished.
func startMitmProxyCapture(ctx context.Context, harPath string) (*exec.Cmd, int) {
	mitmdump, err := exec.LookPath("mitmdump")
	if err != nil {
		return nil, 0
	}

	port := freeLocalPort()
	if port == 0 {
		return nil, 0
	}

	cmd := exec.CommandContext(ctx, mitmdump,
		"-p", strconv.Itoa(port),
		"-w", harPath,
		"--quiet",
		"--ssl-insecure",
	)
	if err := cmd.Start(); err != nil {
		return nil, 0
	}

	// Only report success once the port is genuinely accepting connections.
	for i := 0; i < 20; i++ {
		time.Sleep(150 * time.Millisecond)
		conn, derr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if derr == nil {
			_ = conn.Close()
			return cmd, port
		}
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
	return nil, 0
}

// freeLocalPort asks the kernel for an unused TCP port.
func freeLocalPort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer ln.Close()
	if addr, ok := ln.Addr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return 0
}

// setAndroidWifiProxy configures the device's global HTTP proxy via adb.
func setAndroidWifiProxy(adbPath, deviceID, host string, port int) {
	_, _ = runADB(adbPath, "-s", deviceID, "shell",
		"settings", "put", "global", "http_proxy",
		fmt.Sprintf("%s:%d", host, port))
}

// clearAndroidWifiProxy removes the device's global HTTP proxy setting.
//
// Writing the literal ":0" (the old behaviour) leaves a malformed proxy string
// behind that some Android versions keep trying to parse, so networking stays
// broken after the analysis. Deleting the key is the actual reset.
func clearAndroidWifiProxy(adbPath, deviceID string) {
	_, _ = runADB(adbPath, "-s", deviceID, "shell", "settings", "delete", "global", "http_proxy")
	_, _ = runADB(adbPath, "-s", deviceID, "shell", "settings", "delete", "global", "global_http_proxy_host")
	_, _ = runADB(adbPath, "-s", deviceID, "shell", "settings", "delete", "global", "global_http_proxy_port")
}

// listDeviceDir returns the set of filenames present in a device directory.
// Used to snapshot /sdcard/Download before the app runs so we can diff afterwards.
func listDeviceDir(adbPath, deviceID, dir string) map[string]bool {
	out, err := runADB(adbPath, "-s", deviceID, "shell", "ls", "-1", dir)
	if err != nil {
		return nil
	}
	files := make(map[string]bool)
	for _, name := range strings.Split(out, "\n") {
		name = strings.TrimSpace(name)
		if name != "" {
			files[name] = true
		}
	}
	return files
}

// pullNewDeviceFiles pulls files that appeared in /sdcard/Download after the app
// ran (i.e. files the app itself downloaded) into sessionDir/device_downloads/.
func pullNewDeviceFiles(adbPath, deviceID string, before map[string]bool, sessionDir string, logf func(string, ...any)) {
	const deviceDir = "/sdcard/Download"
	out, err := runADB(adbPath, "-s", deviceID, "shell", "ls", "-1", deviceDir)
	if err != nil {
		return
	}
	var newFiles []string
	for _, name := range strings.Split(out, "\n") {
		name = strings.TrimSpace(name)
		if name != "" && !before[name] {
			newFiles = append(newFiles, name)
		}
	}
	if len(newFiles) == 0 {
		return
	}
	destDir := filepath.Join(sessionDir, "device_downloads")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return
	}
	for _, name := range newFiles {
		src := deviceDir + "/" + name
		dst := filepath.Join(destDir, name)
		if _, err := runADB(adbPath, "-s", deviceID, "pull", src, dst); err == nil {
			logf("✓ Pulled device download → %s\n", name)
		}
	}
}
