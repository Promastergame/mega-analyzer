# Sandbox module: findings and fixes

Update, 2026-10-14: the follow-up [PE audit](pe-analysis-improvements.ru.md)
removes simulated API generation, excludes synthetic collectors from report
evidence, fixes process/time correlation, and preserves offline analysis without
elevation. The description below records the earlier implementation state.

This document records what I found while reading the sandbox implementation end to
end, what I changed, and what is still wrong. It is written for whoever maintains
this next, so it names specific functions and files rather than describing
intentions.

## The headline finding

The Windows monitoring stack does not monitor Windows. `IMPLEMENTATION_STATUS.md`
marks tasks 1 through 17 complete, then admits under "Known Limitations" that the
minifilter driver "uses a placeholder that simulates events", the API tracer "uses
a placeholder for DLL injection", and the WFP monitor "uses a placeholder for
kernel-level packet capture".

Those three placeholders are the entire Windows observation surface. Kernel
events, API calls, and packet captures are generated rather than observed, and
they flow into the report through the same fields as real data with no marker
distinguishing them. That is the actual reason Windows "works poorly": it does not
fail, it produces confident output that describes nothing that happened. A sandbox
that invents evidence is worse than one that reports it cannot observe, because
the first cannot be caught by looking at the results.

I did not implement a minifilter driver, real Detours-based injection, or a WFP
callout driver. Each is a signed-driver project in its own right. What has to
happen before any of that is honest reporting, so the synthetic components are
now surfaced as degraded rather than presented as observations.

Two related Windows problems worth recording. `initializeEnhancedComponents`
fails hard on `checkPrivilegesFunc()`, so a non-elevated run loses the whole
enhanced pipeline through a path that reads like a minor warning. And VSS
snapshotting calls `vssadmin create shadow`, which is Server-only. On Windows 10
and 11 client it always fails, so `-enable-vss` can never work on the operating
system most analysts run.

## The bug that made Android unreachable

`sandbox.Run` opened with a `runtime.GOOS != "windows"` check that returned an
error before dispatching to the Android path. `runAndroidSandbox` and roughly nine
hundred lines behind it were unreachable on Linux and macOS. The Android sandbox
was not unreliable on those hosts, it was dead code.

A test had frozen this in place. `TestRunValidatesConfigBeforePlatformSupport`
asserted that `Run` returns an error containing "supported on Windows only", so
the bug was load-bearing and the suite was green.

The gate now sits immediately before `prepareLaunchSpec`, where it belongs, and
guards only native sample execution. Off Windows, `Run` completes and returns a
report with `Executed: false` and an `ExecutionSkipReason` that names the
requirement and points at `-android-sandbox`. The test asserts that contract
instead.

## Android lifecycle

Seven separate problems, all in the boot and networking path.

Quick Boot was carrying state between analyses. The emulator launched without
`-no-snapshot-load`, so sample N ran on a device still holding sample N-1's
filesystem, accounts, and cached network state. Cold boot is now forced, along
with `-no-audio` and `-no-boot-anim`.

Boot readiness was a race. The old check waited on `sys.boot_completed` alone,
which flips before the package manager is usable, so installs immediately after
boot failed intermittently for no visible reason. `deviceReady` now requires
`sys.boot_completed`, `init.svc.bootanim` stopped, and `pm path android`
returning a package line.

Failed boots orphaned emulators. There was no teardown on the error paths, so
every failure left a process holding a console port until the host was rebooted,
and the next run picked a different port or failed outright. `launchAndConnectEmulator`
now returns a stop closure that the caller defers, doing a graceful `adb emu kill`
before escalating to a process kill.

Boot failures were also silent. Emulator stdout and stderr went nowhere, so a
run that died from a missing KVM group or an unaccelerated x86_64 image reported
only a timeout. Output is captured to `emulator.log` in the session directory and
the last six lines are quoted in the failure message. Boot is bounded at six
minutes rather than an unbounded `adb wait-for-device`, and the emulator process
disappearing mid-boot is detected instead of waited on.

Traffic capture lied. `startDeviceTcpdump` returned a non-nil command whenever
`adb shell` launched, which it does on every device, including the many with no
`tcpdump` binary. "Traffic capture started" appeared in the log and the pcap was
empty. It now probes for `tcpdump`, `/system/bin/tcpdump`, `/system/xbin/tcpdump`,
and `busybox`, confirms the remote capture file materialises, and returns nil
otherwise. Teardown sends `SIGINT` before escalating, because `SIGKILL` truncated
the final block and left a corrupt pcap.

The proxy poisoned the guest. `startMitmProxyCapture` hardcoded port 8080 and the
guest proxy was set whether or not mitmdump actually bound. When it did not, every
HTTP request in the guest went to a closed port and the sample looked like it had
no network activity. The function now picks a free port, dials it to confirm it is
accepting, returns the real port to the caller, and the guest setting is only
applied when there is something listening. Teardown is a deferred
`clearAndroidWifiProxy` on every exit path, and that function now issues
`settings delete` for `http_proxy`, `global_http_proxy_host`, and
`global_http_proxy_port` rather than writing the malformed literal `:0` that used
to be left behind. Separately, the guest does not trust the mitmproxy CA, so
pinned and validated TLS still fails. The report says so now instead of leaving
an analyst to wonder why an app went quiet.

Process attribution was wrong. `getAppPIDs` ran `strings.Contains` against the
whole `ps` line, so any process whose command line happened to contain the package
name was attributed to the sample, and the connection list inherited the error.
It now uses `pidof` first and falls back to exact last-column matching plus
`pkg:subprocess` prefixes.

Smaller items in the same pass: `cfg.Resolution` reached an `adb shell wm size`
argument unvalidated, and the logcat file descriptor leaked on every run because
it was only closed inside the teardown branch.

## Frida

I could not verify that "WildCat" exists as a Frida fork. Searches surfaced
`nowsecure/frida-cycript`, the Frida organisation's own repositories, and the Rust
`frida` crate, none of which match. Rather than guess at what was meant, I built
the thing a fork would have provided: reliable server orchestration plus a curated
hook set. If WildCat is a real project, point me at it and I will compare.

The project already had partial Frida support in `pkg/cmd/analyzer/live_frida.go`,
sitting in `package main` next to the web UI with no connection to the sandbox
package. It had three defects worth naming, because the new code had to avoid
repeating them.

Its liveness check tested `fridaState.srvCmd.ProcessState == nil`. Nothing ever
calls `Wait()` on that command, so `ProcessState` stays nil forever and the check
reported "running" indefinitely, including long after frida-server had died.
`fridaServerLive` now asks the device via `pidof`.

`findFridaServer` returned the first `frida-server*` file it found with no
architecture matching, despite a comment saying the ABI must match. Worse, the
obvious fix is also wrong: `"frida-server-16.2.1-android-x86_64"` contains the
substring `"x86"`, so a naive match selects the 64-bit binary for a 32-bit device,
the push succeeds, and the server silently never starts. `fridaNameMatchesArch`
checks the character after the architecture token to reject that.

There was no host/device version check, which is the most common real-world Frida
failure and produces an unhelpful error. The host CLI version is compared against
the server version parsed from the filename, and a mismatch is reported before
anything is pushed.

The existing code was also attach-only, which is structurally blind to
application startup. Everything a packer or dropper does in `Application.onCreate`
or a static initialiser happens before the attach lands. Spawn mode force-stops
the app and relaunches it under Frida so hooks are installed before any
application code runs.

The integration is three config fields rather than one toggle, because whether to
instrument, whether to do it early enough to see startup, and what to observe are
independent decisions: `-sandbox-frida`, `-sandbox-frida-spawn`, and
`-sandbox-frida-script`. Passing a script or asking for spawn implies the first,
so nobody has to state their intent twice.

What makes it useful rather than decorative is the default hook set in
`frida_default.js`. Every hook answers a question an analyst actually asks:
dynamic code loading via `DexClassLoader`, `InMemoryDexClassLoader`, and
`System.load`, which is where Android droppers keep the real payload; command
execution; crypto transforms and key sizes; outbound connections; device
identifier and SMS and content-provider access; file drops outside the app cache;
reflection into `dalvik` and `SystemProperties` and `Runtime`; and emulator and
root probing. High-frequency low-signal surfaces are deliberately not hooked, so
the transcript stays readable on a real app.

The evasion hooks report rather than defeat. Knowing that a sample probed for
`qemu` properties or checked for `/su` is itself the finding, and silently lying
to the sample makes the rest of the trace impossible to trust.

Results land in the report as a `FridaSession` carrying mode, device ABI, server
and host versions, script path, event count, and the categories observed, with
warnings for everything that did not work. Instrumentation that fails silently
reads as "the sample did nothing", which is the most expensive possible failure
mode for a sandbox.

## Still outstanding

The three Windows placeholders need real implementations: a signed minifilter, a
Detours-based tracer, and a WFP callout driver. VSS needs a client-OS path or an
explicit refusal. `scrcpy_integration.go`, `os_windows.go`, `exploit_analysis.go`,
and the WFP and kernel monitor Windows files have not had a line-by-line pass.
`persist.go` is 297 bytes and looks like a stub.

Snapshot and restore is worth building next. The reference implementations are
clear about the constraints: Cuttlefish requires the device to be suspended first
and only supports x86_64, and QEMU's `savevm` is known broken for 32-bit ARM
TrustZone guests and with `blockdev`. A restore-from-snapshot path modelled on how
Firecracker-based sandboxes do memory snapshots with copy-on-write is what turns a
six-minute cold boot into a sub-second start, and it is the single largest
remaining win for both reliability and UX.
