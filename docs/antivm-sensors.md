# Android sensor playback for analysis

The `sensors` module feeds a reproducible, varying accelerometer and gyroscope
trace to the Android Emulator using `adb -s SERIAL emu sensor set NAME X:Y:Z`.
Acceleration uses m/s² and includes gravity; gyroscope readings use rad/s.
The fixed 28 °C sysfs thermal fixture remains separate.

The AVD profiles enable both motion sensors. Custom profiles can select either
sensor and control the trace:

```json
"sensor": {
  "enabled": true,
  "accelerometer": true,
  "gyroscope": true,
  "motion_seed": 42,
  "motion_interval_millis": 250,
  "motion_duration_seconds": 900
}
```

The default interval is 250 ms and the maximum/default duration is 900 seconds.
The same seed and interval reproduce the same 32-frame trace. Duration may be
5–900 seconds and the interval 100–5000 ms. An analysis/session context ends
playback earlier when it is cancelled. The module's short apply/verify context
does not cancel playback when a session lifetime has been bound to the adapter.
`Stop` waits for the worker and restores its original console sensor vectors.
Reapplying replaces the prior worker rather than adding another one.

For a standalone session, keep it open while inspecting an app:
Use the emulator serial shown by `adb devices` in place of the example below.

```powershell
adb -s emulator-5554 root
go run ./cmd/antivm session start --profile pkg/internal/antivm/profiles/pixel-8-avd-api-35.json --serial emulator-5554 --module sensors --hold 1m --timeout 3m --report json
```

Without `--hold`, the CLI applies, verifies, captures state, restores motion
vectors and exits. With `--hold`, it also verifies sensors again before the
final capture. The legacy engine binds playback to the runtime context and
provides `StopSensorNoise` for explicit cleanup. The thermal bind mount has its
own lifetime and lasts until reboot.

Verification installs a bundled, read-only DEX probe in
`/data/local/tmp/mega-antivm/sensors.dex`. It runs with `app_process`, registers
actual Android `SensorManager` listeners, and counts events and changes in the
observed vectors. Console acceptance, a live worker, or a marker file cannot
substitute for changing Android events. Captures include sensor availability,
event counts, movement, the worker's frame count, and diagnostics. Unsupported
sensors, stopped workers and static events remain visible in verification.
`sensor_noise_active` in the legacy report requires both sensors' verified
movement and an active worker.

No Java/SDK installation is required to run the Go program. To rebuild the
bundled probe after editing its Java source, run
`pkg/internal/antivm/adapter/probes/build.ps1` with a JDK and Android SDK present.
The output is a DEX with minimum API 28, shared across Android CPU architectures.

This tests sensor delivery through the Android service from a shell process.
An app's permissions, foreground state and sampling policy can still affect
its own subscriptions. Playback controls only the explicitly selected AVD.
