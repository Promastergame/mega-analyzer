# Fixed thermal reading for Android analysis

The `sensors` anti-VM module exposes `28000` (28 °C in millidegrees) at
`/sys/class/thermal/thermal_zone0/temp`. It is enabled by `sensor.enabled`
in the device profile and runs through `antivm session start`. The legacy
runtime engine also applies and verifies the fixture when `sensor_noise` is
enabled; it reports `thermal_temperature_millic: 28000` only after readback.

Use a rooted analysis AVD and select its serial:

```powershell
adb -s emulator-5554 root
go run ./cmd/antivm session start --profile pkg/internal/antivm/profiles/pixel-8-avd-api-35.json --serial emulator-5554 --module sensors
```

The module enters init's mount namespace and bind-mounts a fixed temperature
file over an existing thermal reading. If the thermal class exists but zone 0
is absent, it mounts a synthetic class with zone 0, preserving other class
symlinks as absolute links to their device targets. Non-symlink class entries,
an unavailable thermal class, or an incomplete existing zone cause a reported
failure rather than hiding unrelated entries.

Root, `nsenter`, bind-mount support and appropriate SELinux relabel permissions
are required. SELinux stays enabled. The fixture retains the observed sysfs
context; synthetic zone files use Android's `sysfs_thermal` context. Repeated
application with the expected reading does not stack mounts. The mount lasts
until the AVD reboots; it is not a kernel or disk-image
patch. Read-only device captures include the raw reading or an unreadable-file
diagnostic. Verification compares that reading against `28000`, so missing,
zero or differently scaled readings cannot pass.

This fixture covers this native sysfs probe. Battery temperature and
SensorManager readings are separate interfaces. The same module also supports
[verified motion sensor playback](antivm-sensors.md). A successful shell readback
does not establish that every app mount namespace and SELinux domain sees the
fixture; validate visibility with the intended analysis process on the AVD.
