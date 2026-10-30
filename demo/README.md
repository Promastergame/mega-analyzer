# Demo target

`vulnerable-app/` is a tiny, **intentionally insecure** decompiled-APK layout used
to show what Mega-Analyzer reports — no Android SDK, emulator, or real APK
required. Point the analyzer at it and you immediately get a CRITICAL verdict.

```bash
analyzer -t demo/vulnerable-app -report all -sarif
```

Open `analysis_output/REPORT.html` for the interactive report, or feed
`analysis_output/analysis.sarif` to any SARIF viewer.

## What's deliberately wrong here

| File | Planted issues |
| :--- | :--- |
| `AndroidManifest.xml` | `debuggable`, `allowBackup`, cleartext traffic, `sharedUserId=android.uid.system`, exported activity/provider/receiver with no guard, custom `taskAffinity` + `singleTask` (task-hijacking / StrandHogg), `grantUriPermissions`, unverified deep link, dangerous SMS/contacts permissions |
| `smali/.../MainActivity.smali` | hardcoded AWS key & GitHub token, runtime reflection (`Class.forName`), `Runtime.exec`, native `System.loadLibrary`, weak crypto (`DES/ECB`), cleartext API base URL |
| `assets/config.properties` | leaked AWS / Stripe / Slack credentials, `disableTls=true` |

> ⚠️ Everything here is fake. The "secrets" are well-known public **example**
> values (e.g. `AKIAIOSFODNN7EXAMPLE`), not live credentials. Don't model real
> apps on this directory — it is the opposite of a secure baseline.

## `demo_test_apk`

`demo_test_apk/` is a separate plain-Java Android fixture for patch strategy
and SDK-wrapper tests. It includes local wallet/price gates, a localhost:5555
economy and subscription contract, pseudo-ads, feature flags, auth/debug
checks, and a JNI/native lab boundary on localhost:7777. It never contacts a
real service and contains no real credentials.

Analyze the Java tree or a hand-built decoded APK layout with:

```bash
analyzer -t demo/demo_test_apk -report all
```
