# Mega-Analyzer vs MobSF

[Русский](COMPARISON.ru.md)

MobSF is the most direct alternative for mobile security analysis. This is an honest breakdown.

## Feature matrix

| | **Mega-Analyzer** | MobSF |
| :--- | :---: | :---: |
| 100% offline | ✅ | ⚠️ self-host |
| Single binary, no JDK/Docker | ✅ | ❌ |
| APK / DEX static audit | ✅ | ✅ |
| React Native / Hermes | ✅ | ⚠️ |
| Native PE / ELF / Mach-O | ✅ | ➖ |
| JAR / Java / WAR | ✅ | ⚠️ |
| Smali-level privacy & tracking | ✅ | ➖ |
| Dynamic sandbox | ✅ Win + Android | ⚠️ VM addon |
| Live device view + input | ✅ | ➖ |
| MITM / decrypted traffic | ✅ | ⚠️ |
| Artifacts browser (images, video, 3D) | ✅ | ➖ |
| Offline ML scoring | ✅ | ➖ |
| Patch / crack-point discovery | ✅ | ➖ |
| SARIF / CI code scanning | ✅ | ➖ |
| Binary size | ~60 MB | ~500 MB+ |
| License | BSD-3-Clause OR GPLv2 | GPL v3 |
| Price | free | free |

✅ first-class · ⚠️ partial · ➖ not available

## Where Mega-Analyzer goes further

1. **Smali-level privacy and tracking analysis** — not just "dangerous API", but full data-flow tracing: where user data is collected, where it goes, which tracker SDKs touch it, mapped to real code paths in Smali.
2. **Deeper native + JAR analysis** — OmniSec (Rust) builds a full CFG/SSA/PDG for PE, ELF, Mach-O, and DEX with interprocedural taint that tracks flows from Java through JNI into native and back. MobSF does not do this.
3. **Artifacts browser** — images, video, 3D assets, audio and raw payloads from inside the APK are extracted and shown in the HTML report. Useful for finding easter eggs, hidden payloads, and steganography.
4. **Much smaller footprint** — single ~60 MB binary vs MobSF's Docker image (~500 MB+). No Python, no Django, no setup.
5. **License choice** — Mega-Analyzer is maintained by Promaster and distributed under [BSD-3-Clause](../LICENSE) OR [GPLv2](../COPYING), at your option.
6. **No Docker required** — download, run, done. MobSF needs Docker or a full Python environment.
7. **Go + Rust + Elixir stack** (Zig for the sandbox GUI) — no Python, no JVM in the hot path. Startup is instant, memory stays predictable.
8. **Manual patcher with CFG-awareness** — Mega-Analyzer finds patch points and generates the Smali diff; *you* decide what to apply. Automated patching without review is a footgun.

## Where MobSF wins

- More established web UI and third-party integrations
- Larger community and contributor base
- Some dynamic analysis features are more mature
