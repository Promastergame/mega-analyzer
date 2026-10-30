# OMNISEC / Mega Analyzer - v1.0.0-beta.10

## New detector: Injected Mod-Menu / Hook (`mod_menu_injection`, Security, CRITICAL)
Born from comparing a cracked vs original Shadow Fight 2 SE APK.

- Scans native libraries (`.so` / FileTypeNative).
- Flags injected game **mod-menu / inline-hook engines** that are not part of the
  original app - the hallmark of repacked "mod"/"cracked" builds and an
  embedded-code-injection risk (CWE-506).
- High-signal, low-FP markers: `FloatingModMenu`, `tdm_ahz`, `libtdmmod`,
  `modmenu`, `SubstrateHookFunction`, `MSHookFunction`, Dobby, LGL, BearMod.
- One consolidated match per library (lists all matched engines); severity High,
  IsCritical. Notes when an inline function-hooking engine is present.
- Validated: fires on `libtdmmod.so` in the crack (mod_menu_injection: 1),
  silent on the clean original (0). No false positives on libunity/libil2cpp.

## Report
- SVG-only preserved: verified `emoji in HTML: 0`.
- Engine version bumped to v1.0.0-beta.10.
