# Shadow Fight 2 Special Edition — cracked vs original

[Русский](COMPARISON-sf2.ru.md)

| | Original | Cracked |
| :--- | :--- | :--- |
| File | Shadow_Fight_2_SE_v1.0.10.apk | shadow-fight-2-special-edition-1.0.12-vzlom.apk |
| versionName | 1.0.10 | 1.0.12 |
| Size | 147 MB | 125 MB |
| Signature (file) | META-INF/CERT.RSA | META-INF/APKEASYT.RSA (APK Easy Tool) |
| Signing key (SHA-256) | A4:0D:A8:0A:59:D1:70:CA… | A4:0D:A8:0A:59:D1:70:CA… (THE SAME) |
| Key issuer | CN=Android, O=Android, android@android.com | same (public AOSP test key) |
| DEX | classes.dex | classes.dex + classes2.dex (added) |
| Archive dates | 2020-08-20 | 2008-02-29 (reset) |

## What the crack added

- **libtdmmod.so (602 KB)** — an injected native library, **TDM Mod Menu**:
  exports `Java_tdm_ahz_modmenu_FloatingModMenuService_*` and uses
  **Cydia Substrate** (`SubstrateHookFunction`) to hook and patch the game in memory.
- **classes2.dex** — the Java/Kotlin loader for the floating mod menu.
- The **SYSTEM_ALERT_WINDOW** permission (overlay on top of other windows — for the cheat menu).
- POST_NOTIFICATIONS, AD_ID, Crashlytics, an updated Google Play Billing, the Kotlin runtime.
- libil2cpp.so grew from 30.3 to 38.5 MB (patched game logic).

## What the crack removed

- **libgpg.so** (Google Play Games) — bypasses the ownership/license check.
- The INSTALL_PACKAGES and READ/WRITE_EXTERNAL_STORAGE permissions.
- vending.INSTALL_REFERRER / derived.apk.id / splits.

## Vulnerabilities and risks

1. **Signed with the public AOSP test key (both versions!)** — the private key is publicly
   available, so the signature provides no authenticity; anyone can swap the code and re-sign. (CWE-321)
2. **Injected native mod menu with inline hooks (cracked)** — third-party code running with
   the app's full permissions, patching the game in memory; it could steal data or load a payload. (CWE-506)
3. **SYSTEM_ALERT_WINDOW overlay** — an attack surface for tapjacking and phishing over other apps.
4. **Repack indicators** — re-signed with APK Easy Tool, archive dates reset to 2008-02-29, added classes2.dex.
5. License and purchase checks were most likely bypassed (Play Games removed, il2cpp patched).

## Key differences the beta.10 scan surfaced

| Detector | Original | Cracked |
| :--- | :--- | :--- |
| `mod_menu_injection` | 0 | 1 (NEW detector) |
| `malware` | 0 | 1 |
| `STEALER_INDICATOR` | 0 | 1 |
| `SSL_PINNING` | 6 | 15 |
| `SECURITY` | 24 | 51 |
| `TRIAL_EXPIRY` | 3 | 13 |
