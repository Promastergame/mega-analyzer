# Native library diff: official Titan build vs a repacked private-server build

A worked example for `pkg/internal/nativesigs`. Two sets of `arm64-v8a` shared
objects from the same game family were compared: an official Supercell Titan build
and a repacked private-server build (Nulls Brawl). Every observation below maps to
a **generic** rule, never to a hardcoded name.

## Inventory

| Library | Official | Repack | Note |
| --- | --- | --- | --- |
| `libg.so` | 16,251,808 | 20,181,824 | game core, +24% |
| `libfmod.so` | 1,159,088 | 1,179,776 | near-identical FMOD |
| `libc++_shared.so` | 6,766,464 | 1,292,904 | official ships debug info |
| `libflutter.so` | 10,601,880 | absent | Flutter engine dropped |
| `libapp.so` | 12,256,176 | absent | Dart AOT snapshot dropped |
| `libscid_sdk.so` | referenced only | 59,392 | re-namespaced |
| `libsentry.so` | referenced only | 704,344 | rebuilt |
| `libsentry-android.so` | referenced only | 16,832 | rebuilt |
| `libwildcat.so` | absent | 10,685,496 | new instrumentation layer |

All ten files are `ELF 64-bit LSB shared object, ARM aarch64`, stripped.

## Findings

### 1. Section header table gutted — `ELF_SECTION_TABLE_GUTTED`

The official `libg.so` carries 28 section headers; the repack carries 5. `PT_DYNAMIC`
still parses, so `DT_NEEDED` and `DT_SONAME` are readable, but `nm -D` and
`objdump -T` report `no symbols` and symbol-level tooling goes blind. The official
build exports `JNI_OnLoad` plus three consent callbacks; the repack exports nothing.

### 2. New instrumentation layer — `HOOK_FRIDA_CORE` + `MOD_SIGNED_SCRIPT_LOADER`

`libwildcat.so` is a rebranded **Frida** build. Retained Vala source paths give it
away: `subprojects/frida-core/lib/wildcat/server.vala` and `.../wildcat.vala`, plus
`ProcessInvader.acquire_child_gating(...)`, `join_portal`, `leave_portal`, GLib
(`GNullSettingsBackend`, `g_hash_table_iter_next`) and an inline-patching comment
assigning `replacement_method` over `hooked_method`. The Brotli static dictionary is
embedded too, so a compression stack ships with it.

Eight exported symbols, all versioned under a custom `LIBWILDCAT_4.2` namespace:
`wildcat_js_request`, `wildcat_js_get_signed_script`,
`wildcat_js_get_signed_script_size`, `wildcat_js_get_data_path`,
`wildcat_js_usermods_get_file_path`, `wildcat_release_blocking` and two JNI entry
points. That is a signed-script mod loader with a user-mod path — exactly what
`MOD_SIGNED_SCRIPT_LOADER` describes. Runtime error strings name the Java side:
`daniillnull.nulls.mods.loader.ModificationLoader` and `xyz.daniillnull.WildCat`,
both guarded by `it is not a NTTitan based APK?`.

Note it is **not** in any `DT_NEEDED` list — it is loaded from Java, so a
dependency-graph-only scan would miss it entirely. Strings and exports catch it.

### 3. SONAME keeps the real version — `ELF_SONAME_FILENAME_MISMATCH`

The file is `libwildcat.so`, but `DT_SONAME` is
`libwildcat_v4.2.0_build_1_aarch64.so`. Renaming the file hid a precise version and
build number that the SONAME still carries. Cheap, high-value read.

### 4. Vendor SDK re-namespaced — `ELF_JNI_PACKAGE_MISMATCH`

`libscid_sdk.so` still contains Supercell's own C++ classes — mangled
`SupercellId(SupercellIdParams const&)` and `SupercellSocial(SupercellSocialDelegate*)`
plus method strings like `SupercellId.accountBound` — while every exported JNI entry
point was moved to `xyz.daniillnull.connect.sdk.NTConnect`:
`bindAccount`, `forgetAccount`, `loadAccount`, `logOut`, `getSessionTokenResult`,
`generateQrCodeResult`, `setProfile`, `publicProfileData`, `avatarImageData`.

Internal vendor identity and exported Java package disagree, which is the whole
point of the heuristic. The official pair `libflutter.so` + `libapp.so` — the Dart
module whose `package:scid_flutter` code drew the real Supercell ID login — is gone,
replaced by this native account layer.

### 5. Endpoints in plaintext — `ELF_PLAINTEXT_ENDPOINTS_DELTA` + `PRIVATE_SERVER_REDIRECT`

The official `libg.so` yields only two URL strings (`unicode.org`, the LLVM
toolchain URL): its endpoint table is obfuscated. The repack yields them in the
clear, which both identifies the title and exposes the redirect:

- first-party, still present: `id.supercell.com/guest`, `inventory.mtech.supercell.com/v1/serve`, `report.mtech-dev.supercell.com/v1/track`, `link.brawlstars.cn`, `link-dev.brawlstars.com`, `link-staging.brawlstars.com`, `supercell.com/en/terms-of-service/`, `game.qq.com/contract.shtml`
- third-party, injected: `brawl.link.nulls.gg`, `connect.nulls.gg/`

Clustering registrable domains puts two non-vendor hosts beside a dense cluster of
first-party hosts — no domain allowlist needed. Two bare 32-hex URLs also appear,
consistent with Sentry DSN public keys, matching the rebuilt `libsentry.so`
(`sentry-native 0.10.1`, built in CI under `/home/runner/work/sentry-native/`).
Markers `nullsbrawl` and a joke string mentioning a `nulls key` sit alongside.

### 6. Toolchain drift — `ELF_MULTI_TOOLCHAIN_STAMPS` / `TOOLCHAIN_ANDROID_CLANG`

The official `libg.so` carries three different Android clang stamps (9.0.8, 9.0.9,
14.0.7) from vendored code of different eras. `libwildcat.so` was built with clang
14.0.6/14.0.7, while `libscid_sdk.so` and `libsentry.so` share a much newer
`clang 18.0.1 (r522817, +pgo, +lto)` — evidence those two were recompiled from
source by the repacker rather than copied from the official APK.

### 7. Inverse hygiene finding — `ELF_DEBUG_INFO_SHIPPED`

The **official** `libc++_shared.so` is the unusual one: 6.77 MB and `with debug_info,
not stripped`. The repack ships the normal stripped 1.29 MB runtime. Worth flagging
in either direction; it is a hardening observation, not evidence of tampering.

## What generalises

1. Read `DT_SONAME` and symbol version namespaces before trusting file names.
2. Compare exported JNI packages against internal vendor symbols.
3. Count section headers — a gutted table blinds symbol tooling while segments still load.
4. Cluster URL domains instead of allowlisting known bad hosts.
5. Diff plaintext-string volume against a reference build to spot removed obfuscation.
6. Scan every `lib/` entry, not just the dependency graph: the most interesting library here was absent from all `DT_NEEDED` lists.
