# resources.arsc fingerprints: four real builds

Derivation notes for `pkg/internal/arscsigs/android_resource_rules.json`. Every number below
was measured, not estimated. The reference parser is in `demo/tools/`.

## Samples

| # | Package | Label | Size | Global pool | Dups | Keys | Locales | Types |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A | `com.playgendary.tom` | Tomb of the Mask | 2 025 472 | 18 391 | 0 | 6 715 | 96 | 20 |
| B | `com.supercell.brawlstars` | Brawl Stars | 512 048 | 927 | 0 | 5 009 | 0 | 17 |
| C | `smellymoo.sand` | Sand : Box | 714 348 | 8 219 | 0 | 2 281 | 85 | 17 |
| D | `smellymoo.sand` | Sand : Box | 713 588 | 8 219 | **47** | 2 281 | 85 | 17 |

Sample C was extracted from an original APK container. Sample D was supplied as a loose
`resources.arsc`. **C and D are the same app at the same version — D is a repack of C.**

Shared traits across all four, which is what makes them usable as a clean-build envelope:
package id `0x7f`, header size 288, `lastPublicType` and `lastPublicKey` both zero,
`typeIdOffset` zero, zero trailing bytes, UTF-8 value and key pools, UTF-16 type pool,
no sparse or 16-bit-offset entries, no shared-library / overlayable / staged-alias chunks,
and a synthetic placeholder name occupying one gap in the type id space.

## A — standard ad-supported release build

Inventory read straight out of the resource pools, without touching a single class or library:

- AppLovin MAX mediation, including the creative debugger UI package
- Yandex Mobile Ads (CIS mediation adapter)
- Firebase Crashlytics, with a per-build `com.crashlytics.android.build_id`
- Firebase Realtime Database at `tomb-of-the-mask-12823194.firebaseio.com`
- Two Google OAuth client IDs (debug plus release)
- **Unity**, inferred purely from `com.google.firebase.crashlytics.unity_version`
- A bundled Chinese SDK, betrayed by its own error strings — including the misspelled
  `conent_type错误`, which is a wonderfully stable anchor precisely because it is a typo

That Unity inference is why `ENGINE_UNITY_FROM_RESOURCES` exists: engine identification
without parsing any native code, cross-checkable against `nativesigs`.

## B — engine game that ignores Android resources

**Zero** locale-qualified configs, and a value pool of only 927 strings against 5 009 resource
names. The `string` type exists but carries just 322 resolvable entries in the default config.
Localization lives in the engine's own asset bundles, not in `resources.arsc`.

This single sample is the reason `ARSC_LOCALE_COVERAGE_COLLAPSED` is **low** severity rather
than a tamper verdict. A naive rule reading *few locales means a repacker stripped
translations* would flag a completely untouched official build. Externally visible traces are
limited to Helpshift support and two OAuth client IDs.

## C vs D — a confirmed repack, and what gives it away

D is byte-different from C but only 760 bytes smaller. Comparing structure instead of hashes:

**1. Resource names are identical, values are not.**
Both files have exactly 2 281 key strings with a set difference of **zero** in both
directions, and identical entry counts per type. Nothing was recompiled from sources — the
table was edited in place. This is `REPACK_KEYS_EQUAL_VALUES_DIFFER`, the strongest repack
signal obtainable from `resources.arsc` on its own.

**2. The label is rebranded for exactly one locale.**
`app_name` resolves to `Sand : Box` in the default config of *both* files, across 13 locale
variants. In D, one single variant differs:

| Locale | C | D |
| --- | --- | --- |
| default | `Sand : Box` | `Sand : Box` |
| `ru` | `Sand : Box` | **`SandCraft`** |

The application id stays `smellymoo.sand`, so updates and save data still line up, and the
build looks unremarkable to anyone not running a Russian locale. This is a targeted rebrand,
and it is why `REBRAND_LOCALE_SCOPED_LABEL` compares the label across *all* locale configs
instead of only reading the default one — which is what a single-value check would do, and
would have missed this entirely.

**3. The value pool lost its deduplication.**
C reports 0 duplicate strings, D reports 47 unique strings each appearing twice.
aapt2 always deduplicates the value pool, so a clean release build is exactly zero.
Any non-zero count means the pool was serialized by something that is not aapt2 —
`ARSC_STRING_POOL_DUPLICATES`, high severity, and it needs no baseline to fire.

**4. A locale was overwritten rather than translated.**
48 Cyrillic Serbian strings present in C are gone in D. The 47 duplicates that appeared are
Latin-script strings (`Gotovo`, `Ažuriraj`, `Instaliraj`, `Odbij`, `Dolazni poziv`) that
already existed for the neighbouring Bosnian and Croatian locales. The locale configs survive,
but their values were replaced with copies from a sibling locale, destroying the translations.
Hence `REPACK_LOCALE_TABLE_REWRITTEN`.

Note the ordering: signals 1 and 3 are the *detectors*, and they fire on shape alone. Signals
2 and 4 are the *explanation* of what the repacker wanted. A ruleset built only from signal 2
would need to know the app's real name in advance; built from 1 and 3, it generalises.

## Signing, from the sample C container

The APK carries an `APK Sig Block 42` marker at offset 7 139 312 — so it is v2/v3 signed —
and contains **no** `META-INF/*.RSA`, `*.DSA`, `*.EC`, `*.SF` or `*.MF` entries at all.

That is entirely legitimate for a `minSdk 24+` release. It is also precisely the shape a
signature-stripping patcher leaves behind, including this repository's own
`cmd/patch-apk -strip-signatures`. So `SIGN_V1_SIGNATURE_STRIPPED` is high confidence but only
medium severity, and the actual certificate-swap verdict is delegated to
`SIGN_CERTIFICATE_DIGEST_DRIFT`, which compares the SHA-256 of the signer certificate against
a baseline. Comparing display names is worthless — a name is trivially forged, a key is not.

## Cross-layer checks worth running

The resource and native rulesets are much stronger together than apart:

| Resource-layer claim | Native-layer contradiction |
| --- | --- |
| ResTable package name | JNI export prefix in a bundled `.so` |
| Manifest package | ResTable package name |
| Provider authority prefix | Application id |
| Engine inferred from resources | Engine inferred from loaded libraries |
| Vendor hosts in the value pool | Hosts in native string tables |

The last row generalises a case already documented in `demo/nulls_brawl_so_diff.md`, where a
repack kept the original vendor endpoints in place and simply added its own alongside them.
A declared identity that disagrees with the loaded code is nearly always the real finding.

## AXML: one clean manifest, and six false positives of my own making

The manifest from sample C's container, parsed in full (8 808 bytes, root `0x0003`,
declared size equal to file size, 103 pool strings, UTF-8, unsorted, 25 resource-map
entries, one namespace):

| Field | Value |
| --- | --- |
| `package` | `smellymoo.sand` |
| `versionCode` / `versionName` | 21192 / `21.192 Rattlesnake` |
| `minSdk` / `targetSdk` / `compileSdk` | 21 / 36 / 36 |
| `platformBuildVersion` | name 16, code 36 |
| `allowBackup` | `true` |
| `extractNativeLibs` | `true` |
| `debuggable` / `testOnly` | absent |
| Components | 12 activity, 2 service, 2 receiver, 1 provider |
| Permissions | 4 (billing, internet, network state, derived receiver permission) |
| Provider authority | `smellymoo.sand.androidx-startup` |

### What this measurement broke

The rule `REPACK_COMPONENT_FOREIGN_PACKAGE` — flag any declared component whose class sits
outside the application package — matched **six classes on a completely clean build**, and
every single one was a false positive:

| Class | Why it is not tampering |
| --- | --- |
| `com.android.billingclient.api.ProxyBillingActivity` | Play Billing library |
| `com.android.billingclient.api.ProxyBillingActivityV2` | Play Billing library |
| `com.google.android.gms.common.api.GoogleApiActivity` | Play services |
| `com.google.android.datatransport.runtime...BroadcastReceiver` | Firebase transitive dep |
| `com.google.android.datatransport.runtime...SchedulerService` | Firebase transitive dep |
| `fky.pq.vxdjhbnbm.SztxrmMlumugmyetk` | the app's own Application class, **R8-repackaged** |

Six out of six. The last row is the interesting one: R8 with repackaging moves classes into
short generated packages, so a legitimate app's own entry point routinely appears to live
under a foreign package. Any rule that treats prefix mismatch as evidence would fire on a
large share of obfuscated production apps.

The rule is now `low` confidence, `medium` severity, carries an explicit exclude list of known
SDK prefixes, and sets `requires_corroboration`: a foreign package counts only when something
else agrees with it — a foreign JNI export prefix, a foreign host string, or a foreign
provider authority. `AXML_OBFUSCATED_APPLICATION_CLASS` was added specifically to *suppress*
this pattern rather than report it.

This is exactly the calibration that was missing when the manifest rules were first written
from shape alone. One real measurement invalidated one rule outright and forced two others to
be rewritten.

### What the measurement confirmed

Two rules were already conservative and the data proved it was the right call.
`AXML_EXTRACT_NATIVE_LIBS_TRUE` and `AXML_BACKUP_ALLOWED` both fire on this clean build, so
keeping them at `low` severity was correct — with `minSdk 21` neither is remarkable.
Equally, `AXML_WIDE_SDK_SPAN` is deliberately `low`: a 21-to-36 span is ordinary, and matters
only as context for why weaker platform defaults remain reachable.

### A better rename detector

`smellymoo.sand.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` is generated by AGP as the
application id plus a fixed suffix, and `smellymoo.sand.androidx-startup` is derived the same
way. Both are effectively independent copies of the application id stored as plain strings
that manifest editors do not rewrite. Together with the `ResTable` package name that gives
**three** places to cross-check a rename, none of which is the `package` attribute itself:

1. `manifest/@package`
2. `ResTable_package` name in `resources.arsc`
3. AGP-derived permission and authority prefixes

A renamed build usually updates only the first.

### Honest limitation

Every manifest threshold above rests on **one** measured file. That is enough to invalidate a
bad rule, as shown, but not enough to establish a normal range. The `baselines` entry records
exactly what was measured so the next samples can widen or tighten it. Until then the manifest
thresholds are provisional, and the JSON says so.
