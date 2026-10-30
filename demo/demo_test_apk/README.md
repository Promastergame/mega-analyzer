# Mega Analyzer demo_test_apk

Контролируемая Java-фикстура для проверки APK/Smali-патчера. Это не готовый
production APK и не подключается к реальным сервисам: все серверные адреса
локальные или используют домены `example.test`.

Архитектура — по специализациям, карта в [ARCHITECTURE.md](ARCHITECTURE.md):

| Специализация | Пакет | Что внутри |
|---|---|---|
| СЕРВЕР | `server/` | `EconomyClient`, `SubscriptionClient`, `AgeVerificationClient` → `:5555` |
| МОНЕТКИ | `coins/` | `WalletService` (int/цена), `WideWalletService` (long), `CooldownService` |
| ПОДПИСКА | `premium/` | `SubscriptionGate` (AND-funnel), `TokenSessionService` (объекты) |
| РЕКЛАМА | `ads/` | `PseudoAdController`, `PseudoAdView` + `assets/pseudo_ad.svg` |
| АВТОРИЗАЦИЯ | `auth/` | `AuthGate`, `AgeGate`, `FeatureGate`, `IntegrityGate` |
| NATIVE | `nativelab/` | `NativeLabBridge` (`demo_lab`, канал `:7777`) |
| РЕАКТ БУНДЛ | `react/` + `react_native/` | `ReactAgeBridge` ↔ `index.android.bundle` (18+) |

## Сценарии

| Сценарий | Тестовая точка |
|---|---|
| Локальные монетки (int) | `coins/WalletService#getCoins()I`, `spendCoins(I)Z` |
| Цена товара | `coins/WalletService#getGemCost()I` → 0 |
| Монетки (long) | `coins/WideWalletService#getCoinsLong()J` |
| Кулдауны | `coins/CooldownService#getCooldownRemaining(String)I` → 0 |
| Сервер монеток | `server/EconomyClient#fetchCoins()` -> `127.0.0.1:5555` |
| Премиум-гейт (AND) | `premium/SubscriptionGate#hasPremium()Z` (server && cache) |
| Токены (объекты) | `premium/TokenSessionService#getAuthToken()` |
| Псевдо-реклама | `ads/PseudoAdController#shouldShowAd()Z`, `showRewardedAd()`, Canvas + SVG |
| Платная подписка | `server/SubscriptionClient#hasPremium()Z` -> `127.0.0.1:5555` |
| Feature flags | `auth/FeatureGate#isFeatureEnabled(String)Z` |
| Локальная auth-сессия | `auth/AuthGate#isAuthenticated()Z` |
| Integrity/debug | `auth/IntegrityGate#isTrustedDevice()Z` |
| Native lab bridge | `nativelab/NativeLabBridge` и канал `127.0.0.1:7777` |
| Возраст 18+ в Java | `server/AgeVerificationClient#isAdult(String)`, `auth/AgeGate` |
| Возраст 18+ в React Native | `react/ReactAgeBridge`, `react_native/index.android.bundle` |

## Контракт локальных тестовых сервисов

Один локальный fixture-сервис может слушать `127.0.0.1:5555` и отвечать:

```text
/economy/coins       -> {"coins":1000}
/subscription/status -> {"active":true}
/features            -> {"premium":true}
/age/verify         -> {"adult":true,"age":21}
```

Нативный lab bridge использует отдельный порт `127.0.0.1:7777` для сценариев,
которые должны быть видны как Java -> JNI/native boundary. Реализация `.so`
не включена в эту Java-фикстуру: `NativeLabBridge` безопасно деградирует, если
библиотека отсутствует.

## Что должен находить патчер

- app-owned boolean gates;
- numeric value provider (int и wide long/double);
- price/cost provider;
- HTTP URL and endpoint role;
- purchase/subscription response mapping;
- ad decision point;
- ad creative as both Canvas rendering and SVG asset;
- native library load and JNI boundary;
- constant and branch candidates;
- source/body-preserving patch opportunities.

Исходники намеренно небольшие и используют только Android platform API и Java
8. Gradle/AndroidX/Kotlin здесь нет, как и в `zig/apk_editor/android`.

React Native сценарий представлен readable `index.android.bundle` и его
Java-зеркалом `react/ReactAgeBridge`: endpoint, JSON parser, native
bridge и финальный boolean gate находятся в одном JS-графе.

Сборка выполняется тем же ручным toolchain, что и Android-порт редактора:
`aapt2` + `ecj` + `d8` + `zipalign` + `apksigner` (`build.ps1` сам находит все
`src/**/*.java`, пакеты менять безопасно). Готовый decoded APK можно
также собрать внешним Android SDK, а затем прогнать через analyzer и patch
artifact pipeline.
