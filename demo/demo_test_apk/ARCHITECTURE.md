# Mega Patch Lab — архитектура по специализациям

Контролируемая Java-фикстура для проверки APK/Smali-патчера (`pkg/ml`).
Каждый пакет — одна «специализация» с прицелом под конкретные стратегии
патчера. Все серверные адреса — loopback или `example.test`, реальных
сервисов и секретов нет.

```
src/com/megademo/testapp/
├── MainActivity.java        # hub: дергает все специализации
├── server/                  # СЕРВЕР — HTTP-клиенты к фикстуре :5555
│   ├── EconomyClient.java       # GET /economy/coins -> {"coins":N}
│   ├── SubscriptionClient.java  # GET /subscription/status -> {"active":bool}
│   └── AgeVerificationClient.java # GET /age/verify -> {"adult":bool}
├── coins/                   # МОНЕТКИ — локальная экономика и время
│   ├── WalletService.java       # int-геттеры: getCoins, getGemCost (цена!)
│   ├── WideWalletService.java   # long/double: getCoinsLong (wide!)
│   └── CooldownService.java     # таймеры: getCooldownRemaining (ноль!)
├── premium/                 # ПОДПИСКА — гейты доступа и токены
│   ├── SubscriptionGate.java    # AND-funnel hasPremium + boxed Boolean
│   └── TokenSessionService.java # String-токен, скоупы, endpoint-строка
├── ads/                     # РЕКЛАМА — псевдо-SDK
│   ├── PseudoAdController.java  # shouldShowAd / showRewardedAd (AdRemove!)
│   └── PseudoAdView.java        # Canvas-креатив + assets/pseudo_ad.svg
├── auth/                    # АВТОРИЗАЦИЯ — локальные гейты
│   ├── AuthGate.java            # сессия по токену (control-фикстура)
│   ├── AgeGate.java             # server && remembered (AND-funnel 18+)
│   ├── FeatureGate.java         # флаги + premium fallback
│   └── IntegrityGate.java       # Debug.isDebuggerConnected
├── nativelab/               # NATIVE — JNI-граница
│   └── NativeLabBridge.java     # demo_lab.so, канал 127.0.0.1:7777
└── react/                   # РЕАКТ БУНДЛ — Java-зеркало JS-графа
    └── ReactAgeBridge.java      # isAgeApproved == JS canOpenMatureSection
```

`react_native/index.android.bundle` — читаемый JS-граф: endpoint, JSON-парсер,
native bridge и boolean-gate в одном файле (bundle-aware поиск).

## Карта «специализация → стратегия патчера»

| Специализация | Точка | Стратегия |
|---|---|---|
| SERVER | `*Client` URL-строки | `const_replace` (string-pool only, layout не едет) |
| МОНЕТКИ int | `getCoins` | `numeric_max_injection` → MAX_INT |
| МОНЕТКИ цена | `getGemCost` | `price_zero_injection` → 0 (приоритет выше MAX!) |
| МОНЕТКИ wide | `getCoinsLong()J` | `wide_max_injection` → const-wide MAX |
| МОНЕТКИ время | `getCooldownRemaining` | `cooldown_reset_injection` → 0 («готово») |
| ПОДПИСКА AND | `SubscriptionGate.hasPremium` | `entry_gate` (нопинг первого гейта, size-neutral) |
| ПОДПИСКА объекты | `isPremiumBoxed`, `getAuthToken` | `object_return_injection` (FALSE→TRUE, `""`) |
| РЕКЛАМА | `shouldShowAd` | `TargetAdRemove` детектор + `return_false` |
| АВТОРИЗАЦИЯ | `isAuthenticated`, `canOpenMatureSection` | `constant_injection` (хирургия у return) |
| INTEGRITY | `isTrustedDevice` | `invoke_result_hijack` (invoke жив, move-result форс) |
| NATIVE | `isAvailable` | whole-body стаб (граница JNI) |
| РЕАКТ БУНДЛ | `ReactAgeBridge` / bundle | `const_replace` endpoint + boolean-gate |

## Контракт локальных тестовых сервисов

Один fixture-сервис на `127.0.0.1:5555` (см. `fixture-server/README.md`):

```text
/economy/coins       -> {"coins":1000}
/subscription/status -> {"active":true}
/features            -> {"premium":true}
/age/verify          -> {"adult":true,"age":21}
```

Нативный lab bridge — отдельный порт `127.0.0.1:7777`. Реализации `.so` нет:
`NativeLabBridge` безопасно деградирует без библиотеки.

## Что должен находить патчер

- app-owned boolean gates (`auth/`, `premium/`);
- numeric value providers (`coins/`: int + wide);
- price/cost providers (`getGemCost`);
- HTTP URL и endpoint-роли (`server/`, `react/`, `premium/TokenSessionService`);
- purchase/subscription mapping;
- ad decision point + креатив (Canvas и SVG);
- native load и JNI boundary;
- constant и branch candidates с сохранением тела.

Исходники — только Android platform API и Java 8, без Gradle/AndroidX/Kotlin.
Сборка — ручной toolchain (`aapt2` + `ecj` + `d8` + `zipalign` + `apksigner`):

```bash
analyzer -t demo/demo_test_apk -report all
```

> Исторические отчеты `verify*_report/` ссылаются на старую плоскую раскладку
> (`smali/com/megademo/testapp/*.smali`) — это снапшоты до переезда по пакетам.
