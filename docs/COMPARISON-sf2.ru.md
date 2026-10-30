# Shadow Fight 2 Special Edition - Взлом vs Оригинал

[English](COMPARISON-sf2.md)

| | Оригинал | Взлом |
| :--- | :--- | :--- |
| Файл | Shadow_Fight_2_SE_v1.0.10.apk | shadow-fight-2-special-edition-1.0.12-vzlom.apk |
| versionName | 1.0.10 | 1.0.12 |
| Размер | 147 MB | 125 MB |
| Подпись (файл) | META-INF/CERT.RSA | META-INF/APKEASYT.RSA (APK Easy Tool) |
| Ключ подписи (SHA-256) | A4:0D:A8:0A:59:D1:70:CA... | A4:0D:A8:0A:59:D1:70:CA... (ТОТ ЖЕ) |
| Издатель ключа | CN=Android, O=Android, android@android.com | тот же (публичный AOSP test-key) |
| DEX | classes.dex | classes.dex + classes2.dex (добавлен) |
| Даты в архиве | 2020-08-20 | 2008-02-29 (сброшены) |

## Что добавил взлом
- **libtdmmod.so (602 KB)** - инжектированная нативная библиотека **TDM Mod Menu**:
  экспортирует `Java_tdm_ahz_modmenu_FloatingModMenuService_*`, использует
  **Cydia Substrate** (`SubstrateHookFunction`) для хуков и патчинга игры в памяти.
- **classes2.dex** - Java/Kotlin-загрузчик плавающего мод-меню.
- Разрешение **SYSTEM_ALERT_WINDOW** (оверлей поверх других окон - для меню читов).
- POST_NOTIFICATIONS, AD_ID, Crashlytics, обновлённый Google Play Billing, Kotlin-runtime.
- libil2cpp.so вырос 30.3 -> 38.5 MB (пропатченная игровая логика).

## Что взлом убрал
- **libgpg.so** (Google Play Games) - обход проверки владения/лицензии.
- Разрешения INSTALL_PACKAGES, READ/WRITE_EXTERNAL_STORAGE.
- vending.INSTALL_REFERRER / derived.apk.id / splits.

## Уязвимости и риски
1. **Подпись публичным AOSP test-key (обе версии!)** - приватный ключ общедоступен,
   подпись НЕ даёт аутентичности; кто угодно может подменить код и переподписать. (CWE-321)
2. **Инжекция нативного мод-меню с inline-хуками (взлом)** - сторонний код с полными
   правами приложения, патчит игру в памяти; может воровать данные / грузить payload. (CWE-506)
3. **Оверлей SYSTEM_ALERT_WINDOW** - поверхность для tapjacking / фишинга поверх других приложений.
4. **Признаки репака** - переподпись APK Easy Tool + сброшенные даты 2008-02-29 + добавленный classes2.dex.
5. Скорее всего обойдены проверки лицензии/покупок (удалён Play Games, пропатчен il2cpp).

## Что скан beta.10 показал по-разному (ключевое)
- `mod_menu_injection`:  оригинал 0  ->  взлом 1   (НОВЫЙ детектор)
- `malware`:             0  -> 1
- `STEALER_INDICATOR`:   0  -> 1
- `SSL_PINNING`:         6  -> 15
- `SECURITY`:           24  -> 51
- `TRIAL_EXPIRY`:        3  -> 13
