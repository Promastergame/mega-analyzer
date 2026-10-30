# Использование и флаги

[English](USAGE.md)

Полный справочник флагов: [`FlagiFiles.md`](../FlagiFiles.md)

## Три способа запустить

| Команда | Что получаешь |
| :--- | :--- |
| `analyzer -t app.apk` | **Прямой CLI** — по умолчанию. Печатает результат, пишет отчёты. |
| `analyzer -tui -t app.apk` | **Интерактивный TUI**-визард. |
| `analyzer -web` | **Браузерная панель** на `http://localhost:7474`. |

## Однострочники

```bash
# Анализ APK, все форматы отчётов
analyzer -t app.apk -report all

# Демо без подготовки — реальные находки за секунды
analyzer -t demo/vulnerable-app -report all -sarif

# Быстрый проход vs самый тяжёлый
analyzer -t app.apk -p quick
analyzer -t app.apk -p paranoid -report full

# CI — SARIF для code scanning
analyzer -t app.apk -sarif -o ./analysis_output

# Нативный бинарник (авто-роутинг по расширению тоже работает)
analyzer --scan-native -t libnative.so -o ./out
analyzer -t malware.exe

# Decode → правка smali → Rebuild (без apktool)
analyzer -decode -t app.apk -o ./work --copy-original
analyzer -build  -t ./work  -o ./patched.apk

# Детонация
analyzer -t malware.exe -sandbox --sandbox-duration 120
analyzer -t app.apk -android-sandbox

# Поиск точек патча
analyzer -t app.apk -ml-patch
analyzer -t app.apk -ml-patch -ml-patch-fix
```

## Основные флаги

| Флаг | По умолчанию | Описание |
| :--- | :--- | :--- |
| `-t`, `-target <path>` | — | Папка, APK, DEX, PE, ELF, Mach-O |
| `-o`, `-output <dir>` | `analysis_output` | Папка для отчётов |
| `-p`, `-profile <name>` | `balanced` | `quick` · `balanced` · `deep` · `paranoid` |
| `-report <preset>` | `default` | `short` · `default` · `full` · `all` |
| `-sarif` | выкл | Записать `analysis.sarif` |
| `-json` | выкл | JSON в stdout |
| `-q` | выкл | Тихий режим |
| `-tui` | выкл | Интерактивный TUI |
| `-callgraph` / `-correlations` | выкл | Граф вызовов / корреляции |
| `-web` | выкл | Браузерная панель |

## Профили

| Профиль | Для чего |
| :--- | :--- |
| `quick` | Быстрый первый взгляд |
| `balanced` | Повседневный дефолт |
| `deep` | Граф вызовов, корреляции, тяжёлые проходы |
| `paranoid` | Самый тщательный — для критичных целей |

## CI / GitHub Actions

```bash
analyzer -t app-release.apk -report full -sarif -o results
```

Загружай `results/analysis.sarif` через `github/codeql-action/upload-sarif`. См. [CODE_SCANNING.md](CODE_SCANNING.md).

> Новые кастомные папки `-o` требуют маркер `.omnisec-output`. Action создаёт его автоматически.

## Веб-сканер уязвимостей

```bash
# Единый бинарь: безопасная проверка доступности (ровно один GET)
analyzer --web-scan --web-scan-target https://example.test --web-scan-mode status

# Пассивный аудит одного ответа (без fuzz/payload и проб endpoint'ов)
analyzer --web-scan --web-scan-target https://example.test --web-scan-mode passive

# Полный активный vulnscan — только для своей/разрешённой цели
analyzer --web-scan --web-scan-target https://example.test --web-scan-mode active --i-own-this-target
```

`status` считает сайт здоровым только при HTTP 200, а любой полученный ответ —
доступным. `passive` делает один GET и анализирует заголовки, cookies и тело.
Только `active` запускает crawler/fuzzer и требует `--i-own-this-target`.
Старый `cmd/vulnscan` оставлен как совместимый разработческий wrapper; в релизе
собирается один `analyzer`.

Полный список проверок в [`FlagiFiles.md` §11](../FlagiFiles.md#11-web-vulnerability-scanner--дополнительные-cli-точки-входа-cmd).

## Анализ байткода и нативных бинарей

```bash
# APK / Smali / ASM
analyzer --scan-bytecode -t app.apk -o results

# Более глубокий offline taint/dataflow-проход (цель не запускается)
analyzer --scan-bytecode-deep -t decoded-smali -o results

# PE / ELF / .so: Rust scan-native через библиотечный FFI backend
analyzer --scan-native -t libgame.so -o results
```

`--scan-bytecode*` использует BinZAP для байткода/текстового ASM, а
`--scan-native` — Rust OmniSec для нативных PE/ELF. Названия движков показываются
в отчёте, но пользователь выбирает понятный тип входа.
