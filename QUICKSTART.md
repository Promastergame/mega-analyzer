# Mega-Analyzer — Quick Start

> **English** · [Русский ниже ↓](#mega-analyzer--быстрый-старт)

---

## 🚀 Quick Run

To analyze an APK or DEX file and generate a report, run:

```bash
# Linux / macOS
./analyzer -t my_app.apk -report all

# Windows
analyzer.exe -t my_app.apk -report all
```

- **Interactive TUI**: Add the `-tui` flag to open the terminal-based interactive UI.
- **Web Dashboard**: Run `analyzer -web` to launch the browser-based dashboard on `http://localhost:7474`.

## 📦 Try Bundled Demo (No setup required)

```bash
# Run analysis on the demo vulnerable app
./analyzer -t demo/vulnerable-app -report all -sarif
```

This generates `analysis_output/REPORT.html` (interactive HTML report) and `analysis_output/analysis.sarif` (standard SARIF output for IDEs or viewers).

## ⚙️ Native Engines (OmniSec / Zig ML) — Optional

Core and full-native are two separate binaries built at compile time — not a runtime switch:
- **Core** (what prebuilt releases ship): pure Go, no cgo. It never touches native code, so there's nothing to "fall back" from — the advanced engines (OmniSec/Rust, Zig SIMD ML, GNN) are simply not compiled in.
- **Full native** (built via `cicd.ps1` or cgo build tags): links the Rust/Zig engines via cgo. This binary **requires** the `.dll` (Windows) / `.so` (Linux) / `.dylib` (macOS) files next to it (or on `PATH` / `LD_LIBRARY_PATH`) — without them it will not start. There is no silent fallback.

See [docs/FAQ.md](docs/FAQ.md#core-build-vs-full-native--whats-the-difference) and [docs/BUILD.md](docs/BUILD.md) for details.

## 🧰 Native APK decode and build

`decode` and `build` use built-in implementations by default, including edited Smali, supported resources, alignment and signing. No Java, Android SDK, aapt2, android.jar or d8 is needed for Smali/DEX projects. Build accepts a directory or a project ZIP; the web UI offers **Build APK**. Java/Kotlin/Gradle source compilation and unsupported resource features return explicit errors.

```
analyzer decode app.apk -o decoded --standalone
analyzer build decoded -o rebuilt.apk
analyzer build project.zip -o app.apk
go build -tags noembed ./pkg/cmd/analyzer    # omit embedded compatibility tools
```

External build compatibility backends require `--allow-external-tools` explicitly. See [the native APK example](examples/native-apk/README.md) and [build limitations](docs/DECOMPILER.ru.md).

## 📖 Documentation & Guides

- [FlagiFiles.md](FlagiFiles.md) — Exhaustive flag and CLI configuration reference.
- [README.md](README.md) — Full features tour and architectural overview.

---

# Mega-Analyzer — Быстрый старт

> [English above ↑](#mega-analyzer--quick-start) · **Русский**

---

## 🚀 Быстрый запуск

Для анализа APK или DEX файлов и генерации отчета выполните:

```bash
# Linux / macOS
./analyzer -t my_app.apk -report all

# Windows
analyzer.exe -t my_app.apk -report all
```

- **Интерактивный TUI**: Добавьте флаг `-tui` для работы во встроенном консольном интерфейсе.
- **Браузерная панель**: Запустите `analyzer -web` для открытия веб-интерфейса на `http://localhost:7474`.

## 📦 Демо из коробки (без подготовки)

```bash
# Запуск анализа тестового уязвимого приложения
./analyzer -t demo/vulnerable-app -report all -sarif
```

Это создаст интерактивный HTML-отчет в `analysis_output/REPORT.html` и файл в формате SARIF `analysis_output/analysis.sarif` для интеграции с IDE.

## ⚙️ Нативные движки (OmniSec / Zig ML) — Опционально

Core и full-native — это два разных бинарника, выбираются при компиляции, а не в рантайме:
- **Core** (то, что поставляют готовые релизы): чистый Go, без cgo. Он вообще не трогает нативный код, поэтому переключаться не с чего — расширенные движки (OmniSec/Rust, Zig SIMD ML, GNN) просто не скомпилированы.
- **Full native** (собирается через `cicd.ps1` или cgo build-теги): подключает движки Rust/Zig через cgo. Такой бинарник **требует** наличия `.dll` (Windows) / `.so` (Linux) / `.dylib` (macOS) рядом с собой (или в `PATH` / `LD_LIBRARY_PATH`) — без них он не запустится. Тихого фолбэка нет.

Подробности: [docs/FAQ.ru.md](docs/FAQ.ru.md#core-vs-full-native--в-чём-разница) и [docs/BUILD.md](docs/BUILD.md).

## 🧰 Декомпиляция и сборка APK без SDK

`decode` и `build` по умолчанию используют встроенный код: Smali→DEX, поддерживаемые ресурсы, выравнивание и подпись. Для проектов Smali/DEX не нужны Java, Android SDK, aapt2, android.jar и d8. Сборка принимает каталог или ZIP проекта; в браузере доступен режим «Собрать APK». Исходники Java/Kotlin/Gradle и неподдерживаемые ресурсы приводят к понятной ошибке.

```
analyzer decode app.apk -o decoded --standalone
analyzer build decoded -o rebuilt.apk
analyzer build project.zip -o app.apk
go build -tags noembed ./pkg/cmd/analyzer    # без вложенных инструментов совместимости
```

Для внешних средств сборки нужен явный `--allow-external-tools`.
[Пример проекта](examples/native-apk/README.md), [возможности и ограничения](docs/DECOMPILER.ru.md).

## 📖 Документация и руководства

- [FlagiFiles.md](FlagiFiles.md) — Исчерпывающий справочник параметров и конфигурационных флагов.
- [README.ru.md](README.ru.md) — Полный обзор возможностей и архитектурных особенностей на русском языке.
