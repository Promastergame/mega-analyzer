# FlagiFiles — Справочник по CLI и сборке

> **Note (English): this reference is currently Russian-only; an English version is planned — see [docs/USAGE.md](docs/USAGE.md) for a shorter English flag cheat-sheet in the meantime.**

> Шпаргалка с командами сборки, CLI-флагами и переменными окружения для **Mega-Analyzer v1.0.0-beta.1**.
> Это **не скрипт автоматизации** — просто быстрый справочник для копирования команд.
>
> **ВАЖНО:** Готовые наборы флагов для APK находятся в файле `bin/analyzer.flags.txt`.

---

## Содержание

1. [Сборка — Rust (omnisec-cli)](#1-сборка--rust-omnisec-cli)
2. [Сборка — Go (analyzer.exe)](#2-сборка--go-analyzerexe-и-скрипты-автоматизации)
3. [Тесты](#3-тесты)
4. [Флаги Rust CLI (omnisec-cli)](#4-флаги-rust-cli-omnisec-cli)
5. [Флаги Go CLI (analyzer.exe)](#5-флаги-go-cli-analyzerexe)
   - [Основные флаги](#основные-флаги)
   - [Артефакты](#артефакты)
    - [Machine-Code (PE/ELF/SO)](#machine-code-peelfso)
   - [Top-5 Insights](#top-5-insights)
    - [APK Decode / Rebuild](#apk-decode--rebuild--smali-analysis)
   - [OBB / Data / Cache Scanner](#obb--data--cache-scanner)
   - [Cache Security Analyzer](#cache-security-analyzer)
   - [ML-Apli-Cache](#ml-apli-cache)
   - [Sandbox и Detonation](#sandbox-и-detonation)
   - [Windows-Native Sandbox](#windows-native-sandbox)
    - [Private Server Toolkit](#private-server-toolkit--traffic-fuzzing)
   - [Lab DNS Server](#lab-dns-server)
   - [ML Assistant](#ml-assistant)
   - [ML Patcher](#ml-patcher)
   - [JS Bundle Patcher & Deobf](#js-bundle-patcher--deobf)
   - [Deobfuscation](#deobfuscation)
   - [Crack Point Discovery](#crack-point-discovery)
   - [GNN Classification](#gnn-classification)
   - [ProGuard Recovery](#proguard-recovery)
   - [Game Mode и геймификация](#game-mode-и-геймификация)
   - [MobSF-модули](#mobsf-модули)
   - [Medium-Priority Analyzers](#medium-priority-analyzers)
   - [Утилиты](#утилиты)
6. [Переменные окружения](#6-переменные-окружения)
7. [Примеры — Rust CLI](#7-примеры--rust-cli)
8. [Примеры — Go CLI](#8-примеры--go-cli)
9. [Elixir/OTP сервер](#9-elixirotp-сервер)
10. [Build tags / Rust FFI / старое железо](#10-build-tags--rust-ffi--старое-железо)
11. [Web Vulnerability Scanner & Дополнительные CLI-точки входа](#11-web-vulnerability-scanner--дополнительные-cli-точки-входа-cmd)

---

## 1. Сборка — Rust (omnisec-cli)

```bash
# Debug build
cd rust
cargo build

# Release build
cargo build --release

# Запуск из исходников
cargo run --release --bin omnisec-cli -- <command> <args>

# Установка системно
cargo install --path rust/crates/omnisec-cli
```

---

## 2. Сборка — Go (analyzer.exe) и Скрипты Автоматизации

### Прямая компиляция Go-клиента

**Предпочтительно — запускать готовый скрипт из корня проекта:**

```powershell
.\build.ps1                 # Windows: GNN + Rust DLL + bin\analyzer.exe
```

```bash
sh ./build.sh                   # Linux/macOS: GNN + runtime library + bin/analyzer
VERSION=1.0.0-beta.1 sh ./build.sh  # задать версию явно
```

**Windows: стандартная сборка с GNN.** Собирайте именно в `bin\\analyzer.exe` и
запускайте этот же файл. Обычный `go build` без build tag создаёт core-вариант
без GNN и при `-gnn-model` выводит предупреждение.

```powershell
# 1. Один раз (и после изменения Rust GNN): собрать DLL
cd rust
cargo build --release -p omnisec-ml-gnn
cd ..

# 2. GNN-сборка analyzer.exe. Zig нужен как совместимый C-компилятор для CGO.
$env:CGO_ENABLED = "1"
$env:CC = "zig cc"
go build -tags=omnisec_ml_gnn -trimpath `
  -ldflags "-X main.Version=1.0.0-beta.1 -X main.BuildDate=2026-07-27" `
  -o .\bin\analyzer.exe .\pkg\cmd\analyzer

# 3. DLL обязана лежать рядом с EXE
Copy-Item .\rust\target\release\omnisec_ml_gnn.dll .\bin\ -Force
```

Проверка результата:

```powershell
Test-Path .\bin\omnisec_ml_gnn.dll  # True
.\bin\analyzer.exe -t .\app.apk -gnn-model .\rust\gnn_weights.gnnbuf
```

```bash
# Core-сборка без нативных DLL и без GNN (только когда это намеренно нужно)
go build -trimpath -ldflags "-X main.Version=1.0.0-beta.1 -X main.BuildDate=2026-07-27" -o analyzer.exe ./pkg/cmd/analyzer

# Linux AMD64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.Version=1.0.0-beta.1 -X main.BuildDate=2026-07-08" -o OmniSec ./pkg/cmd/analyzer

# Linux ARM 32-bit (старые Android)
GOOS=linux GOARCH=arm CGO_ENABLED=0 go build -ldflags "-X main.Version=1.0.0-beta.1 -X main.BuildDate=2026-07-08" -o OmniSec-arm ./pkg/cmd/analyzer

# Linux ARM64 (современные Android)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-X main.Version=1.0.0-beta.1 -X main.BuildDate=2026-07-08" -o OmniSec-arm64 ./pkg/cmd/analyzer
```

**Cross-compile через PowerShell (Windows):**

```powershell
# ARM 32-bit
$env:GOOS="linux"; $env:GOARCH="arm"; $env:CGO_ENABLED="0"
go build -ldflags "-X main.Version=1.0.0-beta.1 -X main.BuildDate=2026-07-08" -o OmniSec-arm ./pkg/cmd/analyzer

# ARM64
$env:GOOS="linux"; $env:GOARCH="arm64"; $env:CGO_ENABLED="0"
go build -ldflags "-X main.Version=1.0.0-beta.1 -X main.BuildDate=2026-07-08" -o OmniSec-arm64 ./pkg/cmd/analyzer

# Сброс переменных
Remove-Item Env:GOOS; Remove-Item Env:GOARCH
```

### Скрипты автоматизации пайплайна (Корневая папка)

#### `cicd.ps1` — Локальный CI/CD оркестратор
Запуск проверок окружения, линтинга, тестирования, сборки и упаковки дистрибутивов.
```powershell
.\cicd.ps1 -Stage All              # Запуск полного пайплайна
.\cicd.ps1 -Stage Lint             # Только качество кода (cargo fmt, clippy, go fmt, zig fmt)
.\cicd.ps1 -Stage Test             # Только прогон юнит-тестов (Rust, Go, Zig)
.\cicd.ps1 -Stage Build            # Только финальная релизная сборка компонентов
.\cicd.ps1 -Stage Package          # Упаковка дистрибутива в ZIP-архив и расчёт хэшей SHA-256
```

**Параметры и флаги автоматизации:**
* `-SkipLint` — пропустить стадию проверки форматирования/clippy во время сборки.
* `-SkipTest` / `-SkipTests` — полностью пропустить этап тестирования при запуске полного пайплайна.
* `-SkipElixir` — отключить компиляцию сервера Elixir.
* `-SkipZig` — отключить компиляцию ML Runtime и GUI на Zig.
* `-Clean` — быстрая очистка бинарных артефактов (директории `bin/`, `dist/` и выходные файлы Zig).
* `-CleanRust` — глубокая очистка кэша сборки Rust (запускает `cargo clean` в `rust/`).
* `-Linux` — включить режим сборки под Linux (кросс-компиляция Go/Rust, пропуск Windows GUI).
* `-TargetOS <string>` — задать целевую ОС вручную (`windows` или `linux`, по умолчанию определяется по хосту).
* `-Version <string>` — задать версию сборки вручную (по умолчанию `1.0.0-beta.1`).

---

## 3. Тесты

```bash
# Go
go test ./pkg/...
go test ./pkg/internal/analyzer ./pkg/internal/pipeline ./pkg/internal/piracy ./pkg/internal/parser
go vet ./pkg/...

# Rust
cd rust
cargo test
cargo test --release
cargo clippy -- -D warnings
cargo fmt --check
```

---

## 4. Флаги Rust CLI (omnisec-cli)

### Команды Rust CLI (`omnisec-cli`)

| Команда | Описание |
|---|---|
| `info <target>` | Автодетект формата бинарника (PE/ELF) и выгрузка базовых метаданных |
| `disasm <target>` | Линейный дизассемблер исполняемых секций (`--limit N`, `--section <name>`) |
| `scan <target>` | Нативный аудит безопасности PE/ELF/.so, поиск опасных API, паттернов и графовых анкоров уязвимостей ML-Aetrium HDC (`--min-severity <lvl>`, `--aetrium-anchors <path>`) |
| `anchors forge` | Сгенерировать синтетическую БД графовых анкоров уязвимостей (`--output <path>`, `--seed N`, `--examples-per-kind N`) |
| `anchors inspect` | Инспекция существующей БД анкоров `.anchor.json` |
| `debug <target>` | Интерактивный CLI-отладчик машинного кода (`--entry <0xAddr>`) |
| `version` | Вывод версии и метрик сборки Rust |

### Глобальные флаги Rust CLI

| Флаг | Описание |
|---|---|
| `-v`, `--verbose` | Увеличить детализацию логов (можно повторить `-vv`, `-vvv`) |
| `--json` | Вывод результатов в структурированном JSON-формате |

### Обучение GNN-модели (`gnn-train`)

```bash
# Обучение на собранном датасете из ~/.analyzer/gnn-dataset/
cargo run --release -p omnisec-ml-gnn --bin gnn-train -- --dataset ~/.analyzer/gnn-dataset --epochs 150 --out gnn_weights.json
```

| Флаг | Описание |
|---|---|
| `--dataset <file.jsonl\|dir>` | Входной датасет графов: файл `.jsonl` или каталог с ними (если не указан — `dex-synth`, синтетический генератор; ещё вариант `synth`) |
| `--out <path>` | Файл вывода весов JSON (default: `gnn_weights.json`) |
| `--epochs <N>` | Количество эпох обучения (default: 80) |
| `--lr <float>` | Learning rate (default: 0.001) |
| `--n-per-class <N>` | Количество графов на класс при генерации синтетического датасета (default: 400) |
| `--seed <N>` | Seed генератора случайных чисел (default: 1337) |
| `--confirmed-only` | Использовать только записи датасета с `label_confirmed=true` |
| `--mix-synth <N>` | **Файнтюн на реальных данных:** подмешать N графов/класс из синтетического генератора в train (20% из них — в val, чтобы macro_f1 мерил удержание классов). Реальный val остаётся нетронутым. Требует `--dataset <путь>` |
| `--no-class-weighting` | Отключить inverse-frequency веса классов (при сильном перекосе в benign их включение заставляет модель игнорировать мажоритарный класс) |

Пример файнтюна (см. историю: чистые игры → benign, MOD-MENU APK → repack-marker):

```bash
gnn-train --dataset F:/game/gnn_train_v3 --mix-synth 1200 --no-class-weighting --epochs 80 --out weights_v3.json
```

### Сбор датасета для файнтюна (`gnnprobe`)

Утилита только GNN-стадии: smali-каталог → CFG → инференс, без pattern-пайплайна (~40 сек на игру). Собирается вместе с мостом: `go build -tags=omnisec_ml_gnn -o bin/gnnprobe.exe ./pkg/cmd/gnnprobe`.

```bash
# Чистое приложение (аналитик подтвердил отсутствие пиратства):
gnnprobe F:/game/app_smali rust/gnn_weights.json --dataset-out ds_app.jsonl --max-graphs 2000 --benign-confirmed
# Подтверждённый позитив (инжектированный код мода, класс repack-marker):
gnnprobe F:/game/inject_stage rust/gnn_weights.json --label 5 --dataset-out ds_inject.jsonl
```

| Флаг | Описание |
|---|---|
| `<smali_dir> <weights.json>` | Позиционные: smali-дерево и файл весов |
| `--dataset-out <file.jsonl>` | Экспорт графов в формате `pkg/ml/gnndataset` (совместим с `gnn-train`) |
| `--max-graphs <N>` | Сэмплинг при экспорте: половина — топ по confidence не-benign («хард-негативы»), половина — случайные benign |
| `--benign-confirmed` | Все графы получают метку benign с `label_confirmed=true` (исходное предсказание сохраняется в `notes`) |
| `--label <N>` | Принудительная метка для всех графов с `label_confirmed=true` (например `5` = repack-marker) |
| `NOINFER=1` (env) | Пропустить инференс — только parse/CFG/граф (диагностика) |

---

## 5. Флаги Go CLI (analyzer.exe)

> **TUI vs CLI:** по умолчанию анализ запускается **сразу в CLI** — печатает результат и пишет отчёты. Никаких дополнительных флагов для этого не нужно.
> Интерактивный TUI-визард включается явным флагом `-tui`.

```bash
analyzer.exe -t app.apk        # Прямой CLI-анализ (поведение по умолчанию)
analyzer.exe -tui -t app.apk   # Интерактивный TUI-визард
```

### Основные флаги

| Флаг | Описание |
|---|---|
| `-target`, `-t <path>` | Папка, APK или DEX-файл |
| `-output`, `-o <dir>` | Папка для отчётов (default: `analysis_output`) |
| `-workers`, `-w <N>` | Воркеры (default: кол-во CPU ядер) |
| `-timeout <seconds>` | Таймаут (default: 300) |
| `-profile`, `-p <name>` | Профиль: `quick` \| `balanced` \| `deep` \| `paranoid` |
| `-report <preset>` | Формат: `short` \| `default` \| `full` \| `all` |
| `-max-file-size <MB>` | Лимит кода в MB (0 = профиль) |
| `-max-resource-size <MB>` | Лимит ресурсов в MB (0 = профиль) |
| `-callgraph` | Построить граф вызовов |
| `-correlations` | Корреляции между файлами |
| `-deep-scan` | Глубокое сканирование |
| `-quiet`, `-q` | Минимальный вывод |
| `-no-color` | Без цветов |
| `-tui` | Открыть интерактивный TUI-визард (по умолчанию — прямой CLI) |
| `-json` | JSON в stdout |
| `-no-html` | Без HTML-отчёта |
| `-no-json` | Без JSON-отчёта |
| `-sarif` | Записать `analysis.sarif` для GitHub/GitLab/Sonar-style code scanning (локальный JSON, без облака) |
| `-save_log`, `-save-log` | Сохранить полный консольный вывод сессии в файл |
| `-log-output`, `-save-log-output <file>` | Куда писать лог (default: `analysis_log.<ext>` в рабочей папке) |
| `-format <txt\|ansi\|md>` | Формат лога для `-save_log`: txt (без ANSI-цветов), ansi (с цветами), md |
| `-clean-output` | Очистить папку перед отчётами |
| `-keep-temp` | Не удалять временную папку |
| `-dex-only` | Только DEX (пропустить ресурсы) |
| `-max-files <N>` | Лимит файлов (0 = без лимита) |
| `-version`, `-v` | Версия |
| `-help`, `-h` | Помощь |
| `-list-profiles` | Список профилей |

---

### Кастомные профили флагов

Вы можете настроить и использовать **любые** свои профили. При передаче значения в `-profile <имя>` (или `-p <имя>`), анализатор ищет конфигурационный файл в следующем порядке:
1. Файл с именем `analyzer.flags.<имя>.txt` в текущей директории.
2. Если передан прямой путь к файлу (например, `F:\my_flags.txt`), он будет загружен напрямую.

Файлы профилей содержат обычные CLI-флаги, разделенные пробелами или переносами строк. Флаги из командной строки имеют приоритет над флагами из файла профиля.

*Пример использования:*
1. Создайте файл `analyzer.flags.myconfig.txt`.
2. Запустите: `analyzer.exe -p myconfig -t app.apk`.

---

### False Positive / Library Triage

Mega-Analyzer не делает тупой skip библиотек: SDK/library-код анализируется, но FP-filter отделяет подтверждённые риски от boilerplate шума. Сильные сигналы в библиотеках (CVE/CWE, secrets, weak crypto, dynamic loading, command execution, unsafe WebView) остаются видимыми.

| Флаг | Описание |
|---|---|
| `-fp-strict` | Показывать только confirmed app/SDK risks, остальное уводить в suppressed log |
| `-fp-show-suppressed` | Сохранить полный suppressed-noise log в JSON/HTML/SARIF triage data |
| `-fp-min-score <N>` | Минимальный final score FP-фильтра (`-1` = профильный default) |
| `-fp-suppressed-limit <N>` | Лимит suppressed findings (`-1` = default, `0` = без лимита) |

---

### Data-Flow, Content-Cache & DevMega Stream

| Флаг | Описание |
|---|---|
| `-enable-content-cache` | Включить persistent content-addressed cache движок для методов (default: `false`, см. `-enable-content-cache` — выключен по умолчанию: огромные каталоги кэша тормозят старт пайплайна) |
| `-content-cache-dir <path>` | Директория дискового кэша (default: `.analyzer-cache/content`) |
| `-content-cache-max-disk-mb <N>` | Максимальный объём кэша на диске в МБ (default: `2048`) |
| `-enable-data-flow` | Включить summary-based IFDS/IDE Taint & Data-Flow движок (default: `true`) |
| `-data-flow-max-methods <N>` | Лимит методов для анализа data-flow (default: `200000`) |
| `-data-flow-max-findings <N>` | Лимит выявляемых data-flow цепочек (default: `2000`) |
| `-net-json-events` | Трансляция структурированных сетевых событий `@@NETEVENT@@` на stdout для сетевой панели DevMega |
| `-net-remote-edit` | Управление перехватом и модификацией пакетов из удалённого клиента DevMega вместо терминала |
| `-net-filter <expr>` | Фильтр отображения перехваченного трафика (поля: proto, ip, port, len, dir, sni, payload) |
| `-net-flows` | Сборка пакетов в двунаправленные потоки с классификацией протокола и извлечением TLS SNI |

---

### Web UI и REST API

Локальный веб-сервер и REST API для интеграций, автоматизации и drag-and-drop анализа файлов в браузере.

| Флаг | Описание |
|---|---|
| `-web` | Запустить локальный веб-интерфейс (Web UI) для drag-and-drop анализа файлов в браузере |
| `-web-port <port>` | Порт для Web UI сервера (default: `7474`) |
| `-web-ui-token <token>` | Фиксированный токен авторизации (pairing token) для Web UI API (default: генерируется случайный при запуске) |
| `-api` | Запустить встроенный REST API сервер из этого же исполняемого файла |
| `-api-port <port>` | Порт для REST API сервера (default: `5000`) |

---

### APK Patch Editor (GUI)

Нативный высокопроизводительный GUI-редактор APK, написанный на Zig с прямым Win32 UI (без тяжелого Electron/Java).

| Флаг / Команда | Описание |
|---|---|
| `-edit`, `-apk-editor` | Запустить нативный графический редактор Zig APK Patch Editor GUI для целевого APK |
| `analyzer edit <app.apk>` | Позиционная команда для быстрого открытия APK в редакторе |

---

### Нативный отладчик (Machine-Code Debugger)

Интерактивный отладчик машинного кода для прямого анализа PE, ELF, DLL и SO бинарников.

| Флаг | Описание |
|---|---|
| `-debugger` | Запустить интерактивный пошаговый отладчик машинного кода (передайте путь к бинарнику через `-t`) |
| `-debug-entry <addr>` | Переопределить начальную точку входа (Entry Point) для отладчика (в hex `0x401000` или decimal) |

---

### Артефакты

Извлечение НЕ-Smali/НЕ-XML файлов (картинки, 3D, `.so`, аудио, видео, шрифты) в HTML-отчёт:

| Флаг | Описание |
|---|---|
| `-artifacts` | Включить режим артефактов |
| `-allow-export` | Показать кнопки Export в HTML |
| `-artifacts-max-mb <N>` | Лимит на один файл (default: 10 MB) |
| `-artifacts-budget <N>` | Общий лимит embedded payload (default: 200 MB) |
| `-no-image-blur` | Не размывать чувствительные картинки |

---

### Media Forensics

Расширенный анализ медиафайлов (картинки, аудио, PDF) на предмет стеганографии, полиглотов и извлечения полезных нагрузок.

| Флаг | Описание |
|---|---|
| `-enable-media` | Включить глубокий анализ медиафайлов (Polyglot, Steganography, GPS Exif) |
| `-extract-ps1` | Сгенерировать PowerShell-скрипт (`extract_hidden_payloads.ps1`) для распаковки скрытых регионов |
| `-media-scan` | Включить анализ медиафайлов (стеганография, извлечение GPS, поиск payload'ов) |
| `-media-payload <str>` | Внедрить payload в метаданные медиафайла (например, строку SQLi) |
| `-media-stego <path>` | Путь к файлу, который нужно скрыть внутри медиафайла (дописывается в конец, EOF) |
| `-media-scrub` | Очистить все метаданные медиафайлов (удалить GPS, EXIF) |
| `-media-recursive-polyglot` | Если внутри медиафайла найден полиглот APK/DEX, передать его обратно в основной анализатор |

---

### Machine-Code (PE/ELF/SO)

Прямой режим разбора нативных бинарников без APK-pipeline:

| Флаг | Описание |
|---|---|
| `-scan-native` | Разобрать target как нативный PE/ELF/EXE/DLL/SO бинарь |
| `-scan-native-reveal-secrets` | Показать полные (немаскированные) значения embedded-секретов в отчёте (по умолчанию — маскируются) |
| `-scan-bytecode` | Анализировать APK/Smali/текстовый ASM |
| `-scan-bytecode-deep` | Добавить offline taint/dataflow-анализ байткода без запуска цели |

Авто-определение по расширению: `.so`, `.dll`, `.exe`, `.elf`, `.dylib`, `.bin`, `.o`, `.a`, `.sys`.  
Артефакты: `<output>/machine_code/MACHINE_CODE.md` и `machine_code.json`.

---

### Top-5 Insights

Sidecar-анализаторы в `<output>/insights/`:

| Флаг | Описание |
|---|---|
| `-top5` | Включить JNI + Privacy + Graph для APK/DEX |
| `-jni-bridge` | Java/DEX ↔ Native JNI Boundary Analyzer |
| `-privacy` | Mobile Privacy Analyzer |
| `-graph-explorer` | Interactive Graph Explorer (включает JNI + Privacy) |
| `-version-diff`, `-diff` | Сравнить две версии APK/директорий |
| `-diff-old <path>` | Старый APK/директория для `--version-diff` |
| `-diff-new <path>` | Новый APK/директория для `--version-diff` |
| `-firmware` | Firmware/IoT Analyzer для `.bin/.img/archive/rootfs` |

---

### APK Decode / Rebuild / Smali Analysis

> **ВАЖНО о `-decode`:**
> - **Без `-decode` (стандартный скан `analyzer.exe -t app.apk`):** Анализатор не распаковывает Smali-файлы на диск. Байкод `.dex` анализируется **напрямую в памяти** через быстрый Rust-декодер (`omnisec_loader_dex`), что обеспечивает максимальную скорость (до 50-100x быстрее).
> - **С флагом `-decode`:** Выполняет полное декодирование APK в папку (как `apktool d`), распаковывает текстовые `.smali` файлы и ресурсы, и активирует **прямой анализ текстового Smali-кода** движком аналитика.

**Decode** — разобрать APK в директорию и включить текстовый Smali-анализ:

| Флаг | Описание |
|---|---|
| `-decode` | Декодировать APK в директорию и запустить анализ текстового Smali-кода |
| `-no-resources` | Пропустить декодирование ресурсов |
| `-no-smali` | Пропустить конвертацию DEX → Smali |
| `-no-headers`, `-no-smali-header` | Не добавлять метаданные/комментарии `# Disassembled from DEX` в Smali файлы (по умолчанию отключены, чистый Smali) |
| `-copy-original` | Сохранить оригинальный META-INF |
| `-framework-dir <path>` | Директория фреймворков для ресурсов |
| `-dex-backend <auto\|native>` | Встроенный Go-декодер DEX→Smali; оба значения используют нативный движок с поклассовым кэшем (default: `auto`) |
| `-class-cache` | Кэшировать native DEX→Smali поклассово в `.mega-analyzer-cache.db` (default: `true`; отключение: `-class-cache=false`) |

**Build/Rebuild** — собрать APK обратно (как `apktool b`):

| Флаг | Описание |
|---|---|
| `-rebuild`, `-r` | Пересобрать APK из декомпилированной папки |
| `-build`, `-b` | Alias для `--rebuild` |
| `-no-sign` | Пропустить подпись APK |
| `-no-align` | Пропустить ZIP-выравнивание |
| `-preserve-signature` | Экспериментально: сохранить оригинальные META-INF/signing blocks без переподписи (валидно только если подписанные байты не менялись; иначе подпись инвалидна) |
| `-ks <path>` | Keystore (JKS) для подписи rebuilt APK через apksigner; пусто = сгенерированный debug-ключ (unknown publisher, стор отклонит) |
| `-ks-alias <name>` | Alias ключа внутри `-ks` (пусто = default хранилища) |
| `-compression-mode <fast\|balanced\|best>` | Режим ZIP-сжатия при сборке (default: `fast`). `fast` — BestSpeed + STORE для уже сжатых форматов >256KB; `best` — BestCompression |
| `-spool-threshold-mb <N>` | Спулить ZIP-записи больше N MB во временные файлы вместо RAM (0 = default 128MB) |
| `-smali-incremental` | Инкрементальная сборка smali→dex через `.mega-analyzer-build-cache.json` (default: `true`; отключение: `-smali-incremental=false`) |

**Подпись rebuilt APK (fail-closed):**

- Без `-ks` — генерируется debug-ключ (настоящий PKCS#7, офлайн-проверяемый через `offline-v1`); в диагностике код `APK_SIGNED_DEBUG_UNVERIFIED` + SHA-256 подписанта. Android ставит как unknown publisher, сторы отклоняют.
- С `-ks` — только через apksigner (нужны Java + пароль). Пароли НЕ флагами: `ANALYZER_KEYSTORE_PASS` (и `ANALYZER_KEY_PASS`, если отличается от store). Без пароля / без Java — явная ошибка, молчаливого debug-ключа не будет.
- Отпечаток сравнивается с оригиналом из `META-INF` исходников: чужой пользовательский ключ — ошибка `APK_SIGNER_MISMATCH_ORIGINAL`; debug-ключ — предупреждение `APK_SIGNER_DIFFERS_FROM_ORIGINAL` (обновление поверх оригинала отклонит Android).

**Пути к инструментам (auto-detect если не указаны):**

| Флаг | Описание |
|---|---|
| `-aapt2 <path>` | Путь к `aapt2` |
| `-use-smali` | Включить smali→dex (default: `true`) |
| `-use-aapt2` | Включить aapt2 compile+link (default: `true`) |
| `-smali-api <N>` | Android API level нативного сборщика; 0 = автоматически по DEX проекта |
| `-smali-jobs <N>` | Воркеры нативной сборки DEX; 0 = авто (до 4 на процесс) |

**Примеры:**

```powershell
# Быстрый ребилд большой игры (fast ZIP + инкрементальный smali)
.\bin\analyzer.exe -r -t .\decoded_game -o .\patched.apk -compression-mode fast

# Максимальное сжатие для релиза
.\bin\analyzer.exe -r -t .\decoded_app -o .\release.apk -compression-mode best

# Декодирование без JVM через native-бэкенд с кэшем
.\bin\analyzer.exe -decode -t .\app.apk -o .\decoded_app -dex-backend native -class-cache
```

### Smali class-cache viewer (`cmd/cache-viewer`)

Отдельный бинарь для инспекции `.mega-analyzer-cache.db` (бинарный append-only журнал `MACDB001`):

| Флаг | Описание |
|---|---|
| `cache-viewer <db>` | Показать топ записей (сортировка по имени класса) |
| `-limit <N>` | Сколько строк показать (default: 50) |
| `-find <str>` | Case-insensitive фильтр по имени класса |
| `-dump <class>` | Вывести точный Smali текст класса |

---

### OBB / Data / Cache Scanner

| Флаг | Описание |
|---|---|
| `-obb-scan` | Включить deep-scan OBB/data/cache |
| `-obb-data-dir <path>` | Путь к `Android/data/<pkg>/` или OBB-директории |
| `-obb-max-size <N>` | Макс. размер OBB файла в MB (default: 100, 0 = без лимита) |
| `-obb-json` | Записать `OBB_SCAN_REPORT.json` (default: `true`) |

Что сканирует: Unity AssetBundles, Unreal `.pak`/`.utoc`/`.ucas`, Godot `.pck`, скрытые DEX/ELF/PE внутри data-файлов, подозрительные URL и tracker SDK-hints.

---

### Cache Security Analyzer

| Флаг | Описание |
|---|---|
| `--cache-scan` | Сканировать кэш на уязвимости хранения данных |
| `--cache-data-dir <path>` | Путь к кэшу (default: `Android/data/<pkg>/cache`) |

Что ищет: незашифрованные сохранения (coins, gems, score в JSON/XML), утечки API-ключей/токенов, SQLite без шифрования, weak crypto, tracker-конфиги в кэше.

---

### ML-Apli-Cache

| Флаг | Описание |
|---|---|
| `--ml-cache-script` | ML-предсказание цепочек эксплуатации кэша |

Генерирует: `ML_APLI_CACHE_REPORT.json` с ML-скором каждого находки, Predicted Attack Chain и Risk Score 0–100%.

---

### Sandbox и Detonation

| Флаг | Описание |
|---|---|
| `-sandbox` | Запуск в режиме песочницы (анализ поведения) |
| `-sandbox-args <args>` | Аргументы для запускаемого файла |
| `-sandbox-duration <sec>` | Время работы песочницы (default: 60) |
| `-sandbox-memory <MB>` | Лимит памяти на процесс (default: 512) |
| `-sandbox-allow-net` | Разрешить сетевой доступ (default: заблокировано) |
| `-sandbox-profile <preset>` | Профиль: `basic` \| `trace` \| `forensic` \| `paranoid` |
| `-android-sandbox` | Динамическая Android-песочница через ADB |
| `-sandbox-avd <name>` | Запустить конкретный AVD эмулятор |
| `-sandbox-auto-avd` | Автозапуск первого доступного AVD эмулятора |
| `-sandbox-uninstall-after` | Удалить приложение после работы песочницы |
| `-sandbox-capture-traffic` | Перехват PCAP трафика через `tcpdump` на устройстве |
| `-sandbox-mitm` | Запуск `mitmproxy` для HTTPS перехвата |
| `-sandbox-cpu-cores <N>` | Ограничение виртуальных ядер CPU гостя |
| `-sandbox-locale <code` | Язык/локаль гостя (например `en-US`, `ru-RU`) |
| `-sandbox-timezone <zone>` | Часовой пояс гостя (например `Europe/Moscow`) |
| `-sandbox-resolution <res>` | Разрешение экрана (например `1080p`, `720p`, `1920x1080`) |
| `-sandbox-orientation <mode>`| Ориентация экрана (`portrait` \| `landscape`) |
| `-sandbox-privserver <addr>` | Адрес приватного сервера для трафика |
| `-sandbox-private-server <addr>` | Alias для `--sandbox-privserver` |

---

### Windows-Native Sandbox

| Флаг | Описание |
|---|---|
| `-win-sandbox` | Нативная Windows-песочница с мониторингом ядра |
| `-sandbox-vss-revert` | Откат системы через VSS после выполнения |
| `-sandbox-time-scale <N>` | Ускорение времени (1.0 = real-time, 10.0 = 10x) |
| `-sandbox-output <dir>` | Папка для артефактов (PCAP, логи, снимки реестра) |
| `-enable-kernel-monitor` | Мониторинг ФС и реестра на уровне ядра |
| `-enable-vss` | VSS-снимки для сравнения состояния системы |
| `-enable-wfp` | Перехват трафика через Windows Filtering Platform |
| `-enable-api-tracing` | Трассировка системных вызовов |
| `-enable-time-manip` | Обход задержек anti-evasion |

---

### Private Server Toolkit & Traffic Fuzzing

| Флаг | Описание |
|---|---|
| `--intercept` | Запустить MITM TCP-прокси |
| `--port <port>` | Порт прослушивания (default: 9339) |
| `--upstream <host:port>` | Целевой сервер для проксирования |
| `--record <file.json>` | Запись перехваченных пакетов в файл |
| `--interactive`, `-i` | Интерактивное редактирование пакетов в консоли |
| `--net-json-events` | Трансляция сетевых событий `@@NETEVENT@@` для DevMega UI |
| `--net-remote-edit` | Управление редактированием пакетов из DevMega UI |
| `--net-filter <expr>` | Фильтр отображения перехваченного трафика |
| `--net-flows` | Сборка пакетов в потоки с классификацией протокола |
| `--frame <spec>` | Сборка TCP-пакетов в фреймы (`supercell` или `len:HDR,OFF,SZ`) |
| `--fuzz` | Запустить протоколо-зависимый фаззер фреймов |
| `--fuzz-capture <file>` | Файл записи пакетов для мутации |
| `--fuzz-target <host:port>` | Целевой сервер для отправки мутированных фреймов |
| `--fuzz-out <file>` | Сохранить корпус мутаций фаззинга в JSON |
| `--servgen` | Сгенерировать сервер на Go из записанного протокола |
| `--protocol-spec <file.json>` | JSON-спецификация протокола |
| `--from-capture <file.jsonl>` | Построить спецификацию протокола из `.jsonl` дампа |

**Make-Server (Elixir/OTP Private Server Generator):**

| Флаг | Описание |
|---|---|
| `--make-server`, `--privserver` | Генерировать Elixir/OTP-сервер из APK/DEX |
| `--privserver-game <name>` | Имя игры (default: из имени файла) |
| `--privserver-module <name>` | Elixir module prefix |
| `--privserver-output <dir>` | Папка для Elixir-проекта |
| `--privserver-port <port>` | TCP-порт сервера (default: 9339) |
| `--privserver-admin <port>` | HTTP-порт админки (default: 8765) |

Артефакты: `private_server_plan.json`, `PRIVATE_SERVER_READINESS.md`, `private_server/` (полный Elixir/OTP проект с `mix.exs`).

---

### Lab DNS Server

| Флаг | Описание |
|---|---|
| `--lab-dns` | Запустить Lab DNS-сервер |
| `--dns-addr <addr>` | Адрес прослушивания (default: `127.0.0.1:15353`) |
| `--dns-upstream <addr>` | DNS для проксирования (default: `8.8.8.8:53`) |
| `--dns-sinkhole <ip>` | IP для sinkhole-ответов (default: `127.0.0.1`) |

---

### ML Assistant

Работает без target — анализирует историю:

| Флаг | Описание |
|---|---|
| `-suggest`, `-ml` | ML-подсказки для оптимизации правил |
| `-history` | История анализов |
| `-stats` | Агрегированная статистика |
| `-ml-train` | Обучить keyword-relevance модель на основе локальной `history.json` |
| `-ml-train-ensemble` | Обучить ensemble risk модель на основе локальной `history.json` |
| `-ml-train-soft` | Использовать soft labels при обучении моделей |
| `-export-suggestions <file>` | Экспорт подсказок в JSON |
| `-ml-confidence <0-1>` | Минимальный порог доверия (default: 0.5) |
| `-ml-max <N>` | Лимит подсказок (0 = без лимита) |
| `-ml-apply <nums>` | Применить рекомендации: `"1,3,5"`, `"1-10"`, `"all"` |
| `-mark-relevant <path\|kw>` | Пометить находку как релевантную |
| `-mark-noise <path\|kw>` | Пометить находку как шум |
| `-show-feedback` | Показать все overrides и экспортировать в файл |
| `-pattern-stats` | Статистика эффективности паттернов |
| `-export-pattern-stats <file>` | Экспорт статистики в JSON |
| `-feedback-file <file>` | Импорт фидбека из JSON для автоподстройки весов паттернов |
| `-ml-patch-feedback-import <f>` | Импорт метрик обратной связи патчера (JSON) перед скорингом |
| `-ml-patch-feedback-export <f>` | Экспорт метрик обратной связи патчера (JSON) после скоринга |

---

### ML Patcher

| Флаг | Описание |
|---|---|
| `-ml-patch` | Предсказать точки патча в Smali |
| `-ml-patch-fix` | Генерировать патч-код и diff (`PATCHES_WITH_FIX.md`) |
| `-ml-patch-include-libs` | Анализировать библиотеки тоже (не skip; библиотечные CVE/weak crypto/secrets остаются важными) |
| `-ml-patch-min-score <0-100>` | Порог риска для включения (default: 30) |
| `-mode <research>` | Режим: `research` — **обязателен** |
| `-explain` | Детальное объяснение патчей в консоли |
| `-ml-patch-export-format <f>` | Формат: `md`, `json`, `csv` (через запятую) |
| `-ml-patch-export-output <p>` | Путь для экспорта (без расширения) |
| `-ml-patch-min-tier <val>` | Мин. тир паттернов |
| `-ml-patch-deprecated` | Включить устаревшие паттерны |
| `-ml-patch-sdk` | SDK-specific детект (default: `true`) |
| `-ml-patch-combination` | Детект комбинаций паттернов (default: `true`) |
| `-ml-patch-confidence <0-1>` | Мин. уверенность (default: 0.3) |
| `-ml-patch-priority` | Сортировка по приоритету |
| `-ml-patch-cross-lang` | Кросс-языковой детект (default: `true`) |

**Применение патчей:**

| Флаг | Описание |
|---|---|
| `-ml-patch-apply <mode>` | `dry-run` (показать) или `write` (применить) |
| `-ml-patch-backend <engine>` | `smali` (текстовый, stable) или `dex` (бинарный, быстрый) |
| `-ml-patch-output <dir>` | Папка для patch-артефактов |

---

### Экспериментальные модули (--ml-ex & --aeg)

Расширенный набор исследовательских модулей для автоматической генерации эксплойтов (AEG), анализа бинарной схожести (BinSim), поддержки iOS Mach-O и анализа достижимости кода (Reachability).

| Флаг | Описание |
|---|---|
| `-aeg` | Включить Automated Exploit Generation (генерация PoC эксплойтов и шаблонов атак) |
| `-ml-ex` | Включить подсистему экспериментальных модулей |
| `-ml-ex-apply <spec>` | Выбрать активные модули по номерам `1-4`, именам (`macho`, `binsim`, `reach`, `aeg`) или пресетам |
| `-ml-ex-list` | Вывести список всех доступных экспериментальных модулей и выйти |
| `-ml-ex-output <dir>` | Пользовательская директория для сохранения артефактов экспериментальных модулей |
| `-ml-ex-timeout <sec>` | Таймаут на каждый модуль в секундах (default: `120`, `0` = без ограничения) |
| `-ml-ex-parallel` | Запускать выбранные экспериментальные модули параллельно в несколько потоков |
| `-ml-ex-json` | Записать итоговый `experimental_report.json` (default: `true`) |

**Доступные модули:**
1. `macho` — Поддержка Mach-O / iOS (алиасы: `ios`, `ipa`, `darwin`)
2. `binsim` — Анализ бинарной схожести и клонов кода (алиасы: `clones`, `dup`, `similarity`)
3. `reach` — Анализ достижимости кода и путей вызовов (алиасы: `reachability`, `callgraph-ex`)
4. `aeg` — Automated Exploit Generation (алиасы: `exploit`, `poc`)

**Готовые пресеты модулей (`-ml-ex-apply <preset>`):**
- `all` — все модули (`macho` + `binsim` + `reach` + `aeg`)
- `alice` — безопасный исследовательский бандл (`macho` + `binsim` + `reach`)
- `hunter` — поиск клонов и путей (`binsim` + `reach`)
- `mobile` — мобильный аудит (`macho` + `reach`)
- `offense` — атакующий аудит (`reach` + `aeg`)

---

### JS Bundle Patcher & Deobf

Умный анализ, деобфускация и патчинг React Native и Hermes бандлов.

| Флаг | Описание |
|---|---|
| `-js-patch` | Включить умный патчер JS бандлов |
| `-js-patch-apply <mode>` | Режим: `dry-run` (по умолч.) или `write` |
| `-js-patch-server-ip <ip>` | Новый IP/домен для патча URL (напр. 127.0.0.1:9339) |
| `-js-patch-backup` | Создать `.orig` бэкап перед записью патчей |
| `-js-patch-categories <str>`| Список категорий через запятую (server, premium, age и др.) |
| `-js-patch-min-conf <N>` | Порог уверенности 0-100 (по умолч. 40) |
| `-js-patch-output <dir>` | Папка для отчетов `JSPATCH.md` и `jspatch.json` |
| `-js-deobf` | Включить standalone JS деобфускатор |
| `-js-deobf-out <file>` | Файл для сохранения деобфусцированного кода |

---

### Deobfuscation

| Флаг | Описание |
|---|---|
| `-deobf-iterations <N>` | Максимум итераций (0 = профиль) |
| `-deobf-min-confidence <0-100>` | Минимальный confidence для passes |
| `-enable-deobf-cp` | Constant Propagation (default: `true`) |
| `-enable-deobf-dce` | Dead Code Elimination (default: `true`) |
| `-enable-deobf-opr` | Opaque Predicate Removal (default: `true`) |
| `-enable-deobf-ps` | Pattern Simplification (default: `true`) |
| `-enable-deobf-vr` | Variable Name Recovery (default: `true`) |
| `-enable-deobf-mr` | Method Name Recovery (default: `true`) |
| `-enable-name-quality` | Name Quality Analysis (default: `true`) |

---

### Crack Point Discovery

| Флаг | Описание |
|---|---|
| `-crackpoint-analysis` | Поиск точек обхода логических проверок |
| `-crackpoint-threshold <0-1>` | Порог уверенности high-confidence (default: 0.75) |
| `-anomaly-detection` | Детекция аномалий и структурных отклонений |

---

### GNN Classification

| Флаг | Описание |
|---|---|
| `-gnn-model <path>` | Путь к весам GNN в `.gnnbuf` (предпочтительно) или JSON; без флага используются веса из `~/.analyzer/models/`, если файл существует |
| `-skip-gnn` | Принудительно пропустить GNN-классификацию, даже если веса найдены |

> Для работы GNN бинарник должен быть собран с `-tags=omnisec_ml_gnn`, `CGO_ENABLED=1` и содержать рядом `omnisec_ml_gnn.dll`; готовая Windows-команда приведена в разделе «Сборка — Go». `--ml-train` обучает keyword-relevance, а `--ml-train-ensemble` — ensemble risk; эти команды не создают GNN-веса. `__dummy__` предназначен только для проверки интеграции и не должен использоваться для реальных находок. `cmd/pattern-analysis` строит отчёт эффективности правил и GNN не обучает.

---

### ProGuard Recovery

| Флаг | Описание |
|---|---|
| `-proguard-map <path>` | Путь к `mapping.txt` (ProGuard/R8) для восстановления имён |

> **Где взять `mapping.txt`?** Этот файл генерируется при сборке релизного APK с включённым ProGuard/R8. Его можно найти в артефактах CI/CD сборки (например, в Firebase App Distribution или Google Play Console → Release Management → App bundle explorer → Downloads → Mapping file).

---

### Game Mode и геймификация

> **Только для статического анализа.** В динамическом режиме (`--sandbox`) геймификация недоступна.

| Флаг | Описание |
|---|---|
| `-gamemode` | Включить Epic-режим вывода (ретро-консоль, XP, ранги) |
| `-gamemode-output <format>` | Формат: `terminal` \| `markdown` \| `json` (default: `terminal`) |
| `-gamemode-persist` | Сохранять XP и прогресс в локальную БД |
| `-decoy-detection` | Поиск ложных приманок и обманных переходов |
| `-interesting-score` | Расчёт индекса интересности кода (Interesting Score) |
| `-ml-patch-confidence-min <N>` | Мин. порог доверия для рекомендаций в игровом режиме |
| `-ml-patch-priority-sort` | Сортировать точки патча по приоритету → threat score |
| `-ml-patch-cross-language` | Кросс-языковой детект (Dalvik ↔ Native) |

---

### MobSF-модули

| Флаг | Описание |
|---|---|
| `-mobsf-all` | Включить ВСЕ MobSF-анализаторы |
| `-sast-rules` | SAST-сканер (137 правил: OWASP, CWE, MASVS + gov-SSO/WebView-auth: ESIA/Госуслуги, SSL-bypass, OAuth-UUID, HTML-dump, intent-redirect) |
| `-trackers` | Детектор трекеров Exodus Privacy (431 сигнатура) |
| `-nsc-audit` | Аудит `network_security_config.xml` |
| `-manifest-audit` | Глубокий аудит `AndroidManifest.xml` |
| `-apkid` | APKiD-style fingerprinting (packer/obfuscator/anti-debug) |

---

### Medium-Priority Analyzers

| Флаг | Описание |
|---|---|
| `-medium-all` | Включить ВСЕ medium-priority анализаторы |
| `-playstore` | Play Store Metadata Lookup (HTTP) |
| `-sbom` | SBOM Extraction из APK |
| `-permmap` | Permission-to-Code Mapping |
| `-cert-audit` | Certificate Deep Analysis (v1/v2/v3) |
| `-malware-domains` | Проверка URL против blacklist вредоносных доменов |
| `-niap` | NIAP Compliance Rules |

---

### Утилиты

| Флаг | Описание |
|---|---|
| `-validate-config <path>` | Валидировать конфиг-файл перед запуском |
| `-cache-stats` | Статистика кэша (размер, файлы, возраст) |
| `-cache-clear` | Очистить весь кэш |
| `-cache-prune` | Удалить старые файлы кэша |
| `-cache-prune-days <N>` | Удалить файлы старше N дней (default: 7) |
| `-completion <shell>` | Автодополнение: `bash` \| `zsh` \| `fish` |
| `-pprof <addr>` | pprof HTTP-сервер (default: `localhost:6060`) |
| `-cpu-profile <file>` | Записать CPU-профиль |
| `-mem-profile <file>` | Записать heap-профиль |

---

## 6. Переменные окружения

| Переменная | Описание |
|---|---|
| `ANALYZER_CONFIG_PATH=<path>` | Путь к конфиг-файлу |
| `ANALYZER_CACHE_DIR=<dir>` | Директория кэша |
| `ANALYZER_OUTPUT_DIR=<dir>` | Директория для отчётов |
| `ANALYZER_WORKERS=<N>` | Количество воркеров |
| `ANALYZER_TIMEOUT=<seconds>` | Таймаут анализа |
| `ANALYZER_MAX_FILES=<N>` | Лимит файлов |
| `ANALYZER_MAX_FILE_SIZE_MB=<MB>` | Лимит размера кода |
| `ANALYZER_MAX_RESOURCE_SIZE_MB=<MB>` | Лимит размера ресурсов |
| `ANALYZER_LOG_LEVEL=<level>` | Уровень логов: `debug` \| `info` \| `warn` \| `error` |
| `ANALYZER_LOG_FILE=<path>` | Путь к лог-файлу |
| `ANALYZER_PROFILE=<profile>` | Профиль по умолчанию |
| `ANALYZER_DEBUG=<bool>` | Режим отладки (`1`, `true`, `yes`, `on`) |
| `ANALYZER_QUIET=<bool>` | Тихий режим |
| `ANALYZER_NO_COLOR=<bool>` | Отключить цвета |

---

## 7. Примеры — Rust CLI

```bash
# Анализ PE бинарника
cd rust
cargo run --release --bin omnisec-cli -- analyze sample.exe

# Экспорт CFG в DOT
cargo run --release --bin omnisec-cli -- cfg sample.exe --output cfg.dot --dominators --loops

# Метрики кода
cargo run --release --bin omnisec-cli -- metrics sample.exe --mccabe --halstead

# Дизассемблирование
cargo run --release --bin omnisec-cli -- disasm sample.exe --arch x64 --entry 0x401000

# Анализ ELF бинарника
cargo run --release --bin omnisec-cli -- analyze /bin/ls --arch x64

# CFG с визуализацией (требует graphviz)
cargo run --release --bin omnisec-cli -- cfg sample.exe --dot --viz
dot -Tpng cfg.dot -o cfg.png
```

---

## 8. Примеры — Go CLI

```bash
# Интерактивный TUI-визард (опционально; по умолчанию — прямой CLI)
analyzer.exe -tui
analyzer.exe -tui -t ./app.apk
analyzer.exe -tui -t ./app.apk -p paranoid   # профиль можно выбрать в визарде

# Быстрый анализ
analyzer.exe -t ./decompiled_app -p quick

# Стандартный анализ
analyzer.exe -t ./decompiled_app -o analysis_output -p balanced

# Глубокий анализ с call graph и геймификацией (только статический анализ)
analyzer.exe -t ./decompiled_app -p deep -callgraph -gamemode

# Paranoid для финтеха
analyzer.exe -t ./decompiled_app -p paranoid -report full

# JSON для CI/CD
analyzer.exe -t ./decompiled_app -q -json > results.json

# SARIF для локального/CI code scanning UI
analyzer.exe -t ./decompiled_app --sarif -o ./analysis_output

# Меньше шума, но без слепого пропуска библиотек
analyzer.exe -t ./decompiled_app --fp-strict --fp-show-suppressed

# С кастомными лимитами
analyzer.exe -t ./decompiled_app -max-file-size 64 -max-resource-size 128 -p balanced

# Артефакты (картинки, 3D, .so, аудио/видео)
analyzer.exe -t ./app.apk -artifacts
analyzer.exe -t ./app.apk -artifacts -allow-export

# Machine-Code (нативные бинари без APK)
analyzer.exe -scan-native -t ./libnative.so -o ./out
analyzer.exe -t ./malware.exe    # авто-роутинг по расширению

# Decode → правка → Rebuild
analyzer.exe --decode -t ./app.apk -o ./work --copy-original
# ... правим smali в ./work/smali/...
analyzer.exe --build -t ./work -o ./patched.apk

# APK Decode только ресурсы / только smali
analyzer.exe --decode -t ./app.apk -o ./out --no-smali
analyzer.exe --decode -t ./app.apk -o ./out --no-resources

# Top-5 Insights
analyzer.exe -t ./app.apk --top5
analyzer.exe -t ./app.apk --jni-bridge --privacy --graph-explorer -o ./out

# Version Diff
analyzer.exe --version-diff --diff-old ./old.apk --diff-new ./new.apk

# Firmware / IoT
analyzer.exe --firmware -t ./router_firmware.bin -o ./fw_out

# Make-Server (Elixir/OTP)
analyzer.exe --make-server -t ./game.apkanalyzer.exe --make-server -t ./game.apk --privserver-game "My Game" --privserver-port 9339
# ML Patcher
analyzer.exe -t ./decompiled_app --ml-patch --mode research
analyzer.exe -t ./decompiled_app --ml-patch --mode research --ml-patch-fix --ml-patch-include-libs
analyzer.exe -t ./decompiled_app --ml-patch --mode research --ml-patch-apply=write --ml-patch-backend=dex

# GNN + ProGuard (требуется GNN-сборка из раздела 2)
analyzer.exe -t ./app.apk -proguard-map ./mapping.txt -p deep -gnn-model ./rust/gnn_weights.gnnbuf

# ML Assistant
analyzer.exe --suggest
analyzer.exe --ml --ml-confidence 0.7
analyzer.exe --ml-apply 1,3,5
analyzer.exe --ml-apply all

# Feedback
analyzer.exe --mark-relevant "smali/com/payments/Sensitive"
analyzer.exe --mark-noise "Lcom/google/ads/"
analyzer.exe --pattern-stats

# OBB / Cache
analyzer.exe -t ./app.apk --obb-scan
analyzer.exe -t ./app.apk --cache-scan --ml-cache-script

# Sandbox
analyzer.exe -t malware.exe --sandbox --sandbox-duration 120
analyzer.exe -t sample.exe --win-sandbox --enable-kernel-monitor --enable-api-tracing
analyzer.exe -t app.apk --android-sandbox --sandbox-privserver 127.0.0.1:9339

# MobSF модули
analyzer.exe -t ./app.apk --mobsf-all
analyzer.exe -t ./app.apk --sast-rules --trackers --manifest-audit

# Medium analyzers
analyzer.exe -t ./app.apk --medium-all
analyzer.exe -t ./app.apk --cert-audit --malware-domains

# Утилиты
analyzer.exe --cache-stats
analyzer.exe --cache-prune --cache-prune-days 30
analyzer.exe --validate-config ./my-config.json
analyzer.exe --completion bash > ~/.bashrc

# Profiling
analyzer.exe -t ./app.apk --pprof localhost:6060
analyzer.exe -t ./app.apk --cpu-profile cpu.prof
go tool pprof -http=:8080 cpu.prof
```

**Через переменные окружения:**

```bash
export ANALYZER_OUTPUT_DIR=/tmp/analysis
export ANALYZER_WORKERS=8
export ANALYZER_PROFILE=deep
export ANALYZER_DEBUG=true
analyzer.exe -t ./app.apk
```

---

## 9. Elixir/OTP сервер

```bash
# Запуск распределённого Phoenix сервера
cd server
mix phx.server
```

**API эндпоинты:**

```bash
# Символьное выполнение (Z3 SMT)
POST http://localhost:4000/api/v1/symexec/solve
# Body (raw text): (declare-const x Int) (assert (> x 10)) (check-sat)

# Микроэмуляция (OmniSec Micro-Emulator)
POST http://localhost:4000/api/v1/microemu/emulate
# Body (JSON): { "shellcode_hex": "b8010000000502000000c3" }
```

**ML-база данных (Game Mode):**

```
%USERPROFILE%\.analyzer-gamemode\
  history.json   — история анализов и фидбек патчера
```

## 10. Build tags / Rust FFI / старое железо

По умолчанию Go-тесты и CLI используют безопасные стабы Rust FFI, чтобы проект собирался без заранее подготовленных `.dll` / `.so`:

```bash
go test ./...
```

Production FFI включается явно, когда Rust-библиотеки уже собраны:

```bash
cd rust
cargo build --release
cd ..
go test -tags omnisec_rust_ffi ./pkg/internal/apkloader
```

HDC Zig SIMD runtime в Rust теперь тоже opt-in. Чистый Rust fallback включён по умолчанию и не требует GPU/CUDA/внешнего inference-сервера:

```bash
cd rust
cargo test -p omnisec-hdc
cargo test -p omnisec-hdc --features zig-runtime   # только если нужен Zig SIMD runtime
```

---

## 11. Web Vulnerability Scanner & Дополнительные CLI-Точки Входа (`cmd/*`)

Основные URL-режимы и веб-анализ встроены в единый `analyzer.exe`. Дополнительные утилиты в директории `cmd/` предоставляют узкоспециализированные точки входа для тестирования, разработки и отдельного запуска модулей.

### Сборка

```bash
# Core-вариант веб-сканера без GNN
go build -trimpath -ldflags "-s -w" -o analyzer ./pkg/cmd/analyzer
```

### Флаги

#### Основные / safety

| Флаг | Тип | По умолчанию | Описание |
|---|---|---|---|
| `-web-scan` | bool | false | Включить анализ веб-сайта встроенным движком vulnscan |
| `-web-scan-target <URL>` | string | — | Целевой HTTP/HTTPS URL для сканирования |
| `-web-scan-mode <mode>`, `-web-mode` | string | `active` | Режим: `status` (1 быстрый GET на HTTP 200), `passive` (1 ответ без фаззинга), `active` (полный аудит уязвимостей) |
| `-i-own-this-target` | bool | false | **Обязательное подтверждение авторизации** (требуется только для режима `active`) |
| `-lab-mode` | bool | false | **Включение деструктивных лабораторных проверок** (OAST Blind SSRF/RCE, HTTP Request Smuggling / Desync) |
| `-target-allowlist <domains>` | string | — | Список разрешённых доменов через запятую для ограничения области краулинга |
| `-fsm-config <path>` | string | — | Путь к YAML-файлу конфигурации конечного автомата (State-Machine Fuzzing) |
| `--output <dir>` | string | `analysis_output` | Корневая папка отчётов (`web_scan/` создаётся внутри) |

#### Режимы входа (выбрать один)

| Флаг | Тип | Описание |
|---|---|---|
| `--target <URL>` | string | Совместимый alias в developer-wrapper; в analyzer используется `--web-scan-target` |
| `--curl "<curl cmd>"` | string | Скан конкретного запроса, импортированного как curl-команда |
| `--raw-request <file>` | string | Путь к файлу с raw HTTP-запросом (формат Burp Suite) |
| `--raw-scheme <scheme>` | string (`http`\|`https`) | Схема для raw-импорта (default: `https`) |
| `--html-body <file>` | string | **Пассивный аудит сохранённого HTML-файла на диске** (без выполнения сетевых запросов). Ищет секреты, XSS, API-ключи, JWT, скрипты и скрытые формы. |

#### Вывод

| Флаг | Тип | Описание |
|---|---|---|
| `-json` | bool | Выводит все находки в JSON на stdout |
| `-no-color` | bool | Отключить ANSI-цвета в консольном выводе |

### Поддерживаемые curl-флаги при `--curl`

| curl-флаг | Действие |
|---|---|
| `-X / --request <METHOD>` | HTTP метод |
| `-H / --header <Header: Value>` | Добавить заголовок |
| `-d / --data / --data-raw` | Тело запроса (переключает метод на POST) |
| `--data-binary` | Тело запроса в бинарном виде |
| `--data-urlencode` | URL-encoded тело |
| `-b / --cookie <string>` | Cookie |
| `-u / --user <user:pass>` | Basic Auth |
| `-k / --insecure` | Отключить TLS-проверку |
| `-A / --user-agent` | User-Agent |
| `-e / --referer` | Referer |
| `--compressed` | Игнорируется (принимается для совместимости) |
| `-L / -s / -v / -I` | Игнорируются (cosmetic флаги) |

### Проверки по категориям

| ID | Категория | Severity | Описание |
|---|---|---|---|
| `WS-HDR-*` | Security Headers | LOW–HIGH | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `WS-CORS-000` | CORS | CRITICAL | Wildcard origin + `Access-Control-Allow-Credentials: true` |
| `WS-CORS-001` | CORS | HIGH/CRITICAL | Произвольный Origin отражён в `Access-Control-Allow-Origin` |
| `WS-CORS-002` | CORS | MEDIUM | `null` Origin принят |
| `WS-CORS-003` | CORS | HIGH/CRITICAL | Subdomain/prefix bypass origin |
| `WS-REDIR-001` | Open Redirect | MEDIUM | Параметр redirect не валидируется → 3xx на внешний домен |
| `WS-SENS-001` | Sensitive Files | CRITICAL | `.env`, `.env.local`, `.env.production` |
| `WS-SENS-002` | Sensitive Files | CRITICAL | `.git/HEAD`, `.git/config` |
| `WS-SENS-003` | Sensitive Files | HIGH | `/admin`, `/wp-admin` |
| `WS-SENS-004` | Sensitive Files | CRITICAL | `backup.zip`, `backup.tar.gz`, `dump.sql`, `db.sql` |
| `WS-SENS-005` | Sensitive Files | MEDIUM–HIGH | `phpinfo.php`, `/server-status`, `/server-info` |
| `WS-SENS-006` | Sensitive Files | MEDIUM | GraphQL introspection |
| `WS-SENS-007` | Sensitive Files | LOW–CRITICAL | Spring Boot Actuator (`/actuator`, `/actuator/env`, `/actuator/health`) |
| `WS-SENS-008` | Sensitive Files | LOW | `.DS_Store` |
| `WS-SENS-009` | Sensitive Files | MEDIUM | `crossdomain.xml` wildcard |
| `WS-SENS-010` | Sensitive Files | INFO | `robots.txt` Disallow пути |
| `WS-COOK-001` | Cookie Flags | LOW–HIGH | Отсутствует `HttpOnly` |
| `WS-COOK-002` | Cookie Flags | MEDIUM–HIGH | Отсутствует `Secure` |
| `WS-COOK-003` | Cookie Flags | LOW–MEDIUM | Слабый `SameSite` |
| `WS-JWT-001` | JWT | LOW | Утечка sensitive данных в Payload |
| `WS-JWT-002` | JWT | CRITICAL | Принятие токена с `alg: "none"` |
| `WS-JWT-003` | JWT | CRITICAL | Слабый секретный ключ (успешный brute-force) |
| `WS-IDOR-001` | IDOR | HIGH | Успешный доступ к объекту с другим ID |
| `WS-UPLOAD-001` | File Upload | HIGH | Успешная загрузка потенциально вредоносного файла (bypass extensions/content-type) |
| `WS-CSRF-001` | CSRF | MEDIUM | Отсутствие Anti-CSRF токенов и слабая защита SameSite |
| `WS-CACHE-001` | Web Cache Poisoning | MEDIUM–HIGH | Инъекция unkeyed заголовков (`X-Forwarded-Host`) и cache HIT |
| `WS-GQL-001` | GraphQL | MEDIUM | Включен Query Batching |
| `WS-GQL-002` | GraphQL | MEDIUM | Alias Overloading (DoS) |
| `WS-API-001` | API | MEDIUM | Включен HTTP TRACE (Cross-Site Tracing) |
| `WS-API-002` | API | LOW | Неожиданный HTTP метод (Method Confusion) |
| `WS-HOST-001` | Host Header | MEDIUM | Отражение Host / X-Forwarded-Host в Location или теле ответа |
| `WS-HPP-001` | HPP | LOW | HTTP Parameter Pollution |
| `WS-PROTO-001` | Prototype Poll. | LOW | Prototype Pollution через параметры URL |
| `WS-XSS-001` | XSS | CRITICAL | Reflected/Stored XSS в формах |
| `WS-SQLI-001` | SQLi | CRITICAL | Error-based SQL Injection |
| `WS-SQLI-002` | SQLi | CRITICAL | Auth-bypass SQLi (302 → /admin) |
| `WS-LFI-001` | LFI | CRITICAL | Path traversal / Local File Inclusion |
| `WS-SECRET-*` | Secrets | CRITICAL | AWS key, GitHub token, JWT, private key в теле |
| `WS-DESYNC-001` | Desync | CRITICAL | HTTP Request Smuggling (только `--lab-mode`) |
| `WS-OAST-*` | OAST | CRITICAL | Blind SSRF / Blind RCE (только `--lab-mode`) |

### Примеры

```bash
# 1. Проверка доступности: один GET, healthy только при HTTP 200
analyzer --web-scan --web-scan-target http://127.0.0.1:3000 --web-scan-mode status

# 2. Пассивный аудит одного ответа без fuzz/payload
analyzer --web-scan --web-scan-target http://127.0.0.1:3000 --web-scan-mode passive

# 3. Полный активный скан URL
analyzer --web-scan --web-scan-target http://127.0.0.1:3000 --web-scan-mode active --i-own-this-target

# 4. Curl import через совместимый developer-wrapper
go run ./cmd/vulnscan \
  --i-own-this-target \
  --curl "curl 'https://example.com/login' -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'Cookie: sess=abc123' \
    --data 'username=admin&password=pass'" \
  --export-curl --json

# 5. Raw HTTP request (Burp Suite format, developer-wrapper)
go run ./cmd/vulnscan \
  --i-own-this-target \
  --raw-request request.txt \
  --raw-scheme https \
  --export-curl

# 6. Пассивный анализ сохранённого HTML
go run ./cmd/vulnscan --html-body saved_page.html

# 7. Скан + JSON + curl-репродукторы
go run ./cmd/vulnscan \
  --i-own-this-target \
  --target https://testsite.local \
  --output ./results \
  --json \
  --export-curl
```

### Формат raw request (Burp Suite)

```http
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json
Cookie: session=abc123
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...

{"username":"admin","password":"pass"}
```

Сохрани в файл и передай через `--raw-request`.
