# Архитектура Mega-Analyzer (v1.0.0-beta.1)

[🇬🇧 English](ARCHITECTURE.md) · **🇷🇺 Русский**

Mega-Analyzer спроектирован как высокопроизводительная, расширяемая платформа для статического и динамического анализа. Она объединяет компоненты на четырех языках (Go, Rust, Zig, Elixir) для достижения максимальной скорости, безопасности и гибкости.

---

## Общая схема

```text
                        ┌──────────────────────────────┐
                        │     Mega-Analyzer CLI        │
                        │ analyzer.exe / Rust CLI      │
                        └───────────────┬──────────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                               ▼                               ▼
┌───────────────────┐           ┌───────────────────┐           ┌───────────────────┐
│ Android / Bytecode│           │ OmniSec native    │           │ Dynamic / Sandbox │
│ APK / DEX / Smali │           │ PE / ELF / DEX    │           │ Windows local     │
└─────────┬─────────┘           └─────────┬─────────┘           └─────────┬─────────┘
          │                               │                               │
          ▼                               ▼                               ▼
┌───────────────────┐           ┌───────────────────┐           ┌───────────────────┐
│ Pipeline detectors│           │ OmniIR / CFG / SSA│           │ FS/Reg/API/Net    │
│ Rules / Matcher   │           │ Dataflow / PDG    │           │ Behavior evidence │
└─────────┬─────────┘           └─────────┬─────────┘           └─────────┬─────────┘
          │                               │                               │
          └───────────────────────────────┼───────────────────────────────┘
                                          ▼
                               ┌───────────────────────┐
                               │ Reports + Correlation │
                               │ HTML / MD / JSON      │
                               └───────────────────────┘
```

> **Примечание**: Zig static-lib `omnisec-ml-runtime` предоставляет SIMD-оптимизированные XNOR-GEMM / Hamming для горячих путей HDC (Hyperdimensional Computing).

---

## Умное планирование: Adaptive Worker Scheduler

В отличие от стандартных статических пулов потоков, которые могут вызвать перегрузку памяти, в Mega-Analyzer используется адаптивный планировщик (`Scheduler[T, R]`). Он отслеживает нагрузку на систему и динамически масштабирует пул воркеров.

```text
┌─────────────────────────────────────────┐
│  Adaptive Scheduler                     │
│                                         │
│  Monitors:                              │
│    • CPU pressure (scheduling latency)  │
│    • Heap pressure (GC overhead)        │
│    • Queue depth (backpressure)         │
│    • GC pause time (STW impact)         │
│    • Allocation rate                    │
│                                         │
│  Actions:                               │
│    • Scale UP when idle + queue full    │
│    • Scale DOWN when GC/heap stressed   │
│    • Cooldown between decisions         │
│    • Workers self-terminate gracefully  │
└─────────────────────────────────────────┘
```

### Параметры адаптивного планировщика

* `MinWorkers` (по умолчанию: 2) — нижняя граница пула.
* `MaxWorkers` (по умолчанию: `NumCPU * 2`) — верхняя граница пула.
* `CPUHighThreshold` (по умолчанию: 0.85) — порог загрузки CPU для сокращения воркеров.
* `HeapHighThreshold` (по умолчанию: 0.80) — порог использования кучи для высвобождения памяти.
* `QueueDepthThreshold` (по умолчанию: 32) — глубина очереди для добавления воркеров.
* `GCPauseThreshold` (по умолчанию: 5ms) — порог задержки сборщика мусора для scale down.
* `CooldownTime` (по умолчанию: 500ms) — время ожидания между сменой размера пула.

---

## Основные модули

### 1. Go CLI & Core (`pkg/`)
* **Go CLI / TUI (`pkg/cmd/analyzer`)**: Интерфейс командной строки и текстовый интерфейс пользователя.
* **APK/DEX loader (`pkg/internal/apkloader`)**: Разбор структуры APK и DEX без использования внешних Java-библиотек.
* **SIMD ULEB128 (`pkg/internal/apkloader/simdleb`)**: Нативный ассемблерный batch-декодер для ускорения парсинга DEX (+30% к производительности).
* **Pipeline (`pkg/internal/pipeline`)**: Диспетчеризация и выполнение проверок.
* **Content Cache (`pkg/internal/contentcache`)**: Контентно-адресуемый инкрементальный кэш анализов.
* **Dataflow / Taint Engine (`pkg/internal/dataflow`)**: Межпроцедурный анализ потоков данных и taint-анализ.
* **SMT Solver (`pkg/internal/smt`)**: Разбор условий ветвления и символьное вычисление на базе DPLL SAT.
* **Deobf Metrics (`pkg/internal/deobfmetrics`)**: Количественная оценка качества деобфускации.
* **SSA IR (`pkg/internal/ssair`)**: Собственное промежуточное представление SSA для оптимизации кода.

### 2. Rust Core (`rust/crates/`)
Workspace состоит из 39 специализированных библиотек:
* `omnisec-core` — базовые типы и структуры данных.
* `omnisec-loader-*` — модули разбора форматов ELF, PE, MachO, DEX.
* `omnisec-ir`, `omnisec-cfg`, `omnisec-ssa` — построение управляющих графов и SSA форм.
* `omnisec-dataflow`, `omnisec-callgraph` — анализ вызовов и потоков данных.
* `omnisec-deobfuscator` — модули деобфускации.
* `omnisec-ml-gnn` — Graph Neural Network для классификации типов уязвимостей (UAF, Buffer Overflow, Race Conditions и др.).
* `omnisec-emu-x86` — эмулятор для безопасного распаковывания крипто-рутин и строк.
* `omnisec-ebpf` — монитор системных вызовов в ядре Linux/Android.

### 3. Zig ML Runtime & Sandbox (`zig/`)
* **SIMD ML Runtime (`zig/src/`)**: Оптимизированные алгоритмы линейной алгебры и разреженных вычислений на Zig для локального выполнения ML моделей.
* **Windows Sandbox (`zig/sandbox/`)**: Изолированная Windows-песочница для мониторинга активности тестируемых бинарных файлов.

### 4. Elixir/Phoenix Server (`server/`)
* **Phoenix Web Server**: Интерфейс распределенной обработки задач, кэширования и управления отладчиком.
* **Rust NIFs**: Высокопроизводительные функции-мосты на Rust для обработки сигналов и быстрого вывода моделей (Inference).
