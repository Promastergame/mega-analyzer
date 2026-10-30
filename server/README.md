# OmniSec Server 🚀

Distributed binary analysis and interactive debugging server powered by Elixir/OTP and high-performance Rust NIFs.

Этот сервер представляет собой **ультимативную платформу для реверс-инжиниринга**, способную решать любые задачи статического, динамического и интерактивного анализа бинарных файлов в реальном времени!

---

## ⚡ Архитектурные возможности (Что он умеет)

OmniSec Server спроектирован на базе принципов OTP для обеспечения максимальной отказоустойчивости, распределенности и производительности:

### 1. 🌐 Распределенный кластерный мониторинг (`ClusterMonitor`)
-   **Автоматическое обнаружение нод** в локальной сети через Erlang Distribution.
-   Динамическое распределение задач анализа и мониторинг здоровья других нод (heartbeats).
-   Маршрутизация перегрузок (Overflow routing): автоматическое перенаправление тяжелых задач на свободные ноды кластера.
-   Адаптивный контроль ресурсов (память, CPU, ETS-таблицы) с системой раннего предупреждения об исчерпании лимитов.

### 2. 🛡 Отказоустойчивый пул воркеров (`WorkerPool`)
-   Динамический пул Rust NIF воркеров, изолированных от основного BEAM-планировщика через Dirty Schedulers.
-   **FIFO очередь caller deadlines**: если воркеры заняты, запросы ждут освобождения с жесткими таймаутами для недопущения зависания клиентов.
-   **Самовосстановление**: при падении любого Rust NIF воркера пул ловит `:DOWN` сигнал, мгновенно перезапускает воркера в дереве супервизоров и ротирует его обратно в очередь.

### 3. ⏳ Интерактивный Time-Travel Web-Отладчик (`WsServer`)
-   Реальное WebSocket-взаимодействие (plain-JSON поверх `:gen_tcp`, без внешних зависимостей) для управления ходом отладки:
    -   Пошаговая трассировка вперед (`step`) и **назад** (`reverse_step`).
    -   Продолжение выполнения вперед (`continue`) и **назад** (`reverse_continue`).
    -   Чтение/запись регистров и флагов процессора (`registers`, `set_register`, `set_flag`).
    -   Мгновенное чтение, сканирование и патчинг памяти в реальном времени (`patch`, `scan_memory`).
    -   Визуализация графа потока управления (CFG) на лету (`cfg`).
    -   Установка точек останова на адреса/символы (`breakpoint`) и точек наблюдения за доступом к памяти (`add_watch`).

### 4. 🧠 HDC-движок автонейминга (Hyperdimensional Computing)
-   Полностью локальная побитовая ИИ-модель для предсказания названий переменных и функций.
-   Использует 2048-битные разреженные гипервекторы (Vector Symbolic Architectures) и побитовый XOR-binding (`bind`) для объединения структуры с API-вызовами.
-   Обучается "на лету" в реальном времени (`train`) без переобучения всей модели.
-   Потребляет **менее 10 МБ ОЗУ** и работает за микросекунды без floating-point math — идеально для Intel i5-3340!

### 5. 🕸 eBPF-инструментация ядра ОС (Syscall Tracer)
-   Низкоуровневый перехват системных вызовов в пространстве ядра Linux/Android (файловые операции `openat`, запуск процессов `execve`, сеть `connect`).
-   Использует библиотеку `aya` на Linux/Android и переходит в режим высокоточной симуляции eBPF-телеметрии на Windows/macOS для локального тестирования и разработки.
-   Асинхронная отсылка событий в реальном времени в Elixir-оркестратор через NIF.

### 6. 📂 Продвинутый конвейер анализа и безопасность
-   **Static Scan Gateways**: разбор PE, ELF, DEX, JVM контейнеров с оценкой уровня угроз и нахождением вредоносных сигнатур.
-   **Security Controls**: IP-allowlisting (`AllowlistPlug`) и строгая ролевая авторизация пользователей / администраторов (`AuthPlug`, `AdminAuthPlug`).
-   **Результаты кэширования**: ETS-таблицы для мгновенной отдачи аналитики по ранее исследованным бинарникам.

### 7. 🕵️‍♂️ Smart MITM & Private Server Toolkit (Zero-Dependency)
-   **Multi-Protocol Proxy**: полноценный прозрачный TCP и UDP прокси с поддержкой хуков шифрования (Sodium, RC4) для расшифровки на лету.
-   **Live TUI Intercept Dashboard**: встроенная панель управления в терминале, позволяющая в реальном времени перехватывать пакеты и редактировать их содержимое (с поддержкой JSON, MsgPack и Hex-дампов) без разрыва соединения.
-   **Automated Client Patcher**: конвейер, автоматически модифицирующий APK-клиенты игр:
    -   Поиск и подмена захардкоженных IP/доменов серверов в бинарниках (`.dex`, `.so`, конфигах).
    -   Автоматический инжект **Frida Gadget** (`libfrida-gadget.so`) с JS-скриптом для динамического обхода SSL Pinning (CertificatePinner, TrustManager).
    -   Статическое сканирование нативных ARM64 библиотек (`.so`) и забивание NOP-инструкциями известных паттернов SSL Pinning.
    -   Авто-пересборка, zipalign и подписание модифицированного APK тестовым ключом.

### 8. 🧩 Движок Символьного Выполнения (Symbolic Execution & SMT Solving)
-   **Интеграция с Z3/Bitwuzla**: мощный Rust-воркер для символьного выполнения (в духе фреймворков angr или Triton).
-   **Автоматический взлом обфускации**: Сервер математически решает Opaque Predicates (непрозрачные предикаты) и автоматически генерирует инпуты, необходимые для достижения нужной ветки кода.
-   **Поиск уязвимостей**: Построение графа условий для автоматического нахождения Use-After-Free или Buffer Overflow.
-   **API Endpoint**: `POST /api/v1/symexec/solve` (передайте SMT-LIB2 код).

### 9. ☢️ Микро-Эмуляция и Снапшот-Фаззинг (AFL++ & OmniSec Micro-Emulator)
-   **Snapshot Fuzzing**: Возможность заморозить процесс в определенной точке, сделать дамп памяти/регистров и мгновенно запустить фаззинг конкретной функции изолированно, без пересоздания процесса.
-   **Micro-Emulation**: Встроенный эмулятор на базе нашего кастомного движка `omnisec-emu-x86` на чистом Rust (обернутый в Rust NIF). Позволяет выполнять подозрительные участки кода или расшифровывать строки абсолютно изолированно прямо в браузере, не рискуя операционной системой.
-   **API Endpoint**: `POST /api/v1/microemu/emulate` (передайте `{ "shellcode_hex": "..." }`).

### 10. 🕳️ Аппаратная Трассировка (Hardware-Assisted Tracing)
-   **Zero-Overhead Tracing**: Использование аппаратных фичей процессоров — Intel PT (Processor Trace) или ARM CoreSight.
-   **Миллионы инструкций без тормозов**: eBPF идеален для перехвата сисколлов, но Intel PT позволяет писать в лог каждую выполненную инструкцию процессора без падения производительности приложения. Это основа нашего Time-Travel отладчика, делающая его самым быстрым в мире.

---

## 🦀 Rust NIF Библиотеки

Сервер использует четыре Rust NIF (`cdylib`) для высокопроизводительных вычислений:

| NIF | Описание | Крейты |
|-----|----------|--------|
| **`omnisec_debugger_nif`** | Интерактивный Time-Travel отладчик: пошаговая трассировка (step/continue), reverse-debugging (reverse_step/continue), breakpoints, watchpoints, чтение/запись памяти и регистров, CFG, memory scan, патчинг. Регистрируется как `Elixir.OmnisecServer.NativeDebugger`. | `omnisec-debugger`, `omnisec-core`, `omnisec-emu-x86`, `iced-x86` |
| **`omnisec_worker_nif`** | Анализ APK/бинарников, YARA (boreal), eBPF трассировка, HDC-автонейминг, ранжирование hotspot. Регистрируется как `Elixir.OmnisecServer.Native`. | `omnisec-ml-inference`, `omnisec-hdc`, `omnisec-ebpf`, `boreal` |
| **`omnisec_symexec_nif`** | Символьное выполнение через Z3 SMT solver для opaque predicate detection. | `omnisec-z3-worker` |
| **`omnisec_micro_emu_nif`** | Микро-эмуляция x86_64 фрагментов кода (shellcode, crypto loops) через `omnisec-emu-x86`. | `omnisec-micro-emu` |

Все NIF скомпилированы в режиме `:release` и работают на dirty CPU schedulers, не блокируя BEAM.

## 🏗 Архитектура

```
                    ┌─────────────────────────────────────┐
                    │         OmniSec Server (Elixir)     │
                    │                                     │
                    │   HTTP API (:inets) ─── Task Supervisor   │
                    │        │              │              │
                    │   WebSocket      WorkerPool         │
                    │   (live status)   │  │  │           │
                    │              ┌────┘  │  └────┐      │
                    │              ▼       ▼       ▼      │
                    │          Worker1  Worker2  Worker3   │
                    │          (Rust)   (Rust)   (Rust)    │
                    └─────────────────────────────────────┘
```

## Running

```bash
mix deps.get   # no-op: zero hex dependencies (OTP stdlib only)
mix compile
mix test
```

The server boots headless by default (worker pool + NIFs, no HTTP).
To expose the REST + WebSocket API, set `enable_endpoint: true` in
config (see `config/dev.exs`) and run `mix run --no-halt`:
HTTP on `OmnisecServer.HttpServer` port (default 4000),
plain-JSON debugger WebSocket on `OmnisecServer.WsServer` port
(default 4001).
