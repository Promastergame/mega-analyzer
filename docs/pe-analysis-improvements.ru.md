# PE-анализ: аудит и направления развития

 Проверено 14 октября 2026 года (обновлено: реальный Windows Frida API-tracer + строгие защиты + структура PE). Основные проблемы находятся в полноте разбора
PE и качестве доказательств Windows-динамики. Увеличение числа сигнатур само
по себе их не исправит.

## Что исправлено

- В [Go-анализаторе](../pkg/internal/apkloader/native_go_analyzer.go) частичный
  ответ `debug/pe.ImportedSymbols` больше не скрывает последующие дескрипторы
  с нулевым `OriginalFirstThunk`. Используется обход с `FirstThunk` для каждого DLL.
- [Обход импортов](../pkg/internal/apkloader/pe_imports.go) читает обычную и
  отложенную таблицы: PE32/PE32+, RVA и старые VA-дескрипторы delay-load,
  INT/IAT fallback, таблицы внутри заголовков. Ordinal-импорты учитываются
  в лимите работы, но имена по ordinal пока не восстанавливаются.
- Таблицы, thunk-массивы и строки ограничены файловыми данными своей секции.
  Виртуальный хвост секции и overlay не становятся вымышленными импортами.
  Незавершённые таблицы и достижение лимита дают `pe-imports-incomplete`.
- [Встроенный API-трейсер](../pkg/internal/sandbox/api_tracer_windows.go) теперь
  реализует реальный user-mode backend на базе Frida ([frida_windows_default.js](../pkg/internal/sandbox/frida_windows_default.js) +
  локальный `frida` CLI / `frida-server`). Подключение `Attach` выполняется
  **до** `resumeProcess()` (пока процесс находится в `CREATE_SUSPENDED`) с
  синхронным ожиданием handshake `FRIDA_SESSION {"type":"ready"}`, а дочерние
  процессы отслеживаются через `FRIDA_CHILD` и монитор процессов. Канал событий
  ограничен по ёмкости со счётчиком отброшенных вызовов (`DroppedCalls`),
  проверяется совместимость версий и ABI (32-bit WOW64 `x86` vs 64-bit `x86_64`),
  а при отсутствии backend/прав/сервера возвращается типизированная ошибка
  (`errAPITracingUnavailable`), попадающая в `degraded_components` без генерации
  синтетических вызовов. Важно: ETW (`Event Tracing for Windows`) наблюдает
  события процессов, образов, файлов и сети, но **не** является перехватом
  произвольного WinAPI и никогда не выдаётся за хуки WinAPI.
- [Сборка динамического отчёта](../pkg/internal/sandbox/sandbox_windows_integration.go)
  исключает источники с отметкой `synthetic` из событий, MITRE-выводов,
  anti-sandbox анализа, таймлайна и сетевого capture. Реально собранные вызовы
  из `APITracer` не помечаются `synthetic` и напрямую поступают в
  `BehaviorAnalysis`. Базовый анализ и построение отчёта сохраняются
  без прав администратора; недоступность и пробелы покрытия отмечаются по компонентам.
  Успешно прочитанные события внешнего kernel-драйвера больше не получают
  безусловную отметку `synthetic`: текущий Go-коллектор читает named pipe,
  а при отсутствии драйвера возвращает ошибку.
- [peinspect](../pkg/internal/peinspect/pe.go) теперь отдаёт структуру: точка входа (RVA + секция), энтропия секций, размер overlay без сертификата, число TLS-callback'ов. Релокации считаются только при валидном блоке (PageRVA + BlockSize + хотя бы одна запись); CFG — только при GuardFlags (CF instrumented / function table / longjump table) или валидном GuardCF check-pointer, а не по факту наличия Load Config. Потребители (`native_go_analyzer.go`, `experimental/pe.go`) переведены на `CFValid`.
- Подпись Authenticode — отдельный результат: `Signature{Status, Kind, Certs, Signers, Integrity, Trust, Note}`. `present` требует структурно валидных WIN_CERTIFICATE/CMS-блоков; integrity/trust остаются `unknown` офлайн с явной пометкой «требуется WinVerifyTrust». `experimental/pe.go` даёт `pe-signed-unverified` (info) вместо молчания при наличии подписи.
- .NET углублён: `DotNetInfo` отдаёт P/Invoke (`ImplMap`: `dll!function`, cap 16) и подозрительные MemberRef-вызовы (Assembly.Load/From, Activator, Reflection.Emit, Process.Start, WebClient и т.д., cap 16) с происхождением из CLI-метаданных. `dotnetFindings` даёт `dotnet-pinvoke` (medium при memory-injection целях) и `dotnet-dynamic-load` (medium).
- Общая схема доказательств: `peinspect/pe_parity_test.go` — единый корпус PE32/PE32+/ARM64/plain/hardened/corrupt с ожидаемыми arch/hardening/completeness; Rust `omnisec-loader-pe` маппинг архитектур зафиксирован в доке крейта.
- Разделение оценок: `NativeFinding.Assessment` (`hardening`/`capability`/`behavior`/`inventory`) проставляется в `mkFinding` — слабый флаг, одиночный импорт и энтропия больше не читаются как вредоносность; скоринг не менялся.
- [Классификатор](../pkg/internal/sandbox/behavior_classifier_windows.go)
  сортирует копию событий по времени, сопоставляет их внутри одного PID,
  нормализует A/W и Nt/Zw-варианты API, требует совпадения цели по пространствам
  имён (`pid:`, `tid:`, `ph:` для `hProcess`/`ProcessHandle`, `th:` для `hThread`/`ThreadHandle`)
  и успешности всех вызовов цепочки (Win32: ненулевой handle/BOOL; NT/Zw/BCrypt: `NTSTATUS == 0`; Reg*: `LSTATUS == 0`).
  Для цепочки нужны все шаги; пороги повторений не суммируются между
  независимыми процессами. Поиск временного окна выполняется за линейное
  время. Некорректные пользовательские фильтры не вызывают panic и не
  расширяют правило. Отсутствие совпадений оставляет `Unknown`.

## Статус P1: Реальный backend Windows API-трассировки (Что РЕАЛЬНО vs Что ещё отсутствует)

Выбранный основной подход P1: **Frida user-mode inline hooking (`Interceptor.attach`) с инжектом до `resumeProcess()`**. ETW (`Event Tracing for Windows`) используется только как наблюдатель событий ядра/провайдеров (процессы, загрузка образов, файлы, сеть) и **не** является перехватом произвольных вызовов WinAPI.

| Компонент / Возможность | Статус сейчас (REAL) | Что ещё отсутствует / Ограничения (Gaps) |
|---|---|---|
| Инжект до запуска (`CREATE_SUSPENDED`) | **REAL**: `sandbox.go` вызывает `startComponents` -> `apiTracer.Attach` до `resumeProcess()`; `Attach` ждёт `FRIDA_SESSION {"type":"ready"}` перед возвратом. | Если внешний инструмент запускает процесс без `CREATE_SUSPENDED`, ранние инструкции до attach могут быть пропущены. |
| Отслеживание дочерних процессов | **REAL**: хуки `CreateProcessW`/`CreateProcessA` извлекают `dwProcessId` из `PROCESS_INFORMATION`, отправляют `FRIDA_CHILD`, и трейсер автоматически вызывает `Attach(childPID)` (плюс fallback через `FollowChildProcess` монитора). | Если дочерний процесс создан без `CREATE_SUSPENDED`, подключение к нему происходит пост-фактум (событие фиксируется в предупреждениях сессии; при ошибке attach пишется `child_attach` в `degraded_components`). |
| Матрица поддерживаемых WinAPI (`WindowsSupportedAPIMatrix`) | **REAL**: `VirtualAllocEx`, `VirtualAlloc`, `VirtualProtectEx`, `VirtualProtect`, `WriteProcessMemory`, `ReadProcessMemory`, `NtAllocateVirtualMemory`/`Zw*`, `NtWriteVirtualMemory`/`Zw*`, `NtProtectVirtualMemory`/`Zw*`, `CreateRemoteThread`, `CreateRemoteThreadEx`, `CreateProcessW`/`A`, `OpenProcess`, `ResumeThread`, `NtUnmapViewOfSection`/`Zw*`, `NtCreateThreadEx`/`Zw*`, `RtlCreateUserThread`, `NtResumeThread`/`Zw*`, `NtCreateUserProcess`/`Zw*`, `CryptEncrypt`, `CryptDecrypt`, `BCryptEncrypt`, `BCryptDecrypt`, `RegSetValueExW`/`A`, `RegCreateKeyExW`/`A`, `NtSetValueKey`/`Zw*`, `CreateFileW`/`A`, `WriteFile`, `DeleteFileW`/`A`, `MoveFileExW`, `connect`, `WSAConnect`, `send`, `WSASend`, `recv`, `WSARecv`. | Прямые `syscall`/`sysenter` в обход `ntdll.dll`, вызовы из неподдерживаемых категорий и отсутствующие экспорты не перехватываются user-mode хуками и явно отражаются как `coverage_gap` / `hook_gap` в `degraded_components`. |
| Корреляция параметров, целей и кодов возврата | **REAL**: каждый `APICall` содержит `Function`, `Parameters[] {Name, Type, Value}`, реальный `ReturnValue` и `LastError` (`GetLastError()`), что позволяет `targetKey()` и `isSuccessfulCall()` подтверждать цепочки T1055 / T1055.012 / T1486 только при совпадении цели и успешном возврате. | Глубокая реконструкция сложных in-memory буферов (например, дамп всего записанного PE-образа из `WriteProcessMemory`) пока не сохраняется в отдельные артефакты. |
| Контроль ABI (32/64-bit), версий и backpressure | **REAL**: проверка `IsWow64Process` (`x86` vs `x86_64`), сверка `major.minor` версий `frida` и `frida-server`, ограниченный канал (`4096`) со счётчиком `DroppedCalls()`, чистый `Detach`/`Stop` без утечек горутин. | Требует установленного `frida` CLI (`frida-tools`) на хосте Windows; при его отсутствии возвращается типизированная ошибка `errAPITracingUnavailable`. |
| Наблюдение процессов/файлов/реестра/сети вне хуков (Kernel / ETW) | **REAL (контракт)**: `kernel_monitor_windows.go` читает реальный named pipe драйвера; ошибки отбрасываются в `degraded_components`. | Драйвер минифильтра (`MegaAnalyzerKernelMonitor`) и реальный парсер событий ETW в `wfp_monitor_windows.go` (сейчас помечен `synthetic`) остаются отдельными задачами и не маскируются под хуки WinAPI. |

## Следующие улучшения по приоритету

| Приоритет | Работа | Практический результат и критерий готовности |
|---|---|---|
| P1 | Реальный backend Windows API-трассировки на Frida + честное разделение с ETW | **Выполнено для user-mode Frida backend**: подключение до возобновления процесса, наблюдение дочерних процессов, явная матрица `WindowsSupportedAPIMatrix`. Реальный ETW-коллектор для сети (`wfp_monitor_windows.go`) остаётся следующим шагом. |
| P1 | Подтверждение цепочек по аргументам и результатам вызовов | **Выполнено**: сопоставление целевого процесса/потока (`pid:`, `tid:`, `ph:`, `th:`), нормализация A/W и Nt/Zw-вариантов API, отбраковка неуспешных вызовов (`0x0`, `INVALID_HANDLE_VALUE`, ненулевой `NTSTATUS`). |
| P1 | Более строгая проверка защит PE | **Выполнено в `peinspect`**: проверяются `GuardFlags`/таблицы/указатели и структура релокационных блоков. |
| P1 | Структурный обзор PE: TLS callbacks, точка входа, энтропия секций, overlay | **Выполнено в `peinspect`**: адреса и секции точки входа, энтропия секций, размер overlay без сертификата, число TLS-callback'ов. |
| P2 | Подпись Authenticode как отдельный результат | В `peinspect` уже разделены наличие сертификата, целостность и доверие. Добавить проверку через Windows с отдельными результатами для embedded/catalog signature; отсутствие сетевой проверки не обозначать как подтверждённое доверие. |
| P2 | Углубление .NET-анализа | Помимо метаданных сборки анализировать IL-вызовы, P/Invoke и загрузку кода. Давать ссылки на методы и происхождение находки. Управляемую сборку и native PE оценивать с учётом различий исполнения. |
| P2 | Общая схема доказательств Go/Rust и единый набор PE-фикстур | В проекте есть отдельные Go- и Rust-парсеры. Вынести общий корпус PE32/PE32+/ARM64/.NET/повреждённых файлов и сравнивать архитектуру, импорты, защиты и полноту разбора. Исправление одного движка не должно создавать незаметное расхождение с другим. |
| P2 | Разделение оценок | Отдельно показывать слабые защиты, потенциальные возможности и наблюдённое поведение. Например, один импорт `CreateProcessW` или высокая энтропия не доказывают вредоносность. Лимит или ошибка наблюдателя должны снижать полноту оценки, а не создавать «чистый» результат. |

В [Rust PE loader](../rust/crates/omnisec-loader-pe/src/lib.rs) TLS, ресурсы,
debug directory и exception data пока перечислены как следующий этап.
Go-улучшения импортов попадают в основной native-поток через
`extractor.go` → `AnalyzeNativeGo` → `enrichNativeReport`, но отдельно
запускаемый Rust loader ещё не получает поддержку delay-load из этих изменений.

## Проверка

Регрессии находятся в
[pe_imports_coverage_test.go](../pkg/internal/apkloader/pe_imports_coverage_test.go)
и [pe_evidence_windows_test.go](../pkg/internal/sandbox/pe_evidence_windows_test.go).
Они используют искусственные PE-буферы и события в памяти; отдельный тест
читает собственный PE-файл, созданный Go-компилятором. Не требуют запуска
анализируемого EXE, изменения реестра или установки драйвера.

```powershell
go vet ./pkg/internal/sandbox/
go test ./pkg/internal/sandbox/ -run 'TestPE|TestBehavior|TestDetect|TestDefault|TestRegistry|TestProcess|TestRansomware|TestAPI' -count=1
go test ./pkg/internal/peinspect ./pkg/internal/apkloader ./pkg/internal/experimental ./pkg/binzap -run '(PE|NativeGo|NativeScan|NativeFile|DotNet|EnrichNativeReport)' -count=1
go test ./pkg/internal/apkloader -run '^$' -fuzz '^FuzzPEImportCoverage$' -fuzztime=10s -parallel=2
```

Настоящий kernel-драйвер (`MegaAnalyzerKernelMonitor`), реальный ETW-потребитель
в `wfp_monitor_windows.go` и автоматическое извлечение распакованного образа из
памяти остаются отдельными этапами; их отсутствие явно фиксируется в
`degraded_components` и не подменяется демонстрационными данными.
