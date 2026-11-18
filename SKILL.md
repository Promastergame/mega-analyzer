---
name: mega-analyzer-web
description: Собрать и обновить mega-analyzer.lol из текущего Go-анализатора через WASM, отдельный GitHub-репозиторий и Netlify. Использовать для сайта Mega Analyzer и диагностики его сборки.
---

# Mega Analyzer → сайт

## Проект и публикация

- Исходники: `F:/PROJECTS/mega-analyzer`.
- Основной Windows CLI: `bin/analyzer.exe`; параметры его сборки проверять командой `go version -m bin/analyzer.exe`.
- Статический сайт: `F:/PROJECTS/mega-analyzer-site`, GitHub `Promastergame/mega-analyzer-site`, ветка `main`.
- Netlify автоматически публикует этот репозиторий: `publish = "."`, без команды сборки.
- Сайт: https://mega-analyzer.lol; резервный адрес: https://mega-analyzer.netlify.app.
- Панель проекта: https://app.netlify.com/projects/mega-analyzer/overview.

Сайт использует существующий `analyzer --web`: assets в `pkg/cmd/analyzer/web/assets`, браузерный адаптер в `web/wasm`, Go entry point в `pkg/cmd/analyzer/main_wasm.go`. Не подменять его старым движком из `dist/browser`.

EXE из `bin` — ориентир для версии и возможностей, а не вход WASM-компилятора. Windows EXE нельзя перекомпилировать в WASM без исходников. Собирай обе цели из текущего checkout. Go версия указана в `go.mod`; `wasm_exec.js` всегда должен быть из того же Go toolchain, что и WASM.

## Сборка

Сначала проверь `git status --short`, инструкции workspace и версию Go. В основном checkout могут быть чужие незакоммиченные изменения. Сохраняй их и не отправляй основной приватный репозиторий в репозиторий сайта.

Из `F:/PROJECTS/mega-analyzer`:

```powershell
go version
go version -m bin/analyzer.exe
rustup target add wasm32-unknown-unknown
python scripts/build_web_site.py --output .tmp/site/release
node scripts/test_web_wasm.cjs .tmp/site/release
node scripts/test_gnn_wasm.cjs .tmp/site/release
node scripts/test_web_memfs.cjs
go test ./pkg/internal/piracy ./pkg/internal/pipeline
go test ./pkg/cmd/analyzer/web ./pkg/cmd/analyzer
node scripts/test-scan-ui.cjs
node scripts/test-workspace-ui.cjs
```

Builder сам устанавливает `GOOS=js`, `GOARCH=wasm`, `CGO_ENABLED=0`, включает обычные оптимизации Go и inlining, применяет `-trimpath` и `-ldflags=-s -w`, копирует UI, Worker, runtime, лицензии, CSP и Netlify config. Не использовать отладочные `-gcflags="all=-N -l"`. `build-info.json` содержит SHA WASM, fingerprint реально выбранных исходников, commit и признак dirty checkout.

Движок загружается из `static/analyzer.wasm.gz`: Netlify должен отдавать `Content-Encoding: gzip` и `Content-Type: application/wasm` из `_headers`. Те же gzip/MIME-заголовки обязательны для gnn.wasm.gz. Raw WASM сохраняется для тестов. При локальной проверке настрой такие же заголовки; обычный `python -m http.server` без них не декодирует gzip в браузере.

При изменениях Go всегда делай свежую сборку. `--wasm` предназначен только для уже проверенного артефакта, собранного нужным компилятором; он не доказывает соответствие текущим исходникам. Размер файла сам по себе не определяет версию и скорость.

Если пользователь просит обновить Windows CLI, используй `build.ps1` (Rust release GNN + Go CGO с `omnisec_ml_gnn`) либо его проверенную последовательность. Собирай во временный EXE, проверяй его, затем замени `bin/analyzer.exe`. Не затирай работающий процесс и не прерывай активный анализ. При перезапуске `--web` сохраняй текущие параметры и запускай скрыто через `Start-Process -WindowStyle Hidden`.

## Браузерные ограничения и проверки

Анализ выполняется локально: файлы не загружаются, HTTP внутри Go Workers заблокирован. Для каждого задания создаётся новый пул Workers с отдельными runtime и FS; скомпилированный WASM Module переиспользуется в пределах вкладки. Stop и таймаут завершают весь пул. Ограничения: 512 MiB входа, 1024 MiB виртуальных файлов и 20 000 entries на Worker. Таймаут задаётся ползунком или числом от 0 до 3600 секунд; 0 отключает его, по умолчанию 300. Настройки сохраняются в localStorage.

Для full/minecraft пользователь выбирает 1–4 настоящих браузерных Workers (по умолчанию 2). Координатор входит в это число: при 4 это координатор и 3 помощника. Помощники через MessageChannels получают отдельные файлы/классы для matcher, piracy и 22 проверенных независимых детекторов. Для детекторов операндов помощник разбирает AST класса. Общие состояния и связи остаются в координаторе. Smali/CFG, детекторы с общим состоянием, графы, data flow и отчёт выполняются один раз в координаторе; порядок находок сохраняется, ошибка отдельного помощника повторяет сканирование локально. Другие инструменты выполняют неделимую трансформацию в одном Worker. Go goroutines внутри одного Worker сами по себе не добавляют ядра. Не копировать весь APK помощникам и не запускать полный анализ независимо в каждом Worker. Четыре runtime требуют больше памяти; скорость измерять на одинаковом входе и настройках.

Перед первым запуском показывается закрываемый диалог по центру с напоминанием сохранить результаты до обновления страницы. Крестик, кнопка, Escape и клик снаружи закрывают его. Галочка «Больше не показывать» сохраняет `ma-browser-notice-hidden=1`; её действие проверять после перезагрузки. Настройки используют `ma-browser-workers` и `ma-browser-timeout`. Постоянный верхний баннер не возвращать.

DecisionAI отсутствует в веб-меню и маршрутах. Устройства, VM, внешние процессы и proxy доступны только в desktop CLI. Настоящий GNN включён в браузере: builder собирает omnisec-ml-gnn для wasm32-unknown-unknown с release, LTO и simd128. web/wasm/gnn.js передаёт графы Go в отдельную память Rust; runner_gnn.go использует ту же классификацию и пороги, что CLI. Веса брать из rust/gnn_weights.json, сверяя SHA с моделью CLI. Модель и модуль загружаются один раз на вкладку, каждый анализ получает новую память Rust. Не использовать dummy-веса и не записывать training dataset в браузере. -skip-gnn сохраняет действие. Проверяй настоящий inference и паритет вероятностей с native DLL через scripts/test_gnn_wasm.cjs. При экспорте --wasm рядом нужны gnn.wasm и gnn_weights.json из проверенного release; build-info содержит их SHA. Не подключай сервер анализа или `box.ps1` для этого статического сайта.

При изменениях правил проверяй конкретные ложные срабатывания и контрольные опасные примеры. Не скрывай слабое доказательство простым уменьшением риска: сохраняй его как observation с причиной. Для скорости сравни один APK, одинаковый профиль и одинаковую среду; отделяй загрузку движка, scan, post-processing и отчёты.

Для профиля детектора на локальной декодированной копии APK установи `MEGA_ANALYZER_BENCH_CORPUS` и запусти `go test ./pkg/internal/piracy -run '^$' -bench '^BenchmarkPiracyCorpus$' -benchtime=3x -cpuprofile F:/PROJECTS/mega-analyzer/.tmp/piracy.pprof -o F:/PROJECTS/mega-analyzer/.tmp/piracy-bench.exe`. Benchmark отключает кэш повторных входов и не включает приватные образцы в репозиторий. Отдельно проверяй полный WASM-прогон: микробенчмарк не доказывает ускорение всего анализа.

Integration suite проверяет настоящие Go WASM, пул 1/4 с одинаковыми результатами и задачами помощников, сборку APK, Smali decode, отчёты, diff, ZIP metadata, workspace, диапазоны настроек и завершение всего пула по Stop/таймауту. Дополнительно проверь видимый числовой ввод 1/4 и таймаута ниже/выше 300, сохранение настроек, диалог, выбор файла, запуск помощников, preview и скачивание в настоящем браузере. Отмена скачивания в тестовом браузере не доказывает неисправность ZIP. Подробности: `F:/PROJECTS/mega-analyzer/docs/web-wasm.md`.

## Обновление Netlify

После проверок экспортируй проверенный артефакт в отдельный checkout (не запускай Git-чтения параллельно с записью туда):

```powershell
python scripts/build_web_site.py --wasm .tmp/site/release/static/analyzer.wasm --output F:/PROJECTS/mega-analyzer-site
git -C F:/PROJECTS/mega-analyzer-site status --short
```

Builder сохраняет исходный `build-info.json` из release, если SHA и версия Go совпадают. Просмотри diff, закоммить только артефакты сайта и push в `main` в рамках разрешённого пользователем обновления. Для HTTPS используется сохранённая авторизация `gh`:

```powershell
git -C F:/PROJECTS/mega-analyzer-site -c http.sslBackend=schannel -c credential.helper='!gh auth git-credential' push origin main
```

Не запрашивай повторный вход, пока не проверены имеющиеся credentials и DNS. Не выводи токены. После deploy сравни публичный `build-info.json` с release и проверь HTTPS и перенаправление `www`.

Для REG.RU используются `A @ → 75.2.60.5`, `CNAME www → mega-analyzer.netlify.app`. Если появляется парковка, сравни авторитетные DNS, 1.1.1.1 и системный DNS: старый рекурсивный кеш может сохраняться до TTL. Не меняй правильные записи повторно и не фиксируй IP в hosts. Не трогай другие Netlify-проекты.

Проценты CLI в браузере передавать как SSE progress, чтобы UI перерисовывал одну строку; полный scan.log сохранять. Для resources.arsc.json не выключать анализ: поиск regex использует обязательные литералы с проверкой Unicode-fold и кандидаты безопасного ASCII-префикса, затем исходный regex. Проверять совпадение находок и смещений.

При активном пуле браузера физические файлы подаёт одна Go-горутина; классы DEX сохраняют выбранную параллельность. Это даёт MessagePort-ответам время войти в Go. Помощники инициализируют только свои независимые детекторы. memfs использует геометрический рост буферов отчётов и уплотнение под лимитом, обнуляет truncate/holes и переносит только логический размер файла. Проверять test_web_memfs.cjs.

## Проверка ложных срабатываний

Для GNN `license-check` одного score/графа недостаточно: runner_gnn_semantics.go требует независимый вызов Android licensing API либо лицензионный протокол вместе с ветвлением/проверкой подписи. Условные wrappers допускаются на один вызов от подтверждённого verifier; метка не распространяется по всему графу. Предсказания без подтверждения сохраняются в GNN_DIAGNOSTICS.json как observation с причиной license_semantics_not_corroborated и счётчиком uncorroborated_predictions. Не повышать порог confidence вместо проверки семантики.

Data-flow CHA может развернуть интерфейсный/виртуальный вызов на несколько реализаций, включая несвязанные Parcelable.Creator и ветки R8 merged classes. Пока receiver не разрешён, шаг помечается unresolved_dispatch. Пути к Class.forName/reflection через такой шаг — inventory с сохранённым source, sink и path. Имя пакета/IsAppCode и отрицательный GNN не являются доказательством безопасности: прямой внешний input→loader остаётся vulnerability даже в library namespace. Проверяй отрицательные и положительные controls в unresolved_dispatch_test.go и fp_dispatch_test.go.

allowBackup=true — наблюдение о политике, не доказательство извлечения private data через adb. Проверяй Android/device API, target SDK, backup rules и включённые чувствительные данные. Импорт syscall — inventory; сам импорт не доказывает обход hooks. При наличии массива typed findings сводка сайта берёт его как итоговую проекцию и не добавляет повторно raw artifact_findings с прежней severity.

Incomplete analysis сохраняется при реальном лимите охвата. Run limitations и сводка показывают число truncated data-flow slices и stop_reason; это ограничение анализа, не обнаруженная угроза.
