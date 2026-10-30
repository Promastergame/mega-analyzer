# Mega-Analyzer @VERSION@

[English](README.md)

Это **core-сборка**: анализ APK, DEX, Smali, JAR/Minecraft и проверки безопасности
бинарных файлов, отчёты HTML/JSON/SARIF, локальный Web UI и REST API.
Для запуска комплектного демо не нужны Java, Docker или нативные библиотеки.

Запустите из распакованной папки:

```sh
./analyzer -t demo/vulnerable-app -report all -sarif
./analyzer -web
./analyzer --api
```

В Windows используйте `./analyzer.exe` в PowerShell или `analyzer.exe` в cmd.
Отчёты демо появятся в `analysis_output/`. Web UI использует порт 7474,
REST API — 5000. Локальная документация API доступна по `/api/docs`.

Дополнительные движки Rust/Zig/GNN и нативный редактор APK в core-архив не входят.
Для анализа на Android нужны настроенное устройство и Android-инструменты;
сетевые сканы обращаются к явно выбранной цели.
[Различия сборок](https://github.com/Promastergame/mega-analyzer/blob/main/docs/BUILD.ru.md).

Web UI выполняет не более двух сканов одновременно и держит до восьми в очереди.
Лимиты настраиваются через `MEGA_ANALYZER_SCAN_CONCURRENCY` (1–64) и
`MEGA_ANALYZER_WEB_QUEUE_SIZE` (1–128). Ожидающий скан можно отменить до запуска.
Результаты сохраняются в рабочей папке до их удаления пользователем.

`BUILD.json` содержит версию, commit, время сборки и целевую платформу.
При [сообщении об ошибке](https://github.com/Promastergame/mega-analyzer/issues)
приложите его и вывод `analyzer --version`. Уязвимости отправляйте через
[приватный advisory](https://github.com/Promastergame/mega-analyzer/security/advisories/new).
Перед публикацией проверьте логи: они могут содержать данные образца и секреты.

[Быстрый старт](QUICKSTART.md) · [Справочник флагов](FlagiFiles.md)
Mega-Analyzer распространяется под [BSD-3-Clause](LICENSE) ИЛИ [GPLv2](COPYING),
на ваш выбор. Сторонние компоненты сохраняют свои лицензии; см. [NOTICE.txt](NOTICE.txt).

Поддержать Mega-Analyzer можно добровольным [донатом через DonationAlerts](https://www.donationalerts.com/r/promastergame).
