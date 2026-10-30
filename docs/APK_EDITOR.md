# APK Editor — отдельный репозиторий

Windows IDE, Android-приложение и общее Zig-ядро перенесены в локальный
репозиторий `F:\PROJECTS\apk-editor`. Его исходники и сборка больше не входят
в Mega-Analyzer. История до разделения остаётся в Git этого проекта.

## Сборка и запуск

В папке `apk-editor` выполните:

```powershell
.\build.ps1 -Test
.\apk-editor.exe
```

Нужен Zig `0.17.0-dev.2307+392b17125`. Прямые команды: `zig build`,
`zig build core`, `zig build test`. Сборка Android описана в
`apk-editor/android/README.md`. Основной `build.ps1` Mega-Analyzer собирает
только анализатор и его GNN-библиотеку.

## Связь с анализатором

Редактор работает с декодированными папками самостоятельно. Для декодирования
APK, поиска патчей анализатором и пересборки Smali он запускает внешний
`analyzer.exe` с прежним интерфейсом командной строки и JSON-файлами патчей.

Два соседних репозитория обнаруживают исполняемые файлы друг друга:

```text
PROJECTS/
  mega-analyzer/bin/analyzer.exe
  apk-editor/apk-editor.exe
  apk-editor/zig-out/bin/apk-editor.exe
```

Для другого расположения задайте полные пути перед запуском программ:

```powershell
$env:MEGA_ANALYZER_EXE = 'D:\tools\mega-analyzer\analyzer.exe'
$env:APK_EDITOR_EXE = 'D:\tools\apk-editor\apk-editor.exe'
```

Переменные имеют приоритет над автоматическим поиском. Mega-Analyzer также
ищет IDE рядом со своим EXE, в `bin/` и в `PATH`. Редактор поддерживает
`analyzer.exe` рядом со своим EXE или в собственном `bin/`.
Нужные анализатору DLL должны оставаться рядом с `analyzer.exe`.

Личные настройки IDE перенесены в `apk-editor/apkED.local.configuration`
и исключены из нового Git. Конфигурация и её справочник теперь находятся
в корне репозитория IDE.
