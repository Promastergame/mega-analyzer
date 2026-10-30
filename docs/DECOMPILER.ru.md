# Отдельный декомпилятор

`cmd/decompiler` — самостоятельная команда для APK, ZIP-контейнеров APK и одиночных
DEX. Она использует публичный пакет `pkg/decompiler`. Команда `analyzer decode`
обращается к этому же API.

По умолчанию используется нативный Go backend. Наличие Java/Android SDK не меняет
его выбор; поиск и запуск внешних инструментов выполняются только при явном
`--backend baksmali`. Декомпиляция не запускает сканирование безопасности.

## Сборка и запуск

Из корня репозитория, Go 1.27.3+:

```powershell
go build -trimpath -tags noembed -o bin/decompiler.exe ./cmd/decompiler
./bin/decompiler.exe app.apk -o decoded_app
./bin/decompiler.exe classes.dex -o decoded_dex --json
```

На Linux/macOS имя бинарника можно задать как `bin/decompiler`.
Для сборки без C toolchain установите `CGO_ENABLED=0`.
Тег `noembed` исключает вложенные инструменты совместимости из бинарника.

Одиночный DEX сохраняется как `classes.dex`, классы — в `smali/`.
Для APK с несколькими DEX используются `smali/`, `smali_classes2/` и т. д.
Исходные DEX сохраняются для последующей пересборки.

| Параметр | Действие |
| --- | --- |
| `-o`, `--output` | Выходной каталог; по умолчанию `decoded_<имя>` в текущем каталоге |
| `--backend native` | Нативный декодер; `auto` также выбирает его |
| `--standalone` | Запрещает внешний backend для этого запуска |
| `--json` | Один JSON-результат в stdout, в том числе при ошибке декодирования |
| `--timeout 2m` | Ограничение времени; Ctrl+C также отменяет работу |
| `--headers` | Комментарии с источником и хешем DEX в нативном Smali |
| `--java-view` | Рядом со Smali пишет `.java`-псевдокод методов (структурный, Smali первичен) |
| `--no-smali` | Сохраняет DEX без генерации Smali |
| `--no-resources` | Пропускает этап декодирования ресурсов |
| `--class-cache=false` | Отключает кэш генерации Smali; обработка DEX остаётся параллельной |
| `--copy-original` | Сохраняет META-INF в `original/` |

Опции можно указывать до или после входного файла. Для имён, начинающихся с `-`,
используйте разделитель `--`. Справка: `decompiler --help`.

Совместимость с baksmali включается явно:

```powershell
./bin/decompiler.exe app.apk -o decoded_compat --backend baksmali --baksmali-jar tools/baksmali.jar --java java
```

Ошибка явно выбранного baksmali возвращается вызывающему коду. Незаметного
переключения на другой backend нет.

## Результат и ошибки

JSON содержит `input`, `output_dir`, `backend`, `complete`, `dex_files`,
`smali_files`, необязательные `warnings` и, при ошибке, `error`.
Счётчики файлов заполняются после успешного декодирования.

Коды завершения: `0` — успех, `1` — ошибка декодирования или записи результата,
`2` — ошибка аргументов, `130` — отмена через Ctrl+C.
Ошибки разбора аргументов и справка выводятся в stderr.

При ошибке каталог может содержать частичные артефакты. Использовать их как
успешный результат нельзя: проверяйте код завершения и `complete`.
Повреждённые DEX, ресурсы и split APK приводят к ошибке, а предыдущий маркер
успешного кэша сбрасывается до изменения файлов.

Для каждого входного проекта используйте отдельный выходной каталог.
Повторное декодирование может заменить сгенерированные файлы; каталог с ручными
правками следует сохранить отдельно. Два одновременных запуска должны писать
в разные каталоги.

## Go API

```go
import (
    "context"
    "time"

    "mega-analyzer/pkg/decompiler"
)

ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
defer cancel()

result, err := decompiler.Decode(ctx, "app.apk", decompiler.Options{
    OutputDir:  "decoded_app",
    Standalone: true,
    ClassCache: true,
})
if err != nil {
    // result.OutputDir и result.Warnings доступны для диагностики.
    return err
}
// result.Complete == true; result.SmaliFiles содержит число файлов.
```

Внешние типы из `pkg/internal` в контракт не входят. Каждый вызов создаёт свой
загрузчик и передаёт настройки заголовков/standalone как значения. Вызовы не
изменяют глобальные `SetStandalone` и `DisableSmaliHeaders`.

Это публичный пакет и отдельная программа внутри существующего Go-модуля.
Парсер DEX, Smali и работа с ресурсами пока общие с `apkloader`; отдельного
`go.mod` и независимого цикла версий у декомпилятора нет.
Вывод — Smali и ресурсы, а не восстановленный Java/Kotlin-проект. Флаг
`--java-view` добавляет структурный псевдокод (`.java` рядом со `.smali`):
циклы, ветвления и вызовы с результатами; Smali остаётся первичным.

Обратный путь тоже без внешних инструментов: встроенный ассемблер
Smali→DEX (все таблицы DEX, try/catch, payload, multidex-раскладка по
`smali*/`-каталогам, checksum/signature), overlay-энкодер AXML
(манифест и layout поверх оригинального бинаря, resource ID сохраняются) и
адресные правки `resources.arsc` лежат в `pkg/internal/apkloader`.
Подпись — встроенная v1+v2+v3 (RSA-2048, self-signed debug key),
выравнивание — 4 байта и 16 KiB для несжатых `.so`.

## Сборка проекта без SDK

Команда `analyzer build` по умолчанию запрещает обнаружение, распаковку и запуск
внешних инструментов сборки. Наличие установленной Java или Android SDK ничего
не меняет. Веб-режимы «Декодировать» и «Собрать APK» также используют эту политику.

```powershell
./bin/analyzer.exe build decoded_app -o rebuilt.apk
./bin/analyzer.exe build project.zip -o built.apk
./bin/analyzer.exe build examples/native-apk/project -o bin/native-demo.apk
```

ZIP должен содержать один проект с `AndroidManifest.xml` в корне либо в одной
внешней папке. Архив распаковывается во временный каталог и остаётся неизменным.
Выходной APK следует писать вне исходного каталога. В браузере загрузите ZIP
в режиме «Собрать APK» и скачайте `app.apk` из файлов результата.

Код проекта — Smali (`smali/`, `smali_classes2/`, …) или готовый DEX.
`d8` не требуется: встроенный ассемблер сразу создаёт DEX. `android.jar` не
требуется для разрешения ссылок из Smali: классы Android предоставляет среда
исполнения на устройстве. Это не компилятор Java/Kotlin и не реализация Gradle:
проекты с такими исходниками возвращают ошибку вместо APK с потерянным кодом.
Файлы `.java` рядом со Smali остаются только псевдокодом и в сборку не входят.

Для нового проекта встроенный компилятор создаёт бинарный манифест и таблицу
ресурсов. Неподдерживаемые конструкции возвращают ошибку; наличие ZIP-файла
само по себе не считается успешной сборкой. Пример минимального приложения:
[examples/native-apk](../examples/native-apk/README.md).

Подпись по умолчанию — отладочный ключ. Для внешнего keystore/apksigner или
других средств совместимости требуется явный `--allow-external-tools`; этот
параметр несовместим с `--standalone` и недоступен через веб-форму сборки.
Проверка подписи и структуры не подтверждает установку и запуск на устройстве.

## Проверка

```sh
go test -tags noembed ./pkg/decompiler ./cmd/decompiler
go test -race -tags noembed ./pkg/decompiler ./cmd/decompiler
go test -tags noembed ./pkg/internal/apkloader
go test -tags noembed ./pkg/cmd/analyzer -run TestHandleDecode
```

Новые тесты используют синтетический DEX, собранный встроенным ассемблером:
проверяются сохранность DEX, содержимое Smali, несколько DEX, смена настроек
кэша, параллельные вызовы, частичные ошибки, отмена и JSON команды.
Для них не нужны Java, Android SDK или устройство.

Направления дальнейшего разделения описаны в [MODULES.ru.md](MODULES.ru.md).
