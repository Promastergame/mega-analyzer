# Проверка Android anti-VM, 2 ноября 2026

## Реальный AVD

Доступны `MegaAnalyzer_API_28` (Android 9, x86_64) и
`MegaAnalyzer_API_35` (Android 15, x86_64). Образа API 24/25 для Android 7
в используемом SDK нет. AVD `bsd_x64` и `bsd_arm64` зарегистрированы как API 33.

Android 9 успешно загружен штатным Android Emulator 37.2.12 с WHPX на
Windows 10.0.19045. Запуск без окна, с `-read-only`, без Quick Boot,
на `emulator-5572`. Итоговый профиль — выдуманная модель **PromasterPhone 1**,
бренд `promaster`, производитель `Promaster`, device/product `promasterphone1`.
Профиль соответствует установленным Android 9/API 28/x86_64.

Команда полного прогона с чистого запуска:

```powershell
./scripts/android-lab.ps1 -Action Start -ApiLevel 28 -Port 5572 -MaskIdentity
```

| Модуль | Результат | Наблюдение |
| --- | --- | --- |
| identity | passed | Обычный APK видит PromasterPhone 1 / Promaster / promasterphone1, hardware qcom, board sdm845, новый fingerprint и build ID. |
| environment | passed | Прочитаны `ro.kernel.qemu=0`, `ro.boot.qemu=0`, `ro.debuggable=0`, `ro.secure=1`; APK видит `user`, `release-keys`. |
| battery | passed | Прочитаны уровень 71, discharging, температура 315, здоровье good, питание none. |
| display | passed | Прочитаны действующие размер 1080x2160 и плотность 440. |

Отдельная проверка APK подтвердила 13 полей, включая `Settings.Global.device_name`,
security patch и fingerprint
`promaster/promasterphone1/promasterphone1:9/PQ3A.190801.101/190801:user/release-keys`.
Исходная модель `Android SDK built for x86_64` изменилась на `PromasterPhone 1`.
Свежесть обоих снимков подтверждается разными `capture_id`. Итого: `passed`,
код выхода 0, без отказов применения.

Для обновления `Build.*` перезапускается zygote с ожиданием разблокировки
пользователя 0. На Android 9 отключение QEMU-флага выявило смешивание
EGL/GLES-библиотек emulation и SwiftShader при поиске драйверов. Исправление
создаёт согласованные алиасы через hard link во временном bind mount,
сохраняя SELinux-контексты. Системные образы и содержимое библиотек не меняются.
После итогового прогона AVD оставлен запущенным с PromasterPhone 1.

Файлы QEMU/goldfish, некоторые служебные свойства, HAL и x86_64 остаются
доступными. Подтверждено изменение основных идентификаторов и двух QEMU-флагов;
полное скрытие эмулятора не подтверждено.

Снимки APK и отчёты скопированы в [promasterphone-1-api28](promasterphone-1-api28/).
Полная сессия: `.tmp/android-lab/identity-20261102-111216-028/`.
Ранний диагностический прогон без root-помощника, где обычный `setprop` не смог
изменить `ro.*`: `.tmp/android-lab/antivm-20261102-100157-493/`.
Дополнительный реальный прогон батареи со статусом `not-charging`, питанием USB
и температурой 315 также получил `passed` по всем пяти полям; снимки находятся
в `.tmp/android-lab/battery-usb-validation/`.
Те ранние временные изменения не сохранены в базовый AVD.

## Номер SIM и признаки ADB/USB

Номер виртуальной SIM изменён с `+15555215572` на выбранный тестовый
`+12025550123` параметром эмулятора `-phone-number`. Повторный полный прогон
на API 28 получил `passed`, код выхода 0; APK подтвердил 14 полей, включая
номер, прочитанный через `TelephonyManager`. Модель остаётся PromasterPhone 1.

```powershell
./scripts/android-lab.ps1 -Action Start -ApiLevel 28 -Port 5572 `
  -Restart -PhoneNumber '+1 202 555 0123' -MaskIdentity
```

Проверка из обычного APK: `adb_enabled=1`, `usb_state_available=false`,
`usb_connected=null`. Это подтверждает видимость включённой отладки, но не
физическое USB-подключение: sticky broadcast USB_STATE на этом AVD отсутствует.
ADB оставлена включённой для scrcpy и управления лабораторией.

Снимок до перезапуска и итоговые отчёты: [phone-number-api28](phone-number-api28/).
Полная сессия: `.tmp/android-lab/identity-20261102-115724-470/`.
Также проверены отклонение слишком длинных номеров, внедрённых команд/переносов
строк и запуск PhoneNumber/Restart с неподходящим Action; PowerShell parser
и сборка APK завершились успешно.

## Android 15

На Emulator 37.2.13 загрузка с WHPX не достигла готовности за 240 секунд.
На штатном Emulator 37.2.12 процесс QEMU завершился с `0xC0000005` до готовности
Android. Minidump указывает на `qemu-system-x86_64-headless.exe`, offset
`0x2664ad7`, попытку записи по адресу 0. Это ошибка процесса эмулятора на хосте;
прогон модулей anti-VM на Android 15 не выполнен.

Логи последней попытки: `.tmp/android-lab/MegaAnalyzer_API_35-5570.stdout.log`
и `.stderr.log`. Программная эмуляция CPU на Android 9 также падала с
`0xC0000005`; рабочим оказался режим WHPX.

## Автоматические проверки

Успешно выполнены:

```text
go test -timeout 90s ./tools/android-propwriter ./pkg/antivm ./pkg/internal/antivm/...
go vet ./tools/android-propwriter ./pkg/antivm ./pkg/internal/antivm/...
go build -o .tmp/android-lab/antivm.exe ./cmd/antivm
```

PowerShell parser проверил синтаксис `scripts/android-lab.ps1`.
Оба профиля PromasterPhone 1 прошли `profile validate`. Linux-тесты помощника
выполнены внутри AVD: поиск свойств, обработка повреждённого trie, запись
короткого/длинного read-only значения и отказ при активном писателе — `PASS`.
Регрессионные тесты покрывают проверку без применения операций, сохранение
исходного replay, отказы команд при совпавшем состоянии, продолжение после
критического отказа, несовпадения API/ABI, чтение состояния батареи и дисплея,
признаки QEMU в ключах и значения порога `session diff`.
Также проверены корректный статус `passed` для успешной группы и сравнение
уровня батареи 0% (раньше нулевое значение пропускалось).
