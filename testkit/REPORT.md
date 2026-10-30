# Mega-Analyzer — тестовый корпус + 2 новых детектора

## Важная оговорка

В этой песочнице нет Go/Rust/Zig/Elixir тулчейнов и нет сети (egress
заблокирован), поэтому я не смог собрать `./analyzer` и реально прогнать его
на бинарниках. Зато я прочитал ваш код детекторов (`pkg/internal/secrets`,
`pkg/internal/pipeline/security_heuristics.go` и т.д.) и подобрал паттерны в
тестовых бинарниках так, чтобы они били точно в существующие правила — плюс
руками проверил через `strings`, что нужные байты реально доживают до
stripped release-сборки. Прогнать `./analyzer -t native_test_corpus/bin`
у себя — последний шаг, который остался за вами.

## Тестовый корпус: `native_test_corpus/`

5 сценариев × 2 сборки (debug: `-g -O0`, без strip; release: `-O2 -s`,
стрипнутый) = 10 нативных ELF-бинарников. Имена с суффиксом `.elf`, чтобы
сработал ваш авто-роутинг по расширению (`FlagiFiles.md`: `.so/.dll/.exe/
.elf/.dylib/.bin/.o/.a/.sys`).

| Бинарник | Что внутри | Ожидаемые правила из вашего кода |
|---|---|---|
| `secrets_sample_*.elf` | "config dump" со строками: AWS-ключ (офиц. пример-заглушка Amazon `AKIAIOSFODNN7EXAMPLE`), Slack-токен, JWT (пример с jwt.io), PEM-заголовок приватного ключа | `secret/aws-access-key`, `secret/slack-token`, `secret/jwt-token`, `secret/private-key` (`pkg/internal/secrets/providers.go`) |
| `dangerous_api_sample_*.elf` | вызовы `system("true")` и `dlopen()` на несуществующую библиотеку | строковые эвристики `system(` (critical) и `dlopen` (high) из `security_heuristics.go` |
| `evasion_sample_*.elf` | `ptrace(PTRACE_TRACEME, ...)` self-check + строки `VirtualBox`/`VMware`/`QEMU`/`innotek GmbH` | эвристика `ptrace` (anti-debug, high) + сигналы `SignalPtrace`/anti-VM в `threat_patterns.go`/`threat_aggregator.go` |
| `weak_crypto_sample_*.elf` | ручной однобайтовый XOR-шифр | контрольный кейс на "самопальную крипту" — если у вас есть отдельная эвристика на слабую крипту, здесь можно проверить её срабатывание |
| `clean_control_*.elf` | fibonacci, ничего подозрительного | **должен остаться чистым** — контроль на ложные срабатывания |

Все бинарники — полностью инертные: `system()` вызывает только `true`,
`dlopen()` целится в заведомо несуществующую библиотеку, сеть нигде не
используется. Я специально не совмещал `ptrace(PTRACE_TRACEME)` с
последующим `system()`/`exec()` в одном бинарнике — в первой версии
`dangerous_api_sample` они были вместе, и процесс зависал (уходит в
trace-stop без отладчика, который бы его продолжил). В финальной версии
паттерны разнесены по разным сэмплам, все 10 бинарников проверены — ни один
не виснет.

Проверка сохранности строк после strip (`strings` вручную):
```
secrets_sample_release.elf   → AKIA..., xoxb-..., eyJhbGci..., BEGIN RSA PRIVATE KEY  — всё на месте
dangerous_api_sample_release.elf → system, dlopen  — символы динамического линковщика, strip их не трогает
evasion_sample_release.elf   → ptrace, VirtualBox, VMware, QEMU, innotek GmbH — всё на месте
clean_control_release.elf    → совпадений нет
```

## Что улучшено в самом анализаторе

В `pkg/internal/secrets/providers_extra.go` добавил 2 новых провайдер-правила
(в том же стиле, что и остальные 45 — я сначала прочитал все текущие ID,
чтобы не дублировать):

- `secret/facebook-access-token` — токены Facebook/Meta Graph API (префикс `EAA...`)
- `secret/mapbox-token` — Mapbox `pk./sk.` токены (JWT-подобная структура)

Файл лежит в архиве как `providers_extra.go` — просто замените им
`pkg/internal/secrets/providers_extra.go` у себя. Я прогнал по нему
структурные проверки (баланс скобок/бэктиков, компиляция всех 22 regex через
Python `re` как приближённый аналог RE2), но настоящую сборку `go build` и
юнит-тесты (`providers_extra_test.go`) стоит прогнать у вас — Go-тулчейна
тут нет, так что это не заменяет реальную компиляцию.

## Как прогнать у себя

```bash
go build -trimpath -ldflags "-s -w" -o analyzer ./pkg/cmd/analyzer
./analyzer -t native_test_corpus/bin -report all
# или на каждый файл явно:
./analyzer --scan-native -t native_test_corpus/bin/secrets_sample_release.elf -o ./out
```
