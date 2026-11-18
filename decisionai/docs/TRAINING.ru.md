# Обучение на своих данных

Как из размеченных JSONL получается чистая выборка для `train_embed.py`
и как не завысить оценку пересечением train/dev/test.

## Почему так строго

В старых `train/dev` пересекались 38 текстов состояний — оценка была завышена.
Теперь правило простое: **связанные примеры (дубликаты, парафразы, почти
дубликаты ≥0.9) всегда лежат в одном сплите**, а holdout-наборы из `evals/`
в обучение не попадают вообще.

## Путь данных

```
сырые *.labelled.jsonl
  → scripts/data/corpus.py import      (SQLite data/local/corpus.sqlite3, дедуп, карантин конфликтов)
  → scripts/data/corpus.py export      (чистые train/dev/test + manifest.json с sha256)
  → dai data-check -input <файл>       (валидация меток: null запрещён, распределения — по словарю)
  → train_embed.py                     (на старте data_checks.check_directory: стоп при пересечении с тестами)
```

## Команды

```powershell
# собрать корпус v1 из данных проекта (идемпотентно, повтор даёт те же файлы)
python scripts/data/prepare_project.py --output data/prepared/v1
# что внутри: статистика, происхождение, исключённые примеры
python scripts/data/corpus.py stats --db data/local/corpus.sqlite3
# проверить один файл перед обучением/калибровкой
go run ./cmd/dai data-check -input data/prepared/v1/train.labelled.jsonl
```

`data/local/` и `data/prepared/` — в `.gitignore`: база и выборки
пересобираются из исходников, в репозиторий едет только код и `manifest.json`
рядом с выборкой (для сверки `files.<имя>` — sha256 содержимого).

## Формат строк

Одна строка — один пример: `{"state": {...}, "questions": {...}, "labels": {...}}`.
Метка `noul` — число 0..1 (или boolean), `choice` — ключ из `criteria`,
`score` — ключ-уровень. `null` в метках запрещён: раньше он молча считался
ответом «нет» (`s1/labels.go`, тест `TestLabelsRejectNullAndInvalidDistributions`).

## Контроль качества

CI гоняет `eval` с порогами на шести holdout-наборах
(`.github/workflows/ci.yml`, шаг golden eval) и юнит-тесты целостности
(`scripts/data/test_corpus.py`, `scripts/distill/test_data_checks.py`,
`s1/labels_test.go`, `cmd/dai/data_test.go`). Упавший порог = регрессия,
чинить моделью или данными, а не порогом.
