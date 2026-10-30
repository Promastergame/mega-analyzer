# patch_patterns_src — модульная база паттернов

Каталог с **исходниками** базы уязвимых паттернов, разбитыми по категориям.
Из них собирается рантайм-файл `../patch_patterns.json`, который читает загрузчик
(`mustLoadVulnerablePatterns`).

## Структура

| Файл | Содержание |
|------|-----------|
| `<NN>_<category>.json` | Массив паттернов одной категории (например `05_root_detection.json`) |
| `_manifest.json` | Порядок склейки категорий |
| `build.sh` | Сборка `../patch_patterns.json` из посекционных файлов (нужен `jq`) |

## Как редактировать

1. Открой нужный файл категории, например `18_currency.json`.
2. Добавь/поправь паттерн (схема — как у `VulnerablePattern` в `patterns_types.go`):

   ```json
   {
     "id": "pj42",
     "category": "currency",
     "description": "…",
     "method_names": ["getcoins"],
     "class_patterns": ["currency"],
     "required_calls": [],
     "string_patterns": ["coins"],
     "return_type": "I",
     "patch_type": "return_max_int",
     "weight": 1.0,
     "min_match_score": 10
   }
   ```

3. Пересобери базу:

   ```bash
   ./build.sh          # записать ../patch_patterns.json
   ./build.sh --check  # только проверить уникальность id
   ```

## Правила

- **`id` уникален** по всей базе (`build.sh` падает при дублях).
- `return_type`: `Z` (boolean), `V` (void), `I` (int), либо JVM-дескриптор.
- `patch_type`: `return_true`, `return_false`, `return_void`, `return_max_int`,
  `nop`, `remove_check`, `const_replace` (см. `PatchType` в `patterns_types.go`).
- `method_names` / `class_patterns` / `string_patterns` сравниваются в нижнем регистре.

## Важно про порядок

Текущий `../patch_patterns.json` содержит 74 исходных паттерна (в исходном
порядке) + новые. `build.sh` пересобирает файл в порядке категорий из манифеста —
набор паттернов идентичен, меняется только порядок в массиве (на матчинг не
влияет: каждый паттерн независим).
