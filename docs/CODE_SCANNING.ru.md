# Интеграция с GitHub code scanning

[English](CODE_SCANNING.md)

Mega-Analyzer выдаёт [SARIF](https://sarifweb.azurewebsites.net/), поэтому его находки
попадают прямо во вкладку **Security → Code scanning** твоего репозитория и
отображаются инлайн в pull request'ах — так же, как у CodeQL.

## Быстрый старт

1. Скопируй [`examples/code-scanning.yml`](../examples/code-scanning.yml) в
   `.github/workflows/security-scan.yml` своего репозитория.
2. Укажи в `target:` артефакт для сканирования (файл APK/DEX/PE/ELF или
   папку декомпилированного приложения).
3. Запушь. Находки появятся в **Security → Code scanning**.

```yaml
- name: Mega-Analyzer scan
  id: scan
  uses: Promastergame/mega-analyzer@v1
  with:
    target: app/build/outputs/apk/release/app-release.apk
    report: full

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.scan.outputs.sarif-file }}
    category: mega-analyzer
```

## Входные параметры Action

| Параметр | По умолчанию | Описание |
| :--- | :--- | :--- |
| `target` | — (обязателен) | Файл или директория для сканирования. |
| `output` | `mega-analyzer-results` | Директория для сгенерированных отчётов. |
| `report` | `full` | Пресет отчёта: `short` \| `default` \| `full` \| `all`. |
| `args` | `""` | Дополнительные флаги анализатора, добавляются дословно (например, `-profile deep`). |

**Выход:** `sarif-file` — путь к сгенерированному `analysis.sarif`.

## Локальный SARIF

CI не обязателен — флаг `-sarif` работает и локально:

```bash
analyzer -t my_app.apk -sarif -report full
# → analysis_output/analysis.sarif
```

Полученный файл скармливай любому инструменту с поддержкой SARIF (VS Code SARIF
Viewer, GitHub, GitLab, SonarQube и т.д.).
