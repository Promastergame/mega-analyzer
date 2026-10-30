# GitHub code scanning integration

[Русский](CODE_SCANNING.ru.md)

Mega-Analyzer emits [SARIF](https://sarifweb.azurewebsites.net/), so its findings
can show up directly in your repository's **Security → Code scanning** tab,
inline on pull requests, just like CodeQL.

## Quick start

1. Copy [`examples/code-scanning.yml`](../examples/code-scanning.yml) to
   `.github/workflows/security-scan.yml` in your repo.
2. Set `target:` to the artifact you want scanned (an APK/DEX/PE/ELF file, or a
   decompiled app directory).
3. Push. Findings appear under **Security → Code scanning**.

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

## Action inputs

| Input | Default | Description |
| :--- | :--- | :--- |
| `target` | — (required) | File or directory to scan. |
| `output` | `mega-analyzer-results` | Directory for generated reports. |
| `report` | `full` | Report preset: `short` \| `default` \| `full` \| `all`. |
| `args` | `""` | Extra analyzer flags appended verbatim (e.g. `-profile deep`). |

**Output:** `sarif-file` — path to the generated `analysis.sarif`.

## Local SARIF

You don't need CI to produce SARIF — the `-sarif` flag works locally too:

```bash
analyzer -t my_app.apk -sarif -report full
# → analysis_output/analysis.sarif
```

Feed that file to any SARIF-aware tool (VS Code SARIF Viewer, GitHub, GitLab,
SonarQube, etc.).
