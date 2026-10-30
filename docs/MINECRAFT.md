# Minecraft Bedrock packs

The dedicated Minecraft mode reads Bedrock pack contents without running
scripts, game commands or Minecraft itself. It supports `.zip`,
`.mcpack`, `.mcaddon` and extracted directories. Java mods (`.jar`,
Fabric/Quilt/Forge descriptors, bytecode) belong to the JAR analyzer
(`analyzer -t mod.jar`), not here.

## Run

```powershell
# Main executable, after rebuilding from these sources
go build -o bin/analyzer-minecraft.exe ./pkg/cmd/analyzer
.\bin\analyzer-minecraft.exe -minecraft -t "C:\Downloads\addon.mcaddon" -o analysis_output/minecraft
.\bin\analyzer-minecraft.exe -minecraft -t "C:\Downloads\addon.mcaddon" -json

# Browser: select “Minecraft mods & packs” in Analyze
.\bin\analyzer-minecraft.exe -web

# Small standalone CLI, with configurable archive limits
go run ./cmd/minecraft-analyze -path pack.mcpack -output analysis_output/minecraft
go run ./cmd/minecraft-analyze -path textures.zip -json
go run ./cmd/minecraft-analyze -path large-pack.zip -max-entry-mb 64 -max-expand-mb 1024
```

Reports: `REPORT.html` (self-contained, mobile-friendly) and `analysis.json`.
`-json` writes only JSON to stdout and does not write reports. The main CLI
also honors `-timeout` (seconds) and `-max-files` (shared entry count).

## Supported checks

| Content | Inspection |
| --- | --- |
| Java resource/data packs | `pack.mcmeta`, text-component descriptions, declared pack formats; sibling `data/` and `assets/` classification |
| Bedrock | JSON/JSONC manifest, UUID/version validation, module types, script entry existence, bundled dependency UUID/version matching |
| Nested archives | Recursive ZIP/MCPACK/MCADDON inspection, including two packs inside an add-on (`.jar` entries are skipped with a pointer to the JAR analyzer) |
| Scripts | Static indicators for OS shells, dynamic evaluation, credentials, webhooks and privileged game commands |
| Assets | Inventory of textures/models/sounds/languages; PNG/JPEG dimensions and large-texture memory estimate |
| Archive integrity | CRC/read failures, unsafe paths, case collisions, symbolic links, extreme compression and shared resource limits |

External dependencies are informational: a required pack may already be
installed in the game. A bundled version mismatch is a separate finding.
Ordinary metadata URLs, reflection and standard Script API modules do not
increase the score by themselves.

## Limits and interpretation

Defaults: 256 MiB input, 512 MiB expanded content across all levels, 32 MiB per
entry, 50,000 shared entries and three nested levels. No archive entry is
extracted to disk. Directory symbolic links are skipped; file reads are
confined with `os.Root`. SHA-256 describes the original archive; directories
do not have a synthetic archive hash.

`complete: false` means some content could not be fully inspected (for example,
size limits, invalid JSON or a damaged ZIP entry). See findings for the reason. The score is a bounded sum of unique
indicator categories, **not a malware probability or a safety certificate**.
Static references do not prove a call is reachable or executed.

Marketplace encrypted content is not decrypted. Native code, image pixel payloads, trust
signatures and compatibility with an installed mod set are not evaluated. Java
archives and bytecode are out of scope here — see the JAR analyzer.

## Проверка на русском

Форматы дополнений Bedrock называются **`.mcpack`** (пак) и **`.mcaddon`**
(сборка паков). В веб-интерфейсе откройте **Minecraft mods & packs**, выберите
файл и нажмите **Analyze**. Кнопка **Open Report** откроет отчёт с русской
навигацией: пакеты и версии, зависимости, находки и список файлов.

Для распакованной папки используйте CLI:

```powershell
.\bin\analyzer-minecraft.exe -minecraft -t "C:\Minecraft\resourcepacks\MyPack" -o analysis_output/my-pack
```

## Validation

```text
go test ./pkg/minecraft ./cmd/minecraft-analyze ./pkg/cmd/analyzer/web ./pkg/cmd/analyzer
```

  Tests build archives in memory and exercise nested Bedrock packs, dependencies,
  texture dimensions, CRC failures, limits, unsafe paths, output escaping and
  the main/web CLI dispatch. Java mod descriptors and bytecode are covered by
  the JAR analyzer suite (`pkg/internal/jarloader`).

## JAR/Minecraft precision review (2026-09-20)

See [the Russian review](review-jar-minecraft/REVIEW.ru.md) for changes,
known limits, and validation status. ZIP payloads with a different extension
are now inspected by signature under the same budgets. Java class framing is
checked through fields/methods/attributes; constant-pool references still do
not prove invocation or reachability. Launcher/webhook string checks use
actual cpString literals rather than arbitrary UTF8 pool metadata.

This source revision adds regression and fuzz tests. They were executed during
integration (`bash scripts/validate-jar-minecraft.sh`, `go test -race` on the
touched packages); re-run the script before relying on a new build.
