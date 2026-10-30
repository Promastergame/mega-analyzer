> Historical checklist. Current release procedure: [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md). The old gnnprobe/LICENSE findings below have been fixed.

# Release checklist — v1.0.0-beta.10

Только то, что попадёт в релиз независимо от текущего WIP в worktree.
CI/workflows не трогаем. `FlagiFiles.md` остаётся в корне.

## Обязательно перед тегом

1. **`pkg/cmd/gnnprobe/main.go` — нет build-constraint.** Использует `gnn.Model`/`gnn.LoadModel`,
   которые объявлены только под `//go:build cgo && omnisec_ml_gnn` (`pkg/ml/gnn/bridge.go`).
   Без тега `go build ./...` падает у любого, кто склонирует репо (это в HEAD, не в WIP).
   Фикс — одна строка в начале файла:
   ```go
   //go:build cgo && omnisec_ml_gnn
   ```

2. **`LICENSE`** — сейчас шуточный русский текст («НЕ ДЛЯ ВНЕШНИХ ГЛАЗ. ДАЖЕ GitHub»).
   README и бейдж заявляют «Proprietary», и этот файл `release.yml` кладёт в каждый архив.
   Нужен нормальный текст (proprietary / source-available, EN), согласованный с `NOTICE.txt`.

3. **Теги.** `VERSION` и `main.go` = `1.0.0-beta.10`, есть `docs/CHANGES-beta.{8,9,10}.md`,
   в git только `v1.0.0-beta.1..3`. Релизов 4–9 на GitHub нет.
   Достаточно тегнуть только `v1.0.0-beta.10`; в release notes одной строкой упомянуть, что 4–9 не публиковались.

## Желательно

4. **Release notes.** `release.yml` использует `--generate-notes` (список коммитов).
   `docs/CHANGES-beta.10.md` уже есть — можно вставить его текст в описание релиза вручную после публикации
   (без правок workflow).

5. **`.gitignore`** — блок `*.exe/*.dll/*.so/*.dylib` дважды (строки 6–11 и 207–210). Косметика.

6. **README-бейджи** Go/Rust/Zig/Elixir/coverage/tests — статические SVG в `.github/assets/badges/`,
   устареют при следующем бампе toolchain. Проверить актуальность цифр перед тегом.

7. **Line endings** — 26 из первых 400 `.go` в CRLF, git ругается `LF will be replaced by CRLF`.
   Если надоест: `* text=auto` в `.gitattributes` + `git add --renormalize .` отдельным коммитом. Не блокер.

## Порядок

1. Закончить текущий WIP, `go build ./... && go test ./...` зелёные.
2. Build-tag в `gnnprobe`, новый `LICENSE`.
3. `git tag v1.0.0-beta.10 && git push origin v1.0.0-beta.10`.
4. После публикации — вставить `CHANGES-beta.10.md` в описание релиза.
