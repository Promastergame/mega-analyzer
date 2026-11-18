V1 MEMORY PATCH 03 - CUMULATIVE

README.md: Russian UTF-8 BOM + CRLF. This file: ASCII only.

CHANGES
1. Nim+FASM direct matrix packing removes an extra Nim copy.
   Removed array payload: 9,165,312 bytes per encoder of this architecture.
2. Bit-identical word tables/scales share arrays. Different weights do not.
3. NEW: matching tokenizers share vocabulary maps, token lists and strings
   even when word weights differ. Full ordered vocabulary, size and lower
   mode must match. The comparison does not allocate a joined vocabulary.
No model weights, transformer layers, ensemble members or math are changed.
Shared tables are immutable at inference. No global cache.

INSTALL (WINDOWS, NO WSL)
Back up nim\dainim.nim and semai\encoder.go.
Extract into project root, replacing files. Patches 01/02 are included.
PowerShell, project root:

python tests\check_pack.py models\encoder-tiny.dte
go test ./semai -run '(WordShare|TokenizerShare)' -count=1 -v
Remove-Item Env:DAI_NO_FASM -ErrorAction SilentlyContinue
.\BUILD-NIM-WINDOWS.cmd

Use required Nim, Go and MinGW tools in PATH. The script runs NimParity.
Do not use a failed build. Rollback: restore both files and rebuild.

MEASUREMENTS
Live Go heap increase, after loading three encoders and forcing GC:
Original loader (earlier run): 127,541,224 bytes.
Patch 02 (this step control):   94,967,168 bytes.
Patch 03:                      88,873,352 bytes.
New reduction: about 6.09 MB; about 30.3% vs the original measurement.
One control run per variant. This is NOT total process RAM or RSS,
and NOT a Nim+FASM measurement. Repeat: go run ./tools/memprobe
Do not add the removed Nim payload to this number as measured RSS.

CHECKED
Python reference: 18 matrix packings are bit-exact.
Sharing guards, real model tokenizer and output parity on two texts per
pair pass in the Go reference path. Transformer layers stay independent.
go test ./... passes. Logs: checks/.

NOT CHECKED
Modified Nim compilation, native forward parity, Windows build, full RAM,
speed, p50, ECE, full task quality. Earlier Nim download returned HTTP 403.
Existing teacher provenance is unchanged. No new weights are included.

V2
This patch does not modify or delete v2. Keep one verified archive of its
source, configs, tokenizer, best weights and measurements before deleting
working copies. Never delete the only copy.
