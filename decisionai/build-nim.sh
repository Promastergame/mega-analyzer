#!/bin/sh
# v1.15: Linux build of dai with the Nim accelerator + FASM AVX kernel (any AVX CPU, 2011+).
# Needs Go 1.22+, Nim 2.2.x, gcc; fasm optional (prebuilt nim/fagemm.o is used otherwise).
set -e
cd "$(dirname "$0")/nim"
if [ "${DAI_NO_FASM:-0}" = 1 ]; then
  nim c --app:staticlib --noMain --mm:arc -d:danger --opt:speed --passC:-O3 --passC:-ffast-math --passC:-march=native -o:libdainim.a dainim.nim
else
  command -v fasm >/dev/null && fasm fagemm.asm fagemm.o
  OMP=""
  if [ "${DAI_OMP:-0}" = 1 ]; then OMP="-d:omp --panics:on --passC:-fopenmp"; export CGO_LDFLAGS="-fopenmp"; fi  # v1.16 multi-core forward
  nim c --app:staticlib --noMain --mm:arc -d:danger -d:fasm $OMP --opt:speed --passC:-O3 --passC:-ffast-math --passC:-mavx -o:libdainim.a dainim.nim
  ar rcs libdainim.a fagemm.o
fi
cd ..
mkdir -p bin
candidate=bin/dai-native.candidate
trap 'rm -f "$candidate"' EXIT HUP INT TERM
CGO_ENABLED=1 go build -tags nim -trimpath -ldflags="-s -w" -o "$candidate" ./cmd/dai
CGO_ENABLED=1 go test -tags nim ./semai ./s1 ./cmd/dai -count=1
mv -f "$candidate" bin/dai-native
echo "OK: bin/dai-native (tested Nim accelerator); legacy bin/dai unchanged."
