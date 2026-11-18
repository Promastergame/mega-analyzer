@echo off
rem Build dai-native.exe with the Nim transformer accelerator (about 10x faster decide).
rem v1.15: + hand-written FASM AVX kernel (nim\fagemm.asm) for all matrix products incl. attention,
rem about 2x faster again. Works on any CPU with AVX (Intel Sandy/Ivy Bridge 2011+, AMD Bulldozer+);
rem AVX2/FMA are NOT required (i5-3340 etc. are fine).
rem Needs: Go 1.22+, Nim 2.2.x, MinGW-w64 gcc in PATH (Nim ships one in nim\dist\mingw64\bin).
rem FASM is optional: if fasm.exe is in PATH the kernel is re-assembled, otherwise the prebuilt
rem nim\fagemm.obj (from the same source) is used. Set DAI_NO_FASM=1 to build without the kernel.
setlocal
cd /d "%~dp0"
where nim >nul 2>nul || (echo [!] nim not found in PATH & exit /b 1)
where gcc >nul 2>nul || (echo [!] gcc not found: add MinGW-w64 bin to PATH & exit /b 1)
pushd nim
rem v1.16: set DAI_OMP=1 for a multi-core forward pass (OpenMP, needs MinGW libgomp; OMP_NUM_THREADS limits cores)
set OMP=
if "%DAI_OMP%"=="1" (set "OMP=-d:omp --panics:on --passC:-fopenmp" & set "CGO_LDFLAGS=-fopenmp")
if "%DAI_NO_FASM%"=="1" goto plain
where fasm >nul 2>nul && (fasm -d WIN64=1 fagemm.asm fagemm.obj || (popd & exit /b 1))
if not exist fagemm.obj (echo [!] nim\fagemm.obj missing & popd & exit /b 1)
nim c --app:staticlib --noMain --mm:arc -d:danger -d:fasm %OMP% --opt:speed --passC:-O3 --passC:-ffast-math --passC:-mavx -o:libdainim.a dainim.nim || (popd & exit /b 1)
ar rcs libdainim.a fagemm.obj || (popd & exit /b 1)
goto built
:plain
nim c --app:staticlib --noMain --mm:arc -d:danger --opt:speed --passC:-O3 --passC:-ffast-math --passC:-march=native -o:libdainim.a dainim.nim || (popd & exit /b 1)
:built
popd
set CGO_ENABLED=1
if not exist bin mkdir bin
set "CANDIDATE=bin\dai-native.candidate.exe"
go build -tags nim -trimpath -ldflags="-s -w" -o "%CANDIDATE%" .\cmd\dai || exit /b 1
go test -tags nim ./semai ./s1 ./cmd/dai -count=1 || (del /q "%CANDIDATE%" 2>nul & exit /b 1)
move /y "%CANDIDATE%" bin\dai-native.exe >nul || exit /b 1
echo OK: bin\dai-native.exe (tested Nim accelerator). Legacy bin\dai.exe was not overwritten.
echo Run RUN-DAI.cmd serve
