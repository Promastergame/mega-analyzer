@echo off
setlocal
cd /d "%~dp0"
if exist bin\dai-native.exe (echo Using tested native binary. & bin\dai-native.exe %* & exit /b)
if exist bin\dai-go.exe (echo Using pure-Go binary. & bin\dai-go.exe %* & exit /b)
echo No new-style binary found. Run BUILD-NIM-WINDOWS.cmd or BUILD-S1.cmd.
exit /b 1
