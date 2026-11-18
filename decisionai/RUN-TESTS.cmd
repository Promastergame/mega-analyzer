@echo off
cd /d "%~dp0"
"%~dp0bin\decision-ai.exe" test -input examples\tests.json
if errorlevel 1 (echo FAILED) else (echo PASSED)
pause
