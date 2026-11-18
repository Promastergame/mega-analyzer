@echo off
cd /d "%~dp0"
if not exist bin\decision-ai.exe (echo Run BUILD-WINDOWS.cmd first. & pause & exit /b 1)
echo Open http://127.0.0.1:7475 in your browser after the server starts.
echo Press Ctrl+C to stop. Input files are never modified.
"%~dp0bin\decision-ai.exe" serve
pause
