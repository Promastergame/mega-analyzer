@echo off
cd /d "%~dp0"
if not exist bin\decision-ai.exe (echo Run BUILD-WINDOWS.cmd first. & pause & exit /b 1)
echo SYNTHETIC DEMO MODEL. Real accuracy has not been established.
echo After startup open http://127.0.0.1:7475/text in your browser.
echo Press Ctrl+C to stop. No files are patched automatically.
"%~dp0bin\decision-ai.exe" serve -text-model models\demo-text-model.json
pause
