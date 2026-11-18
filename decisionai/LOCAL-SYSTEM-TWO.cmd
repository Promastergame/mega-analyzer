@echo off
rem v1.14: local System Two - Qwen2.5-1.5B-Instruct answers uncertain questions offline (no key, no cloud).
rem   1) pip install torch transformers
rem   2) download Qwen/Qwen2.5-1.5B-Instruct into models\qwen2.5-1.5b
rem   3) run this window, then: dai serve -escalate local/qwen2.5-1.5b -escalate-url http://127.0.0.1:8088/decisions
setlocal
cd /d "%~dp0"
if not exist models\qwen2.5-1.5b\config.json (echo [!] models\qwen2.5-1.5b not found & exit /b 1)
set DTYPE=bf16
python scripts\distill\llm_teacher.py serve models\qwen2.5-1.5b 8088
