# System One distillation data (v1.7)

Regenerate everything: `python3 scripts/distill/build_dataset.py` (needs `bin/dai`), then
`python3 scripts/teacher/nli_teacher.py <mDeBERTa dir> data/distill/teacher-nli.json data/distill/*.plans.jsonl`,
then `python3 scripts/distill/train_embed.py <rubert-tiny2 dir> models data/distill models/s1-distilled.dte 6`.

| file | what |
| --- | --- |
| `syn-train.jsonl`, `syn-dev.jsonl` | synthetic labelled requests (gen_synth.py, seeds 7 / 99) |
| `train.labelled.jsonl` | 1447 requests / 3039 questions: synthetic + patch texts + skill-routing dev/examples |
| `dev.labelled.jsonl` | synthetic dev + evals/golden-calib (early stopping, lex-scale choice) |
| `calib.labelled.jsonl` | synthetic dev + golden-calib ×5 (temperature fit) |
| `*.plans.jsonl` | `dai distill-export` output: exact chunks + option hypotheses the engine scores |
| `teacher-nli.json` | 11 307 pair → [entail, neutral, contra] from mDeBERTa-v3-base-xnli (fp32) |
| `train_embed.log` | the shipped training run; `train_crossenc_negative.log` — the cross-encoder attempt that lost |

## v1.8 (teacher: Jev)
`syn2.jsonl` (gen_synth2.py, 700) → Jev (`scripts/teacher/jev_teacher.py`, answers in `data/jev/`) → `jev_labels.py` → `syn2.labelled.jsonl` → `dai distill-export` → `syn2.plans.jsonl`.
Train/dev Jev answers: `data/jev/{train,dev}.jev.jsonl` → `{train,dev}.jevlabels.jsonl`. Training:
`JEVA=0.5 ALPHA=0.15 EXTRA=data/distill/syn2.plans.jsonl python3 scripts/distill/train_embed.py ...` (`train_embed_v18.log`).
Held-out `syn2-holdout.jsonl` (seed 777) → `evals/distill/jev-holdout.jsonl`.

## v1.11
`gen_synth3.py data/distill/syn3.jsonl 4000 31` → Jev (`data/jev/syn3.jev.jsonl`, $0.089) → `jev_labels.py` → near-duplicate filter vs all test sets (word Jaccard > 0.5, 184 dropped) → `syn3.labelled.jsonl` (3816) → `syn3.plans.jsonl`.
`MAXTEXTS=80 MALLOC_ARENA_MAX=2 MALLOC_MMAP_THRESHOLD_=65536 JEVA=0.5 ALPHA=0.15 EXTRA=data/distill/syn2.plans.jsonl,data/distill/syn3.plans.jsonl train_embed.py ... models/s1-distilled-b.dte 3` (`train_embed_v111.log`).

## v1.12

- `syn4.*` — 3000 запросов по 10 базовым задачам (`scripts/distill/gen_synth4.py`), метки Jev ($0.047). Используется для проверки `experts/basics.go` (`go test ./experts -run BasicsVsJev`) и экспериментов `train_reason.py`.
- `syn5.jsonl` — 534 реалистичных текста от дешёвой LLM (`scripts/distill/gen_llm.py`), без меток; отфильтрованы против всех тестов (Jaccard > 0.5).
- `test-base-tasks.plans.jsonl`, `test-jev-holdout.plans.jsonl` — экспорт тестов для оценки в Python-скриптах обучения (не для обучения).

## v1.13

- `paraphrases.json` — 3 перефраза к каждой из 133 формулировок вопросов в обучении (тот же язык / другой язык / коротко), написаны вручную; проверено, что перефразы не повторяют вопросы `evals/unseen.jsonl` (Jaccard слов ≤ 0.6; единственное совпадение — исходная обучающая формулировка «Are customers affected?»).
- `*.para.labelled.jsonl` / `*.para.plans.jsonl` — syn2–syn4 (50% запросов переписаны) и train (все), `scripts/distill/augment_questions.py`; метки учителей не меняются.
- `test-unseen.plans.jsonl` — экспорт слепого теста для отчётов скриптов обучения (не для обучения).
- Обучение v1.13: `INIT=hf EXTRA=syn2.para,syn3.para,syn4.para,train.para … train_embed.py /data/hf/rubert-tiny-turbo models data/distill out.dte 3` (~55 мин на 2 CPU, ≤ 1,6 ГБ RAM).

## v1.17

- `syn7.labelled.jsonl` / `syn7.plans.jsonl`: 3000 запросов `scripts/distill/gen_synth7.py` (метки по построению: хватает ли, размер нехватки, лимиты, сроки, сравнения, флаги; выдуманные имена и единицы). В обучение идёт `data/iso/syn7.plans.jsonl`: из него убраны 10 запросов с общими фрагментами с тестами.
- `data/iso/`: изолированные train/dev/test для v1.17; в `dev.plans.jsonl` добавлен `syn7h` (`--holdout`, словарь не пересекается с syn7).
- Обучение модели C: `INIT=hf JEVA=0.5 ALPHA=0.15 MAXTEXTS=80 EXTRA=data/iso/syn2.para.plans.jsonl,data/distill/syn3.para.plans.jsonl,data/distill/syn4.para.plans.jsonl,data/distill/train.para.plans.jsonl,data/distill/syn5.gemma.plans.jsonl,data/distill/syn6.qwen.plans.jsonl,data/distill/syn6.gemma.plans.jsonl,data/iso/syn7.plans.jsonl train_embed.py /data/hf/turbo models data/iso models/s1-distilled-c.dte 2` (`train_embed_v117.log`, 47 мин на 2 CPU, до 2 ГБ RAM).
