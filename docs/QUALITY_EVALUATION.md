# Security detection quality evaluation

[Русский](QUALITY_EVALUATION.ru.md)

The checked-in corpus contains paired vulnerable and benign Android/Smali
fixtures. Run it from the repository root:

```bash
go run ./cmd/eval -min-precision 1 -min-recall 1 -rule-thresholds testdata/eval/thresholds.json
```

The command emits machine-readable per-rule and micro-averaged precision,
recall, and F1. Add a minimal positive fixture and a confusing benign fixture
for every detector change. Corpus schema changes require incrementing
`version` in `testdata/eval/corpus.json`.

Corpus v5 contains 97 cases, with precision, recall and F1 of 1.00 on this
fixed set: 70 expected category detections, zero false positives and zero
false negatives. These are regression metrics, not an estimate of accuracy
on arbitrary APKs.

## Arrays and helper calls

The 23 `arrays-*` cases exercise the complete pipeline. Additional engine
tests live in `pkg/internal/dataflow/array_flow_test.go`. Coverage includes:

- `filled-new-array`, `filled-new-array/range`, element stores and loads;
- complete arrays consumed by `Runtime.exec` and `ProcessBuilder`, array
  parameters and array return values;
- local `move-object` aliases, branch joins, unreachable stores, register
  reuse for a new allocation, and safe element overwrites;
- numeric index equivalence and indices whose reaching definitions disagree;
- `Intent.getStringArrayExtra` and `Bundle.getStringArray` sources;
- SQL escaping inside helpers, mixed escaped/raw return paths, and bound
  SQL parameters kept separate from query text;
- source, helper and sink files/lines retained in JSON evidence paths and
  the saved evidence graph.

Array contents are a conservative CFG abstraction. Only a definite store to
the same element of the same array kills an earlier value. Unknown indices
and possible aliases retain all possible origins. Branch feasibility and
arbitrary object mutations inside external methods are outside this model.

Array traversal shares the existing depth, global step and per-sink budgets.
Exhaustion is visible in `data_flow_stats.limit_reached` and `slices_truncated`;
later sinks can still be analyzed while the global budget permits.
