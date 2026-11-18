#!/usr/bin/env python3
"""Local NLI teacher: label every (chunk, hypothesis) pair of distill plans with the
3-way probabilities of a ~10x larger multilingual cross-encoder
(MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7, 278M params, MIT).
fp32 only: dynamic int8 quantisation of DeBERTa collapses its outputs to ~neutral.
LLM teachers (label.py, OpenAI-compatible API) can be mixed in on top when an API key
is available; this teacher works offline and gives *pair-level* soft targets.
  python3 nli_teacher.py <teacher dir> out.json plans1.jsonl [plans2.jsonl ...]
Output: {"premise\\x00hypothesis": [entail, neutral, contra], ...} (cached / resumable)."""
import sys, json, os, time, torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
src, out, files = sys.argv[1], sys.argv[2], sys.argv[3:]
torch.set_num_threads(2)
tok = AutoTokenizer.from_pretrained(src); m = AutoModelForSequenceClassification.from_pretrained(src, torch_dtype=torch.float32).float().eval()
MAXQ = int(os.environ.get("MAXQ", "0"))  # cap questions per train/dev file (0 = all); skill_routing is skipped
import random
lab = {v.lower(): int(k) for k, v in m.config.id2label.items()}
idx = [lab["entailment"], lab["neutral"], lab["contradiction"]]
cache = json.load(open(out)) if os.path.exists(out) else {}
pairs = []
for fn in files:
    qs = []
    for l in open(fn, encoding="utf-8"):
        d = json.loads(l)
        qs += [(d["chunks"], q) for q in d["questions"] if q.get("task") != "skill_routing"]
    if MAXQ and len(qs) > MAXQ and "/test-" not in fn:
        qs = random.Random(5).sample(qs, MAXQ)
    for chunks, q in qs:
        for o in q["options"]:
            if o.get("escape"):
                continue
            for c in chunks:
                k = c + "\x00" + o["hyp"]
                if k not in cache:
                    cache[k] = None; pairs.append((c, o["hyp"]))
    print(fn, "pairs so far", len(pairs), flush=True)
print("todo", len(pairs), flush=True)
t0 = time.time(); B = 16
with torch.inference_mode():
    for i in range(0, len(pairs), B):
        b = pairs[i:i + B]
        e = tok([p for p, _ in b], [h for _, h in b], truncation=True, max_length=256, padding=True, return_tensors="pt")
        pr = m(**e).logits.softmax(-1)[:, idx].tolist()
        for (p, h), v in zip(b, pr):
            cache[p + "\x00" + h] = [round(x, 5) for x in v]
        if (i // B) % 10 == 0:
            print(f"{i + len(b)}/{len(pairs)} {time.time() - t0:.0f}s", flush=True)
            json.dump({k: v for k, v in cache.items() if v is not None}, open(out, "w"), ensure_ascii=False)
json.dump({k: v for k, v in cache.items() if v is not None}, open(out, "w"), ensure_ascii=False)
print("done", len(cache), f"{time.time() - t0:.0f}s")
