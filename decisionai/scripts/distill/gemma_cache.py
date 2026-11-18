#!/usr/bin/env python3
"""v1.14: encode every distinct text (case chunks + option hypotheses) of the given plan files with the
frozen EmbeddingGemma 2 text tower once; token states are cached (fp16) for adapter training.
  python3 gemma_cache.py GEMMA_DIR OUT_DIR plans.jsonl...
Chunks get the document prefix, hypotheses the fact-checking query prefix (asymmetric task)."""
import sys, os, json, time, numpy as np, torch, transformers as T
torch.set_num_threads(2)
gd, out = sys.argv[1:3]; files = sys.argv[3:]
os.makedirs(out, exist_ok=True)
DOC, QRY = "title: none | text: ", "task: fact checking | query: "
cfg = T.AutoConfig.from_pretrained(gd); cfg.vision_config = None; cfg.audio_config = None
m = T.AutoModel.from_pretrained(gd, config=cfg, dtype=torch.float32).eval(); tok = T.AutoTokenizer.from_pretrained(gd)
want = {}
for f in files:
    for l in open(f, encoding="utf-8"):
        d = json.loads(l)
        for c in d["chunks"]: want[c] = "c"
        for q in d["questions"]:
            for o in q["options"]:
                if not o.get("escape"): want.setdefault(o["hyp"], "h")
idx_fn = f"{out}/index.json"; idx = json.load(open(idx_fn)) if os.path.exists(idx_fn) else {}
todo = [t for t in want if t not in idx]; print("texts", len(want), "todo", len(todo), flush=True)
npre = {k: len(tok(p, add_special_tokens=False)["input_ids"]) for k, p in (("c", DOC), ("h", QRY))}
todo.sort(key=len); shard = len([f for f in os.listdir(out) if f.startswith("shard")]); t0 = time.time(); done = 0
def flush(buf):
    global shard
    if not buf: return
    arrs = [a for _, a, _ in buf]; offs = np.cumsum([0] + [len(a) for a in arrs])
    np.save(f"{out}/shard{shard}.npy", np.concatenate(arrs).astype(np.float16))
    for i, (t, a, s) in enumerate(buf): idx[t] = [shard, int(offs[i]), int(offs[i + 1]), s]
    json.dump(idx, open(idx_fn + ".tmp", "w"), ensure_ascii=False); os.replace(idx_fn + ".tmp", idx_fn); shard += 1
buf = []
with torch.no_grad():
    for i in range(0, len(todo), 8):
        b = todo[i:i + 8]; inp = [(DOC if want[t] == "c" else QRY) + t for t in b]
        e = tok(inp, truncation=True, max_length=320, padding=True, return_tensors="pt")
        x = m(**e).last_hidden_state
        for j, t in enumerate(b):
            n = int(e["attention_mask"][j].sum()); ids = e["input_ids"][j][e["attention_mask"][j].bool()]
            # inner start: skip BOS + task prefix tokens
            s = 1 + npre[want[t]] if ids[0] == tok.bos_token_id else npre[want[t]]
            mrow = e["attention_mask"][j].bool(); buf.append((t, x[j][mrow].numpy(), s))
        done += len(b)
        if sum(len(a) for _, a, _ in buf) > 40000: flush(buf); buf = []
        if done % 400 < 8: print(done, f"{time.time() - t0:.0f}s", flush=True)
flush(buf); print("done", len(idx), f"{time.time() - t0:.0f}s")
