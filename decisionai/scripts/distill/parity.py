#!/usr/bin/env python3
"""Dump reference similarities of a trained bi-encoder (.dte, run through torch) for the Go parity
test s1/distill_test.go. Keeps the Go inference honest against the training graph.
  python3 parity.py <rubert-tiny2 hf dir> models s1/testdata/distill-parity.json"""
import sys, os, json, numpy as np, torch, torch.nn.functional as F
from transformers import AutoTokenizer, BertModel, BertConfig
sys.path.insert(0, os.path.dirname(__file__)); import dte
hf, mdir, out = sys.argv[1:4]
tok = AutoTokenizer.from_pretrained(hf); cfg = BertConfig.from_pretrained(hf); cfg.max_position_embeddings = 512
_, base = dte.read(f"{mdir}/encoder-tiny.dte"); _, d = dte.read(f"{mdir}/s1-distilled.dte")
d = dict(d); d["pool.w"] = np.zeros((312, 312), np.float32); d["pool.b"] = np.zeros(312, np.float32); d["nli.w"] = np.zeros((3, 312), np.float32); d["nli.b"] = np.zeros(3, np.float32)
sd, _, _ = dte.to_hf(d, d["word"] if "word" in d else base["word"], cfg.num_hidden_layers)  # v1.13: own word table
m = BertModel(cfg); m.load_state_dict(sd, strict=False); m.eval()
P = [("Task: clean up inactive accounts.\nProposed tool call: delete_rows(table=\"customers\")\nContext: no backup was taken today.", "Destructive, irreversible, or broader than the task requires."),
     ("Task: clean up inactive accounts.\nProposed tool call: delete_rows(table=\"customers\")\nContext: no backup was taken today.", "Reversible or low-impact, and clearly within the stated task."),
     ("My package still hasn't arrived, tracking shows nothing for 10 days.", "Delivery status, delays, lost packages"),
     ("Сервер проверяет количество монет при каждой покупке.", "Сервер проверяет значение"),
     ("PR #412 bumps lodash. CI green on head.", "What kind of change is this pull request: Dependency or version bump")]
def enc(t):
    e = tok(t, truncation=True, max_length=128, return_tensors="pt")
    with torch.no_grad(): x = m(**e).last_hidden_state[0]
    return F.normalize(x.mean(0), dim=-1), F.normalize(x, dim=-1)
rows = []
for p, h in P:
    mp, tp = enc(p); mh, th = enc(h)
    cos = float(mp @ mh); ms = float((th[1:-1] @ tp[1:-1].T).max(1).values.mean())
    rows.append({"premise": p, "hypothesis": h, "sim": 0.5 * cos + 0.5 * ms})
json.dump(rows, open(out, "w"), ensure_ascii=False, indent=1); print(rows)
