#!/usr/bin/env python3
"""Fine-tune rubert-tiny2 as a 3-way NLI cross-encoder (entailment / neutral / contradiction).
Word embeddings stay frozen so the shipped cross-encoder file can share the base word table.
Usage: python train_nli.py <rubert-tiny2 dir> <nli data dir> <out.npz> [minutes]"""
import sys, time, json, random, numpy as np, pandas as pd, torch, torch.nn as nn
from transformers import AutoTokenizer, AutoModel

src, data, out = sys.argv[1], sys.argv[2], sys.argv[3]
BUDGET = float(sys.argv[4]) * 60 if len(sys.argv) > 4 else 1200
import os
PEAK = float(os.environ.get('LR', '1.2e-4')); DOMX = int(os.environ.get('DOMX', '2')); NGEN = float(os.environ.get('NGEN', '1.0'))
torch.set_num_threads(2); torch.manual_seed(0); random.seed(0)
LAB = {"entailment": 0, "neutral": 1, "contradiction": 2}
tok = AutoTokenizer.from_pretrained(src)

def rows_ru(path, srcs, n, seed):
    d = pd.read_parquet(path, columns=["premise_ru", "hypothesis_ru", "label", "source"])
    d = d[d.label.isin(LAB) & d.source.isin(srcs)].sample(frac=1, random_state=seed).head(n)
    return [(a, b, LAB[l]) for a, b, l in zip(d.premise_ru, d.hypothesis_ru, d.label)]
tr = rows_ru(f"{data}/ru_train0.parquet", {"snli", "sick", "copa"}, 30000, 1)
dev_all = rows_ru(f"{data}/ru_dev.parquet", {"mnli", "fever", "anli_r1", "anli_r2", "anli_r3", "imppres", "joci", "help", "snli"}, 10**9, 2)
random.Random(3).shuffle(dev_all)
ev_ru, tr_dev = dev_all[:2500], dev_all[2500:2500 + 18000]
s = pd.read_parquet(f"{data}/snli_train.parquet"); s = s[s.label >= 0].sample(frac=1, random_state=4)
tr_en = [(a, b, {0: 0, 1: 1, 2: 2}[l]) for a, b, l in zip(s.premise.head(16000), s.hypothesis.head(16000), s.label.head(16000))]
sv = pd.read_parquet(f"{data}/snli_val.parquet"); sv = sv[sv.label >= 0].head(2500)
ev_en = [(a, b, int(l)) for a, b, l in zip(sv.premise, sv.hypothesis, sv.label)]
dom = json.load(open("domain_nli.json"))
dtr = [(a, b, LAB[l]) for a, b, l in dom["train"]]
neu = [x for x in dtr if x[2] == 1]; oth = [x for x in dtr if x[2] != 1]
dtr = oth + neu[: int(len(oth) * 0.6)]
ev_dom = [(a, b, LAB[l]) for a, b, l in dom["heldout"]]
gen = tr + tr_dev + tr_en
random.shuffle(gen)
train = gen[: int(len(gen) * NGEN)] + dtr * DOMX
random.shuffle(train)
print("train", len(train), "dom", len(dtr), flush=True)

class M(nn.Module):
    def __init__(s):
        super().__init__(); s.b = AutoModel.from_pretrained(src); s.drop = nn.Dropout(0.1); s.cls = nn.Linear(s.b.config.hidden_size, 3)
    def forward(s, **k):
        return s.cls(s.drop(s.b(**k).pooler_output))
m = M()
import os
if os.environ.get('INIT'):
    z = np.load(os.environ['INIT']); m.load_state_dict({k: torch.tensor(z[k]) for k in z.files}); print('resumed from', os.environ['INIT'], flush=True)
m.b.embeddings.word_embeddings.weight.requires_grad = False
params = [p for p in m.parameters() if p.requires_grad]
opt = torch.optim.AdamW(params, lr=1.2e-4, weight_decay=0.01)

def enc(batch):
    e = tok([a for a, _, _ in batch], [b for _, b, _ in batch], truncation=True, max_length=96, padding=True, return_tensors="pt")
    return e, torch.tensor([y for _, _, y in batch])

def evaluate(rows, name):
    m.eval(); ok = 0
    with torch.no_grad():
        for i in range(0, len(rows), 128):
            e, y = enc(rows[i:i + 128]); ok += (m(**e).argmax(-1) == y).sum().item()
    m.train(); print(f"  eval {name}: acc={ok / len(rows):.3f} (n={len(rows)})", flush=True); return ok / len(rows)

BS = 32; t0 = time.time(); step = 0; est_steps = None; lossf = nn.CrossEntropyLoss(); run = 0.0
m.train(); ep = 0
while True:
    random.shuffle(train)
    for i in range(0, len(train) - BS, BS):
        el = time.time() - t0
        if el > BUDGET: break
        frac = el / BUDGET
        lr = PEAK * min(1, (step + 1) / 150) * max(0.05, 1 - frac)
        for g in opt.param_groups: g["lr"] = lr
        e, y = enc(train[i:i + BS]); loss = lossf(m(**e), y)
        opt.zero_grad(); loss.backward(); nn.utils.clip_grad_norm_(params, 1.0); opt.step()
        run = 0.98 * run + 0.02 * loss.item() if step else loss.item(); step += 1
        if step % 100 == 0: print(f"step {step} ep {ep} loss {run:.3f} lr {lr:.2e} t={el:.0f}s", flush=True)
    else:
        ep += 1; continue
    break
print("done steps", step, flush=True)
r = {"ru_dev": evaluate(ev_ru, "ru mixed (held-out)"), "snli_en": evaluate(ev_en, "snli en val"), "domain_heldout_phrasing": evaluate(ev_dom, "domain held-out phrasing")}
json.dump(r, open(out + ".metrics.json", "w"))
sd = {k: v.detach().numpy() for k, v in m.state_dict().items()}
np.savez(out, **sd)
print("saved", out, flush=True)
