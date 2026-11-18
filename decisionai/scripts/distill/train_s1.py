#!/usr/bin/env python3
"""Distil the System One decision model (v1.7).

Student : the bundled NLI cross-encoder (rubert-tiny2, 3 layers, 29M; models/nli-tiny.dte),
          word table frozen (shared with encoder-tiny.dte), everything else trained.
Teacher : (a) labels by construction / human labels, (b) pair-level 3-way probabilities of
          mDeBERTa-v3-base-xnli (nli_teacher.py), optionally (c) LLM answer frequencies.
Loss    : the engine's own aggregation is reproduced in torch (max over chunks,
          z = log e − ½ log c for options, signed log-odds for noul), so the student is
          trained on exactly what `dai decide` computes:
            L = KL(target ‖ p) + Brier(p, target) + λ · KL(teacher_pair ‖ student_pair)
          target = (1−α)·smoothed label + α·teacher question distribution.
  python3 train_s1.py <rubert-tiny2 hf dir> <models dir> <data/distill dir> <out.dte> [epochs]
Env: ALPHA (0.2) LAMBDA (0.3) LR (6e-5) SKILLS (1 = train on skill_routing too)."""
import sys, os, json, math, random, time
import numpy as np, torch, torch.nn as nn, torch.nn.functional as F
from transformers import AutoTokenizer, BertModel, BertConfig
sys.path.insert(0, os.path.dirname(__file__)); import dte

hf, mdir, ddir, out = sys.argv[1:5]; EPOCHS = int(sys.argv[5]) if len(sys.argv) > 5 else 4
ALPHA = float(os.environ.get("ALPHA", 0.2)); LAM = float(os.environ.get("LAMBDA", 0.3)); LR = float(os.environ.get("LR", 6e-5))
SKILLS = os.environ.get("SKILLS", "1") == "1"; EPS = 0.01
torch.set_num_threads(2); torch.manual_seed(0); random.seed(0)
tok = AutoTokenizer.from_pretrained(hf); cfg = BertConfig.from_pretrained(hf); cfg.max_position_embeddings = 512  # DTE keeps 512
bmeta, base = dte.read(f"{mdir}/encoder-tiny.dte"); cmeta, cross = dte.read(f"{mdir}/nli-tiny.dte")
sd, cw, cb = dte.to_hf(cross, base["word"], cfg.num_hidden_layers)

class Student(nn.Module):
    def __init__(s):
        super().__init__(); s.b = BertModel(cfg, add_pooling_layer=True); r = s.b.load_state_dict(sd, strict=False); assert not r.unexpected_keys and all("position_ids" in k for k in r.missing_keys), r
        s.cls = nn.Linear(cfg.hidden_size, 3); s.cls.weight.data, s.cls.bias.data = cw.clone(), cb.clone(); s.drop = nn.Dropout(0.1)
    def forward(s, **k):
        return s.cls(s.drop(s.b(**k).pooler_output))
m = Student(); m.b.embeddings.word_embeddings.weight.requires_grad = False
teacher = json.load(open(f"{ddir}/teacher-nli.json")) if os.path.exists(f"{ddir}/teacher-nli.json") else {}

def load(fn):
    rows = []
    for l in open(fn, encoding="utf-8"):
        d = json.loads(l)
        for q in d["questions"]:
            if q.get("label") is None or (q.get("task") == "skill_routing" and not SKILLS):
                continue
            rows.append((d["chunks"], q))
    return rows

def target(q):
    keys = [o["key"] for o in q["options"]]; lab = q["label"]; t = np.zeros(len(keys))
    if q["type"] == "noul":
        v = float(lab) if not isinstance(lab, bool) else (1.0 if lab else 0.0); return np.array([v, 1 - v]) * 0.94 + 0.03
    if isinstance(lab, dict):
        for k, v in lab.items(): t[keys.index(k)] = v
    else:
        t[keys.index(lab)] = 1
    if q["type"] == "score":  # ordinal smoothing toward neighbours
        sm = np.convolve(t, [0.1, 0.8, 0.1], mode="same"); t = sm / sm.sum()
    else:
        t = t * 0.92 + 0.08 / len(t)
    return t

def side(e, c):
    return (torch.log(e + EPS) - torch.log(c + EPS)) * (e + c)

def question_probs(q, E, C):
    """E, C: [n_options, n_chunks] entail/contra (escape rows ignored). Mirrors s1/engine.go."""
    e, c = E.max(1).values, C.max(1).values; esc = [bool(o.get("escape")) for o in q["options"]]
    if q["type"] == "noul":
        if not q["has_criteria"]:
            z = side(e[0], c[0])
        else:
            zt = side(e[0], c[0]) if not esc[0] else 0; zf = side(e[1], c[1]) if not esc[1] else 0
            z = (zt - zf) / 1.5 if not esc[0] and not esc[1] else (zt if not esc[0] else -zf)
        p = torch.sigmoid(torch.as_tensor(z)); return torch.stack([p, 1 - p]), e
    z = torch.log(e + EPS) - 0.5 * torch.log(c + EPS)
    keep = torch.tensor([not x for x in esc])
    z = torch.where(keep, z, torch.full_like(z, -30.0))
    return torch.softmax(z, 0), e

def pairs_of(chunks, q):
    return [(c, o["hyp"]) for o in q["options"] if not o.get("escape") for c in chunks] if q["type"] != "noul" or True else None

def run(batch, train=True):
    allp, spans = [], []
    for chunks, q in batch:
        ps = []
        for o in q["options"]:
            for c in chunks:
                ps.append((c, o["hyp"] if not o.get("escape") else "-"))
        spans.append((len(allp), len(ps))); allp += ps
    enc = tok([a for a, _ in allp], [b for _, b in allp], truncation="longest_first", max_length=96, padding="max_length", return_tensors="pt")
    logits = m(**enc); P = logits.softmax(-1)
    loss = 0.0; probs = []
    for (chunks, q), (s, n) in zip(batch, spans):
        k = len(chunks); Pq = P[s:s + n].view(len(q["options"]), k, 3)
        pq, e = question_probs(q, Pq[:, :, 0], Pq[:, :, 2]); probs.append(pq.detach().numpy())
        t = target(q)
        lab = q["label"]
        if q["type"] == "choice" and isinstance(lab, str) and any(o["key"] == lab and o.get("escape") for o in q["options"]):
            # gold = abstain: no substantive option may look supported
            loss = loss + F.binary_cross_entropy(e[[not o.get("escape") for o in q["options"]]].clamp(1e-4, 1 - 1e-4), torch.zeros(sum(1 for o in q["options"] if not o.get("escape")))).mean()
            continue
        tq = teacher_q(q, chunks)
        if tq is not None and ALPHA > 0:
            t = (1 - ALPHA) * t + ALPHA * tq
        tt = torch.tensor(t, dtype=torch.float32); pq = pq.clamp(1e-6, 1)
        valid = tt > 0
        loss = loss + (tt[valid] * (torch.log(tt[valid]) - torch.log(pq[valid]))).sum() + ((pq - tt) ** 2).sum()
        if LAM > 0 and teacher:
            rows = [(oi, ci) for oi, o in enumerate(q["options"]) if not o.get("escape") for ci in range(k)]
            tp = [teacher.get(chunks[ci] + "\x00" + q["options"][oi]["hyp"]) for oi, ci in rows]
            ok = [i for i, v in enumerate(tp) if v is not None]
            if ok:
                T3 = torch.tensor([tp[i] for i in ok], dtype=torch.float32).clamp(1e-4, 1)
                S3 = torch.stack([Pq[rows[i][0], rows[i][1]] for i in ok]).clamp(1e-6, 1)
                loss = loss + LAM * (T3 * (T3.log() - S3.log())).sum(1).mean()
    return loss / len(batch), probs

TQ_TEMP = {"noul": 1.0, "choice": 1.0, "score": 1.0}
def teacher_q(q, chunks):
    if not teacher:
        return None
    E, C = [], []
    for o in q["options"]:
        er, cr = [], []
        for c in chunks:
            v = teacher.get(c + "\x00" + o["hyp"]) if not o.get("escape") else [0, 1, 0]
            if v is None:
                return None
            er.append(v[0]); cr.append(v[2])
        E.append(er); C.append(cr)
    p, _ = question_probs(q, torch.tensor(E), torch.tensor(C))
    p = p.numpy().astype(np.float64); T = TQ_TEMP[q["type"]]
    p = np.exp(np.log(np.clip(p, 1e-6, 1)) / T); return p / p.sum()

MAXP = int(os.environ.get("MAXPAIRS", 160))  # pair budget per step (4 GB RAM box)
def npairs(row):
    return len(row[0]) * len(row[1]["options"])
def batches(rows):
    out, cur, n = [], [], 0
    for r in rows:
        if cur and n + npairs(r) > MAXP:
            out.append(cur); cur, n = [], 0
        cur.append(r); n += npairs(r)
    if cur:
        out.append(cur)
    return out
def evaluate(rows, name):
    m.eval(); hit = {}; br = {}
    with torch.no_grad():
        for b in batches(rows):
            _, ps = run(b, False)
            for (chunks, q), p in zip(b, ps):
                t = target(q); ty = q["type"]
                hit.setdefault(ty, []).append(int(np.argmax(p) == np.argmax(t))); br.setdefault(ty, []).append(float(((p - (t == t.max())) ** 2).sum()))
    m.train()
    return {k: (round(float(np.mean(v)), 4), len(v), round(float(np.mean(br[k])), 3)) for k, v in hit.items()}

train = load(f"{ddir}/train.plans.jsonl"); dev = load(f"{ddir}/dev.plans.jsonl")
tests = {os.path.basename(f)[5:-12]: load(f"{ddir}/{f}") for f in sorted(os.listdir(ddir)) if f.startswith("test-") and f.endswith(".plans.jsonl")}
print("train", len(train), "dev", len(dev), "teacher pairs", len(teacher), flush=True)
# fit teacher question temperatures on train labels (calibrated soft targets)
if teacher:
    for ty in TQ_TEMP:
        best = (1e9, 1.0)
        for T in [0.25, 0.35, 0.5, 0.7, 1.0, 1.4, 2.0, 3.0]:
            TQ_TEMP[ty] = T; nll = []
            for chunks, q in train:
                if q["type"] == ty:
                    tq = teacher_q(q, chunks)
                    if tq is not None: nll.append(-math.log(max(1e-6, float(tq @ (target(q) == target(q).max())))))
            if nll and np.mean(nll) < best[0]: best = (np.mean(nll), T)
        TQ_TEMP[ty] = best[1]
    print("teacher temps", TQ_TEMP, flush=True)
if os.environ.get("SKIPBEFORE") != "1": print("before", "dev", evaluate(dev, "dev"), {k: evaluate(v, k) for k, v in tests.items()}, flush=True)
params = [p for p in m.parameters() if p.requires_grad]
opt = torch.optim.AdamW(params, lr=LR, weight_decay=0.01)
random.shuffle(train)
steps = EPOCHS * len(batches(train)) + 10; sched = torch.optim.lr_scheduler.OneCycleLR(opt, LR, total_steps=steps, pct_start=0.1)
best = (-1, None); t0 = time.time(); step = 0
def devscore(r):
    return sum(v[0] * v[1] for v in r.values()) / sum(v[1] for v in r.values())
for ep in range(EPOCHS):
    random.shuffle(train)
    for b in batches(train):
        loss, _ = run(b); opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(params, 1.0); opt.step(); sched.step(); step += 1
        if step % 25 == 0:
            import resource
            print(f"ep {ep} step {step}/{steps} loss {loss.item():.4f} {time.time() - t0:.0f}s rss {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024}MB", flush=True)
    r = evaluate(dev, "dev"); s = devscore(r)
    print(f"== epoch {ep} dev {r} score {s:.4f}", flush=True)
    if s > best[0]:
        best = (s, {k: v.detach().clone() for k, v in m.state_dict().items()})
m.load_state_dict(best[1]); m.eval()
print("after (best dev)", {k: evaluate(v, k) for k, v in tests.items()}, flush=True)
bsd = {k[2:]: v for k, v in m.state_dict().items() if k.startswith("b.")}
meta = {k: v for k, v in cmeta.items() if k != "tensors"}
meta["source"] = "cointegrated/rubert-tiny2 + NLI fine-tune + System One distillation v1.7 (teacher mDeBERTa-v3-base-xnli)"
dte.write(out, meta, dte.from_hf(bsd, m.cls.weight, m.cls.bias, cfg.num_hidden_layers))
print("wrote", out, os.path.getsize(out))
