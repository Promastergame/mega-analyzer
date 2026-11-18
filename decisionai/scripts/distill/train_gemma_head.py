#!/usr/bin/env python3
"""v1.14 "System One Large": frozen EmbeddingGemma 2 text tower + small trained adapter, scored exactly like the
engine (½cos(mean) + ½MaxSim → σ(s·(sim−b)) → question aggregation). Token states come from gemma_cache.py.
  python3 train_gemma_head.py CACHE_DIR data/distill out.pt [epochs]
Env: JEVA (0.5) ALPHA (0.15) EXTRA (comma list of soft plan files) LR (1e-3) DIM (256) LAYERS (1)
Also: PREDICT=plans.jsonl,... OUT_LABELS=x.jsonl -> writes soft labels (teacher for distillation into the small model)."""
import sys, os, json, math, random, time, numpy as np, torch, torch.nn as nn, torch.nn.functional as F
torch.set_num_threads(2); torch.manual_seed(0); random.seed(0)
cdir, ddir, out = sys.argv[1:4]; EPOCHS = int(sys.argv[4]) if len(sys.argv) > 4 else 8
JEVA = float(os.environ.get("JEVA", 0.5)); ALPHA = float(os.environ.get("ALPHA", 0.15)); LR = float(os.environ.get("LR", 1e-3))
DIM = int(os.environ.get("DIM", 256)); NL = int(os.environ.get("LAYERS", 1)); EPS = 0.01
EXTRA = [x for x in os.environ.get("EXTRA", "").split(",") if x]
idx = json.load(open(f"{cdir}/index.json")); shards = {}
def states(t):
    s, a, b, inner = idx[t]
    if s not in shards: shards[s] = np.load(f"{cdir}/shard{s}.npy", mmap_mode="r")
    return torch.from_numpy(np.asarray(shards[s][a:b], dtype=np.float32)), inner

class Adapter(nn.Module):
    def __init__(s):
        super().__init__()
        s.inp = nn.Linear(768, DIM); s.skip = nn.Linear(768, DIM, bias=False)
        s.enc = nn.ModuleList([nn.TransformerEncoderLayer(DIM, 4, DIM * 2, dropout=0.1, batch_first=True, norm_first=True) for _ in range(NL)])
        s.out = nn.LayerNorm(DIM); s.scale = nn.Parameter(torch.tensor(12.0)); s.bias = nn.Parameter(torch.tensor(0.55))
    def forward(s, x, mask):
        h = s.inp(x)
        for l in s.enc: h = l(h, src_key_padding_mask=~mask)
        return s.out(h + s.skip(x))
A = Adapter()

JEV = {}
for nm in ("train", "dev"):
    fn = f"{os.path.dirname(os.path.abspath(ddir))}/jev/{nm}.jevlabels.jsonl"
    if JEVA > 0 and os.path.exists(fn):
        for l in open(fn, encoding="utf-8"):
            d = json.loads(l); JEV.update({(d["group"], k): v for k, v in d["labels"].items()})
teacher = json.load(open(f"{ddir}/teacher-nli.json")) if os.path.exists(f"{ddir}/teacher-nli.json") else {}
def load(fn, soft=False, unlabelled=False):
    rows = []
    for l in open(fn, encoding="utf-8"):
        d = json.loads(l)
        for q in d["questions"]:
            if (q.get("label") is None and not unlabelled) or q.get("task") == "skill_routing": continue
            q = dict(q); q["soft"] = soft; q["group"] = d.get("group"); j = JEV.get((d.get("group"), q["id"])) if not soft else None
            if j is not None: q["jev"] = j
            rows.append((d["chunks"], q))
    return rows
def soft_dist(q, lab):
    keys = [o["key"] for o in q["options"]]
    if q["type"] == "noul": v = float(lab); return np.array([v, 1 - v]) * 0.96 + 0.02
    if not isinstance(lab, dict): lab = {str(lab): 1.0}
    t = np.array([float(lab.get(k, 0)) for k in keys]) + 0.01; return t / t.sum()
def target_raw(q):
    keys = [o["key"] for o in q["options"]]; lab = q["label"]; t = np.zeros(len(keys))
    if q["type"] == "noul":
        v = float(lab) if not isinstance(lab, bool) else (1.0 if lab else 0.0); return np.array([v, 1 - v]) * 0.94 + 0.03
    if isinstance(lab, dict):
        for k, v in lab.items(): t[keys.index(k)] = v
    else: t[keys.index(lab)] = 1
    if q["type"] == "score": sm = np.convolve(t, [0.1, 0.8, 0.1], mode="same"); return sm / sm.sum()
    return t * 0.92 + 0.08 / len(t)
def target(q):
    if q.get("soft"): return soft_dist(q, q["label"])
    t = target_raw(q)
    if "jev" in q and JEVA > 0: t = (1 - JEVA) * t + JEVA * soft_dist(q, q["jev"])
    return t
def side(e, c): return (torch.log(e + EPS) - torch.log(c + EPS)) * (e + c)
def question_probs(q, E, C):
    e, c = E.max(1).values, C.max(1).values; esc = [bool(o.get("escape")) for o in q["options"]]
    if q["type"] == "noul":
        if not q["has_criteria"]: z = side(e[0], c[0])
        else:
            zt = side(e[0], c[0]) if not esc[0] else 0; zf = side(e[1], c[1]) if not esc[1] else 0
            z = (zt - zf) / 1.5 if not esc[0] and not esc[1] else (zt if not esc[0] else -zf)
        p = torch.sigmoid(torch.as_tensor(z)); return torch.stack([p, 1 - p]), e
    z = torch.log(e + EPS) - 0.5 * torch.log(c + EPS)
    keep = torch.tensor([not x for x in esc]); z = torch.where(keep, z, torch.full_like(z, -30.0))
    return torch.softmax(z, 0), e
def teacher_q(q, chunks):
    if not teacher or ALPHA <= 0: return None
    E, C = [], []
    for o in q["options"]:
        er, cr = [], []
        for c in chunks:
            v = teacher.get(c + "\x00" + o["hyp"]) if not o.get("escape") else [0, 1, 0]
            if v is None: return None
            er.append(v[0]); cr.append(v[2])
        E.append(er); C.append(cr)
    p, _ = question_probs(q, torch.tensor(E), torch.tensor(C)); p = p.numpy().astype(np.float64); return p / p.sum()

def encode(texts):
    xs, ins = zip(*[states(t) for t in texts]); n = max(len(x) for x in xs)
    X = torch.zeros(len(xs), n, 768); M = torch.zeros(len(xs), n, dtype=torch.bool); I = torch.zeros(len(xs), n)
    for i, (x, s) in enumerate(zip(xs, ins)):
        X[i, :len(x)] = x; M[i, :len(x)] = True; I[i, s:len(x) - 1] = 1
        if I[i].sum() == 0: I[i, :len(x)] = 1
    y = A(X, M); mf = I
    mean = F.normalize((y * mf[..., None]).sum(1) / mf.sum(1, keepdim=True).clamp(min=1), dim=-1)
    return mean, F.normalize(y, dim=-1), I, mf.sum(1)
def sims(hi, pi, mean, tokn, inner, L):
    cos = (mean[hi] * mean[pi]).sum(-1)
    S = torch.einsum("nid,njd->nij", tokn[hi], tokn[pi]).masked_fill(inner[pi][:, None, :] == 0, -2.0)
    w = inner[hi]; ms = (S.max(-1).values * w).sum(-1) / w.sum(-1).clamp(min=1)
    return 0.5 * cos + 0.5 * ms
def run(batch, train=True):
    texts, ix = [], {}
    def tid(t):
        if t not in ix: ix[t] = len(texts); texts.append(t)
        return ix[t]
    plan = [([tid(c) for c in ch], [tid(o["hyp"]) for o in q["options"] if not o.get("escape")]) for ch, q in batch]
    mean, tokn, inner, L = encode(texts)
    hi = torch.tensor([h for cid, hid in plan for h in hid for c in cid]); pi = torch.tensor([c for cid, hid in plan for h in hid for c in cid])
    E_all = torch.sigmoid(A.scale * (sims(hi, pi, mean, tokn, inner, L) - A.bias))
    loss = 0.0; probs = []; off = 0
    for (chunks, q), (cid, hid) in zip(batch, plan):
        esc = [bool(o.get("escape")) for o in q["options"]]; n = len(cid) * len(hid)
        Ereal = E_all[off:off + n].view(len(hid), len(cid)); off += n
        E = torch.zeros(len(esc), len(cid)); k = 0; rows = []
        for j, x in enumerate(esc):
            if x: rows.append(torch.zeros(len(cid)))
            else: rows.append(Ereal[k]); k += 1
        E = torch.stack(rows); pq, e = question_probs(q, E, 1 - E); probs.append(pq.detach().numpy())
        if not train: continue
        lab = q["label"]
        if q["type"] == "choice" and isinstance(lab, str) and any(o["key"] == lab and o.get("escape") for o in q["options"]):
            sub = e[[not x for x in esc]]; loss = loss + F.binary_cross_entropy(sub.clamp(1e-4, 1 - 1e-4), torch.zeros_like(sub)); continue
        t = target(q); tq = teacher_q(q, chunks)
        if tq is not None: t = (1 - ALPHA) * t + ALPHA * tq
        tt = torch.tensor(t, dtype=torch.float32); pq = pq.clamp(1e-6, 1); v = tt > 0
        loss = loss + (tt[v] * (torch.log(tt[v]) - torch.log(pq[v]))).sum() + ((pq - tt) ** 2).sum()
    return loss / len(batch), probs
def batches(rows, maxt=64):
    out, cur, n = [], [], 0
    for r in rows:
        k = len(r[0]) + len(r[1]["options"])
        if cur and n + k > maxt: out.append(cur); cur, n = [], 0
        cur.append(r); n += k
    if cur: out.append(cur)
    return out
def evaluate(rows):
    A.eval(); hit = {}
    with torch.no_grad():
        for b in batches(rows):
            _, ps = run(b, False)
            for (ch, q), p in zip(b, ps):
                lab = q["label"]
                if q["type"] == "choice" and isinstance(lab, str) and any(o["key"] == lab and o.get("escape") for o in q["options"]): continue
                t = target(q); hit.setdefault(q["type"], []).append(int(np.argmax(p) == np.argmax(t)))
    A.train(); return {k: (round(float(np.mean(v)), 4), len(v)) for k, v in hit.items()}
tot = lambda r: (sum(round(a * n) for a, n in r.values()), sum(n for a, n in r.values()))

if os.environ.get("PREDICT"):
    A.load_state_dict(torch.load(out)); A.eval(); fo = open(os.environ["OUT_LABELS"], "w", encoding="utf-8")
    for fn in os.environ["PREDICT"].split(","):
        rows = load(fn, unlabelled=True); res = {}
        with torch.no_grad():
            for b in batches(rows):
                _, ps = run(b, False)
                for (ch, q), p in zip(b, ps): res.setdefault(q["group"], {})[q["id"]] = {o["key"]: round(float(x), 4) for o, x in zip(q["options"], p)}
        for g, lab in res.items(): fo.write(json.dumps({"group": g, "labels": lab}, ensure_ascii=False) + "\n")
    print("wrote", os.environ["OUT_LABELS"]); sys.exit(0)

train = load(f"{ddir}/train.plans.jsonl"); dev = load(f"{ddir}/dev.plans.jsonl")
for x in EXTRA: train += load(x, soft=True)
tests = {os.path.basename(f)[5:-12]: load(f"{ddir}/{f}") for f in sorted(os.listdir(ddir)) if f.startswith("test-") and f.endswith(".plans.jsonl")}
print("train", len(train), "dev", len(dev), "params", sum(p.numel() for p in A.parameters()), flush=True)
opt = torch.optim.AdamW(A.parameters(), lr=LR, weight_decay=0.01); steps = int(EPOCHS * len(batches(train)) * 1.05) + 50
sched = torch.optim.lr_scheduler.OneCycleLR(opt, LR, total_steps=steps, pct_start=0.1); best = (-1, None); t0 = time.time(); step = 0
for ep in range(EPOCHS):
    random.shuffle(train)
    for b in batches(train):
        loss, _ = run(b); opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(A.parameters(), 1.0); opt.step(); step += 1
        if step < steps: sched.step()
        if step % 200 == 0: print(f"ep {ep} step {step}/{steps} loss {loss.item():.4f} {time.time() - t0:.0f}s", flush=True)
    r = evaluate(dev); h, n = tot(r); te = {k: tot(evaluate(v)) for k, v in tests.items()}
    print(f"== epoch {ep} dev {r} {h}/{n} tests {te}", flush=True)
    if h / n > best[0]: best = (h / n, {k: v.detach().clone() for k, v in A.state_dict().items()}); torch.save(best[1], out)
A.load_state_dict(best[1]); torch.save(A.state_dict(), out)
print("after (best dev)", {k: evaluate(v) for k, v in tests.items()}, flush=True)
