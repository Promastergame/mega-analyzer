#!/usr/bin/env python3
"""v1.12 ReasonHead: a small cross-attention model that *reads the state and the option together*
on top of the frozen distilled bi-encoder (models/s1-distilled.dte).

  bi-encoder token states  C (chunk, n_c×312)   H (option hypothesis, n_h×312)
  P = LN(W·x) → 128-d, + segment embedding
  2 × [ H += MHA(LN H → LN [C;H]) ; H += FFN(LN H) ]       (hypothesis tokens attend to the state)
  r = MLP(LN mean(H))   (last layer zero-init)
  logit = 12·(sim_bi − 0.55) + r,  e = σ(logit), c = 1 − e      (starts exactly at the bi-encoder)
Trained through the engine aggregation (max over chunks, listwise KL + Brier), targets = labels ⊕ Jev
as in train_embed.py. Writes models/s1-reason.dte (DTE1, f32).
  python3 train_reason.py <rubert-tiny2 hf> models data/distill out.dte [epochs]
Env: JEVA (0.5) LR (1e-3) EXTRA (plan files) MAXPAIRS (384) D (128)"""
import sys, os, json, math, random, time, resource
import numpy as np, torch, torch.nn as nn, torch.nn.functional as F
from transformers import AutoTokenizer, BertModel, BertConfig
sys.path.insert(0, os.path.dirname(__file__)); import dte

hf, mdir, ddir, out = sys.argv[1:5]; EPOCHS = int(sys.argv[5]) if len(sys.argv) > 5 else 8
JEVA = float(os.environ.get("JEVA", 0.5)); LR = float(os.environ.get("LR", 1e-3)); MAXP = int(os.environ.get("MAXPAIRS", 384))
EXTRA = [x for x in os.environ.get("EXTRA", "").split(",") if x]; D = int(os.environ.get("D", 128)); EPS = 0.01
torch.set_num_threads(2); torch.manual_seed(0); random.seed(0)

# ---------- frozen bi-encoder: precompute token states ----------
tok = AutoTokenizer.from_pretrained(hf); cfg = BertConfig.from_pretrained(hf); cfg.max_position_embeddings = 512
_, base = dte.read(f"{mdir}/encoder-tiny.dte"); _, dd = dte.read(f"{mdir}/s1-distilled.dte")
dd = dict(dd); dd["pool.w"] = np.zeros((312, 312), np.float32); dd["pool.b"] = np.zeros(312, np.float32); dd["nli.w"] = np.zeros((3, 312), np.float32); dd["nli.b"] = np.zeros(3, np.float32)
sd, _, _ = dte.to_hf(dd, base["word"], cfg.num_hidden_layers)
bert = BertModel(cfg); bert.load_state_dict(sd, strict=False); bert.eval()

JEV = {}
for nm in ("train", "dev"):
    fn = f"{os.path.dirname(os.path.abspath(ddir))}/jev/{nm}.jevlabels.jsonl"
    if os.path.exists(fn):
        for l in open(fn, encoding="utf-8"):
            d = json.loads(l); JEV.update({(d["group"], k): v for k, v in d["labels"].items()})

def load(fn, soft=False):
    rows = []
    for l in open(fn, encoding="utf-8"):
        d = json.loads(l)
        for q in d["questions"]:
            if q.get("label") is None or q.get("task") == "skill_routing":
                continue
            q = dict(q); q["soft"] = soft; j = JEV.get((d.get("group"), q["id"])) if not soft else None
            if j is not None: q["jev"] = j
            rows.append((d["chunks"], q))
    return rows

def soft_dist(q, lab):
    keys = [o["key"] for o in q["options"]]
    if q["type"] == "noul":
        v = float(lab); return np.array([v, 1 - v]) * 0.96 + 0.02
    t = np.array([float(lab.get(k, 0)) for k in keys]) + 0.01; return t / t.sum()
def target_raw(q):
    keys = [o["key"] for o in q["options"]]; lab = q["label"]; t = np.zeros(len(keys))
    if q["type"] == "noul":
        v = float(lab) if not isinstance(lab, bool) else (1.0 if lab else 0.0); return np.array([v, 1 - v]) * 0.94 + 0.03
    if isinstance(lab, dict):
        for k, v in lab.items(): t[keys.index(k)] = v
    else: t[keys.index(lab)] = 1
    if q["type"] == "score":
        sm = np.convolve(t, [0.1, 0.8, 0.1], mode="same"); t = sm / sm.sum()
    else: t = t * 0.92 + 0.08 / len(t)
    return t
def target(q):
    if q.get("soft"): return soft_dist(q, q["label"])
    t = target_raw(q)
    if "jev" in q and JEVA > 0: t = (1 - JEVA) * t + JEVA * soft_dist(q, q["jev"])
    return t
def is_abstain(q):
    lab = q["label"]; return q["type"] == "choice" and isinstance(lab, str) and any(o["key"] == lab and o.get("escape") for o in q["options"])

train = load(f"{ddir}/train.plans.jsonl"); dev = load(f"{ddir}/dev.plans.jsonl")
for x in EXTRA: train += load(x, soft=True)
tests = {os.path.basename(f)[5:-12]: load(f"{ddir}/{f}") for f in sorted(os.listdir(ddir)) if f.startswith("test-") and f.endswith(".plans.jsonl")}
texts = {}
for rows in [train, dev] + list(tests.values()):
    for chunks, q in rows:
        for c in chunks: texts.setdefault(c, None)
        for o in q["options"]: texts.setdefault(o["hyp"] if not o.get("escape") else "-", None)
keys = list(texts); t0 = time.time()
with torch.no_grad():
    for i in range(0, len(keys), 48):
        b = keys[i:i + 48]; e = tok(b, truncation=True, max_length=128, padding=True, return_tensors="pt")
        x = bert(**e).last_hidden_state; L = e["attention_mask"].sum(1)
        for j, t in enumerate(b): texts[t] = x[j, :L[j]].to(torch.float16).clone()
del bert
print(f"encoded {len(keys)} texts in {time.time() - t0:.0f}s; train {len(train)} dev {len(dev)} jev {len(JEV)}", flush=True)

def bi_sim(c, h):
    """exact semai sim on raw states: ½cos(mean) + ½ MaxSim(h→c) over inner tokens"""
    mc, mh = F.normalize(c.mean(0), dim=-1), F.normalize(h.mean(0), dim=-1)
    if len(c) < 3 or len(h) < 3: return 0.5 * (mc @ mh)
    tc, th = F.normalize(c[1:-1], dim=-1), F.normalize(h[1:-1], dim=-1)
    return 0.5 * (mc @ mh) + 0.5 * (th @ tc.T).max(1).values.mean()

# ---------- the head ----------
class Head(nn.Module):
    def __init__(s, d=D, heads=4, layers=2, ff=256):
        super().__init__(); s.inp = nn.Linear(312, d); s.inln = nn.LayerNorm(d); s.seg = nn.Parameter(torch.zeros(2, d))
        s.ln_q = nn.ModuleList(nn.LayerNorm(d) for _ in range(layers)); s.ln_kv = nn.ModuleList(nn.LayerNorm(d) for _ in range(layers))
        s.q = nn.ModuleList(nn.Linear(d, d) for _ in range(layers)); s.k = nn.ModuleList(nn.Linear(d, d) for _ in range(layers))
        s.v = nn.ModuleList(nn.Linear(d, d) for _ in range(layers)); s.o = nn.ModuleList(nn.Linear(d, d) for _ in range(layers))
        s.ln_f = nn.ModuleList(nn.LayerNorm(d) for _ in range(layers)); s.f1 = nn.ModuleList(nn.Linear(d, ff) for _ in range(layers)); s.f2 = nn.ModuleList(nn.Linear(ff, d) for _ in range(layers))
        s.out_ln = nn.LayerNorm(d); s.p1 = nn.Linear(d, 64); s.p2 = nn.Linear(64, 1); nn.init.zeros_(s.p2.weight); nn.init.zeros_(s.p2.bias)
        s.d, s.nh, s.nl = d, heads, layers
    def proj(s, x, seg): return s.inln(s.inp(x)) + s.seg[seg]
    def forward(s, C, cm, H, hm):
        """C [P,Lc,d] cm [P,Lc] (bool valid), H [P,Lh,d] hm [P,Lh] -> r [P]"""
        P, Lh, d = H.shape; hd = d // s.nh
        for l in range(s.nl):
            kv = s.ln_kv[l](torch.cat([C, H], 1)); km = torch.cat([cm, hm], 1)
            q = s.q[l](s.ln_q[l](H)).view(P, Lh, s.nh, hd).transpose(1, 2)
            k = s.k[l](kv).view(P, -1, s.nh, hd).transpose(1, 2); v = s.v[l](kv).view(P, -1, s.nh, hd).transpose(1, 2)
            a = (q @ k.transpose(-1, -2)) / math.sqrt(hd); a = a.masked_fill(~km[:, None, None, :], -1e4).softmax(-1)
            H = H + s.o[l]((a @ v).transpose(1, 2).reshape(P, Lh, d))
            H = H + s.f2[l](F.gelu(s.f1[l](s.ln_f[l](H))))
        m = hm.float()[..., None]; pooled = (H * m).sum(1) / m.sum(1).clamp(min=1)
        return s.p2(F.gelu(s.p1(s.out_ln(pooled)))).squeeze(-1)
head = Head()

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

SIM = {}
def pair_sim(c, h):
    k = (c, h)
    if k not in SIM: SIM[k] = float(bi_sim(texts[c].float(), texts[h].float()))
    return SIM[k]
def pad(xs):
    L = max(len(x) for x in xs); out = torch.zeros(len(xs), L, 312); m = torch.zeros(len(xs), L, dtype=torch.bool)
    for i, x in enumerate(xs): out[i, :len(x)] = x.float(); m[i, :len(x)] = True
    return out, m

def run(batch):
    pc, ph, sims = [], [], []
    for chunks, q in batch:
        for o in q["options"]:
            h = o["hyp"] if not o.get("escape") else "-"
            for c in chunks: pc.append(c); ph.append(h); sims.append(pair_sim(c, h))
    uc = list(dict.fromkeys(pc)); uh = list(dict.fromkeys(ph)); ic = {t: i for i, t in enumerate(uc)}; ih = {t: i for i, t in enumerate(uh)}
    Cr, cm = pad([texts[t] for t in uc]); Hr, hm = pad([texts[t] for t in uh])
    Cp, Hp = head.proj(Cr, 0), head.proj(Hr, 1)
    gi = torch.tensor([ic[t] for t in pc]); gh = torch.tensor([ih[t] for t in ph])
    r = head(Cp[gi], cm[gi], Hp[gh], hm[gh])
    E_all = torch.sigmoid(12.0 * (torch.tensor(sims) - 0.55) + r)
    loss = 0.0; probs = []; off = 0
    for chunks, q in batch:
        n = len(chunks) * len(q["options"]); E = E_all[off:off + n].view(len(q["options"]), len(chunks)); off += n
        pq, e = question_probs(q, E, 1 - E); probs.append(pq.detach().numpy())
        if is_abstain(q):
            sub = e[[not o.get("escape") for o in q["options"]]]
            loss = loss + F.binary_cross_entropy(sub.clamp(1e-4, 1 - 1e-4), torch.zeros_like(sub)); continue
        tt = torch.tensor(target(q), dtype=torch.float32); pq = pq.clamp(1e-6, 1)
        loss = loss + (tt * (torch.log(tt) - torch.log(pq))).sum() + ((pq - tt) ** 2).sum()
    return loss / len(batch), probs

def batches(rows):
    out, cur, n = [], [], 0
    for r in rows:
        k = len(r[0]) * len(r[1]["options"])
        if cur and n + k > MAXP: out.append(cur); cur, n = [], 0
        cur.append(r); n += k
    if cur: out.append(cur)
    return out
def evaluate(rows):
    head.eval(); hit = {}
    with torch.no_grad():
        for b in batches(rows):
            _, ps = run(b)
            for (chunks, q), p in zip(b, ps):
                if is_abstain(q): continue
                t = target(q); hit.setdefault(q["type"], []).append(int(np.argmax(p) == np.argmax(t)))
    head.train()
    return {k: (round(float(np.mean(v)), 4), len(v)) for k, v in hit.items()}
devscore = lambda r: sum(v[0] * v[1] for v in r.values()) / sum(v[1] for v in r.values())
print("before (= bi-encoder)", "dev", evaluate(dev), {k: evaluate(v) for k, v in tests.items()}, flush=True)
opt = torch.optim.AdamW(head.parameters(), lr=LR, weight_decay=0.01)
steps = EPOCHS * len(batches(train)) + 10; sched = torch.optim.lr_scheduler.OneCycleLR(opt, LR, total_steps=steps, pct_start=0.1)
best = (-1, None); t0 = time.time(); step = 0
for ep in range(EPOCHS):
    random.shuffle(train)
    for b in batches(train):
        loss, _ = run(b); opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(head.parameters(), 1.0); opt.step(); sched.step(); step += 1
        if step % 100 == 0: print(f"ep {ep} step {step}/{steps} loss {loss.item():.4f} {time.time() - t0:.0f}s rss {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024}MB", flush=True)
    r = evaluate(dev); s = devscore(r); print(f"== epoch {ep} dev {r} score {s:.4f}", {k: evaluate(v) for k, v in tests.items()}, flush=True)
    if s > best[0]: best = (s, {k: v.detach().clone() for k, v in head.state_dict().items()})
head.load_state_dict(best[1]); head.eval()
print("after (best dev)", {k: evaluate(v) for k, v in tests.items()}, flush=True)
t = [(k, v.detach().numpy().astype(np.float32)) for k, v in head.state_dict().items()]
meta = {"kind": "reason-head", "d": D, "heads": head.nh, "layers": head.nl, "ff": head.f1[0].out_features, "ln_eps": 1e-5, "bi_scale": 12.0, "bi_bias": 0.55,
        "encoder": "s1-distilled.dte", "source": "System One ReasonHead v1.12 (teachers: Jev + labels)"}
dte.write(out, meta, t); print("wrote", out, os.path.getsize(out))
