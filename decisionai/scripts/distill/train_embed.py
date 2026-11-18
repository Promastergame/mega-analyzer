#!/usr/bin/env python3
"""Distil the System One decision model into the bi-encoder (v1.7, shipped as models/s1-distilled.dte).

Student : rubert-tiny2 bi-encoder (models/encoder-tiny.dte), word table frozen and shared, the
          3 transformer layers trained. The engine's embed scoring is reproduced exactly:
            sim = ½·cos(mean_p, mean_h) + ½·MaxSim(h→p),  e = σ(12·(sim − 0.55)),  c = 1 − e,
          max over chunks, z = log e − ½ log c (choice/score), signed log-odds (noul).
Targets : (1−α)·smoothed label + α·teacher distribution (mDeBERTa-v3 NLI through the same
          aggregation, temperature-fitted on train labels) — KL + Brier, listwise per question.
  python3 train_embed.py <rubert-tiny2 hf dir> <models dir> <data/distill dir> <out.dte> [epochs]
v1.8: second teacher = Jev (typesafe/jev-1.13 via OpenRouter, data/jev/*.jevlabels.jsonl):
          target = (1−α−β)·label + β·Jev + α·mDeBERTa; data/distill/syn2.plans.jsonl (Jev-only soft labels)
          is added to train.
Memory: run with MALLOC_ARENA_MAX=1 MALLOC_MMAP_THRESHOLD_=131072 MALLOC_TRIM_THRESHOLD_=131072 (glibc fragmentation
otherwise grows RSS to ~4 GB on the full v1.14 set).
Env: ALPHA (0.2) JEVA (0.0) EXTRA (comma list of extra plan files) LR (5e-5) SKILLS (0) MAXTEXTS (96 texts per step)."""
import sys, os, json, math, random, time
from data_checks import check_directory

if len(sys.argv) < 5:
    raise SystemExit("usage: train_embed.py <HF model dir> <models dir> <prepared data dir> <new output.dte> [epochs]")
try:
    print("data isolation", check_directory(sys.argv[3], [x for x in os.environ.get("EXTRA", "").split(",") if x]), flush=True)
except (ValueError, OSError) as exc:
    raise SystemExit(str(exc))
try:
    import resource
except ImportError:  # Windows has no Unix resource module.
    resource = None
import numpy as np, torch, torch.nn.functional as F
from transformers import AutoTokenizer, BertModel, BertConfig
sys.path.insert(0, os.path.dirname(__file__)); import dte

hf, mdir, ddir, out = sys.argv[1:5]; EPOCHS = int(sys.argv[5]) if len(sys.argv) > 5 else 6
ALPHA = float(os.environ.get("ALPHA", 0.2)); LR = float(os.environ.get("LR", 5e-5)); SKILLS = os.environ.get("SKILLS", "0") == "1"
MAXT = int(os.environ.get("MAXTEXTS", 96)); JEVA = float(os.environ.get("JEVA", 0.0)); EXTRA = [x for x in os.environ.get("EXTRA", "").split(",") if x]; EPS = 0.01; SCALE, BIAS = 12.0, 0.55
torch.set_num_threads(int(os.environ.get("TORCH_THREADS", "2"))); torch.manual_seed(0); random.seed(0)
DEV = torch.device(os.environ.get("TORCH_DEVICE", "cpu"))  # TORCH_DEVICE=cuda on Colab GPUs


def ten(data, dtype=torch.float32):
    return torch.tensor(data, dtype=dtype).to(DEV)


def tonumpy(t):
    return t.detach().cpu().numpy()
tok = AutoTokenizer.from_pretrained(hf); cfg = BertConfig.from_pretrained(hf); cfg.max_position_embeddings = 512
bmeta, base = dte.read(f"{mdir}/encoder-tiny.dte")
# the bi-encoder file has no pooler / NLI head: borrow shapes, they are not used
fake = dict(base); fake["pool.w"] = np.zeros((cfg.hidden_size, cfg.hidden_size), np.float32); fake["pool.b"] = np.zeros(cfg.hidden_size, np.float32)
fake["nli.w"] = np.zeros((3, cfg.hidden_size), np.float32); fake["nli.b"] = np.zeros(3, np.float32)
sd, _, _ = dte.to_hf(fake, base["word"], cfg.num_hidden_layers)
m = BertModel(cfg, add_pooling_layer=True); r = m.load_state_dict(sd, strict=False); m.to(DEV)
assert not r.unexpected_keys and all("position_ids" in k for k in r.missing_keys), r
INIT = os.environ.get("INIT", "")  # INIT=hf: start from the HF checkpoint in argv[1] (e.g. rubert-tiny-turbo), own word table
if INIT == "hf":
    from safetensors.torch import load_file
    hsd = {k.removeprefix("bert."): v for k, v in load_file(f"{hf}/model.safetensors").items()}
    hsd["embeddings.position_embeddings.weight"] = hsd["embeddings.position_embeddings.weight"][:cfg.max_position_embeddings]
    hsd = {k: v for k, v in hsd.items() if k in m.state_dict() and m.state_dict()[k].shape == v.shape}
    r2 = m.load_state_dict(hsd, strict=False); print("init from", hf, "missing", [k for k in r2.missing_keys if "pooler" not in k and "position_ids" not in k], flush=True)
m.embeddings.word_embeddings.weight.requires_grad = False
for p in m.pooler.parameters(): p.requires_grad = False
teacher = json.load(open(f"{ddir}/teacher-nli.json")) if os.path.exists(f"{ddir}/teacher-nli.json") else {}

JEV = {}
for nm in ("train", "dev"):
    fn = f"{os.path.dirname(os.path.abspath(ddir))}/jev/{nm}.jevlabels.jsonl"
    if JEVA > 0 and os.path.exists(fn):
        for l in open(fn, encoding="utf-8"):
            d = json.loads(l); JEV.update({(d["group"], k): v for k, v in d["labels"].items()})

def load(fn, soft=False):
    rows = []
    for l in open(fn, encoding="utf-8"):
        d = json.loads(l)
        for q in d["questions"]:
            if q.get("label") is None or (q.get("task") == "skill_routing" and not SKILLS):
                continue
            q = dict(q); q["soft"] = soft; j = JEV.get((d.get("group"), q["id"])) if not soft else None
            if j is not None: q["jev"] = j
            rows.append((d["chunks"], q))
    return rows

def soft_dist(q, lab):
    keys = [o["key"] for o in q["options"]]
    if q["type"] == "noul":
        v = float(lab); return np.array([v, 1 - v]) * 0.96 + 0.02
    if not isinstance(lab, dict): lab = {str(lab): 1.0}  # hard label (e.g. train.para)
    t = np.array([float(lab.get(k, 0)) for k in keys]) + 0.01; return t / t.sum()

def target(q, mix=True):
    if q.get("soft"):
        return soft_dist(q, q["label"])
    t = target_raw(q)
    if mix and "jev" in q and JEVA > 0:
        t = (1 - JEVA) * t + JEVA * soft_dist(q, q["jev"])
    return t

def target_raw(q):
    keys = [o["key"] for o in q["options"]]; lab = q["label"]; t = np.zeros(len(keys))
    if q["type"] == "noul":
        v = float(lab) if not isinstance(lab, bool) else (1.0 if lab else 0.0); return np.array([v, 1 - v]) * 0.94 + 0.03
    if isinstance(lab, dict):
        for k, v in lab.items(): t[keys.index(k)] = v
    else:
        t[keys.index(lab)] = 1
    if q["type"] == "score":
        sm = np.convolve(t, [0.1, 0.8, 0.1], mode="same"); t = sm / sm.sum()
    else:
        t = t * 0.92 + 0.08 / len(t)
    return t

def side(e, c):
    return (torch.log(e + EPS) - torch.log(c + EPS)) * (e + c)

def question_probs(q, E, C):
    e, c = E.max(1).values, C.max(1).values; esc = [bool(o.get("escape")) for o in q["options"]]
    if q["type"] == "noul":
        if not q["has_criteria"]:
            z = side(e[0], c[0])
        else:
            zt = side(e[0], c[0]) if not esc[0] else 0; zf = side(e[1], c[1]) if not esc[1] else 0
            z = (zt - zf) / 1.5 if not esc[0] and not esc[1] else (zt if not esc[0] else -zf)
        p = torch.sigmoid(torch.as_tensor(z)); return torch.stack([p, 1 - p]), e
    z = torch.log(e + EPS) - 0.5 * torch.log(c + EPS)
    keep = torch.tensor([not x for x in esc]).to(DEV); z = torch.where(keep, z, torch.full_like(z, -30.0))
    return torch.softmax(z, 0), e

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
    p, _ = question_probs(q, ten(E), ten(C))
    p = np.exp(np.log(np.clip(tonumpy(p).astype(np.float64), 1e-6, 1)) / TQ_TEMP[q["type"]]); return p / p.sum()

def encode(texts):
    e = tok(texts, truncation=True, max_length=128, padding=True, return_tensors="pt")
    e = {k: v.to(DEV) for k, v in e.items()}
    x = m(**e).last_hidden_state; mask = e["attention_mask"].float()
    mean = (x * mask[..., None]).sum(1) / mask.sum(1, keepdim=True); mean = F.normalize(mean, dim=-1)
    tokn = F.normalize(x, dim=-1); L = mask.sum(1).long()
    inner = mask.clone(); inner[:, 0] = 0; inner[torch.arange(len(texts), device=DEV), L - 1] = 0  # drop [CLS]/[SEP]
    return mean, tokn, inner, L

def sims(hi, pi, mean, tokn, inner, L):
    """sim(h, p) for index tensors hi, pi (exactly semai: ½cos(mean) + ½MaxSim(h, p))."""
    cos = (mean[hi] * mean[pi]).sum(-1)
    S = torch.einsum("nid,njd->nij", tokn[hi], tokn[pi])
    S = S.masked_fill(inner[pi][:, None, :] == 0, -2.0)
    best = S.max(-1).values; w = inner[hi]
    ms = (best * w).sum(-1) / w.sum(-1).clamp(min=1)
    ok = ((L[hi] >= 3) & (L[pi] >= 3)).float()
    return 0.5 * cos + 0.5 * ms * ok

def run(batch):
    texts, ix = [], {}
    def tid(t):
        if t not in ix: ix[t] = len(texts); texts.append(t)
        return ix[t]
    plan = []
    for chunks, q in batch:
        cid = [tid(c) for c in chunks]
        hid = [tid(o["hyp"]) if not o.get("escape") else tid("-") for o in q["options"]]
        plan.append((cid, hid))
    mean, tokn, inner, L = encode(texts)
    hi = torch.tensor([h for cid, hid in plan for h in hid for c in cid], dtype=torch.long).to(DEV); pi = torch.tensor([c for cid, hid in plan for h in hid for c in cid], dtype=torch.long).to(DEV)
    E_all = torch.sigmoid(SCALE * (sims(hi, pi, mean, tokn, inner, L) - BIAS))
    loss = 0.0; probs = []; off = 0
    for (chunks, q), (cid, hid) in zip(batch, plan):
        n = len(cid) * len(hid); E = E_all[off:off + n].view(len(hid), len(cid)); off += n
        pq, e = question_probs(q, E, 1 - E); probs.append(tonumpy(pq))
        lab = q["label"]
        if q["type"] == "choice" and isinstance(lab, str) and any(o["key"] == lab and o.get("escape") for o in q["options"]):
            sub = e[[not o.get("escape") for o in q["options"]]]
            loss = loss + F.binary_cross_entropy(sub.clamp(1e-4, 1 - 1e-4), torch.zeros_like(sub)); continue
        t = target(q); tq = teacher_q(q, chunks)
        if tq is not None and ALPHA > 0:
            t = (1 - ALPHA) * t + ALPHA * tq  # (label/Jev mix) ⊕ mDeBERTa
        tt = ten(t); pq = pq.clamp(1e-6, 1); v = tt > 0
        loss = loss + (tt[v] * (torch.log(tt[v]) - torch.log(pq[v]))).sum() + ((pq - tt) ** 2).sum()
    return loss / len(batch), probs

def ntexts(row):
    return len(row[0]) + len(row[1]["options"])
def batches(rows):
    out, cur, n = [], [], 0
    for r in rows:
        if cur and n + ntexts(r) > MAXT:
            out.append(cur); cur, n = [], 0
        cur.append(r); n += ntexts(r)
    if cur: out.append(cur)
    return out

def evaluate(rows):
    m.eval(); hit = {}; br = {}
    with torch.no_grad():
        for b in batches(rows):
            _, ps = run(b)
            for (chunks, q), p in zip(b, ps):
                t = target(q); ty = q["type"]; g = (t == t.max()).astype(float)
                lab = q["label"]
                if q["type"] == "choice" and isinstance(lab, str) and any(o["key"] == lab and o.get("escape") for o in q["options"]):
                    continue  # abstain resolution happens in the engine, not here
                hit.setdefault(ty, []).append(int(np.argmax(p) == np.argmax(t))); br.setdefault(ty, []).append(float(((p - g) ** 2).sum()))
    m.train()
    return {k: (round(float(np.mean(v)), 4), len(v), round(float(np.mean(br[k])), 3)) for k, v in hit.items()}

train = load(f"{ddir}/train.plans.jsonl"); dev = load(f"{ddir}/dev.plans.jsonl")
for x in EXTRA: train += load(x, soft=True)
print("jev targets", len(JEV), "jev-mixed train questions", sum("jev" in q for _, q in train), "soft", sum(q["soft"] for _, q in train), flush=True)
tests = {os.path.basename(f)[5:-12]: load(f"{ddir}/{f}") for f in sorted(os.listdir(ddir)) if f.startswith("test-") and f.endswith(".plans.jsonl")}
print("train", len(train), "dev", len(dev), "teacher pairs", len(teacher), flush=True)
if teacher:
    for ty in TQ_TEMP:
        best = (1e9, 1.0)
        for T in [0.35, 0.5, 0.7, 1.0, 1.4, 2.0, 3.0]:
            TQ_TEMP[ty] = T; nll = []
            for chunks, q in train:
                if q["type"] == ty:
                    tq = teacher_q(q, chunks)
                    if tq is not None: tr = target_raw(q) if not q.get("soft") else target(q); nll.append(-math.log(max(1e-6, float(tq @ (tr == tr.max())))))
            if nll and np.mean(nll) < best[0]: best = (np.mean(nll), T)
        TQ_TEMP[ty] = best[1]
    print("teacher temps", TQ_TEMP, flush=True)
print("before dev", evaluate(dev), {k: evaluate(v) for k, v in tests.items()}, flush=True)
def save_dte():
    g = lambda k: tonumpy(m.state_dict()[k])
    L = cfg.num_hidden_layers; t = [("pos", g("embeddings.position_embeddings.weight")[:512]), ("type", g("embeddings.token_type_embeddings.weight")),
         ("emb_ln.w", g("embeddings.LayerNorm.weight")), ("emb_ln.b", g("embeddings.LayerNorm.bias"))]
    for i in range(L):
        p = f"encoder.layer.{i}."
        for nm, key in dte.LAYER:
            t += [(f"l{i}.{nm}.w", g(p + key + ".weight")), (f"l{i}.{nm}.b", g(p + key + ".bias"))]
        t += [(f"l{i}.ln1.w", g(p + "attention.output.LayerNorm.weight")), (f"l{i}.ln1.b", g(p + "attention.output.LayerNorm.bias")),
              (f"l{i}.ln2.w", g(p + "output.LayerNorm.weight")), (f"l{i}.ln2.b", g(p + "output.LayerNorm.bias"))]
    meta = {k: v for k, v in bmeta.items() if k != "tensors"}; meta["vocab"] = ""; meta["vocab_size"] = 0
    if INIT == "hf":  # carry the (frozen) word table of the new base, int8 per row like encoder-tiny.dte
        w = g("embeddings.word_embeddings.weight"); sc = np.maximum(np.abs(w).max(1), 1e-8) / 127.0
        t = [("word.scale", sc.astype(np.float32)), ("word", np.round(w / sc[:, None]).clip(-127, 127).astype(np.int8))] + t
        meta["vocab"] = bmeta["vocab"]; meta["vocab_size"] = bmeta["vocab_size"]
    meta["source"] = ("sergeyzh/rubert-tiny-turbo" if INIT == "hf" else "cointegrated/rubert-tiny2") + (" + System One distillation (teachers: Jev, mDeBERTa-v3, Gemma, Qwen)" if JEVA > 0 or EXTRA else " + System One distillation v1.7")
    dte.write(out, meta, t); print("wrote", out, os.path.getsize(out), flush=True)

params = [p for p in m.parameters() if p.requires_grad]
opt = torch.optim.AdamW(params, lr=LR, weight_decay=0.01)
random.shuffle(train); steps = EPOCHS * len(batches(train)) + 10
sched = torch.optim.lr_scheduler.OneCycleLR(opt, LR, total_steps=steps, pct_start=0.1)
best = (-1, None); t0 = time.time(); step = 0
devscore = lambda r: sum(v[0] * v[1] for v in r.values()) / sum(v[1] for v in r.values())
for ep in range(EPOCHS):
    random.shuffle(train)
    for b in batches(train):
        loss, _ = run(b); opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(params, 1.0); opt.step(); sched.step(); step += 1
        if step % 50 == 0:
            rss = f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024}MB" if resource else "n/a"
            print(f"ep {ep} step {step}/{steps} loss {loss.item():.4f} {time.time() - t0:.0f}s rss {rss}", flush=True)
    r = evaluate(dev); s = devscore(r); print(f"== epoch {ep} dev {r} score {s:.4f}", flush=True)
    if s > best[0]:
        best = (s, {k: v.detach().clone() for k, v in m.state_dict().items()}); save_dte()  # checkpoint: survives an OOM kill later
m.load_state_dict(best[1]); m.eval()
print("after (best dev)", {k: evaluate(v) for k, v in tests.items()}, flush=True)
save_dte()
