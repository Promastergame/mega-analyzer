#!/usr/bin/env python3
"""DecisionAI vs TypeSafe Jev, side by side on the same requests.

  python3 scripts/compare_jev.py ours  [-backend s1] [-cases evals/jev-compare/cases.jsonl]
      runs bin/dai decide on every case -> evals/jev-compare/ours-<backend>.jsonl
  python3 scripts/compare_jev.py jev   (OPENROUTER_API_KEY -> typesafe/jev-1.13, or TYPESAFE_API_KEY -> api.typesafe.ai)
      -> evals/jev-compare/jev.jsonl         (or paste Jev responses there by hand: {"id":..,"response":{..}})
  python3 scripts/compare_jev.py compare [-backend s1]
      agreement of top answers, |Δnoul|, Jensen–Shannon of distributions, accuracy of both vs labels
Stdlib only."""
import json, math, os, subprocess, sys, urllib.request
args = sys.argv[1:]; cmd = args[0] if args else "compare"
opt = lambda k, d: args[args.index(k) + 1] if k in args else d
ESC = opt("-escalate", "")  # v1.9 cascade: uncertain answers re-asked from this remote model
CASES = opt("-cases", "evals/jev-compare/cases.jsonl"); BACK = opt("-backend", "s1"); DIR = os.path.dirname(CASES)
cases = [json.loads(l) for l in open(CASES, encoding="utf-8") if l.strip()]

def dist(a):
    """answer -> {key: p}; noul -> {"true": p, "false": 1-p}"""
    if a.get("type") == "noul" or "noul" in a:
        p = float(a["noul"]); return {"true": p, "false": 1 - p}
    pr = a.get("probabilities") or {}
    return {str(k): float(v) for k, v in pr.items()}

def top(d):
    return max(d, key=d.get) if d else None

def js(p, q):
    keys = set(p) | set(q); m = {k: (p.get(k, 0) + q.get(k, 0)) / 2 for k in keys}
    kl = lambda a: sum(a.get(k, 0) * math.log2(a.get(k, 0) / m[k]) for k in keys if a.get(k, 0) > 0)
    return (kl(p) + kl(q)) / 2

def label_key(v):
    return ("true" if v else "false") if isinstance(v, bool) else str(v)

if cmd == "ours":
    out = open(f"{DIR}/ours-{BACK}{'-cascade' if ESC else ''}.jsonl", "w", encoding="utf-8")
    for c in cases:
        r = subprocess.run(["bin/dai", "decide", "-backend", BACK] + (["-escalate", ESC] if ESC else []), input=json.dumps(c["request"], ensure_ascii=False).encode(), capture_output=True, check=True)
        out.write(json.dumps({"id": c["id"], "response": json.loads(r.stdout)}, ensure_ascii=False) + "\n")
    print("wrote", out.name)
elif cmd == "jev":
    out = open(f"{DIR}/jev.jsonl", "w", encoding="utf-8")
    if os.environ.get("OPENROUTER_API_KEY"):  # v1.8: Jev via OpenRouter's decisions API (typesafe/jev-1.13)
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "teacher")); import jev_teacher as jt
        for c in cases:
            out.write(json.dumps({"id": c["id"], "response": jt.call(jt.to_jev(c["request"]))}, ensure_ascii=False) + "\n")
    else:
      key = os.environ["TYPESAFE_API_KEY"]
      for c in cases:
        req = dict(c["request"]); req["model"] = os.environ.get("JEV_MODEL", "jev-latest")
        rq = urllib.request.Request("https://api.typesafe.ai/v1/systemone", json.dumps(req).encode(),
                                    {"Content-Type": "application/json", "Authorization": "Bearer " + key})
        with urllib.request.urlopen(rq, timeout=60) as r:
            out.write(json.dumps({"id": c["id"], "response": json.load(r)}, ensure_ascii=False) + "\n")
    print("wrote", out.name)
else:
    load = lambda p: {d["id"]: d["response"] for d in (json.loads(l) for l in open(p, encoding="utf-8") if l.strip())}
    ours = load(f"{DIR}/ours-{BACK}{'-cascade' if ESC else ''}.jsonl"); jev = load(f"{DIR}/jev.jsonl") if os.path.exists(f"{DIR}/jev.jsonl") else {}
    agree = jsd = n = 0; acc = {"ours": [0, 0], "jev": [0, 0]}
    print(f"{'case':22} {'question':13} {'gold':8} {'ours':>16} {'jev':>16}")
    for c in cases:
        for qid in c["request"]["questions"]:
            o = dist(ours[c["id"]]["answers"][qid]); j = dist(jev[c["id"]]["answers"][qid]) if c["id"] in jev else {}
            g = label_key(c["labels"][qid]) if qid in c.get("labels", {}) else None
            fmt = lambda d: f"{top(d)}:{d[top(d)]:.2f}" if d else "—"
            print(f"{c['id']:22} {qid:13} {str(g):8} {fmt(o):>16} {fmt(j):>16}")
            if g is not None:
                acc["ours"][0] += top(o) == g; acc["ours"][1] += 1
                if j: acc["jev"][0] += top(j) == g; acc["jev"][1] += 1
            if j:
                n += 1; agree += top(o) == top(j); jsd += js(o, j)
    for k, (h, t) in acc.items():
        if t: print(f"{k} vs labels: {h}/{t} = {h / t:.1%}")
    if n:
        print(f"agreement ours↔jev: {agree}/{n} = {agree / n:.1%}; mean Jensen–Shannon {jsd / n:.3f} bits")
    else:
        print("no jev.jsonl yet: run `compare_jev.py jev` with TYPESAFE_API_KEY or paste responses")
