#!/usr/bin/env python3
"""Score Jev responses (jev_teacher.py output) against labels with the same metrics as `dai eval`
(agreement = argmax match, Brier). python3 eval_jev.py labelled.jsonl jev.jsonl [--errors]"""
import json, sys, collections
rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
jev = {}
for l in open(sys.argv[2], encoding="utf-8"):
    d = json.loads(l); jev[d["group"]] = d["response"]
hit = collections.defaultdict(list); br = collections.defaultdict(list); errs = []
for i, r in enumerate(rows):
    resp = jev.get(r.get("group") or f"row{i}")
    if not resp or "answers" not in resp: continue
    for qid, lab in r["labels"].items():
        a = resp["answers"].get(qid); q = r["request"]["questions"][qid]
        if a is None: continue
        if q["type"] == "noul":
            p = {"true": a["noul"], "false": 1 - a["noul"]}
            if isinstance(lab, bool): g = {"true": float(lab), "false": float(not lab)}
            else: g = {"true": float(lab), "false": 1 - float(lab)}
        else:
            keys = sorted(q["criteria"], key=float) if q["type"] == "score" else list(q["criteria"])
            pr = a.get("probabilities", {})
            p = {k: float(pr.get(str(i) if q["type"] == "score" else k, 0)) for i, k in enumerate(keys)}
            g = {k: 0.0 for k in keys}
            if isinstance(lab, dict): g.update({k: float(v) for k, v in lab.items()})
            else: g[str(lab)] = 1.0
        top = max(p, key=p.get); gt = max(g, key=g.get)
        hit[q["type"]].append(top == gt); br[q["type"]].append(sum((p[k] - g[k]) ** 2 for k in g))
        if top != gt: errs.append((r.get("group"), qid, gt, top, round(p[top], 2)))
print({t: (round(sum(v) / len(v), 4), len(v), round(sum(br[t]) / len(br[t]), 3)) for t, v in hit.items()})
if "--errors" in sys.argv:
    for e in errs: print("  ", e)
