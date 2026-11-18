#!/usr/bin/env python3
"""Turn Jev responses into soft labels: noul -> float, choice/score -> probability dict.
python3 jev_labels.py requests.jsonl jev.jsonl out.labelled.jsonl"""
import json, sys
jev = {json.loads(l)["group"]: json.loads(l)["response"] for l in open(sys.argv[2], encoding="utf-8")}
n = 0
with open(sys.argv[3], "w", encoding="utf-8") as f:
    for i, l in enumerate(open(sys.argv[1], encoding="utf-8")):
        r = json.loads(l); resp = jev.get(r.get("group") or f"row{i}")
        if not resp or "answers" not in resp: continue
        labels = {}
        for qid, q in r["request"]["questions"].items():
            a = resp["answers"].get(qid)
            if a is None: continue
            if q["type"] == "noul": labels[qid] = round(float(a["noul"]), 4); continue
            keys = sorted(q["criteria"], key=float) if q["type"] == "score" else list(q["criteria"])
            pr = a.get("probabilities", {})
            d = {k: float(pr.get(str(j) if q["type"] == "score" else k, 0)) for j, k in enumerate(keys)}
            s = sum(d.values())
            if s > 0: labels[qid] = {k: round(v / s, 4) for k, v in d.items()}
        if labels:
            r["labels"] = labels; f.write(json.dumps(r, ensure_ascii=False) + "\n"); n += 1
print("wrote", n)
