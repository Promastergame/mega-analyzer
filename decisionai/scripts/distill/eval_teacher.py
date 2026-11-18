"""Zero-shot accuracy of the NLI teacher on distill plans, through the engine aggregation."""
import json, sys, numpy as np
T = json.load(open(sys.argv[1])); EPS = 0.01
def side(e, c): return (np.log(e + EPS) - np.log(c + EPS)) * (e + c)
for fn in sys.argv[2:]:
    hit = {}
    for l in open(fn, encoding="utf-8"):
        d = json.loads(l)
        for q in d["questions"]:
            if q.get("label") is None or q.get("task") == "skill_routing": continue
            E = []; C = []; esc = [bool(o.get("escape")) for o in q["options"]]
            for o in q["options"]:
                v = [T.get(c + "\x00" + o["hyp"], [0, 1, 0]) if not o.get("escape") else [0, 1, 0] for c in d["chunks"]]
                E.append(max(x[0] for x in v)); C.append(max(x[2] for x in v))
            E, C = np.array(E), np.array(C); keys = [o["key"] for o in q["options"]]; lab = q["label"]
            if q["type"] == "noul":
                if not q["has_criteria"]: z = side(E[0], C[0])
                else:
                    zt = side(E[0], C[0]) if not esc[0] else 0; zf = side(E[1], C[1]) if not esc[1] else 0
                    z = (zt - zf) / 1.5 if not any(esc) else (zt if not esc[0] else -zf)
                ok = (z > 0) == bool(lab)
            else:
                z = np.log(E + EPS) - 0.5 * np.log(C + EPS); sup = E.max()
                z = np.where(esc, np.log(1 - sup + EPS) if sup < 0.2 else -9, z)
                if isinstance(lab, dict): lab = max(lab, key=lab.get)
                ok = keys[int(np.argmax(z))] == lab
            hit.setdefault(q["type"], []).append(ok)
    print(fn.split("/")[-1], {k: (round(np.mean(v), 4), len(v)) for k, v in hit.items()})
