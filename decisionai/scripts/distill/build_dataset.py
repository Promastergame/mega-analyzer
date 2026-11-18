#!/usr/bin/env python3
"""Assemble the System One distillation dataset (v1.7) from project sources.

train : synthetic minimal-pair requests (gen_synth.py, seed 7) + patch-confirmation
        texts (examples/text-synthetic-training.json, subsample) + skill-routing dev
        cases and few-shot examples (evals/skill-routing.jsonl, skill-examples.jsonl)
        (option order is already shuffled by the generator)
dev   : synthetic seed 99 + evals/golden-calib.jsonl   (early stopping, temperature fit)
test  : NEVER read here — evals/golden-test, hard-cases, distill/decision-blind,
        skill-routing-holdout/-blind2/-stress.
Writes data/distill/{train,dev}.labelled.jsonl, then `dai distill-export` turns them
into engine plans (chunks + per-option hypotheses)."""
import json, random, subprocess, os, sys
R = random.Random(11)
root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(root); os.makedirs("data/distill", exist_ok=True)
SKILL_Q = "Какой скил нужен?"

def lines(p):
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]

def skill_rows(path, key):
    out = []
    for d in lines(path):
        acc = d.get("accept") or [d.get("skill")]
        lab = acc[0] if len(acc) == 1 else {k: 1 / len(acc) for k in acc}
        out.append({"group": "skill-" + d.get("group", "ex"), "request": {"state": d["state"], "questions": {
            "skill": {"type": "choice", "task": "skill_routing", "instructions": SKILL_Q}}}, "labels": {"skill": lab}})
    return out

def permute(rows):
    out = []
    for r in rows:
        qs = {}
        for k, q in r["request"]["questions"].items():
            q = dict(q)
            if q["type"] == "choice" and isinstance(q.get("criteria"), dict):
                it = list(q["criteria"].items()); R.shuffle(it); q["criteria"] = dict(it)
            qs[k] = q
        out.append({"group": r["group"] + "-perm", "request": {"state": r["request"]["state"], "questions": qs}, "labels": r["labels"]})
    return out

subprocess.run([sys.executable, "scripts/distill/gen_synth.py", "data/distill/syn-train.jsonl", "220", "7"], check=True)
subprocess.run([sys.executable, "scripts/distill/gen_synth.py", "data/distill/syn-dev.jsonl", "40", "99"], check=True)
train = lines("data/distill/syn-train.jsonl")
txt = json.load(open("examples/text-synthetic-training.json", encoding="utf-8"))["samples"]
R.shuffle(txt)
for s in txt[:160]:
    x = s["input"]
    train.append({"group": "text-" + s["group"], "request": {"state": x["state"], "questions": {"confirm": {"type": "noul", "instructions": x["question"],
                  "criteria": {"true": x["true_when"], "false": x["false_when"]}}}}, "labels": {"confirm": s["label"] == 1}})
train += skill_rows("evals/skill-routing.jsonl", "accept") + skill_rows("evals/skill-examples.jsonl", "skill")
test_states = set()
for p in ["evals/golden-test.jsonl", "evals/hard-cases.jsonl", "evals/distill/decision-blind.jsonl"]:
    test_states |= {json.dumps(d["request"]["state"], ensure_ascii=False) for d in lines(p)}
for p in ["evals/skill-routing-holdout.jsonl", "evals/skill-routing-blind2.jsonl", "evals/skill-routing-stress.jsonl"]:
    test_states |= {json.dumps(d["state"], ensure_ascii=False) for d in lines(p)}
dev = lines("data/distill/syn-dev.jsonl") + lines("evals/golden-calib.jsonl")
before = len(train)
train = [r for r in train if json.dumps(r["request"]["state"], ensure_ascii=False) not in test_states]
dev = [r for r in dev if json.dumps(r["request"]["state"], ensure_ascii=False) not in test_states]
print(f"train {len(train)} (dropped {before - len(train)} overlapping test states), dev {len(dev)}")
for name, rows in [("train", train), ("dev", dev)]:
    with open(f"data/distill/{name}.labelled.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(f"data/distill/{name}.plans.jsonl", "w") as f:
        subprocess.run(["bin/dai", "distill-export", "-experts=false", "-skills", "evals/skills", "-input", f"data/distill/{name}.labelled.jsonl"], stdout=f, check=True)
for name in ["golden-test", "hard-cases", "distill/decision-blind"]:
    with open(f"data/distill/test-{os.path.basename(name)}.plans.jsonl", "w") as f:
        subprocess.run(["bin/dai", "distill-export", "-experts=false", "-input", f"evals/{name}.jsonl"], stdout=f, check=True)
