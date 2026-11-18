#!/usr/bin/env python3
"""Teacher labelling: turn DecisionAI requests into reference *probabilities* from 1-2 large LLMs.

For each question the teacher is constrained to answer with exactly one declared key; we sample
it N times (temperature 1) and use answer frequencies as the reference distribution. With two
teachers the distributions are averaged (as in TypeSafe's workflow evals). Output is the
Labelled JSONL accepted by `dai eval` / `dai calibrate`.

Usage (any OpenAI-compatible endpoint, stdlib only):
  export TEACHER_BASE_URL=https://api.openai.com/v1 TEACHER_API_KEY=...
  python3 label.py -i requests.jsonl -o labelled.jsonl --models gpt-5.6,other-model --samples 8
Input lines: either a bare request {"state":..,"questions":..} or {"group":..,"request":{..}}.
"""
import argparse, collections, json, os, sys, urllib.request

def chat(base, key, model, prompt, n):
    body = json.dumps({"model": model, "n": n, "temperature": 1.0,
                       "messages": [{"role": "system", "content": "Answer with exactly one of the allowed keys and nothing else."},
                                    {"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions", body,
                                 {"Content-Type": "application/json", "Authorization": "Bearer " + key})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = json.load(r)
    return [c["message"]["content"].strip().strip('"\'`. ').lower() for c in data["choices"]]

def options(q):
    if q["type"] == "noul":
        return ["true", "false"]
    return list(q["criteria"].keys())

def prompt_for(state, q):
    st = state if isinstance(state, str) else json.dumps(state, ensure_ascii=False, indent=1)
    lines = [f"STATE:\n{st}\n", f"QUESTION ({q['type']}): {json.dumps(q['instructions'], ensure_ascii=False)}"]
    if q["type"] == "noul":
        crit = q.get("criteria") or {}
        lines.append(f"true = {crit.get('true', 'yes')}\nfalse = {crit.get('false', 'no')}")
    else:
        for k, v in q["criteria"].items():
            lines.append(f"{k} = {v if v else k}")
    lines.append("Allowed keys: " + ", ".join(options(q)))
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--models", required=True, help="comma-separated teacher model names")
    ap.add_argument("--samples", type=int, default=8)
    a = ap.parse_args()
    base, key = os.environ.get("TEACHER_BASE_URL", "https://api.openai.com/v1"), os.environ["TEACHER_API_KEY"]
    models = [m for m in a.models.split(",") if m]
    with open(a.input, encoding="utf-8") as fi, open(a.output, "w", encoding="utf-8") as fo:
        for ln, line in enumerate(fi, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            req = row.get("request", row)
            labels = {}
            for qid, q in req["questions"].items():
                keys = options(q)
                dist = collections.Counter()
                for m in models:
                    outs = chat(base, key, m, prompt_for(req["state"], q), a.samples)
                    valid = [o for o in outs if o in keys]
                    for o in valid:
                        dist[o] += 1 / (len(valid) * len(models))
                    if len(valid) < len(outs):
                        print(f"line {ln} {qid} {m}: {len(outs)-len(valid)} invalid samples dropped", file=sys.stderr)
                if not dist:
                    continue
                labels[qid] = dist["true"] if q["type"] == "noul" else {k: round(v, 4) for k, v in dist.items()}
            fo.write(json.dumps({"group": row.get("group", f"line-{ln}"), "request": req, "labels": labels}, ensure_ascii=False) + "\n")
            print(f"labelled {ln}", file=sys.stderr)

if __name__ == "__main__":
    main()
