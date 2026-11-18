#!/usr/bin/env python3
"""Jev (TypeSafe System One) as a teacher / comparison model via OpenRouter's decisions API.

  OPENROUTER_API_KEY=... python3 jev_teacher.py in.labelled.jsonl out.jev.jsonl [threads]
Each line of `in` is {"group","request","labels"}; requests are converted to Jev's wire format
(score criteria map {"0":..} -> ordered array, `task`/`polarity` fields dropped, skill_routing
questions without criteria skipped). Output: {"group", "response"} per line, resumable (cache by group).
Stdlib only."""
import json, os, sys, time, hashlib, urllib.request, concurrent.futures as cf
KEY = os.environ.get("OPENROUTER_API_KEY", ""); MODEL = os.environ.get("JEV_MODEL", "typesafe/jev-1.13")
NOUL_ONLY = os.environ.get("NOUL_ONLY", "1" if MODEL.startswith("respan/") else "0") == "1"
URL = "https://openrouter.ai/api/alpha/decisions"

def to_jev(req):
    qs = {}
    for k, q in req["questions"].items():
        if q.get("task") == "skill_routing" and not q.get("criteria"):
            continue
        if NOUL_ONLY and q["type"] != "noul":  # Respan Span-01 (Lite) scores noul behaviours only
            continue
        j = {"type": q["type"], "instructions": q["instructions"]}
        c = q.get("criteria")
        if q["type"] == "score" and isinstance(c, dict):
            keys = sorted(c, key=lambda x: float(x))
            j["criteria"] = [c[x] if c[x] else x for x in keys]
        elif c is not None:
            j["criteria"] = c
        qs[k] = j
    st = req["state"]
    if NOUL_ONLY and not isinstance(st, str):  # Respan accepts a string or a chat transcript only
        st = json.dumps(st, ensure_ascii=False, indent=1)
    return {"model": MODEL, "state": st, "questions": qs}

def call(body):
    for attempt in range(5):
        try:
            r = urllib.request.Request(URL, json.dumps(body, ensure_ascii=False).encode(), {"Content-Type": "application/json", "Authorization": "Bearer " + KEY})
            with urllib.request.urlopen(r, timeout=90) as f:
                return json.load(f)
        except urllib.error.HTTPError as e:
            msg = e.read().decode()[:300]
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(2 ** attempt); continue
            return {"error": f"{e.code} {msg}"}
        except Exception as e:
            time.sleep(2 ** attempt); err = str(e)
    return {"error": "retries exhausted"}

def main():
    src, dst = sys.argv[1], sys.argv[2]; TH = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    rows = [json.loads(l) for l in open(src, encoding="utf-8") if l.strip()]
    done = {}
    if os.path.exists(dst):
        for l in open(dst, encoding="utf-8"):
            d = json.loads(l)
            if "error" not in d["response"]: done[d["key"]] = d
    todo = []
    for i, r in enumerate(rows):
        r.setdefault("group", r.get("group") or f"row{i}")
        body = to_jev(r["request"])
        if not body["questions"]:
            continue
        key = hashlib.sha1(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]
        if key not in done: todo.append((r["group"], key, body))
    print(f"{len(rows)} rows, {len(done)} cached, {len(todo)} to call", flush=True)
    cost = 0.0; t0 = time.time()
    with open(dst, "a", encoding="utf-8") as out, cf.ThreadPoolExecutor(TH) as ex:
        futs = {ex.submit(call, b): (g, k) for g, k, b in todo}
        for i, f in enumerate(cf.as_completed(futs)):
            g, k = futs[f]; resp = f.result()
            cost += (resp.get("usage") or {}).get("cost", 0) or 0
            out.write(json.dumps({"group": g, "key": k, "response": resp}, ensure_ascii=False) + "\n"); out.flush()
            if "error" in resp: print("ERR", g, resp["error"][:200], flush=True)
            if (i + 1) % 100 == 0: print(f"{i + 1}/{len(todo)} ${cost:.4f} {time.time() - t0:.0f}s", flush=True)
    print(f"done ${cost:.4f}")

if __name__ == "__main__":
    main()
