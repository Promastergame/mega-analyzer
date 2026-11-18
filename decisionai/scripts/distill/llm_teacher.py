"""Local LLM teacher / System Two (v1.14): Qwen2.5-Instruct on CPU answers DecisionAI questions offline.
Option probabilities come straight from next-token logits over option labels (no generation). Weights f32
(DTYPE=bf16 for models that do not fit RAM in f32); INT8=1 dynamic quantisation is available but hurts Qwen.
  eval : llm_teacher.py eval  MODEL_DIR evals/unseen.jsonl [...]        -> accuracy vs gold labels
  label: llm_teacher.py label MODEL_DIR in.jsonl out.labelled.jsonl     -> soft labels (resumable)
  serve: llm_teacher.py serve MODEL_DIR [port=8088]                      -> local System Two: the same
         decisions API as -escalate (POST /decisions), so `dai -escalate local/qwen2.5-1.5b
         -escalate-url http://127.0.0.1:8088/decisions` cascades uncertain answers to it, offline."""
import json, math, os, sys, time, torch
from transformers import AutoTokenizer, AutoModelForCausalLM
torch.set_num_threads(int(os.environ.get("THREADS", 2))); torch.set_grad_enabled(False)
mode, mdir = sys.argv[1], sys.argv[2]
tok = AutoTokenizer.from_pretrained(mdir)
model = AutoModelForCausalLM.from_pretrained(mdir, dtype=torch.bfloat16, low_cpu_mem_usage=True)
base = model.model
import torch.ao.nn.quantized.dynamic as qd
def quantise(mod):
    for name, ch in list(mod.named_children()):
        if isinstance(ch, torch.nn.Linear):
            f = torch.nn.Linear(ch.in_features, ch.out_features, bias=ch.bias is not None)
            f.weight.data = ch.weight.data.float()
            if ch.bias is not None: f.bias.data = ch.bias.data.float()
            f.qconfig = torch.ao.quantization.per_channel_dynamic_qconfig
            setattr(mod, name, qd.Linear.from_float(f)); del f
        else: quantise(ch)
(quantise(base.layers) if os.environ.get("INT8") else None)
for m in (base.modules() if os.environ.get("DTYPE", "f32") == "f32" else []):
    if not isinstance(m, qd.Linear):
        for n, p in list(m.named_parameters(recurse=False)): setattr(m, n, torch.nn.Parameter(p.data.float(), requires_grad=False))
        for n, b in list(m.named_buffers(recurse=False)): setattr(m, n, b.float()) if b.is_floating_point() else None
E = base.embed_tokens.weight  # tied LM head: logits for the few option tokens only
del model.lm_head
SYS = "You are a precise, careful decision analyst. Read the case and answer the question. Think about what the text actually says, including negations, context and intent. Reply with exactly one option label and nothing else."
LET = "ABCDEFGHIJ"

def opts(q):
    t = q["type"]; cr = q.get("criteria") or {}
    if t == "noul":
        if cr and isinstance(cr, dict) and ("true" in cr or "false" in cr):
            return "Options:\nyes = " + cr.get("true", "yes") + "\nno = " + cr.get("false", "no"), ["yes", "no"], ["true", "false"]
        return "Options: yes / no", ["yes", "no"], ["true", "false"]
    keys = list(cr.keys())
    labs = [str(i) for i in range(len(keys))] if t == "score" else list(LET[:len(keys)])
    return "Options:\n" + "\n".join(f"{l} = {cr[k]}" for l, k in zip(labs, keys)), labs, keys

def ids_of(labs):
    out = []
    for l in labs:
        v = set()
        for s in (l, " " + l, l.capitalize(), l.upper()):
            t = tok.encode(s, add_special_tokens=False)
            if t: v.add(t[0])
        out.append(sorted(v))
    return out

def answer_state(state, qs):
    res = {}
    for qid, q in qs.items():
        o, labs, keys = opts(q)
        msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": "Case:\n" + state.strip()[:3000] + "\n\nQuestion: " + q.get("instructions", "") + "\n" + o + "\nAnswer with only the label."}]
        ids = tok(tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True), return_tensors="pt", add_special_tokens=False).input_ids
        h = base(input_ids=ids).last_hidden_state[0, -1].float()
        lg = [torch.logsumexp(h @ E[i].float().T, 0).item() for i in ids_of(labs)]
        m = max(lg); p = [math.exp(x - m) for x in lg]; s = sum(p); p = [x / s for x in p]
        res[qid] = (keys, p)
    return res

def to_label(q, keys, p):
    if q["type"] == "noul": return round(p[0], 4)
    return {k: round(v, 4) for k, v in zip(keys, p)}

def serve(port):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    name = "local/" + os.path.basename(mdir.rstrip("/"))
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                st = body.get("state"); st = st if isinstance(st, str) else json.dumps(st, ensure_ascii=False)
                qs = {}
                for qid, q in (body.get("questions") or {}).items():
                    q = dict(q); cr = q.get("criteria")
                    if isinstance(cr, list): q["criteria"] = {str(i): v for i, v in enumerate(cr)}  # score levels by index
                    if isinstance(q.get("instructions"), (dict, list)): q["instructions"] = json.dumps(q["instructions"], ensure_ascii=False)
                    qs[qid] = q
                ans = {}
                for qid, (keys, p) in answer_state(st, qs).items():
                    t = qs[qid]["type"]
                    ans[qid] = {"type": t, "noul": round(p[0], 4)} if t == "noul" else {"type": t, "probabilities": {k: round(v, 4) for k, v in zip(keys, p)}}
                out = json.dumps({"model": name, "answers": ans, "usage": {"cost": 0}}).encode(); code = 200
            except Exception as e:
                out = json.dumps({"error": {"message": str(e)}}).encode(); code = 400
            self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    print(f"{name} serving POST http://127.0.0.1:{port}/decisions", flush=True)
    HTTPServer(("127.0.0.1", port), H).serve_forever()

if mode == "serve":
    serve(int(sys.argv[3]) if len(sys.argv) > 3 else 8088)
elif mode == "eval":
    for fn in sys.argv[3:]:
        hit = {}; t0 = time.time(); n = 0
        for line in open(fn, encoding="utf-8"):
            d = json.loads(line); r = d["request"]; qs = {k: v for k, v in r["questions"].items() if k in d["labels"]}
            st = r["state"] if isinstance(r["state"], str) else json.dumps(r["state"], ensure_ascii=False)
            for qid, (keys, p) in answer_state(st, qs).items():
                q = qs[qid]; g = d["labels"][qid]; n += 1
                pred = keys[max(range(len(p)), key=p.__getitem__)]
                ok = (pred == "true") == bool(g) if q["type"] == "noul" else pred == str(g)
                hit.setdefault(q["type"], []).append(ok)
        print(fn, {k: f"{100*sum(v)/len(v):.0f}/{len(v)}" for k, v in hit.items()}, "total", sum(sum(v) for v in hit.values()), "/", n, f"{(time.time()-t0)/max(1,n):.2f}s/q", flush=True)
else:
    src, dst = sys.argv[3], sys.argv[4]; done = set()
    if os.path.exists(dst): done = {json.loads(l)["group"] for l in open(dst, encoding="utf-8")}
    t0 = time.time(); k = 0
    with open(dst, "a", encoding="utf-8") as f:
        for line in open(src, encoding="utf-8"):
            d = json.loads(line)
            if d["group"] in done: continue
            r = d["request"]; st = r["state"] if isinstance(r["state"], str) else json.dumps(r["state"], ensure_ascii=False)
            res = answer_state(st, r["questions"])
            d["labels"] = {qid: to_label(r["questions"][qid], *kp) for qid, kp in res.items()}; d["teacher"] = os.path.basename(mdir.rstrip("/"))
            f.write(json.dumps(d, ensure_ascii=False) + "\n"); f.flush(); k += 1
            if k % 20 == 0: print(f"{k} done, {(time.time()-t0)/k:.2f}s/request", flush=True)
