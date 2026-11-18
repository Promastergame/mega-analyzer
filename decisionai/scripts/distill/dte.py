"""Read/write DTE1 files (semai/encoder.go format) as numpy dicts."""
import json, struct, numpy as np

def read(path):
    with open(path, "rb") as f:
        assert f.read(4) == b"DTE1"
        n = struct.unpack("<I", f.read(4))[0]
        meta = json.loads(f.read(n)); base = 8 + n; raw = f.read()
    out = {}
    for t in meta["tensors"]:
        b = raw[t["offset"]:t["offset"] + t["size"]]
        dt = {"f32": "<f4", "i8r": "i1"}[t["dtype"]]
        out[t["name"]] = np.frombuffer(b, dtype=dt).reshape(t["shape"])
    if "word" in out:
        out["word"] = out["word"].astype(np.float32) * out["word.scale"][:, None]
    return meta, out

def write(path, meta, tensors):
    """tensors: list of (name, array); all stored f32 except "word" (int8, pass already-quantised ints)."""
    meta = dict(meta); meta["tensors"] = []; blobs = []; off = 0
    for name, a in tensors:
        dt = "f32"
        if name == "word":  # int8 per-row quantised word table (+ "word.scale"), as in encoder-tiny.dte
            raw = np.ascontiguousarray(a, dtype="i1").tobytes(); dt = "i8r"
        else:
            raw = np.ascontiguousarray(a, dtype="<f4").tobytes()
        meta["tensors"].append({"name": name, "dtype": dt, "shape": list(a.shape), "offset": off, "size": len(raw)}); off += len(raw); blobs.append(raw)
    hb = json.dumps(meta, ensure_ascii=False).encode()
    with open(path, "wb") as f:
        f.write(b"DTE1"); f.write(struct.pack("<I", len(hb))); f.write(hb)
        for b in blobs: f.write(b)

LAYER = [("q", "attention.self.query"), ("k", "attention.self.key"), ("v", "attention.self.value"),
         ("o", "attention.output.dense"), ("f1", "intermediate.dense"), ("f2", "output.dense")]

def to_hf(cross, word, L):
    """DTE cross-encoder tensors (+ shared word table) -> HF BertModel state dict (prefix-less)."""
    import torch
    T = lambda a: torch.tensor(np.array(a, dtype=np.float32))
    sd = {"embeddings.word_embeddings.weight": T(word), "embeddings.position_embeddings.weight": T(cross["pos"]),
          "embeddings.token_type_embeddings.weight": T(cross["type"]),
          "embeddings.LayerNorm.weight": T(cross["emb_ln.w"]), "embeddings.LayerNorm.bias": T(cross["emb_ln.b"]),
          "pooler.dense.weight": T(cross["pool.w"]), "pooler.dense.bias": T(cross["pool.b"])}
    for i in range(L):
        p = f"encoder.layer.{i}."
        for nm, key in LAYER:
            sd[p + key + ".weight"] = T(cross[f"l{i}.{nm}.w"]); sd[p + key + ".bias"] = T(cross[f"l{i}.{nm}.b"])
        sd[p + "attention.output.LayerNorm.weight"] = T(cross[f"l{i}.ln1.w"]); sd[p + "attention.output.LayerNorm.bias"] = T(cross[f"l{i}.ln1.b"])
        sd[p + "output.LayerNorm.weight"] = T(cross[f"l{i}.ln2.w"]); sd[p + "output.LayerNorm.bias"] = T(cross[f"l{i}.ln2.b"])
    return sd, T(cross["nli.w"]), T(cross["nli.b"])

def from_hf(sd, cls_w, cls_b, L):
    g = lambda k: sd[k].detach().cpu().numpy()
    t = [("pos", g("embeddings.position_embeddings.weight")[:512]), ("type", g("embeddings.token_type_embeddings.weight")),
         ("emb_ln.w", g("embeddings.LayerNorm.weight")), ("emb_ln.b", g("embeddings.LayerNorm.bias"))]
    for i in range(L):
        p = f"encoder.layer.{i}."
        for nm, key in LAYER:
            t += [(f"l{i}.{nm}.w", g(p + key + ".weight")), (f"l{i}.{nm}.b", g(p + key + ".bias"))]
        t += [(f"l{i}.ln1.w", g(p + "attention.output.LayerNorm.weight")), (f"l{i}.ln1.b", g(p + "attention.output.LayerNorm.bias")),
              (f"l{i}.ln2.w", g(p + "output.LayerNorm.weight")), (f"l{i}.ln2.b", g(p + "output.LayerNorm.bias"))]
    t += [("pool.w", g("pooler.dense.weight")), ("pool.b", g("pooler.dense.bias")),
          ("nli.w", cls_w.detach().cpu().numpy()), ("nli.b", cls_b.detach().cpu().numpy())]
    return t
