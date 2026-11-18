#!/usr/bin/env python3
"""Write the fine-tuned NLI cross-encoder (train/train_nli.py output) as a DTE1 file WITHOUT the word table
(it is shared with encoder-tiny.dte, because the word embeddings were frozen during fine-tuning).
  python scripts/convert_nli.py <base hf dir> <nli_ft.npz> models/nli-tiny.dte
Needs only numpy."""
import json, struct, sys, os
import numpy as np

def main():
    hf, npz, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    cfg = json.load(open(os.path.join(hf, "config.json")))
    sd = np.load(npz)
    L = cfg["num_hidden_layers"]
    tensors = []
    def f32(name, a):
        a = np.ascontiguousarray(a, dtype="<f4"); tensors.append((name, "f32", list(a.shape), a.tobytes()))
    p = "b.embeddings."
    f32("pos", sd[p + "position_embeddings.weight"][:512]); f32("type", sd[p + "token_type_embeddings.weight"])
    f32("emb_ln.w", sd[p + "LayerNorm.weight"]); f32("emb_ln.b", sd[p + "LayerNorm.bias"])
    for i in range(L):
        q = f"b.encoder.layer.{i}."
        for nm, key in [("q", "attention.self.query"), ("k", "attention.self.key"), ("v", "attention.self.value"),
                        ("o", "attention.output.dense"), ("f1", "intermediate.dense"), ("f2", "output.dense")]:
            f32(f"l{i}.{nm}.w", sd[q + key + ".weight"]); f32(f"l{i}.{nm}.b", sd[q + key + ".bias"])
        f32(f"l{i}.ln1.w", sd[q + "attention.output.LayerNorm.weight"]); f32(f"l{i}.ln1.b", sd[q + "attention.output.LayerNorm.bias"])
        f32(f"l{i}.ln2.w", sd[q + "output.LayerNorm.weight"]); f32(f"l{i}.ln2.b", sd[q + "output.LayerNorm.bias"])
    f32("pool.w", sd["b.pooler.dense.weight"]); f32("pool.b", sd["b.pooler.dense.bias"])
    f32("nli.w", sd["cls.weight"]); f32("nli.b", sd["cls.bias"])
    meta = {"format": "DTE1", "source": cfg.get("_name_or_path", "") + " + NLI fine-tune", "hidden": cfg["hidden_size"], "layers": L,
            "heads": cfg["num_attention_heads"], "inter": cfg["intermediate_size"], "vocab_size": 0, "max_pos": 512,
            "eps": cfg["layer_norm_eps"], "lower": False, "vocab": "", "tensors": []}
    off = 0
    for name, dt, shape, raw in tensors:
        meta["tensors"].append({"name": name, "dtype": dt, "shape": shape, "offset": off, "size": len(raw)}); off += len(raw)
    hb = json.dumps(meta, ensure_ascii=False).encode("utf-8")
    with open(dst, "wb") as f:
        f.write(b"DTE1"); f.write(struct.pack("<I", len(hb))); f.write(hb)
        for _, _, _, raw in tensors: f.write(raw)
    print("wrote", dst, os.path.getsize(dst))
main()
