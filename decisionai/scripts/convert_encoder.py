#!/usr/bin/env python3
"""Convert a BERT-style HuggingFace checkpoint (model.safetensors + vocab.txt + config.json)
into the compact DTE1 file read by semai/encoder.go. Needs only numpy.

  python scripts/convert_encoder.py <hf_dir> models/encoder-tiny.dte

The big word-embedding table is stored int8 with one float32 scale per row; everything else is float32.
Source model used for the shipped file: cointegrated/rubert-tiny2 (MIT licence), see models/ENCODER-NOTICE.md.
"""
import json, struct, sys, os
import numpy as np

def read_safetensors(path):
    with open(path, "rb") as f:
        n = struct.unpack("<Q", f.read(8))[0]
        head = json.loads(f.read(n))
        base = 8 + n
        out = {}
        for k, v in head.items():
            if k == "__metadata__":
                continue
            s, e = v["data_offsets"]
            f.seek(base + s)
            raw = f.read(e - s)
            dt = {"F32": np.float32, "F16": np.float16, "I64": np.int64}[v["dtype"]]
            out[k] = np.frombuffer(raw, dtype=dt).reshape(v["shape"])
        return out

def main():
    src, dst = sys.argv[1], sys.argv[2]
    cfg = json.load(open(os.path.join(src, "config.json")))
    tcfg = json.load(open(os.path.join(src, "tokenizer_config.json")))
    t = read_safetensors(os.path.join(src, "model.safetensors"))
    vocab = open(os.path.join(src, "vocab.txt"), encoding="utf-8").read().split("\n")
    if vocab and vocab[-1] == "":
        vocab.pop()
    maxpos = 512
    L = cfg["num_hidden_layers"]
    tensors = []  # (name, dtype, shape, bytes)
    def f32(name, a):
        a = np.ascontiguousarray(a, dtype="<f4")
        tensors.append((name, "f32", list(a.shape), a.tobytes()))
    def i8r(name, a):
        a = np.asarray(a, dtype=np.float32)
        sc = np.maximum(np.abs(a).max(axis=1), 1e-12) / 127.0
        q = np.clip(np.rint(a / sc[:, None]), -127, 127).astype(np.int8)
        tensors.append((name + ".scale", "f32", [a.shape[0]], sc.astype("<f4").tobytes()))
        tensors.append((name, "i8r", list(a.shape), q.tobytes()))
    p = "bert.embeddings."
    i8r("word", t[p + "word_embeddings.weight"])
    f32("pos", t[p + "position_embeddings.weight"][:maxpos])
    f32("type", t[p + "token_type_embeddings.weight"])
    f32("emb_ln.w", t[p + "LayerNorm.weight"]); f32("emb_ln.b", t[p + "LayerNorm.bias"])
    for i in range(L):
        q = f"bert.encoder.layer.{i}."
        for nm, key in [("q", "attention.self.query"), ("k", "attention.self.key"), ("v", "attention.self.value"),
                        ("o", "attention.output.dense"), ("f1", "intermediate.dense"), ("f2", "output.dense")]:
            f32(f"l{i}.{nm}.w", t[q + key + ".weight"]); f32(f"l{i}.{nm}.b", t[q + key + ".bias"])
        f32(f"l{i}.ln1.w", t[q + "attention.output.LayerNorm.weight"]); f32(f"l{i}.ln1.b", t[q + "attention.output.LayerNorm.bias"])
        f32(f"l{i}.ln2.w", t[q + "output.LayerNorm.weight"]); f32(f"l{i}.ln2.b", t[q + "output.LayerNorm.bias"])
    meta = {"format": "DTE1", "source": cfg.get("_name_or_path", ""), "hidden": cfg["hidden_size"], "layers": L,
            "heads": cfg["num_attention_heads"], "inter": cfg["intermediate_size"], "vocab_size": len(vocab),
            "max_pos": maxpos, "eps": cfg["layer_norm_eps"], "lower": bool(tcfg.get("do_lower_case", False)),
            "vocab": "\n".join(vocab), "tensors": []}
    off = 0
    for name, dt, shape, raw in tensors:
        meta["tensors"].append({"name": name, "dtype": dt, "shape": shape, "offset": off, "size": len(raw)})
        off += len(raw)
    hb = json.dumps(meta, ensure_ascii=False).encode("utf-8")
    with open(dst, "wb") as f:
        f.write(b"DTE1"); f.write(struct.pack("<I", len(hb))); f.write(hb)
        for _, _, _, raw in tensors:
            f.write(raw)
    print("wrote", dst, os.path.getsize(dst), "bytes")

if __name__ == "__main__":
    main()
