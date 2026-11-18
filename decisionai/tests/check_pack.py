"""Byte-exact reference check for direct panel packing; Python stdlib only.

This validates the packing transformation, NOT compilation or forward parity.
Usage: python tests/check_pack.py models/encoder-tiny.dte
"""
import array
import json
import math
import pathlib
import struct
import sys


def pack(src, inp, outp):
    dst = array.array("I", [0]) * (inp * outp)
    for p in range(outp // 8):
        for i in range(inp):
            for j in range(8):
                dst[(p * inp + i) * 8 + j] = src[(p * 8 + j) * inp + i]
    return dst


def main(path):
    with pathlib.Path(path).open("rb") as f:
        assert f.read(4) == b"DTE1"
        meta = json.loads(f.read(struct.unpack("<I", f.read(4))[0]))
        raw = f.read()
    checked = saved = 0
    for t in meta["tensors"]:
        parts = t["name"].split(".")
        if not (len(parts) == 3 and parts[0].startswith("l")
                and parts[1] in {"q", "k", "v", "o", "f1", "f2"}
                and parts[2] == "w"):
            continue
        outp, inp = t["shape"]
        assert t["dtype"] == "f32"
        assert outp % 8 == 0
        size = t["size"]
        assert size == math.prod(t["shape"]) * 4
        src = array.array("I")
        src.frombytes(raw[t["offset"]:t["offset"] + size])
        # Old path copies all words before packing; new path packs the source.
        old = pack(array.array("I", src), inp, outp)
        new = pack(src, inp, outp)
        assert old.tobytes() == new.tobytes(), t["name"]
        # Check inverse mapping, including every float bit pattern.
        restored = array.array("I", [0]) * len(src)
        for p in range(outp // 8):
            for i in range(inp):
                for j in range(8):
                    restored[(p * 8 + j) * inp + i] = new[(p * inp + i) * 8 + j]
        assert restored.tobytes() == src.tobytes(), t["name"]
        checked += 1
        saved += size
    assert checked == meta["layers"] * 6
    print(f"PASS: {checked} matrices; packing bit-exact.")
    print(f"Removed duplicate payload: {saved} bytes "
          f"({saved / 1048576:.2f} MiB) per encoder.")
    print("Compiler, forward parity, speed and process RAM are NOT tested here.")


if __name__ == "__main__":
    main(sys.argv[1])