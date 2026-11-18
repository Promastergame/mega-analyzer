#!/usr/bin/env python3
"""T1: own contrastive pairs for DAI-Enc v2 "turbo" stage. No external models: decisions + own rules.
  python3 build_pairs.py <out.jsonl> <plans.jsonl>... ; tests/dev templates are excluded (isolation).
kinds: hyp   chunk -> correct hypothesis, negs = sibling options (hard)
       agree chunk -> chunk with the same confident answers on the same question set, negs = chunks with other answers
       neg   hypothesis -> its rule-negation as hard negative (polarity), positive = the hypothesis itself with token dropout"""
import argparse
import json, re, random, collections, os
from pathlib import Path

norm = lambda s: re.sub(r"\d+", "#", s.lower())
# own polarity lexicon (RU/EN), longest first; applied once per hypothesis
SWAP = [("необратим", "обратим"), ("нельзя", "можно"), ("опасн", "безопасн"), ("разрушительн", "безвредн"),
        ("не наблюдался", "наблюдался"), ("не затронут", "затронут"), ("не требует", "требует"), ("нет риска", "есть риск"),
        ("без сервера", "с сервера"), ("только читает", "изменяет данные"), ("полностью", "частично"), ("не решил", "решил"),
        ("irreversible", "reversible"), ("cannot", "can"), ("unsafe", "safe"), ("destructive", "harmless"),
        ("not affected", "affected"), ("without", "with"), ("read-only", "writes data"), ("never", "always"),
        ("no risk", "high risk"), ("no user impact", "severe user impact")]
def negate(h):
    if ": " in h:
        p, t = h.split(": ", 1); n = negate(t); return p + ": " + n if n else None
    for a, b in SWAP:
        for x, y in ((a, b), (b, a)):
            if x == b and re.search(r"(?<!\w)" + re.escape(a), h, re.I): continue
            m = re.search(r"(?<!\w)" + re.escape(x) + r"(?=\w*)", h, re.I)
            if m and (m.start() == 0 or not h[m.start() - 1].isalpha()):
                return h[:m.start()] + y + h[m.end():]
    return None
def drop(t, p=0.1, rng=None):
    """Only omit politeness fillers; content dropout can invert the label.

    Subjects, roles, negation, quantifiers, amounts, units and word order stay
    intact. An unchanged positive view is valid when no safe filler occurs.
    """
    rng = rng or random
    words = t.split()
    fillers = {"пожалуйста", "please", "kindly"}
    kept = [w for w in words if w.lower().strip(",.!?") not in fillers or rng.random() >= p]
    return " ".join(kept or words)


def rows(path):
    with open(path, encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except ValueError as error:
                    raise ValueError(f"{path}:{number}: {error}") from error


def build(output, inputs, isolation, seed=0):
    rng = random.Random(seed)
    isolation = Path(isolation)
    if not isolation.is_dir():
        raise ValueError(f"isolation directory does not exist: {isolation}")
    protected = sorted(p for p in isolation.iterdir() if p.is_file()
                       and p.name.startswith(("test-", "dev", "calib")) and p.suffix == ".jsonl")
    if not protected:
        raise ValueError("isolation directory must contain dev/test/calib plans")
    banned = {norm(c) for p in protected for row in rows(p) for c in row["chunks"]}
    cnt, groups, done, seen_h = collections.Counter(), collections.defaultdict(list), set(), set()
    result = []

    def emit(**row):
        row["negs"] = sorted({x for x in row["negs"] if x and x not in (row["a"], row["b"])})
        if not row["a"] or not row["b"] or not row["negs"]:
            cnt["bad"] += 1
            return
        key = (row["kind"], row["a"], row["b"], tuple(row["negs"]))
        if key in done:
            cnt["dup"] += 1
            return
        done.add(key)
        result.append(row)
        cnt[row["kind"]] += 1

    for path in inputs:
        for row in rows(path):
            chunks = row["chunks"]
            if not chunks or any(norm(c) in banned for c in chunks):
                cnt["skipped_isolation"] += 1
                continue
            # A document-level label does not label its first chunk. Without
            # evidence alignment, generate polarity pairs only for such rows.
            chunk = chunks[0] if len(chunks) == 1 else None
            for q in row["questions"]:
                lab = q.get("label")
                if lab is None or q.get("task") == "skill_routing":
                    continue
                opts = [o for o in q["options"] if not o.get("escape") and o.get("hyp")]
                if q["type"] == "noul":
                    v = float(lab)
                    best, conf = ("true" if v >= 0.5 else "false"), max(v, 1 - v)
                else:
                    dist = lab if isinstance(lab, dict) else {str(lab): 1.0}
                    best = max(dist, key=dist.get)
                    conf = dist[best]
                if conf < 0.85:
                    continue
                if chunk is not None:
                    sig = (q["type"], tuple(sorted(o["hyp"] for o in opts)))
                    if (chunk, best) not in groups[sig]:
                        groups[sig].append((chunk, best))
                    pos = [o for o in opts if o["key"] == best]
                    if pos and (q["type"] != "noul" or len(opts) == 2):
                        emit(kind="hyp", a=chunk, b=pos[0]["hyp"], negs=[o["hyp"] for o in opts if o["key"] != best])
                for option in opts:
                    h = option["hyp"]
                    if h in seen_h:
                        continue
                    seen_h.add(h)
                    negative = negate(h)
                    if negative and negative != h:
                        emit(kind="neg", a=h, b=drop(h, rng=rng), negs=[negative])
    for xs in groups.values():
        by = collections.defaultdict(list)
        for chunk, best in xs:
            by[best].append(chunk)
        # Conflicting document labels must not become positive/negative views
        # of the same text, even when the input escaped corpus quarantine.
        labels_by_chunk = collections.defaultdict(set)
        for chunk, best in xs:
            labels_by_chunk[chunk].add(best)
        by = {key: [c for c in values if len(labels_by_chunk[c]) == 1] for key, values in by.items()}
        for best, chunks in by.items():
            others = [c for key, values in by.items() if key != best for c in values]
            if not others:
                continue
            rng.shuffle(chunks)
            for i in range(0, len(chunks) - 1, 2):
                if chunks[i] != chunks[i + 1]:
                    emit(kind="agree", a=chunks[i], b=chunks[i + 1], negs=rng.sample(others, min(3, len(others))))
    # Read/validate every input before replacing an existing output.
    with open(output, "w", encoding="utf-8", newline="\n") as stream:
        for row in result:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    return dict(cnt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("--isolation", default=os.environ.get("DAI_ISO"))
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    if not args.isolation:
        parser.error("set --isolation or DAI_ISO to the protected plan directory")
    print(json.dumps(build(args.output, args.inputs, args.isolation, args.seed), sort_keys=True))


if __name__ == "__main__":
    main()
