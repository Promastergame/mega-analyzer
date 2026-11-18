"""Question-wording augmentation (v1.13): rewrite question instructions with hand-written paraphrases
(same language, the other language, terse form) while keeping the teacher labels. The ~133 training
wordings were the main reason the student memorised phrasings instead of meaning.
usage: augment_questions.py in.labelled.jsonl out.labelled.jsonl [p_request=0.5] [seed=13]"""
import json, random, sys
src, dst = sys.argv[1], sys.argv[2]; P = float(sys.argv[3]) if len(sys.argv) > 3 else 0.5
R = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 13)
PARA = json.load(open(__file__.rsplit("/", 3)[0] + "/data/distill/paraphrases.json", encoding="utf-8"))
n = m = 0
with open(dst, "w", encoding="utf-8") as out:
    for line in open(src, encoding="utf-8"):
        r = json.loads(line); n += 1
        if R.random() < P:
            for q in r["request"]["questions"].values():
                alts = PARA.get(q.get("instructions", ""))
                if alts and R.random() < 0.8:
                    q["instructions"] = R.choice(alts); m += 1
            r["group"] = r.get("group", "") + "-para"
        out.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"{src}: {n} requests, {m} questions reworded", file=sys.stderr)
