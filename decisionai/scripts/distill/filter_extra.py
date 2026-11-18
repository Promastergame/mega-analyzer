"""Drop EXTRA plan rows that would trip the isolation guard (same group or same
whole-chunks signature as v2 dev/test). Writes data/prepared/v2extra/*.plans.jsonl.

Usage: python filter_extra.py   (prints FINAL EXTRA list for the training env)
"""
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from data_checks import signatures

ROOT = pathlib.Path(__file__).resolve().parents[2]
V2 = ROOT / 'data/prepared/v2'
OUT = ROOT / 'data/prepared/v2extra'
OUT.mkdir(parents=True, exist_ok=True)

CANDS = ['data/iso/syn2.para.plans.jsonl', 'data/distill/syn3.para.plans.jsonl',
         'data/distill/syn4.para.plans.jsonl', 'data/distill/train.para.plans.jsonl',
         'data/distill/syn5.gemma.plans.jsonl', 'data/distill/syn6.qwen.plans.jsonl',
         'data/distill/syn6.gemma.plans.jsonl']


def sig(chunks):
    return hashlib.sha256(json.dumps(chunks, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


dev_g, dev_s, _ = signatures([V2 / 'dev.plans.jsonl'])
tst_g, tst_s, _ = signatures(sorted(V2.glob('test-*.plans.jsonl')))
banned_g = set(dev_g) | set(tst_g)
banned_s = set(dev_s) | set(tst_s)
print('banned groups:', len(banned_g), 'banned chunk-sets:', len(banned_s), flush=True)

kept_files, kept_q, drop_q = [], 0, 0
for rel in CANDS:
    rows = [json.loads(l) for l in open(ROOT / rel, encoding='utf-8-sig') if l.strip()]
    keep = [r for r in rows
            if not (r.get('group') in banned_g or sig(r.get('chunks')) in banned_s)]
    dst = OUT / pathlib.Path(rel).name
    dst.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in keep), encoding='utf-8')
    kq = sum(len(r.get('questions', [])) for r in keep)
    dq = sum(len(r.get('questions', [])) for r in rows) - kq
    kept_q += kq
    drop_q += dq
    kept_files.append(f'data/prepared/v2extra/{dst.name}')
    print(f'{rel}: keep {len(keep)}/{len(rows)} rows ({kq} questions)', flush=True)
print(f'kept questions: {kept_q}, dropped: {drop_q}')
print('EXTRA=' + ','.join(kept_files))
