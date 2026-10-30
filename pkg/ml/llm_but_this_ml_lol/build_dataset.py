"""
Regenerates keys_dataset.json and negatives.json from the source files.
Run after editing any source dataset, then rebuild the binary.

    python build_dataset.py

Checks performed:
  1. Schema validation -- every service has required fields
  2. Positive deduplication -- duplicate credential values are reported
  3. Conflict check -- positives & negatives must be empty
  4. Trailing-comma + block-comment stripping (robust JSONC parser)
  5. Data-driven thresholds -- min_len / min_entropy auto-computed per family
  6. Quality metrics -- precision / recall / FPR printed at the end
"""

import json
import base64
import binascii
import math
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))

# -- JSONC parser (fix #3) ------------------------------------------------------

def strip_jsonc(text: str) -> str:
    # 1. Block comments  /* … */
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    # 2. Line comments  //  (char-by-char to skip // inside strings)
    out = []
    i, n = 0, len(text)
    in_str = esc = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            esc = (not esc and c == '\\')
            if not esc and c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif c == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                i += 1
            continue
        else:
            out.append(c)
        i += 1
    result = ''.join(out)
    # 3. Trailing commas  ,}  or  ,]
    result = re.sub(r',\s*([}\]])', r'\1', result)
    return result


def load(filename: str) -> dict:
    path = os.path.join(HERE, filename)
    try:
        raw = open(path, encoding='utf-8').read()
        return json.loads(strip_jsonc(raw))
    except json.JSONDecodeError as e:
        print(f'[ERROR] Cannot parse {filename}: {e}')
        sys.exit(1)


def save(filename: str, data) -> None:
    path = os.path.join(HERE, filename)
    json.dump(data, open(path, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print(f'  wrote {filename}  ({os.path.getsize(path):,} bytes)')


# -- Shannon entropy helper -----------------------------------------------------

def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


# -- Credential value extractor -------------------------------------------------

_CRED_FIELD = re.compile(
    r'(key|token|secret|password|credential|signing|webhook|'
    r'connection_string|private_key|access_token|vault_token)',
    re.IGNORECASE,
)
# Field names that sound like credentials but hold metadata, not secret values.
_META_FIELDS = re.compile(
    r'^(token_type|token_scope|auth_method|auth_uri|auth_domain|'
    r'token_uri|registry_url|cluster_name|workspace_id|catalog|'
    r'schema|org_id|project_id|team_id|client_id|sp_tenant_id)$',
    re.IGNORECASE,
)
# Structurally unusable: PEM headers, known-bad templates.
_SKIP_SUBSTR = ('-----begin', '-----end', '[synthetic', '[not real')


def extract_cred_values(cred: dict) -> list[tuple[str, str]]:
    """Return (field_name, value) pairs that look like real credential strings."""
    out = []
    for field, val in cred.items():
        if not isinstance(val, str):
            continue
        if _META_FIELDS.match(field):
            continue
        if field in _NON_SECRET_FIELDS:
            continue
        if not _CRED_FIELD.search(field):
            continue
        v = val.strip()
        if len(v) < 12:
            continue
        low = v.lower()
        if any(s in low for s in _SKIP_SUBSTR):
            continue
        out.append((field, v))
    return out


# -- Schema validation (fix #4) ------------------------------------------------

def validate_schema(svc: dict) -> list[str]:
    errors = []
    for svc_name, svc_data in svc.items():
        if not isinstance(svc_data, dict):
            errors.append(f'{svc_name}: not a dict')
            continue
        if 'service_name' not in svc_data:
            errors.append(f'{svc_name}: missing "service_name"')
        if 'credentials' not in svc_data:
            errors.append(f'{svc_name}: missing "credentials"')
            continue
        creds = svc_data['credentials']
        if not isinstance(creds, list) or len(creds) == 0:
            errors.append(f'{svc_name}: "credentials" must be a non-empty list')
            continue
        for i, cred in enumerate(creds):
            if not isinstance(cred, dict):
                errors.append(f'{svc_name}[{i}]: not a dict')
                continue
            if 'id' not in cred:
                errors.append(f'{svc_name}[{i}]: missing "id"')
            if not extract_cred_values(cred):
                errors.append(f'{svc_name}[{i}]: no extractable credential values')
    return errors


# -- Classifier simulation for metrics (fix #6) --------------------------------

_PLACEHOLDER = [
    'example', 'sample', 'dummy', 'placeholder', 'changeme',
    'your_', 'your-', '_here', 'goes_here', 'replace_me', 'replaceme',
    'insert_', 'enter_', 'paste_', 'do_not_use', 'donotuse',
    'redact', 'filtered', 'lorem', 'ipsum',
    'mock_', 'stub_', 'fake_', 'demo_', 'testkey', 'fakekey',
    '<', '>', '${', '{{', '[your',
]

_HEX32 = re.compile(r'^[0-9a-f]{32}$')
_HEX40 = re.compile(r'^[0-9a-f]{40}$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_HEX128 = re.compile(r'^[0-9a-f]{128}$')
_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
_SHA_LINE = re.compile(r'^(?:sha\d{1,3}|md5|etag|commit|tree|blob|digest|integrity):\s*([A-Za-z0-9+/=_:-]+)$')

_NON_SECRET_FIELDS = {
    'project_url', 'inference_endpoint_url', 'base_url', 'registry_url',
    'auth_uri', 'token_uri', 'openai_endpoint', 'keyvault_url', 'vault_addr',
    'workers_subdomain', 'domain',
}

_FAMILIES = {
    'aws':         ['AKIA', 'ASIA', 'AGPA', 'AIDA', 'AROA', 'AIPA', 'ANPA', 'ANVA'],
    'github':      ['github_pat_', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'],
    'anthropic':   ['sk-ant-'],
    'openai':      ['sk-proj-', 'sk-'],
    'google':      ['AIza'],
    'slack':       ['xoxb-', 'xoxp-', 'xapp-', 'xoxe-'],
    'stripe':      ['sk_live_', 'sk_test_', 'pk_live_', 'pk_test_', 'whsec_'],
    'gitlab':      ['glpat-', 'glgat-', 'gldt-', 'glrt-'],
    'docker':      ['dckr_pat_', 'ghcr_pat_'],
    'huggingface': ['hf_'],
    'npm':         ['npm_'],
    'pypi':        ['pypi-'],
    'pinecone':    ['pcsk_'],
    'vault':       ['hvs.'],
    'sendgrid':    ['SG.'],
    'databricks':  ['dapi-'],
    'atlassian':   ['ATATT'],
    'notion':      ['secret_'],
    'jwt':         ['eyJ'],
    'shopify':     ['shppa_', 'shpca_', 'shpat_', 'shpss_', 'shpua_'],
    'linear':      ['lin_api_'],
    'planetscale': ['pscale_tkn_', 'pscale_oauth_'],
    'mapbox':      ['pk.eyJ', 'sk.eyJ', 'tk.eyJ'],
    'circleci':    ['CCIPAT_'],
}

_SEQ_DIGITS = '0123456789'
_SEQ_ALPHA  = 'abcdefghijklmnopqrstuvwxyz'


def _is_sequential(low: str) -> bool:
    """True if the string is mostly a straight run of digits or letters."""
    if len(low) < 4:
        return False
    rev = low[::-1]
    for seq in (_SEQ_DIGITS, _SEQ_ALPHA):
        if low in seq or rev in seq:
            return True
    # Step test: >= 75% of adjacent pairs differ by exactly +/-1
    pairs = len(low) - 1
    if pairs < 3:
        return False
    inc = sum(1 for i in range(pairs) if ord(low[i+1]) - ord(low[i]) == 1)
    dec = sum(1 for i in range(pairs) if ord(low[i]) - ord(low[i+1]) == 1)
    return inc * 4 >= pairs * 3 or dec * 4 >= pairs * 3


def _is_bulk_placeholder(v: str, low: str) -> bool:
    """True only when a placeholder word dominates the value (>30% of length)."""
    for m in _PLACEHOLDER:
        if m not in low:
            continue
        # 'example'/'sample' are only noise when they are a large fraction of
        # the total string — a 50-char key ending in 'example' is still a key.
        if m in ('example', 'sample'):
            if len(m) / len(v) < 0.30 or len(v) >= 32:
                continue
        return True
    return False


def _is_segmented_id(v: str) -> bool:
    parts = v.split('-')
    if len(parts) < 3 or sum(ch.isalnum() for ch in v) < len(v) * 3 // 4:
        return False
    return all(len(p) >= 2 for p in parts)


def _is_likely_digest(v: str) -> bool:
    cleaned = v.strip('"\'' '`')
    if not cleaned:
        return False
    if _HEX32.fullmatch(cleaned) or _HEX40.fullmatch(cleaned) or _HEX64.fullmatch(cleaned) or _HEX128.fullmatch(cleaned):
        return True
    try:
        if len(cleaned) % 2 == 0 and len(cleaned) >= 16:
            binascii.unhexlify(cleaned)
            return True
    except (binascii.Error, ValueError):
        pass
    if any(c in cleaned for c in '+/='):
        try:
            base64.b64decode(cleaned, validate=True)
            return True
        except Exception:
            pass
    return False


def _match_non_secret_structure(v: str, low: str) -> str:
    if _UUID.fullmatch(low):
        return "uuid-like identifier"
    if v.count('-') >= 3 and len(v) >= 20 and _is_segmented_id(v):
        return "structured identifier, not a secret"
    if _HEX32.fullmatch(low) or _HEX40.fullmatch(low) or _HEX64.fullmatch(low) or _HEX128.fullmatch(low):
        return "hex digest/checksum, not a secret"
    if low.startswith(('sha', 'md5', 'etag:', 'commit:', 'tree:', 'blob:', 'integrity:')):
        m = _SHA_LINE.fullmatch(low)
        if m and _is_likely_digest(m.group(1)):
            return "digest/fingerprint line, not a secret"
    if low.startswith(('md5-', 'sha256:', 'sha1:')):
        return "checksum-like string, not a secret"
    return ""


def classify(v: str, neg_set: set | None = None) -> bool:
    v = v.strip()
    low = v.lower()
    if not v or any(c in v for c in ' \t\r\n'):
        return False
    # Negatives DB lookup (mirrors Go step 1)
    if neg_set and low in neg_set:
        return False
    if _match_non_secret_structure(v, low):
        return False
    fields = v.split()
    if len(fields) > 1 and fields[0].lower() in {'bearer', 'basic'}:
        v = ' '.join(fields[1:])
        low = v.lower()
    # Prefix/family match BEFORE placeholder check — a known prefix wins over
    # the word "example" that may appear inside synthetic training values.
    for prefixes in _FAMILIES.values():
        for p in prefixes:
            if v.startswith(p):
                body = v[len(p):]
                if len(body) < 6 or _is_bulk_placeholder(body, low):
                    continue
                return True
    # Placeholder markers (after prefix so family always wins)
    if _is_bulk_placeholder(v, low):
        return False
    if len(v) < 12:
        return False
    if len(set(v)) == 1:
        return False
    if len(set(v)) / len(v) < 0.30:
        return False
    if _is_sequential(low):
        return False
    ent = entropy(v)
    if ent >= 3.6 and len(v) >= 20:
        return True
    if ent >= 3.2 and len(v) >= 12:
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

print('== build_dataset ==')

# Load sources
pos  = load('ml_dataset_this_is_keys.json')
neg1_raw = load('ml_negative_dataset_this_is_keys.json')['ml_negative_database']['negatives']
neg2_raw = load('ml_negative_dataset_v2_this_is_keys.json')['ml_negative_database_v2']['negatives']
print(f'  loaded sources: {len(neg1_raw)} + {len(neg2_raw)} negatives')

svc = pos['ml_training_database']['services']

# -- Fix #4: schema validation -------------------------------------------------
errors = validate_schema(svc)
if errors:
    print('\n[SCHEMA ERRORS]')
    for e in errors:
        print(f'  X {e}')
    sys.exit(1)
print(f'  OK schema valid ({len(svc)} services)')

# -- Fix #1: positive deduplication -------------------------------------------
pos_values: set[str] = set()
dups: list[str] = []
for svc_name, svc_data in svc.items():
    for cred in svc_data['credentials']:
        for field, val in extract_cred_values(cred):
            if val in pos_values:
                dups.append(f'{svc_name}.{field}: {val[:40]}')
            pos_values.add(val)

if dups:
    print(f'\n[WARNING] {len(dups)} duplicate positive values:')
    for d in dups:
        print(f'  ! {d}')
else:
    print(f'  OK no duplicate positives ({len(pos_values)} unique values)')

# -- Negative dedup (already existed, kept as-is) -----------------------------
neg_seen: set[str] = set()
merged_negs: list[dict] = []
for item in neg1_raw + neg2_raw:
    v = item.get('value', '')
    if v in neg_seen:
        continue
    neg_seen.add(v)
    merged_negs.append({'id': item['id'], 'value': v, 'reason': item.get('reason', '')})
print(f'  OK {len(merged_negs)} negatives after dedup (from {len(neg1_raw)+len(neg2_raw)})')

# -- Fix #2: conflict check ----------------------------------------------------
conflict = pos_values & neg_seen
if conflict:
    print(f'\n[CONFLICT] {len(conflict)} values in BOTH positives and negatives:')
    for v in sorted(conflict):
        print(f'  X {v[:60]}')
    sys.exit(1)
print('  OK positives & negatives = {}')

# -- Fix #5: data-driven thresholds -------------------------------------------
print('\n  Data-driven thresholds per service:')
print(f'  {"service":<22} {"n":>4} {"min_len":>8} {"min_ent":>8} {"avg_ent":>8}')
print('  ' + '-' * 54)
for svc_name, svc_data in sorted(svc.items()):
    vals = [v for cred in svc_data['credentials']
            for _, v in extract_cred_values(cred)]
    if not vals:
        continue
    lengths   = [len(v) for v in vals]
    entropies = [entropy(v) for v in vals]
    # 20% headroom below observed minimum
    min_len = max(8, int(min(lengths) * 0.80))
    min_ent = max(2.0, round(min(entropies) * 0.85, 2))
    avg_ent = round(sum(entropies) / len(entropies), 2)
    print(f'  {svc_name:<22} {len(vals):>4} {min_len:>8} {min_ent:>8} {avg_ent:>8}')

# -- Fix total_records ---------------------------------------------------------
real_count = sum(len(v['credentials']) for v in svc.values())
pos['ml_training_database']['metadata']['total_records'] = real_count

# -- Save outputs --------------------------------------------------------------
print()
save('keys_dataset.json', pos)
negdoc = {
    'ml_negative_database': {
        'metadata': {
            'version': '1.0.0',
            'description': 'Synthetic NON-secrets -- placeholders, junk, docs examples, UUIDs, hashes, code refs',
            'total_records': len(merged_negs),
            'warning': 'ALL values here are NEGATIVES -- not real secrets',
        },
        'negatives': merged_negs,
    }
}
save('negatives.json', negdoc)

# -- Fix #6: quality metrics ---------------------------------------------------
tp = fn = fp = tn = 0
fn_list: list[str] = []
fp_list: list[str] = []

neg_set = {item['value'].lower() for item in merged_negs}

for svc_name, svc_data in svc.items():
    for cred in svc_data['credentials']:
        for field, val in extract_cred_values(cred):
            if classify(val, neg_set):
                tp += 1
            else:
                fn += 1
                fn_list.append(f'{svc_name}.{field}: {val[:50]}')

for item in merged_negs:
    val = item.get('value', '')
    if classify(val, neg_set):
        fp += 1
        fp_list.append(f'{item["id"]}: {val[:50]}')
    else:
        tn += 1

precision = tp / (tp + fp) if (tp + fp) else 0.0
recall    = tp / (tp + fn) if (tp + fn) else 0.0
fpr       = fp / (fp + tn) if (fp + tn) else 0.0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

print(f'\n  Quality metrics:')
print(f'  Positives {tp+fn:>4}  ->  TP={tp}  FN={fn}  recall={recall:.1%}')
print(f'  Negatives {fp+tn:>4}  ->  TN={tn}  FP={fp}  FPR={fpr:.1%}')
print(f'  Precision={precision:.1%}  F1={f1:.1%}')

if fn_list:
    print(f'\n  ! missed positives (FN={fn}):')
    for item in fn_list[:8]:
        print(f'    - {item}')
    if len(fn_list) > 8:
        print(f'    ... and {len(fn_list)-8} more')

if fp_list:
    print(f'\n  ! false alarms (FP={fp}):')
    for item in fp_list[:8]:
        print(f'    – {item}')

status = 'OK OK' if f1 >= 0.80 else '! F1 below 0.80 -- review dataset'
print(f'\n  {status}  ({real_count} positives, {len(merged_negs)} negatives, F1={f1:.1%})')
