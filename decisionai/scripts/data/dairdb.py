#!/usr/bin/env python3
"""DAI data base v2 — training data registry on top of corpus.py. Python stdlib only (sqlite3/json/urllib).

  python scripts/data/dairdb.py --db data/local/dai.sqlite3 <command> ...

  migrate  --from data/local/corpus.sqlite3     copy v1 registry, label provenance = legacy:<file>
  import   FILES --role train|dev|test|holdout --teacher NAME
  index                                          (re)compute language, template hash, question schemas
  stats                                          quality, provenance, coverage (schemas/domains/types/langs)
  gen      --n SCHEMAS [--model qwen3:4b] [--ollama http://127.0.0.1:11434] [--teacher-model M] [--seed S]
           new question schemas + cases from a local model; kept only where a blind second labelling agrees
  export   --output DIR --dai bin/dai [--near 0.5] [--calib-schemas 0.08] [--calib-max 300]
           isolated splits train/dev/test/calib(+unseen schemas) + plans + manifest, registered as a run
  pairs    --plans DIR/train.plans.jsonl --builder scripts/.../build_pairs.py   contrastive pairs -> table + jsonl
  run      add --name N --kind eval|train [--dataset DIR] [--report dai-eval.json] [--notes ..] | list
  weak     [--run N]                              failure rates by suite/type/question from registered eval runs

Isolation rules (export): protected rows (holdout/dev/test roles) keep only themselves; a train row is dropped when
it shares a state, group, template (lower, digits→#) or is a near duplicate (char 5-gram Jaccard ≥ --near) of a
protected row. Generated schemas stay together (group = schema), so a schema is never split across train/calib."""
import argparse, collections, datetime, hashlib, json, math, os, pathlib, random, re, shutil, sqlite3, subprocess, sys, urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import corpus as C  # noqa: E402  (validate / request_key / import_files / Components / profile: one source of truth)

VERSION = 2
NOW = lambda: datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

SCHEMA = """
CREATE TABLE IF NOT EXISTS labels (
  example_id TEXT NOT NULL REFERENCES examples(id), teacher TEXT NOT NULL, labels TEXT NOT NULL,
  normalized TEXT NOT NULL, confidence REAL, created TEXT NOT NULL, PRIMARY KEY (example_id, teacher));
CREATE TABLE IF NOT EXISTS meta (
  example_id TEXT PRIMARY KEY REFERENCES examples(id), lang TEXT, domain TEXT, template_hash TEXT, chars INTEGER);
CREATE INDEX IF NOT EXISTS meta_template ON meta(template_hash);
CREATE TABLE IF NOT EXISTS schemas (
  hash TEXT PRIMARY KEY, type TEXT NOT NULL, qid TEXT NOT NULL, instructions TEXT NOT NULL, criteria TEXT);
CREATE TABLE IF NOT EXISTS example_schemas (
  example_id TEXT NOT NULL REFERENCES examples(id), schema_hash TEXT NOT NULL REFERENCES schemas(hash),
  PRIMARY KEY (example_id, schema_hash));
CREATE TABLE IF NOT EXISTS gen (
  id TEXT PRIMARY KEY, created TEXT NOT NULL, model TEXT NOT NULL, teacher TEXT NOT NULL, domain TEXT, lang TEXT,
  seed INTEGER, spec TEXT, raw TEXT, status TEXT NOT NULL, reason TEXT, kept INTEGER DEFAULT 0, dropped INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS pairs (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, a TEXT NOT NULL, b TEXT NOT NULL, negs TEXT NOT NULL, source TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
  name TEXT PRIMARY KEY, created TEXT NOT NULL, kind TEXT NOT NULL, dataset TEXT, manifest_sha TEXT,
  metrics TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS failures (
  run TEXT NOT NULL REFERENCES runs(name), suite TEXT NOT NULL, example INTEGER NOT NULL, question TEXT NOT NULL,
  type TEXT, expected TEXT, predicted TEXT, probability REAL, PRIMARY KEY (run, suite, example, question));
"""


def connect(path):
    path = pathlib.Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path); db.execute("PRAGMA foreign_keys = ON")
    v = db.execute("PRAGMA user_version").fetchone()[0]
    if v not in (0, 1, VERSION):
        raise ValueError(f"unsupported database version {v}")
    db.execute("PRAGMA user_version = 0")  # let corpus.connect create/verify the v1 tables
    db.close(); db = C.connect(path); db.executescript(SCHEMA)
    db.execute(f"PRAGMA user_version = {VERSION}"); C.VERSION = VERSION
    return db


# ------------------------------------------------------------------ text helpers
def norm_text(s):
    return re.sub(r"\s+", " ", re.sub(r"\d+", "#", s.casefold())).strip()

def state_text(state):
    return state if isinstance(state, str) else C.canonical(state)

def lang_of(s):
    cyr = len(re.findall(r"[а-яё]", s, re.I)); lat = len(re.findall(r"[a-z]", s, re.I))
    return "ru" if cyr > lat else "en" if lat else "other"

def shingles(s, n=5):
    t = norm_text(s)
    return {t[i:i + n] for i in range(max(1, len(t) - n + 1))}

def schema_key(qid, q):
    crit = q.get("criteria")
    if q["type"] == "score" and isinstance(crit, dict):
        crit = list(crit.items())
    elif isinstance(crit, dict):
        crit = sorted(crit.items())
    return C.digest(C.canonical([q["type"], C.canonical(q["instructions"]), crit]))


def index(db, ids=None):
    rows = db.execute("SELECT id, request FROM examples" + ("" if ids is None else
                      " WHERE id IN (%s)" % ",".join("?" * len(ids))), tuple(ids or ()))
    n = 0
    with db:
        for key, req in rows.fetchall():
            r = json.loads(req); st = state_text(r["state"])
            dom = None
            for (g,) in db.execute("SELECT group_id FROM origins WHERE example_id=? AND group_id LIKE 'gen:%'", (key,)):
                dom = g.split(":")[1]
            db.execute("INSERT OR REPLACE INTO meta VALUES(?,?,?,?,?)", (key, lang_of(st), dom, C.digest(norm_text(st)), len(st)))
            db.execute("DELETE FROM example_schemas WHERE example_id=?", (key,))
            for qid, q in r["questions"].items():
                h = schema_key(qid, q)
                db.execute("INSERT OR IGNORE INTO schemas VALUES(?,?,?,?,?)",
                           (h, q["type"], qid, C.canonical(q["instructions"]), C.encoded(q.get("criteria"))))
                db.execute("INSERT OR IGNORE INTO example_schemas VALUES(?,?)", (key, h))
            n += 1
    return {"indexed": n}


# ------------------------------------------------------------------ migrate / import
def migrate(db, old):
    src = sqlite3.connect(old)
    with db:
        for row in src.execute("SELECT id,state_hash,request,labels,normalized,conflict FROM examples"):
            db.execute("INSERT OR IGNORE INTO examples VALUES(?,?,?,?,?,?)", row)
        for row in src.execute("SELECT example_id,source,line,group_id,role FROM origins"):
            db.execute("INSERT OR IGNORE INTO origins VALUES(?,?,?,?,?)", row)
        for row in src.execute("SELECT example_id,labels,source,line FROM conflicts"):
            db.execute("INSERT OR IGNORE INTO conflicts VALUES(?,?,?,?)", row)
        # label provenance: every non-holdout origin file is a teacher of the merged label
        for key, source, labels, normalized in src.execute(
                "SELECT o.example_id, o.source, e.labels, e.normalized FROM origins o JOIN examples e ON e.id=o.example_id "
                "WHERE o.role != 'holdout' AND e.normalized != '{}'"):
            db.execute("INSERT OR IGNORE INTO labels VALUES(?,?,?,?,?,?)",
                       (key, "legacy:" + pathlib.PurePosixPath(source.replace("\\", "/")).name, labels, normalized, None, NOW()))
    out = index(db); out["examples"] = db.execute("SELECT COUNT(*) FROM examples").fetchone()[0]
    return out


def import_files(db, paths, role, teacher):
    counts = C.import_files(db, paths, role)
    ids = []
    with db:
        for path in paths:
            for line, row in C.read_rows(path):
                if "request" not in row:
                    continue
                key = C.request_key(row["request"]); ids.append(key)
                if role != "holdout" and "labels" in row:
                    norm = C.validate(row)
                    db.execute("INSERT OR REPLACE INTO labels VALUES(?,?,?,?,?,?)",
                               (key, teacher, C.encoded(row["labels"]), C.canonical(norm), row.get("confidence"), NOW()))
    counts.update(index(db, sorted(set(ids)))); return counts


# ------------------------------------------------------------------ generation with a local model (ollama)
DOMAINS = [
    ("devops-incidents", "incident reports and alerts from production systems"),
    ("security-alerts", "security scanner findings, leaked secrets, suspicious logins"),
    ("agent-tool-calls", "an AI agent proposing a tool call with its task and environment"),
    ("code-review", "pull request descriptions and review comments"),
    ("customer-support", "customer messages to an online shop or service"),
    ("banking", "bank customer messages, transactions and card issues"),
    ("insurance-claims", "insurance claim descriptions"),
    ("healthcare-triage", "patient messages to a clinic (non-diagnostic triage)"),
    ("hr-recruiting", "job applications, candidate notes and HR requests"),
    ("legal-contracts", "contract clauses and legal requests"),
    ("real-estate", "rental and real estate listings and tenant messages"),
    ("logistics", "shipment, warehouse and delivery updates"),
    ("travel", "travel bookings, flight changes and hotel complaints"),
    ("education", "student questions, homework submissions and teacher notes"),
    ("product-reviews", "product and app store reviews"),
    ("content-moderation", "user posts and comments on a forum"),
    ("finance-news", "short financial news and company announcements"),
    ("it-helpdesk", "employee IT helpdesk tickets"),
    ("data-privacy", "requests and documents that may contain personal data"),
    ("manufacturing", "machine logs and quality control notes"),
    ("energy-utilities", "utility outage reports and meter readings"),
    ("telecom", "mobile and internet provider complaints"),
    ("gaming", "game player reports, bug reports and chat"),
    ("food-delivery", "food delivery orders and complaints"),
    ("public-services", "citizen requests to city services"),
    ("science-papers", "paper abstracts and peer review notes"),
    ("marketing", "marketing copy and campaign feedback"),
    ("procurement", "purchase requests, invoices and vendor quotes"),
    ("smart-home", "smart home device events and user commands"),
    ("automotive", "car service requests and vehicle telemetry notes"),
    ("cloud-billing", "cloud cost alerts and billing questions"),
    ("ml-ops", "model training logs, data drift and evaluation notes"),
]
TYPE_MIXES = [["choice"], ["noul"], ["score"], ["choice", "noul"], ["choice", "score"], ["noul", "score"],
              ["choice", "noul", "score"]]
STYLES = ["short chat messages", "formal emails", "log lines with key=value fields", "terse notes with abbreviations",
          "long rambling messages", "JSON-like structured records rendered as text", "bullet lists"]
TRICKS = ["negations (\"not\", \"no longer\", \"не\")", "distractor details that point to a wrong option",
          "the decisive fact only at the end", "numbers and thresholds that decide the answer",
          "mixed Russian and English", "sarcasm or indirect wording", "two similar options that differ in one detail",
          "typos and informal spelling", "facts that were true earlier but changed"]
LANGS = {"ru": "Russian", "en": "English"}

GEN_PROMPT = """You create training data for a model that answers structured questions about short texts.
Domain: {domain} ({desc}).
Write ONE question schema with {nq} question(s) of these types in this order: {types}. Then write {k} cases.
Rules for the schema:
- ids are short snake_case; "instructions" is the question in {lang};
- choice: 3-6 options, "criteria" = {{"option_key": "what this option means, in {lang}"}};
- score: 4 or 5 ordered levels with keys "0","1","2",.. from lowest to highest, "criteria" = {{"0": "...", ...}};
- noul: a yes/no question, "criteria" = {{"true": "what yes means", "false": "what no means"}}.
Rules for cases:
- "state" is a realistic text in {lang}, 1-5 sentences, written as {style};
- make it hard: use {tricks}; but a careful human must be able to answer every question unambiguously;
- spread the labels: use many different options/levels and both true and false across the cases;
- labels: choice -> option key, score -> level key, noul -> true or false.
Return JSON only:
{{"questions": {{"id": {{"type": "...", "instructions": "...", "criteria": {{...}}}}}}, "cases": [{{"state": "...", "labels": {{"id": ...}}}}]}}"""

TEACH_PROMPT = """Read the text and answer every question. Think carefully, take negations and numbers literally.
Text:
<<<
{state}
>>>
Questions:
{questions}
Return JSON only: {{{fmt}}}"""


def ollama(url, model, prompt, seed, temperature):
    body = {"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False, "format": "json",
            "think": False, "options": {"temperature": temperature, "seed": seed, "num_ctx": 8192}}
    req = urllib.request.Request(url.rstrip("/") + "/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        content = json.loads(r.read().decode())["message"]["content"]
    content = re.sub(r"^```(json)?|```$", "", content.strip()).strip()
    return content, json.loads(content)


def describe(questions):
    out = []
    for qid, q in questions.items():
        crit = q.get("criteria") or {}
        if q["type"] == "noul":
            out.append(f'- {qid} (answer true or false): {q["instructions"]}  true = {crit.get("true", "yes")}; false = {crit.get("false", "no")}')
        else:
            opts = "; ".join(f'"{k}" = {v}' for k, v in crit.items())
            out.append(f'- {qid} (answer one key): {q["instructions"]}  options: {opts}')
    return "\n".join(out)


def clean_schema(qs, types):
    if not isinstance(qs, dict) or len(qs) != len(types):
        raise ValueError(f"expected {len(types)} questions, got {len(qs) if isinstance(qs, dict) else type(qs).__name__}")
    out = {}
    for (qid, q), typ in zip(qs.items(), types):
        if not isinstance(q, dict) or q.get("type") != typ:
            raise ValueError(f"{qid}: expected type {typ}")
        crit = q.get("criteria")
        if typ == "noul":
            if not isinstance(crit, dict) or set(crit) != {"true", "false"}:
                raise ValueError(f"{qid}: noul criteria must be true/false")
        elif typ == "score":
            if not isinstance(crit, dict) or list(crit) != [str(i) for i in range(len(crit))] or not 4 <= len(crit) <= 5:
                raise ValueError(f"{qid}: score levels must be \"0\"..\"3|4\" in order")
        elif not isinstance(crit, dict) or not 3 <= len(crit) <= 6:
            raise ValueError(f"{qid}: choice needs 3-6 options")
        if not all(isinstance(v, str) and v.strip() for v in crit.values()) or not str(q.get("instructions", "")).strip():
            raise ValueError(f"{qid}: empty instructions/criteria")
        out[re.sub(r"[^a-z0-9_]", "_", qid.lower())[:40] or "q"] = {"type": typ, "instructions": q["instructions"].strip(),
                                                                    "criteria": {str(k): v.strip() for k, v in crit.items()}}
    return out


def same(q, a, b):
    if q["type"] == "noul":
        f = lambda v: v if isinstance(v, bool) else str(v).strip().lower() in ("true", "yes", "да", "1")
        return f(a) == f(b)
    return str(a).strip() == str(b).strip()


def gen(db, n, model, teacher_model, url, seed, k, langs):
    rnd = random.Random(seed); counts = collections.Counter()
    cov = collections.Counter(d for (d,) in db.execute("SELECT domain FROM meta WHERE domain IS NOT NULL"))
    for i in range(n):
        dom, desc = min(DOMAINS, key=lambda d: (cov[d[0]], rnd.random()))
        types = rnd.choice(TYPE_MIXES); lang = rnd.choice(langs)
        spec = {"domain": dom, "types": types, "lang": lang, "style": rnd.choice(STYLES), "tricks": rnd.sample(TRICKS, 2), "k": k}
        s = rnd.randrange(1 << 30)
        gid = C.digest(f"{model}:{s}:{C.canonical(spec)}")[:24]
        prompt = GEN_PROMPT.format(domain=dom, desc=desc, nq=len(types), types=", ".join(types), k=k, lang=LANGS[lang],
                                   style=spec["style"], tricks=" and ".join(spec["tricks"]))
        raw, status, reason, kept, dropped = "", "rejected", "", 0, 0
        try:
            raw, out = ollama(url, model, prompt, s, 0.9)
            qs = clean_schema(out.get("questions"), types)
            cases = out.get("cases") or []
            batch = []
            for j, case in enumerate(cases[:k]):
                st = str(case.get("state", "")).strip(); labs = case.get("labels") or {}
                if len(st) < 20:
                    dropped += 1; continue
                labs = {re.sub(r"[^a-z0-9_]", "_", str(q).lower())[:40] or "q": v for q, v in labs.items()}
                fmt = ", ".join(f'"{qid}": ' + ("true|false" if q["type"] == "noul" else "\"key\"") for qid, q in qs.items())
                _, ans = ollama(url, teacher_model, TEACH_PROMPT.format(state=st, questions=describe(qs), fmt=fmt), s + j + 1, 0.0)
                agreed = {qid: labs[qid] for qid, q in qs.items() if qid in labs and qid in ans and same(q, labs[qid], ans[qid])
                          and (q["type"] == "noul" or str(labs[qid]) in q["criteria"])}
                if not agreed:
                    dropped += 1; counts["case_disagree"] += 1; continue
                req = {"state": st, "questions": {q: qs[q] for q in agreed}}
                labels = {q: (bool(same(qs[q], v, True)) if qs[q]["type"] == "noul" else str(v)) for q, v in agreed.items()}
                C.validate({"request": req, "labels": labels})
                batch.append({"group": f"gen:{dom}:{gid}", "request": req, "labels": labels})
                counts["questions_dropped"] += len(qs) - len(agreed)
            if batch:
                path = pathlib.Path(db.execute("PRAGMA database_list").fetchone()[2]).parent / "gen" / f"{gid}.labelled.jsonl"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("".join(C.encoded(r) + "\n" for r in batch), encoding="utf-8")
                import_files(db, [str(path)], "train", f"gen:{model}+verify:{teacher_model}")
                kept = len(batch); status = "ok"; cov[dom] += kept
        except (ValueError, KeyError, TypeError, AttributeError, OSError) as exc:
            reason = f"{type(exc).__name__}: {exc}"[:300]
        with db:
            db.execute("INSERT OR REPLACE INTO gen VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (gid, NOW(), model, teacher_model, dom, lang, s, C.encoded(spec), raw[:20000], status, reason, kept, dropped))
        counts[status] += 1; counts["cases_kept"] += kept; counts["cases_dropped"] += dropped
        print(f"[{i + 1}/{n}] {dom} {lang} {'+'.join(types)}: {status} kept {kept} dropped {dropped} {reason[:80]}", file=sys.stderr, flush=True)
    return dict(counts)


# ------------------------------------------------------------------ export with strong isolation + unseen-schema calib
def prepare(db, seed, dev_fraction, test_fraction, near, calib_schemas, calib_max):
    rows = C.records(db)
    meta = {k: (lang, tmpl) for k, lang, tmpl in db.execute("SELECT example_id, lang, template_hash FROM meta")}
    sch = collections.defaultdict(set)
    for k, h in db.execute("SELECT example_id, schema_hash FROM example_schemas"):
        sch[k].add(h)
    comp = C.Components(rows); seen = {}
    for key, row in rows.items():
        for link in ["state:" + row["state_hash"], "tmpl:" + meta.get(key, ("", ""))[1]] + ["group:" + g for g in row["groups"]]:
            if link in seen:
                comp.join(key, seen[link])
            else:
                seen[link] = key
    groups = collections.defaultdict(list)
    for key, row in rows.items():
        groups[comp.find(key)].append(row)
    # near duplicates of protected rows (char 5-grams; very common shingles are not indexed)
    prot = [r for r in rows.values() if r["roles"] & {"holdout", "dev", "test"}]
    psh = [shingles(state_text(r["request"]["state"])) for r in prot]
    inv = collections.defaultdict(list)
    for i, s in enumerate(psh):
        for g in s:
            inv[g].append(i)
    inv = {g: v for g, v in inv.items() if len(v) <= 50}
    near_roots = set()
    if near < 1:
        for key, row in rows.items():
            if row["roles"] != {"train"}:
                continue
            s = shingles(state_text(row["request"]["state"]))
            cnt = collections.Counter(i for g in s for i in inv.get(g, ()))
            if any(o / (len(s) + len(psh[i]) - o) >= near for i, o in cnt.items()):
                near_roots.add(comp.find(key))
    # unseen-schema calibration split: whole components that own schemas used nowhere else, until the budget is met
    owners = collections.defaultdict(set)
    for root, members in groups.items():
        for r in members:
            for h in sch[r["id"]]:
                owners[h].add(root)
    free = {root for root, members in groups.items()
            if root not in near_roots and all(r["roles"] == {"train"} and not r["conflict"] for r in members)}
    trainable = sum(len(groups[r]) for r in free); budget = int(trainable * calib_schemas)
    calib_roots, held, size = set(), set(), 0
    for root in sorted(free, key=lambda r: C.digest(f"{seed}:calib:{r}")):
        own = {h for r in groups[root] for h in sch[r["id"]] if owners[h] == {root}}
        if not own or len(groups[root]) > calib_max or size + len(groups[root]) > budget:
            continue
        calib_roots.add(root); held |= own; size += len(groups[root])
        if size >= budget:
            break
    calib_q = [0, 0]
    splits = {"train": [], "dev": [], "test": [], "calib": []}; removed = collections.Counter()
    for root, members in sorted(groups.items()):
        roles = set().union(*(r["roles"] for r in members))
        fixed = "holdout" if "holdout" in roles else "test" if "test" in roles else "dev" if "dev" in roles else None
        anchor = min(["g:" + g for r in members for g in r["groups"]] or ["s:" + r["state_hash"] for r in members])
        fr = int(C.digest(f"{seed}:{anchor}")[:16], 16) / 2**64
        split = fixed or ("calib" if root in calib_roots else "test" if fr < test_fraction else "dev" if fr < test_fraction + dev_fraction else "train")
        for r in members:
            if r["conflict"]:
                removed["conflict"] += 1
            elif fixed == "holdout":
                removed["protected_holdout" if "holdout" in r["roles"] else "holdout_overlap"] += 1
            elif fixed and fixed not in r["roles"]:
                removed["fixed_split_overlap"] += 1
            elif not fixed and root in near_roots:
                removed["near_protected"] += 1
            elif split == "train" and sch[r["id"]] & held:
                removed["held_schema_leak"] += 1
            else:
                if split == "calib":
                    qs = r["request"]["questions"]; calib_q[0] += len(qs)
                    calib_q[1] += sum(schema_key(i, q) in held for i, q in qs.items())
                splits[split].append({"group": "corpus-" + C.digest(anchor)[:24], "request": r["request"], "labels": r["labels"]})
    man = {"schema_version": VERSION, "seed": seed, "dev_fraction": dev_fraction, "test_fraction": test_fraction,
           "near": near, "calib_schemas": calib_schemas, "calib_max": calib_max, "held_schemas": len(held), "calib_unseen_questions": calib_q[1], "calib_questions": calib_q[0],
           "components": len(groups), "excluded": dict(removed), "splits": {k: C.profile(v) for k, v in splits.items()}}
    return splits, man


def export(db, output, dai, skills, name, **opt):
    splits, man = prepare(db, **opt)
    if not splits["train"]:
        raise ValueError("no training examples remain")
    out = pathlib.Path(output); out.mkdir(parents=True, exist_ok=False); man["files"] = {}
    for sp, rows in splits.items():
        p = out / f"{sp}.labelled.jsonl"; text = "".join(C.encoded(r) + "\n" for r in rows)
        p.write_text(text, encoding="utf-8", newline="\n"); man["files"][p.name] = C.digest(text)
        if dai and rows:
            plans = out / f"{sp}.plans.jsonl"
            cmd = [str(pathlib.Path(dai).resolve()), "distill-export", "-backend", "lexical", "-experts=false",
                   "-input", str(p), "-output", str(plans)] + (["-skills", skills] if skills else [])
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
            man["files"][plans.name] = hashlib.sha256(plans.read_bytes()).hexdigest()
    man["teachers"] = dict(db.execute("SELECT teacher, COUNT(*) FROM labels GROUP BY teacher"))
    text = json.dumps(man, ensure_ascii=False, indent=2) + "\n"
    (out / "manifest.json").write_text(text, encoding="utf-8")
    with db:
        db.execute("INSERT OR REPLACE INTO runs VALUES(?,?,?,?,?,?,?)",
                   (name or "export-" + out.name, NOW(), "export", str(out.resolve()), C.digest(text), C.encoded(man["splits"]), None))
    return man


# ------------------------------------------------------------------ pairs, runs, weak spots, stats
def pairs(db, plans, builder):
    out = pathlib.Path(plans).with_name("pairs.jsonl")
    iso = out.parent / "iso"; iso.mkdir(exist_ok=True)   # builder bans chunks of every dev*/test-* plans file here
    for f in iso.iterdir():
        f.unlink()
    for split, name in (("dev", "dev.plans.jsonl"), ("test", "test-main.plans.jsonl"), ("calib", "test-calib.plans.jsonl")):
        src = out.parent / f"{split}.plans.jsonl"
        if src.exists():
            shutil.copyfile(src, iso / name)
    subprocess.run([sys.executable, builder, str(out), plans], check=True, env={**os.environ, "DAI_ISO": str(iso)})
    n = collections.Counter()
    with db:
        for line in out.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            db.execute("INSERT OR IGNORE INTO pairs VALUES(?,?,?,?,?,?)",
                       (C.digest(C.canonical([r["kind"], r["a"], r["b"]])), r["kind"], r["a"], r["b"], C.encoded(r["negs"]), plans))
            n[r["kind"]] += 1
    return {"file": str(out), **n}


def run_add(db, name, kind, dataset, reports, notes):
    metrics = {}
    with db:
        db.execute("INSERT OR REPLACE INTO runs VALUES(?,?,?,?,?,?,?)", (name, NOW(), kind, dataset, None, "{}", notes))
        for rp in reports or []:
            r = json.loads(pathlib.Path(rp).read_text(encoding="utf-8"))
            suite = pathlib.Path(rp).stem
            metrics[suite] = {t: v.get("agreement") for t, v in r.get("by_type", {}).items()}
            for f in r.get("failures") or []:
                db.execute("INSERT OR REPLACE INTO failures VALUES(?,?,?,?,?,?,?,?)",
                           (name, suite, f["example"], f["question"], f.get("type"), str(f.get("expected")),
                            str(f.get("predicted")), f.get("probability")))
        db.execute("UPDATE runs SET metrics=? WHERE name=?", (C.encoded(metrics), name))
    return {"run": name, "metrics": metrics}


def weak(db, run):
    q = "SELECT suite, type, question, COUNT(*) FROM failures" + (" WHERE run=?" if run else "") + \
        " GROUP BY suite, type, question ORDER BY COUNT(*) DESC LIMIT 30"
    return [dict(zip(("suite", "type", "question", "failures"), r)) for r in db.execute(q, (run,) if run else ())]


def stats(db):
    base = C.stats(db); base.pop("sources", None)
    one = lambda q: db.execute(q).fetchone()[0]
    sch = db.execute("SELECT s.type, COUNT(DISTINCT s.hash) FROM schemas s GROUP BY s.type").fetchall()
    top = db.execute("SELECT s.qid, s.type, COUNT(*) c FROM example_schemas e JOIN schemas s ON s.hash=e.schema_hash "
                     "GROUP BY e.schema_hash ORDER BY c DESC LIMIT 10").fetchall()
    total_q = one("SELECT COUNT(*) FROM example_schemas") or 1
    return {**base,
            "langs": dict(db.execute("SELECT lang, COUNT(*) FROM meta GROUP BY lang")),
            "domains": dict(db.execute("SELECT COALESCE(domain,'legacy'), COUNT(*) FROM meta GROUP BY 1")),
            "schemas": {"distinct": one("SELECT COUNT(*) FROM schemas"), "by_type": dict(sch),
                        "top10_share": round(sum(c for _, _, c in top) / total_q, 3),
                        "top10": [f"{q}/{t}:{c}" for q, t, c in top]},
            "teachers": dict(db.execute("SELECT teacher, COUNT(*) FROM labels GROUP BY teacher ORDER BY 2 DESC LIMIT 25")),
            "gen": dict(db.execute("SELECT status, COUNT(*) FROM gen GROUP BY status")),
            "gen_cases": dict(zip(("kept", "dropped"), db.execute("SELECT COALESCE(SUM(kept),0), COALESCE(SUM(dropped),0) FROM gen").fetchone())),
            "pairs": dict(db.execute("SELECT kind, COUNT(*) FROM pairs GROUP BY kind")),
            "runs": [r[0] for r in db.execute("SELECT name FROM runs ORDER BY created")]}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default="data/local/dai.sqlite3")
    c = p.add_subparsers(dest="cmd", required=True)
    m = c.add_parser("migrate"); m.add_argument("--from", dest="src", required=True)
    i = c.add_parser("import"); i.add_argument("paths", nargs="+"); i.add_argument("--role", default="train",
        choices=("train", "dev", "test", "holdout")); i.add_argument("--teacher", required=True)
    c.add_parser("index"); c.add_parser("stats")
    g = c.add_parser("gen"); g.add_argument("--n", type=int, required=True); g.add_argument("--model", default="qwen3:4b")
    g.add_argument("--teacher-model"); g.add_argument("--ollama", default="http://127.0.0.1:11434")
    g.add_argument("--seed", type=int, default=1); g.add_argument("--cases", type=int, default=6)
    g.add_argument("--langs", default="ru,en")
    e = c.add_parser("export"); e.add_argument("--output", required=True); e.add_argument("--dai"); e.add_argument("--skills")
    e.add_argument("--name"); e.add_argument("--seed", type=int, default=17); e.add_argument("--dev-fraction", type=float, default=0.05)
    e.add_argument("--test-fraction", type=float, default=0.05); e.add_argument("--near", type=float, default=0.5)
    e.add_argument("--calib-schemas", type=float, default=0.08); e.add_argument("--calib-max", type=int, default=300)
    pa = c.add_parser("pairs"); pa.add_argument("--plans", required=True); pa.add_argument("--builder", required=True)
    r = c.add_parser("run"); r.add_argument("action", choices=("add", "list")); r.add_argument("--name")
    r.add_argument("--kind", default="eval"); r.add_argument("--dataset"); r.add_argument("--report", nargs="*")
    r.add_argument("--notes")
    w = c.add_parser("weak"); w.add_argument("--run")
    a = p.parse_args(argv); db = connect(a.db)
    try:
        if a.cmd == "migrate": res = migrate(db, a.src)
        elif a.cmd == "import": res = import_files(db, a.paths, a.role, a.teacher)
        elif a.cmd == "index": res = index(db)
        elif a.cmd == "stats": res = stats(db)
        elif a.cmd == "gen": res = gen(db, a.n, a.model, a.teacher_model or a.model, a.ollama, a.seed, a.cases, a.langs.split(","))
        elif a.cmd == "export": res = export(db, a.output, a.dai, a.skills, a.name, seed=a.seed, dev_fraction=a.dev_fraction,
                                             test_fraction=a.test_fraction, near=a.near, calib_schemas=a.calib_schemas, calib_max=a.calib_max)
        elif a.cmd == "pairs": res = pairs(db, a.plans, a.builder)
        elif a.cmd == "run":
            res = run_add(db, a.name, a.kind, a.dataset, a.report, a.notes) if a.action == "add" else \
                [dict(zip(("name", "created", "kind", "metrics"), x)) for x in db.execute("SELECT name, created, kind, metrics FROM runs ORDER BY created")]
        else: res = weak(db, a.run)
        print(json.dumps(res, ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, sqlite3.Error, subprocess.CalledProcessError) as exc:
        print(f"dairdb: {exc}", file=sys.stderr); sys.exit(1)
