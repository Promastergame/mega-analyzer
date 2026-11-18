#!/usr/bin/env python3
"""Offline, stdlib-only dataset registry for DecisionAI. See docs/TRAINING.ru.md."""
import argparse
import collections
import hashlib
import json
import math
import pathlib
import re
import sqlite3
import subprocess
import sys

VERSION = 1


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def no_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def read_rows(path):
    with open(path, encoding="utf-8-sig") as stream:
        for line, text in enumerate(stream, 1):
            if not text.strip() or text.lstrip().startswith("#"):
                continue
            try:
                row = json.loads(text, object_pairs_hook=no_duplicate_keys,
                                 parse_constant=lambda v: (_ for _ in ()).throw(ValueError(f"non-finite number: {v}")))
                if not isinstance(row, dict):
                    raise ValueError("record must be an object")
                yield line, row
            except (ValueError, TypeError) as exc:
                raise ValueError(f"{path}:{line}: {exc}") from exc


def label_distribution(question, label):
    typ = question["type"]
    if typ == "noul":
        if not isinstance(label, (int, float, bool)) or not math.isfinite(label) or not 0 <= label <= 1:
            raise ValueError("noul label must be boolean or a finite number in 0..1")
        return {"true": float(label), "false": 1 - float(label)}
    criteria = question.get("criteria")
    keys = set(criteria) if isinstance(criteria, dict) else None
    if isinstance(label, str) and label:
        dist = {label: 1.0}
    elif isinstance(label, dict) and label:
        dist = dict(label)
    else:
        raise ValueError("choice/score label must be a key or a nonempty distribution")
    for key, value in dist.items():
        if keys is not None and key not in keys:
            raise ValueError(f"label key {key!r} is not declared")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError("probabilities must be finite nonnegative numbers")
    total = sum(dist.values())
    if total <= 0 or not math.isfinite(total):
        raise ValueError("distribution must have a finite positive sum")
    return {key: value / total for key, value in dist.items() if value > 0}


def validate(row, labelled=True):
    request = row.get("request")
    if not isinstance(request, dict) or "state" not in request:
        raise ValueError("request.state is required")
    state = request["state"]
    if state is None or state == {} or state == [] or (isinstance(state, str) and not state.strip()):
        raise ValueError("state must not be empty")
    if len(encoded(state).encode("utf-8")) > 256 * 1024:
        raise ValueError("state exceeds 256 KiB")
    questions = request.get("questions")
    if not isinstance(questions, dict) or not 1 <= len(questions) <= 64:
        raise ValueError("request needs 1..64 questions")
    if not isinstance(row.get("group", ""), str):
        raise ValueError("group must be a string")
    labels = row.get("labels", {})
    if labelled and (not isinstance(labels, dict) or set(labels) != set(questions)):
        raise ValueError("labels must cover exactly the declared question IDs")
    normalized = {}
    for qid, question in questions.items():
        if not qid or len(qid.encode("utf-8")) > 128 or not isinstance(question, dict):
            raise ValueError("invalid question ID or question object")
        typ = question.get("type")
        if typ not in ("noul", "choice", "score"):
            raise ValueError(f"{qid}: unsupported type {typ!r}")
        instruction = question.get("instructions")
        if instruction is None or not str(instruction).strip() or instruction in ({}, []):
            raise ValueError(f"{qid}: instructions required")
        criteria = question.get("criteria")
        dynamic = question.get("task") == "skill_routing" and typ == "choice" and criteria is None
        if typ != "noul" and not dynamic:
            if not isinstance(criteria, dict) or not 2 <= len(criteria) <= 255 or "" in criteria:
                raise ValueError(f"{qid}: criteria needs 2..255 nonempty keys")
        if typ == "noul" and criteria is not None:
            if not isinstance(criteria, dict) or not criteria or set(criteria) - {"true", "false"}:
                raise ValueError(f"{qid}: invalid noul criteria")
        if question.get("abstain_key") and question["abstain_key"] not in (criteria or {}):
            raise ValueError(f"{qid}: undeclared abstain_key")
        if labelled:
            normalized[qid] = label_distribution(question, labels[qid])
    return normalized


def request_key(request):
    # Object order does not change a state. SCORE option order DOES define its scale.
    value = dict(request)
    value.pop("model", None)
    value["questions"] = {}
    for key, question in request["questions"].items():
        question = dict(question)
        if question["type"] == "score" and isinstance(question.get("criteria"), dict):
            question["criteria"] = list(question["criteria"].items())
        value["questions"][key] = question
    return digest(canonical(value))


def connect(path):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys = ON")
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version not in (0, VERSION):
        db.close()
        raise ValueError(f"unsupported database version {version}")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS examples (
            id TEXT PRIMARY KEY, state_hash TEXT NOT NULL, request TEXT NOT NULL,
            labels TEXT NOT NULL, normalized TEXT NOT NULL, conflict INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS examples_state ON examples(state_hash);
        CREATE TABLE IF NOT EXISTS origins (
            example_id TEXT NOT NULL REFERENCES examples(id), source TEXT NOT NULL,
            line INTEGER NOT NULL, group_id TEXT NOT NULL, role TEXT NOT NULL,
            PRIMARY KEY (example_id, source, line, role)
        );
        CREATE TABLE IF NOT EXISTS conflicts (
            example_id TEXT NOT NULL REFERENCES examples(id), labels TEXT NOT NULL,
            source TEXT NOT NULL, line INTEGER NOT NULL,
            PRIMARY KEY (example_id, source, line)
        );
    """)
    db.execute(f"PRAGMA user_version = {VERSION}")
    return db


def import_files(db, paths, role="train"):
    counts = collections.Counter()
    # A malformed line rolls back the entire import, including previous files.
    with db:
        for path in paths:
            source = pathlib.Path(path).resolve().as_posix()
            for line, row in read_rows(path):
                if role == "holdout" and "request" not in row and "state" in row:
                    row = {"group": row.get("group", ""), "request": {"state": row["state"], "questions": {
                        "skill": {"type": "choice", "task": "skill_routing", "instructions": "Select a skill"}}}}
                try:
                    norm = validate(row, labelled=role != "holdout")
                except (ValueError, TypeError, OverflowError) as exc:
                    raise ValueError(f"{path}:{line}: {exc}") from exc
                request = row["request"]
                key = request_key(request)
                normalized = canonical(norm)
                labels = encoded(row.get("labels", {}) if role != "holdout" else {})
                old = db.execute("SELECT normalized FROM examples WHERE id=?", (key,)).fetchone()
                if old is None:
                    db.execute("INSERT INTO examples(id,state_hash,request,labels,normalized) VALUES(?,?,?,?,?)",
                               (key, digest(canonical(request["state"])), encoded(request), labels, normalized))
                    counts["inserted"] += 1
                elif role != "holdout" and old[0] == "{}":
                    db.execute("UPDATE examples SET labels=?, normalized=? WHERE id=?", (labels, normalized, key))
                    counts["labelled"] += 1
                elif role != "holdout" and old[0] != normalized:
                    db.execute("UPDATE examples SET conflict=1 WHERE id=?", (key,))
                    db.execute("INSERT OR IGNORE INTO conflicts VALUES(?,?,?,?)", (key, labels, source, line))
                    counts["conflicts"] += 1
                else:
                    counts["duplicates"] += 1
                db.execute("INSERT OR IGNORE INTO origins VALUES(?,?,?,?,?)",
                           (key, source, line, row.get("group", "").strip(), role))
                counts["rows"] += 1
    return dict(counts)


class Components:
    def __init__(self, keys):
        self.parent = {key: key for key in keys}

    def find(self, key):
        parent = self.parent
        while key != parent[key]:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def join(self, a, b):
        a, b = self.find(a), self.find(b)
        if a != b:
            self.parent[max(a, b)] = min(a, b)


def records(db):
    out = {}
    for key, state, request, labels, conflict in db.execute("SELECT id,state_hash,request,labels,conflict FROM examples ORDER BY id"):
        out[key] = {"id": key, "state_hash": state, "request": json.loads(request), "labels": json.loads(labels),
                    "conflict": bool(conflict), "groups": set(), "roles": set()}
    for key, group, role in db.execute("SELECT example_id,group_id,role FROM origins"):
        if group:
            out[key]["groups"].add(group)
        out[key]["roles"].add(role)
    return out


def profile(rows):
    types, labels, instructions = collections.Counter(), collections.Counter(), set()
    for row in rows:
        for key, question in row["request"]["questions"].items():
            typ = question["type"]
            types[typ] += 1
            instructions.add(canonical(question["instructions"]))
            if key in row.get("labels", {}):
                dist = label_distribution(question, row["labels"][key])
                winners = sorted(k for k, v in dist.items() if v == max(dist.values()))
                labels[typ + ":" + "|".join(winners)] += 1
    return {"examples": len(rows), "questions": sum(types.values()), "by_type": dict(types),
            "label_counts": dict(sorted(labels.items())), "unique_instructions": len(instructions)}


def stats(db):
    rows = list(records(db).values())
    return {**profile(rows), "conflicting_examples": sum(r["conflict"] for r in rows),
            "unique_states": len({r["state_hash"] for r in rows}),
            "origins_by_role": dict(db.execute("SELECT role,COUNT(*) FROM origins GROUP BY role")),
            "sources": [dict(zip(("source", "role", "rows"), row)) for row in
                        db.execute("SELECT source,role,COUNT(*) FROM origins GROUP BY source,role ORDER BY source,role")]}


def state_tokens(state):
    return set(re.findall(r"\w+", canonical(state).casefold()))


def prepare(db, seed=17, dev_fraction=0.1, test_fraction=0.1, near_threshold=0.9):
    if not (0 <= dev_fraction < 1 and 0 <= test_fraction < 1 and dev_fraction + test_fraction < 1):
        raise ValueError("dev/test fractions must be nonnegative and sum to less than 1")
    if not (0 < near_threshold <= 1):
        raise ValueError("near threshold must be in (0, 1]; 1 disables approximate matching")
    rows = records(db)
    components = Components(rows)
    seen = {}
    for key, row in rows.items():
        for link in ["state:" + row["state_hash"]] + ["group:" + group for group in row["groups"]]:
            if link in seen:
                components.join(key, seen[link])
            else:
                seen[link] = key
    groups = collections.defaultdict(list)
    for key, row in rows.items():
        groups[components.find(key)].append(row)

    # Approximate matching is only against protected references, never a source of labels.
    protected = [row for row in rows.values() if row["roles"] & {"holdout", "dev", "test"}]
    token_sets = [state_tokens(row["request"]["state"]) for row in protected]
    inverted = collections.defaultdict(set)
    for index, tokens in enumerate(token_sets):
        for token in tokens:
            inverted[token].add(index)
    near = set()
    if near_threshold < 1:
        checked = {}
        for row in rows.values():
            if row["roles"] != {"train"}:
                continue
            state_hash = row["state_hash"]
            if state_hash not in checked:
                tokens = state_tokens(row["request"]["state"])
                candidates = collections.Counter(index for token in tokens for index in inverted[token])
                checked[state_hash] = any(
                    overlap / (len(tokens) + len(token_sets[index]) - overlap) >= near_threshold
                    for index, overlap in candidates.items()
                )
            if checked[state_hash]:
                near.add(components.find(row["id"]))

    splits = {"train": [], "dev": [], "test": []}
    removed = collections.Counter()
    largest = 0
    for root, members in sorted(groups.items()):
        largest = max(largest, len(members))
        roles = set().union(*(row["roles"] for row in members))
        # Fixed evaluation sets keep ONLY their original rows; adjacent training rows are discarded.
        fixed = "holdout" if "holdout" in roles else "test" if "test" in roles else "dev" if "dev" in roles else None
        anchor = min(["g:" + g for row in members for g in row["groups"]] or ["s:" + row["state_hash"] for row in members])
        fraction = int(digest(f"{seed}:{anchor}")[:16], 16) / 2**64
        split = fixed or ("test" if fraction < test_fraction else "dev" if fraction < test_fraction + dev_fraction else "train")
        for row in members:
            if row["conflict"]:
                removed["conflict"] += 1
            elif fixed == "holdout":
                removed["protected_holdout" if "holdout" in row["roles"] else "holdout_overlap"] += 1
            elif fixed and fixed not in row["roles"]:
                removed["fixed_split_overlap"] += 1
            elif not fixed and root in near:
                removed["near_holdout_overlap"] += 1
            else:
                splits[split].append({"group": "corpus-" + digest(anchor)[:24], "request": row["request"], "labels": row["labels"]})
    manifest = {"schema_version": VERSION, "seed": seed, "dev_fraction": dev_fraction, "test_fraction": test_fraction,
                "near_threshold": near_threshold, "components": len(groups), "largest_component": largest,
                "excluded": dict(removed), "splits": {key: profile(value) for key, value in splits.items()}}
    return splits, manifest


def export(db, output, **options):
    dai = options.pop("dai", None)
    skills = options.pop("skills", None)
    splits, manifest = prepare(db, **options)
    if not splits["train"]:
        raise ValueError("no training examples remain after validation and holdout protection")
    output = pathlib.Path(output)
    # Never overwrite a dataset that might already be in use by a training run.
    output.mkdir(parents=True, exist_ok=False)
    manifest["files"] = {}
    for name, rows in splits.items():
        path = output / f"{name}.labelled.jsonl"
        content = "".join(encoded(row) + "\n" for row in rows)
        path.write_text(content, encoding="utf-8", newline="\n")
        manifest["files"][path.name] = digest(content)
        if dai and rows:
            plans = output / ("test-corpus.plans.jsonl" if name == "test" else f"{name}.plans.jsonl")
            command = [str(pathlib.Path(dai).resolve()), "distill-export", "-backend", "lexical", "-experts=false",
                       "-input", str(path), "-output", str(plans)]
            if skills:
                command += ["-skills", skills]
            subprocess.run(command, check=True)
            manifest["files"][plans.name] = hashlib.sha256(plans.read_bytes()).hexdigest()
    manifest["sources"] = stats(db)["sources"]
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/local/corpus.sqlite3")
    commands = parser.add_subparsers(dest="command", required=True)
    load = commands.add_parser("import", help="atomically import labelled JSONL; conflicting duplicates are quarantined")
    load.add_argument("paths", nargs="+")
    load.add_argument("--role", choices=("train", "dev", "test", "holdout"), default="train")
    commands.add_parser("stats", help="inspect corpus quality and provenance")
    out = commands.add_parser("export", help="export isolated splits and an integrity manifest into a NEW directory")
    out.add_argument("--output", required=True)
    out.add_argument("--seed", type=int, default=17)
    out.add_argument("--dev-fraction", type=float, default=0.1)
    out.add_argument("--test-fraction", type=float, default=0.1)
    out.add_argument("--near-threshold", type=float, default=0.9)
    out.add_argument("--dai", help="also export model-free training plans using this dai executable")
    out.add_argument("--skills", help="skill registry for plan export if training data contains skill_routing")
    args = parser.parse_args(argv)
    db = connect(args.db)
    try:
        if args.command == "import":
            result = import_files(db, args.paths, args.role)
        elif args.command == "stats":
            result = stats(db)
        else:
            result = export(db, args.output, seed=args.seed, dev_fraction=args.dev_fraction, test_fraction=args.test_fraction,
                            near_threshold=args.near_threshold, dai=args.dai, skills=args.skills)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, sqlite3.Error, subprocess.CalledProcessError) as exc:
        print(f"corpus: {exc}", file=sys.stderr)
        sys.exit(1)
