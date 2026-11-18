"""Check training/evaluation isolation before importing ML dependencies."""
import hashlib
import json
import pathlib


def signatures(paths):
    groups, states = {}, {}
    count = 0
    for path in paths:
        with open(path, encoding="utf-8-sig") as stream:
            for line, text in enumerate(stream, 1):
                if not text.strip():
                    continue
                row = json.loads(text)
                chunks, questions = row.get("chunks"), row.get("questions")
                location = f"{path}:{line}"
                if not isinstance(chunks, list) or not chunks or not all(isinstance(c, str) and c.strip() for c in chunks):
                    raise ValueError(f"{location}: missing or empty chunks")
                if not isinstance(questions, list) or not questions or any(q.get("label") is None for q in questions):
                    raise ValueError(f"{location}: every question needs a non-null label")
                if row.get("group"):
                    groups.setdefault(row["group"], location)
                signature = hashlib.sha256(json.dumps(chunks, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
                states.setdefault(signature, location)
                count += len(questions)
    if count == 0:
        raise ValueError("empty training/evaluation split: " + ", ".join(map(str, paths)))
    return groups, states, count


def check_plan_splits(train, dev, tests=()):
    # Tests may overlap each other, but neither training nor validation may see them.
    splits = {"train": signatures(train), "dev": signatures(dev)}
    if tests:
        splits["test"] = signatures(tests)
    for left, right in (("train", "dev"), ("train", "test"), ("dev", "test")):
        if right not in splits:
            continue
        for index, kind in ((0, "group"), (1, "state/chunks")):
            overlap = sorted(splits[left][index].keys() & splits[right][index].keys())
            if overlap:
                key = overlap[0]
                raise ValueError(
                    f"dataset leakage: {len(overlap)} shared {kind} between {left} and {right}; "
                    f"{splits[left][index][key]} overlaps {splits[right][index][key]}. "
                    "Prepare isolated splits with scripts/data/corpus.py (docs/TRAINING.ru.md)."
                )
    return {name: value[2] for name, value in splits.items()}


def check_directory(directory, extra=()):
    directory = pathlib.Path(directory)
    return check_plan_splits([directory / "train.plans.jsonl", *map(pathlib.Path, extra)],
                             [directory / "dev.plans.jsonl"], sorted(directory.glob("test-*.plans.jsonl")))
