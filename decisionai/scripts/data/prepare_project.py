#!/usr/bin/env python3
"""Build a clean, reproducible corpus from the existing project data (no network)."""
import argparse
import json
import pathlib
import sys

import corpus

ROOT = pathlib.Path(__file__).resolve().parents[2]
TRAIN = ["train", "train.para", "syn2", "syn2.para", "syn3", "syn3.para", "syn4", "syn4.para", "syn6.qwen", "syn7"]
HOLDOUT = ["golden-test", "hard-cases", "distill/decision-blind", "distill/jev-holdout", "base-tasks",
           "unseen", "unseen2", "unseen3", "regression-experts"]
SKILL_HOLDOUT = ["skill-routing-holdout", "skill-routing-blind2", "skill-routing-stress", "skill-routing-notion"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=str(ROOT / "data/local/corpus.sqlite3"))
    parser.add_argument("--output", default=str(ROOT / "data/prepared/v1"))
    parser.add_argument("--dai", help="also export training plans with a compiled dai executable")
    args = parser.parse_args(argv)
    # Check all source paths before mutating the database.
    train = [ROOT / f"data/distill/{name}.labelled.jsonl" for name in TRAIN]
    dev = ROOT / "data/distill/dev.labelled.jsonl"
    heldout = [ROOT / f"evals/{name}.jsonl" for name in HOLDOUT + SKILL_HOLDOUT]
    for path in train + [dev] + heldout:
        if not path.is_file():
            raise ValueError(f"missing source dataset: {path}")
    if pathlib.Path(args.output).exists():
        raise ValueError("output directory already exists; choose a new version with --output")
    db = corpus.connect(args.db)
    try:
        result = {"train_import": corpus.import_files(db, train), "dev_import": corpus.import_files(db, [dev], "dev"),
                  "holdout_import": corpus.import_files(db, heldout, "holdout")}
        result["export"] = corpus.export(db, args.output, dai=args.dai, skills=str(ROOT / "evals/skills"),
                                         dev_fraction=0, test_fraction=0.1)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, corpus.sqlite3.Error, corpus.subprocess.CalledProcessError) as exc:
        print(f"prepare: {exc}", file=sys.stderr)
        sys.exit(1)
