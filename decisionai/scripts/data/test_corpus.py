import copy
import json
import pathlib
import tempfile
import unittest

import corpus


def row(state="text", group="", label=True, instruction="Is it ready?"):
    return {"group": group, "request": {"state": state, "questions": {
        "ready": {"type": "noul", "instructions": instruction}}}, "labels": {"ready": label}}


class CorpusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.db = corpus.connect(self.root / "corpus.sqlite3")
        self.number = 0

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def load(self, rows, role="train"):
        self.number += 1
        path = self.root / f"input-{self.number}.jsonl"
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        return corpus.import_files(self.db, [path], role)

    def test_semantic_duplicate_and_score_order(self):
        a = row({"amount": 42, "ready": True}, "a")
        b = row({"ready": True, "amount": 42}, "b", 1.0)
        self.assertEqual(self.load([a, b]), {"inserted": 1, "duplicates": 1, "rows": 2})
        self.assertEqual(corpus.stats(self.db)["origins_by_role"], {"train": 2})
        request = {"state": "scale", "questions": {"q": {"type": "score", "instructions": "Rate", "criteria": {"a": "low", "b": "high"}}}}
        reverse = copy.deepcopy(request)
        reverse["questions"]["q"]["criteria"] = {"b": "high", "a": "low"}
        self.assertNotEqual(corpus.request_key(request), corpus.request_key(reverse))
        request["questions"]["q"]["type"] = "choice"
        reverse["questions"]["q"]["type"] = "choice"
        self.assertEqual(corpus.request_key(request), corpus.request_key(reverse))

    def test_conflicting_labels_quarantined(self):
        self.load([row("conflict", label=True), row("conflict", label=False), row("clean")])
        splits, report = corpus.prepare(self.db, dev_fraction=0, test_fraction=0)
        self.assertEqual(report["excluded"], {"conflict": 1})
        self.assertEqual([r["request"]["state"] for r in splits["train"]], ["clean"])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM conflicts").fetchone()[0], 1)

    def test_null_missing_unknown_labels_and_nonfinite_values(self):
        for label in (None, "true", -0.1, 1.1, float("nan"), float("inf")):
            with self.subTest(label=label), self.assertRaises(ValueError):
                corpus.validate(row(label=label))
        a = row()
        a["labels"] = {}
        with self.assertRaises(ValueError):
            corpus.validate(a)
        q = {"type": "choice", "criteria": {"a": "a", "b": "b"}}
        for label in ({"a": None}, {"a": -1}, {"c": 1}, {"a": 0}, {"a": True}, {"a": 1e308, "b": 1e308}):
            with self.subTest(label=label), self.assertRaises(ValueError):
                corpus.label_distribution(q, label)

    def test_import_rolls_back_all_files_on_error(self):
        path = self.root / "invalid.jsonl"
        path.write_text(json.dumps(row()) + '\n{"request": {}}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid.jsonl:2"):
            corpus.import_files(self.db, [path])
        self.assertEqual(corpus.stats(self.db)["examples"], 0)
        path.write_text('{"request": {}, "request": {}}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            corpus.import_files(self.db, [path])

    def test_transitive_groups_and_state_aliases_are_isolated(self):
        self.load([row("same", "a"), row("same", "b", instruction="Ready?"), row("different", "b"),
                   *[row(f"independent {i}", f"independent-{i}") for i in range(50)]])
        splits, _ = corpus.prepare(self.db)
        locations = {}
        for name, rows in splits.items():
            for r in rows:
                locations.setdefault(r["request"]["state"], set()).add(name)
        self.assertEqual(locations["same"], locations["different"])
        self.assertEqual(len(locations["same"]), 1)
        groups = [{r["group"] for r in rows} for rows in splits.values()]
        self.assertFalse(groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2])
        self.assertEqual(splits, corpus.prepare(self.db)[0])

    def test_holdout_excludes_related_train_without_exporting_test_labels(self):
        self.load([row("secret test", "original"), row("counterfactual", "original"), row("safe")])
        self.load([row("secret test", "test", instruction="Unseen question?")], "holdout")
        splits, report = corpus.prepare(self.db, dev_fraction=0, test_fraction=0, near_threshold=1)
        self.assertEqual([r["request"]["state"] for r in splits["train"]], ["safe"])
        self.assertEqual(report["excluded"]["holdout_overlap"], 2)
        self.assertEqual(report["excluded"]["protected_holdout"], 1)

    def test_fixed_dev_keeps_only_designated_rows(self):
        self.load([row("a", "project", instruction="Train?"), row("b", "project"), row("safe")])
        self.load([row("a", "dev", instruction="Development?")], "dev")
        splits, report = corpus.prepare(self.db, dev_fraction=0, test_fraction=0, near_threshold=1)
        self.assertEqual(len(splits["dev"]), 1)
        self.assertEqual(splits["dev"][0]["request"]["questions"]["ready"]["instructions"], "Development?")
        self.assertEqual(len(splits["train"]), 1)
        self.assertEqual(report["excluded"]["fixed_split_overlap"], 2)

    def test_near_holdout_excludes_entire_family(self):
        self.load([row("red blue green gold silver orange violet black white", "family"), row("paired", "family"), row("unrelated")])
        self.load([row("red blue green gold silver orange violet black white pink")], "holdout")
        splits, report = corpus.prepare(self.db, dev_fraction=0, test_fraction=0, near_threshold=0.9)
        self.assertEqual(report["excluded"]["near_holdout_overlap"], 2)
        self.assertEqual([r["request"]["state"] for r in splits["train"]], ["unrelated"])

    def test_export_preserves_score_order_and_does_not_overwrite(self):
        a = row()
        a["request"]["questions"]["ready"] = {"type": "score", "instructions": "Rate", "criteria": {"low": "low", "high": "high"}}
        a["labels"]["ready"] = "high"
        self.load([a])
        output = self.root / "prepared"
        report = corpus.export(self.db, output, dev_fraction=0, test_fraction=0)
        content = (output / "train.labelled.jsonl").read_text(encoding="utf-8")
        q = json.loads(content)["request"]["questions"]["ready"]
        self.assertEqual(list(q["criteria"]), ["low", "high"])
        self.assertEqual(report["files"]["train.labelled.jsonl"], corpus.digest(content))
        with self.assertRaises(FileExistsError):
            corpus.export(self.db, output, dev_fraction=0, test_fraction=0)


if __name__ == "__main__":
    unittest.main()
