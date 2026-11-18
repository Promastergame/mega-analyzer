import json
import pathlib
import random
import tempfile
import unittest

import build_pairs


class ContrastivePairsTest(unittest.TestCase):
    def test_positive_views_preserve_meaning(self):
        for sentence in [
            "Алина не передала Борису 1500 г муки вчера",
            "Only Ada can send 2 kg to Ben today",
            "The call cannot modify any data without approval",
        ]:
            for probability in [0, 0.5, 1]:
                self.assertEqual(build_pairs.drop(sentence, probability, random.Random(4)), sentence)
        self.assertEqual(build_pairs.drop("Please do not send 12 USD to Bob", 1),
                         "do not send 12 USD to Bob")

    def test_long_polarity_pairs_are_exported_and_reproducible(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            (root / "dev.plans.jsonl").write_text(json.dumps({"chunks": ["protected"]}) + "\n", encoding="utf-8")
            hypothesis = "This call cannot modify customer data without explicit approval"
            row = {"chunks": ["ordinary input"], "questions": [{"type": "noul", "label": True,
                   "options": [{"key": "true", "hyp": hypothesis}, {"key": "false", "escape": True}]}]}
            source, output = root / "train.jsonl", root / "pairs.jsonl"
            source.write_text(json.dumps(row) + "\n", encoding="utf-8")
            build_pairs.build(output, [source], root)
            first = output.read_bytes()
            build_pairs.build(output, [source], root)
            self.assertEqual(output.read_bytes(), first)
            pairs = [json.loads(line) for line in first.splitlines()]
            self.assertEqual(len(pairs), 1)
            self.assertEqual(pairs[0]["kind"], "neg")
            self.assertEqual(pairs[0]["b"], hypothesis)
            self.assertIn("can modify", pairs[0]["negs"][0])

    def test_protection_checks_every_chunk_and_calibration(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            (root / "calib.plans.jsonl").write_text(json.dumps({"chunks": ["customer 42"]}) + "\n", encoding="utf-8")
            row = {"chunks": ["new text", "customer 73"], "questions": [{"type": "noul", "label": 1,
                   "options": [{"key": "true", "hyp": "cannot modify data"}]}]}
            source, output = root / "train.jsonl", root / "pairs.jsonl"
            source.write_text(json.dumps(row) + "\n", encoding="utf-8")
            counts = build_pairs.build(output, [source], root)
            self.assertEqual(counts["skipped_isolation"], 1)
            self.assertEqual(output.read_text(encoding="utf-8"), "")

    def test_failed_input_preserves_previous_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            (root / "dev.plans.jsonl").write_text(json.dumps({"chunks": ["protected"]}) + "\n", encoding="utf-8")
            output, source = root / "pairs.jsonl", root / "train.jsonl"
            output.write_text("previous result", encoding="utf-8")
            source.write_text("invalid JSON\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_pairs.build(output, [source], root)
            self.assertEqual(output.read_text(encoding="utf-8"), "previous result")


if __name__ == "__main__":
    unittest.main()
