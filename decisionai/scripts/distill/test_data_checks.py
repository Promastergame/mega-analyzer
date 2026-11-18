import json
import pathlib
import tempfile
import unittest

from data_checks import check_plan_splits


class DataChecksTest(unittest.TestCase):
    def test_cross_split_leakage_and_missing_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)

            def write(name, group, chunks, label=True):
                path = root / name
                path.write_text(json.dumps({"group": group, "chunks": chunks,
                                            "questions": [{"id": "q", "label": label}]}) + "\n", encoding="utf-8")
                return path

            train = write("train", "project-a", ["text a"])
            dev = write("dev", "project-b", ["text b"])
            self.assertEqual(check_plan_splits([train], [dev]), {"train": 1, "dev": 1})
            test = write("test", "project-c", ["text a"])
            with self.assertRaisesRegex(ValueError, "shared state/chunks between train and test"):
                check_plan_splits([train], [dev], [test])
            write("dev", "project-a", ["different"])
            with self.assertRaisesRegex(ValueError, "shared group"):
                check_plan_splits([train], [dev])
            write("dev", "project-b", ["different"], None)
            with self.assertRaisesRegex(ValueError, "non-null label"):
                check_plan_splits([train], [dev])


if __name__ == "__main__":
    unittest.main()
