import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import compare_reports as diff


def report(*findings):
    return {"report_metadata": {"schema_version": 1, "analyzer_version": "test", "commit": "test"},
            "findings": list(findings), "coverage": {}, "data_flow_stats": {}}


def finding(identity, severity="high", line=1):
    return {"fingerprint": identity, "rule_id": "test.rule", "severity": severity, "confidence": 0.8,
            "locations": [{"file": "source.smali", "line": line}]}


class ReportComparisonTests(unittest.TestCase):
    def test_evidence_changes_but_line_movement_does_not(self):
        import copy
        before = report(finding("same"))
        before["findings"][0]["evidence"] = [{"type": "code", "snippet": "exec(input)", "location": {"file": "a.smali", "line": 2}}]
        after = copy.deepcopy(before)
        after["findings"][0]["evidence"][0]["location"]["line"] = 100
        self.assertEqual(diff.compare(before, after)["summary"]["changed"], 0)
        after["findings"][0]["evidence"].append({"type": "runtime", "description": "Observed process execution"})
        result = diff.compare(before, after)
        self.assertEqual(result["changed"][0]["fields"], ["evidence"])
        self.assertEqual(diff.regression_exit_code(result, "high"), 0)

    def test_path_order_is_significant_evidence_order_is_not(self):
        import copy
        before = report(finding("same"))
        before["findings"][0].update(evidence=[{"type": "a"}, {"type": "b"}], steps=[{"method": "source"}, {"method": "sink"}])
        after = copy.deepcopy(before)
        after["findings"][0]["evidence"].reverse()
        self.assertEqual(diff.compare(before, after)["summary"]["changed"], 0)
        after["findings"][0]["steps"].reverse()
        self.assertEqual(diff.compare(before, after)["changed"][0]["fields"], ["steps"])

    def test_added_removed_changed_and_line_movement(self):
        before = report(finding("moved"), finding("gone"), finding("changed", "low"))
        after = report(finding("moved", line=20), finding("new"), finding("changed", "high"))
        result = diff.compare(before, after)
        self.assertEqual(result["summary"], {"added": 1, "removed": 1, "changed": 1, "unchanged": 1})
        self.assertEqual(result["changed"][0]["fields"], ["severity"])
        self.assertEqual(diff.regression_exit_code(result, "high"), 1)
        self.assertEqual(diff.regression_exit_code(result, "critical"), 0)
        self.assertEqual(before["findings"][0]["locations"][0]["line"], 1)

    def test_severity_crossing_is_a_regression(self):
        result = diff.compare(report(finding("same", "low")), report(finding("same", "critical")))
        self.assertEqual(diff.regression_exit_code(result, "high"), 1)

    def test_partial_scan_does_not_claim_success(self):
        after = report()
        after["coverage"]["limit_reached"] = True
        result = diff.compare(report(finding("gone")), after)
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(diff.regression_exit_code(result), 3)
        self.assertEqual(result["summary"]["removed"], 1)
        self.assertTrue(result["warnings"])

    def test_cancelled_scan_and_different_settings_are_not_comparable(self):
        before, after = report(), report()
        before["run"] = {"status": "complete", "core_settings": {"max_files": 100}}
        after["run"] = {"status": "incomplete", "stop_reason": "cancelled", "core_settings": {"max_files": 100}}
        self.assertEqual(diff.regression_exit_code(diff.compare(before, after)), 3)
        after["run"] = {"status": "complete", "core_settings": {"max_files": 10}}
        self.assertEqual(diff.regression_exit_code(diff.compare(before, after)), 3)

    def test_input_order_does_not_change_diff(self):
        before, after = report(finding("b")), report(finding("c"), finding("a"))
        expected = diff.compare(before, after)
        after["findings"].reverse()
        self.assertEqual(diff.compare(before, after), expected)

    def test_invalid_identity_and_severity_are_rejected(self):
        for items in ([finding("same"), finding("same")], [finding("", "high")], [finding("f", "unknown")]):
            with self.subTest(items=items), self.assertRaises(ValueError):
                diff.compare(report(), report(*items))

    def test_cli_preserves_inputs_and_rejects_legacy_exports(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            before, after, output = root / "before.json", root / "after.json", root / "diff.json"
            before.write_text(json.dumps(report()))
            after.write_text(json.dumps(report(finding("new"))))
            original = before.read_bytes()
            self.assertEqual(diff.main([str(before), str(after), "--output", str(output), "--fail-on-new", "high"]), 1)
            result = json.loads(output.read_text())
            self.assertEqual(len(result["inputs"]["before"]["sha256"]), 64)
            self.assertEqual(diff.main([str(before), str(after), "--output", str(before)]), 2)
            self.assertEqual(before.read_bytes(), original)
            after.write_text('{"stats":{"total_matches":4}}')
            self.assertEqual(diff.main([str(before), str(after)]), 2)
