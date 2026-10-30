#!/usr/bin/env python3
"""Compare typed findings in two Mega-Analyzer analysis.json reports, offline."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import tempfile

SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CHANGE_FIELDS = ("severity", "confidence", "occurrences", "kind", "title", "description", "cwe", "masvs", "evidence", "steps", "provenance")


def comparison_value(item, field):
    """Ignore source-line movement and evidence ordering, preserving path order."""
    value = item.get(field)
    if field not in ("evidence", "steps", "provenance"):
        return value

    def normalize(value):
        if isinstance(value, dict):
            return {k: normalize(v) for k, v in value.items() if k not in ("line", "column")}
        if isinstance(value, list):
            return [normalize(v) for v in value]
        return value

    value = normalize(value or [])
    if field != "steps" and isinstance(value, list):
        value = sorted(value, key=lambda v: json.dumps(v, sort_keys=True, ensure_ascii=False))
    return value


def load_report(path):
    data = Path(path).read_bytes()
    report = json.loads(data)
    if not isinstance(report, dict):
        raise ValueError("Expected an analysis.json object: " + str(path))
    metadata = report.get("report_metadata")
    if not isinstance(metadata, dict) or metadata.get("schema_version") != 1 or not isinstance(report.get("findings"), list):
        raise ValueError("Report lacks the typed export contract; regenerate it with the current analyzer: " + str(path))
    return report, hashlib.sha256(data).hexdigest()


def index_findings(report):
    result = {}
    for item in report["findings"]:
        if not isinstance(item, dict) or not all(isinstance(item.get(k), str) and item[k] for k in ("fingerprint", "rule_id")):
            raise ValueError("Each finding must have a rule_id and fingerprint")
        if item.get("severity") not in SEVERITY:
            raise ValueError("Unknown finding severity for " + item["rule_id"])
        confidence = item.get("confidence", 0)
        if isinstance(confidence, bool) or not isinstance(confidence, (float, int)) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("Invalid finding confidence for " + item["rule_id"])
        key = (item["rule_id"], item["fingerprint"])
        if key in result:
            raise ValueError("Duplicate finding identity: " + item["rule_id"])
        result[key] = item
    return result


def coverage_warnings(report, label):
    warnings = []
    run = report.get("run")
    if isinstance(run, dict) and run.get("status") != "complete":
        warnings.append(label + ": run " + str(run.get("stop_reason") or run.get("status")))
    for section, counters in (
        ("coverage", ("parse_failed", "files_failed", "skipped_by_size", "skipped_by_limit", "limit_reached")),
        ("data_flow_stats", ("cancelled", "limit_reached", "slice_limit_reached", "slices_truncated", "cfg_incomplete_methods", "methods_truncated")),
    ):
        stats = report.get(section)
        if not isinstance(stats, dict):
            warnings.append(label + ": missing " + section)
            continue
        for key in counters:
            if stats.get(key):
                warnings.append(f"{label}: {section}.{key}={stats[key]}")
    return warnings


def compare(before, after):
    old, new = index_findings(before), index_findings(after)
    old_keys, new_keys = set(old), set(new)
    changed = []
    for key in sorted(old_keys & new_keys):
        fields = [field for field in CHANGE_FIELDS if comparison_value(old[key], field) != comparison_value(new[key], field)]
        if fields:
            changed.append({"fields": fields, "before": old[key], "after": new[key]})
    warnings = coverage_warnings(before, "before") + coverage_warnings(after, "after")
    comparable = not warnings
    if before.get("run") and after.get("run"):
        for field in ("core_settings", "profile", "timeout_seconds", "identity"):
            if before["run"].get(field) != after["run"].get(field):
                warnings.append("Core scan " + field + " differs")
                comparable = False
    for field in ("analyzer_version", "commit"):
        if before["report_metadata"].get(field) != after["report_metadata"].get(field):
            warnings.append("Analyzer " + field + " differs; detector changes can affect the result")
    if before.get("app_package") != after.get("app_package"):
        warnings.append("Application package differs; confirm that these are the intended inputs")
        comparable = False
    added = [new[k] for k in sorted(new_keys - old_keys)]
    removed = [old[k] for k in sorted(old_keys - new_keys)]
    return {
        "schema_version": 1,
        "scope": "typed_findings",
        "coverage_complete": comparable,
        "summary": {"added": len(added), "removed": len(removed), "changed": len(changed), "unchanged": len(old_keys & new_keys) - len(changed)},
        "added": added, "removed": removed, "changed": changed, "warnings": warnings,
    }


def regression_exit_code(result, threshold=None):
    if not result["coverage_complete"]:
        return 3
    if threshold:
        minimum = SEVERITY[threshold]
        if any(SEVERITY[f["severity"]] >= minimum for f in result["added"]):
            return 1
        if any(SEVERITY[c["after"]["severity"]] >= minimum > SEVERITY[c["before"]["severity"]] for c in result["changed"]):
            return 1
    return 0


def write_result(path, result):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".report-diff-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(result, handle, indent=2, ensure_ascii=False, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--output", type=Path, help="Write a JSON diff; otherwise print it")
    parser.add_argument("--fail-on-new", choices=SEVERITY, help="Exit 1 for new findings or severity increases crossing this threshold")
    args = parser.parse_args(argv)
    try:
        if args.output and args.output.resolve() in {args.before.resolve(), args.after.resolve()}:
            raise ValueError("The output must not overwrite an input report")
        before, before_hash = load_report(args.before)
        after, after_hash = load_report(args.after)
        result = compare(before, after)
        result["inputs"] = {
            "before": {"sha256": before_hash, "report_metadata": before["report_metadata"], "timestamp": before.get("timestamp")},
            "after": {"sha256": after_hash, "report_metadata": after["report_metadata"], "timestamp": after.get("timestamp")},
        }
        if args.output:
            write_result(args.output, result)
            print(json.dumps(result["summary"]))
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        for warning in result["warnings"]:
            print("Warning: " + warning, file=sys.stderr)
        return regression_exit_code(result, args.fail_on_new)
    except (OSError, ValueError, TypeError) as error:
        print("Cannot compare reports: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
