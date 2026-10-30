//! Minimal SARIF 2.1.0 exporter.
//!
//! SARIF is the de-facto interchange format for static-analysis results.
//! Emitting it lets the scan report drop straight into code-scanning
//! dashboards and SOC pipelines without every consumer having to learn our
//! bespoke JSON shape.

use omnisec_json::{JsonValue as Value, json};

use crate::{ScanReport, Severity};

/// Render a [`ScanReport`] as a SARIF 2.1.0 log document.
#[must_use]
pub fn to_sarif(report: &ScanReport) -> Value {
    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.id,
                "level": sarif_level(f.severity),
                "message": { "text": f.description },
                "properties": {
                    "title": f.title,
                    "category": f.category.slug(),
                    "severity": f.severity.tag(),
                    "confidence": format!("{:?}", f.confidence).to_lowercase(),
                    "cwe": f.cwe,
                    "evidence": f.evidence,
                    "fileOffset": f.file_offset,
                }
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "omnisec-scan-native",
                "version": report.scanner_version,
                "informationUri": "https://omnisec.dev",
            }},
            "results": results,
            "properties": {
                "score": report.score,
                "verdict": report.verdict.name(),
                "scoringModel": report.scoring_model,
                "schemaVersion": report.schema_version,
            }
        }]
    })
}

const fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Info | Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_mapping() {
        assert_eq!(sarif_level(Severity::Info), "note");
        assert_eq!(sarif_level(Severity::Medium), "warning");
        assert_eq!(sarif_level(Severity::Critical), "error");
    }
}
