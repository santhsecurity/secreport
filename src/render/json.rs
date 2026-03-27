use crate::models::GenericFinding;

pub(crate) fn render_json_generic(
    findings: &[GenericFinding<'_>],
) -> Result<String, serde_json::Error> {
    let items: Vec<_> = findings.iter().map(GenericFinding::json_value).collect();
    serde_json::to_string_pretty(&items)
}

pub(crate) fn render_jsonl_generic(
    findings: &[GenericFinding<'_>],
) -> Result<String, serde_json::Error> {
    let mut out = Vec::with_capacity(findings.len());
    for finding in findings {
        out.push(serde_json::to_string(&finding.json_value())?);
    }
    Ok(out.join("\n"))
}

pub(crate) fn render_sarif_generic(
    findings: &[GenericFinding<'_>],
    tool_name: &str,
) -> Result<String, serde_json::Error> {
    let rules: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.detail },
                "help": {
                    "text": f.exploit_hint.unwrap_or(f.detail),
                    "markdown": f.exploit_hint.unwrap_or(f.detail),
                },
                "properties": {
                    "tags": f.tags,
                    "severity": f.severity.to_string(),
                    "precision": f.confidence.map(|_| "high").unwrap_or("medium"),
                    "cwe": f.cwe_ids,
                    "cve": f.cve_ids,
                }
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let fingerprint = format!(
                "{}:{}:{}:{}",
                f.rule_id, f.target, f.title, f.detail
            );
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": f.sarif_level,
                "message": { "text": format!("{}\n{}", f.title, f.detail) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.target }
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": fingerprint,
                },
                "codeFlows": [{
                    "threadFlows": [{
                        "locations": [{
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": { "uri": f.target }
                                },
                                "message": { "text": f.detail }
                            }
                        }]
                    }]
                }],
                "properties": {
                    "tags": f.tags,
                    "severity": f.severity.to_string(),
                    "confidence": f.confidence,
                    "cwe_ids": f.cwe_ids,
                    "cve_ids": f.cve_ids,
                    "exploit_hint": f.exploit_hint,
                }
            })
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": tool_name, "rules": rules } },
            "results": results,
        }]
    }))
}
