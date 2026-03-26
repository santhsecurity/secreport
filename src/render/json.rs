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
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": f.sarif_level,
                "message": { "text": format!("{}\n{}", f.title, f.detail) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.target }
                    }
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
            "tool": { "driver": { "name": tool_name } },
            "results": results,
        }]
    }))
}
