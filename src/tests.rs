use crate::{render, Format};
use secfinding::{Finding, Severity};

#[test]
fn format_from_str() {
    assert_eq!(Format::from_str_loose("json"), Some(Format::Json));
    assert_eq!(Format::from_str_loose("SARIF"), Some(Format::Sarif));
    assert_eq!(Format::from_str_loose("md"), Some(Format::Markdown));
    assert_eq!(Format::from_str_loose("anything"), None);
}

#[test]
fn empty_findings_text() {
    let out = render(&[], Format::Text, "test").unwrap();
    assert!(out.contains("No findings"));
}

#[test]
fn markdown_output_handles_unicode_in_all_fields() {
    let finding = Finding::builder("スキャナー", "https://例え.テスト", Severity::High)
        .title("検出: 無効な JSON 文字列")
        .detail("詳細: 🚨 重要な脆弱性を検出しました")
        .tag("脆弱性")
        .tag("unicode-✓")
        .build()
        .unwrap();

    let out = render(&[finding], Format::Markdown, "テストツール").unwrap();

    assert!(out.contains("検出: 無効な JSON 文字列"));
    assert!(out.contains("https://例え.テスト"));
    assert!(out.contains("脆弱性"));
}

#[test]
fn markdown_output_escapes_formatting_syntax() {
    let finding = Finding::new(
        "scan[n]**er**",
        "https://example.com/report",
        Severity::Critical,
        "Title with `backticks` and [link](javascript:alert(1))",
        "Detail with table | row | value",
    )
    .unwrap();
    let out = render(std::slice::from_ref(&finding), Format::Markdown, "tool").unwrap();

    assert!(out.contains(r"\`backticks\`"));
    assert!(out.contains(r"\[link\]"));
    assert!(!out.contains("[link](javascript:alert(1))"));
    assert!(out.contains(r"\<javascript:alert(1)\>"));
    assert!(out.contains(r"Detail with table \| row \| value"));
    assert!(out.contains(r"**Scanner:** scan\[n\]\*\*er\*\*"));
}

#[test]
fn sarif_schema_and_result_shape() {
    let finding = Finding::new(
        "scanner-sarif",
        "https://target",
        Severity::High,
        "Injection Attempt",
        "Payload blocked",
    )
    .unwrap();
    let out = render(&[finding], Format::Sarif, "gossan").unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&out).unwrap();

    assert_eq!(sarif["$schema"], "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "gossan");

    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "scanner-sarif/injection-attempt");
    assert_eq!(
        result["message"]["text"],
        "Injection Attempt\nPayload blocked"
    );
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "https://target"
    );
}

#[test]
fn json_output_valid_and_roundtrips() {
    let f = Finding::new("s", "t", Severity::High, "Test", "Detail").unwrap();
    let out = render(&[f], Format::Json, "tool").unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["title"], "Test");
}

#[test]
fn jsonl_output_one_per_line() {
    let findings = vec![
        Finding::new("s", "t1", Severity::Low, "A", "").unwrap(),
        Finding::new("s", "t2", Severity::High, "B", "").unwrap(),
    ];
    let out = render(&findings, Format::Jsonl, "tool").unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
}

#[test]
fn text_output_strips_ansi() {
    let f = Finding::new(
        "scan\x1b[31mner\x1b[0m",
        "target",
        Severity::High,
        "\x1b[1mTitle\x1b[0m",
        "Detail",
    )
    .unwrap();
    let out = render(&[f], Format::Text, "tool").unwrap();
    assert!(!out.contains("\x1b[31m"));
    assert!(out.contains("scanner"));
    assert!(out.contains("Title"));
}
