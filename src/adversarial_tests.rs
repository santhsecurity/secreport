#![allow(clippy::cloned_ref_to_slice_refs, clippy::nonminimal_bool)]

use crate::{emit, render, render_any, Format};
use secfinding::{Finding, Reportable, Severity};

#[test]
fn adversarial_10k_findings() {
    let mut findings = Vec::new();
    for i in 0..10_000 {
        let finding = Finding::new(
            "stress-scanner",
            format!("https://target-{}.example.com", i),
            match i % 5 {
                0 => Severity::Critical,
                1 => Severity::High,
                2 => Severity::Medium,
                3 => Severity::Low,
                _ => Severity::Info,
            },
            format!("Finding #{}", i),
            format!("Detail for finding number {}", i),
        )
        .unwrap();
        findings.push(finding);
    }

    for format in [
        Format::Text,
        Format::Json,
        Format::Jsonl,
        Format::Sarif,
        Format::Markdown,
    ] {
        let output = render(&findings, format, "stress-test").unwrap();
        assert!(
            !output.is_empty(),
            "Format {:?} should produce output",
            format
        );
        match format {
            Format::Json => {
                let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
                assert_eq!(parsed.as_array().unwrap().len(), 10_000);
            }
            Format::Jsonl => {
                assert_eq!(output.lines().count(), 10_000);
            }
            Format::Sarif => {
                let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
                assert_eq!(
                    parsed["runs"][0]["results"].as_array().unwrap().len(),
                    10_000
                );
            }
            Format::Text => {
                let finding_count = output.matches("Finding #").count();
                assert_eq!(finding_count, 10_000, "Text should render every finding");
            }
            Format::Markdown => {
                let finding_count = output.matches("\n### ").count();
                assert_eq!(
                    finding_count, 10_000,
                    "Markdown should render every finding"
                );
            }
        }
    }
}

#[test]
fn adversarial_100kb_detail_strings() {
    let huge_detail = "A".repeat(100_000);
    let huge_title = "B".repeat(1000);

    let finding = Finding::new(
        "huge-scanner",
        "https://example.com",
        Severity::High,
        huge_title.clone(),
        huge_detail.clone(),
    )
    .unwrap();

    for format in [
        Format::Text,
        Format::Json,
        Format::Jsonl,
        Format::Sarif,
        Format::Markdown,
    ] {
        let output = render(std::slice::from_ref(&finding), format, "huge-test").unwrap();
        assert!(!output.is_empty());
        if format != Format::Jsonl {
            assert!(output.contains("AAAA") || output.len() > 1000);
        }
    }
}

#[test]
fn adversarial_unicode_in_all_fields() {
    let finding = Finding::builder("スキャナー", "https://例え.テスト/路径", Severity::Critical)
        .title("CVE-2024-日本語の脆弱性 🚨")
        .detail("詳細: これはテストです\nالعربية\nРусский\nעברית")
        .tag("日本語タグ")
        .tag("عربي")
        .tag("русский")
        .tag("emoji-🔒-🔑-🛡️")
        .cve("CVE-2024-12345")
        .reference("https://例え.テスト/参考")
        .exploit_hint("curl -X POST https://例え.テスト/テスト")
        .matched_value("マッチ値-🎯")
        .build()
        .unwrap();

    for format in [Format::Text, Format::Json, Format::Sarif, Format::Markdown] {
        let output = render(std::slice::from_ref(&finding), format, "ユニコード ツール").unwrap();
        assert!(
            output.contains("スキャナー") || output.contains("例え") || output.contains("日本語"),
            "Unicode should be preserved in {:?}",
            format
        );
    }
}

#[test]
fn adversarial_sarif_special_chars_rule_ids() {
    struct CustomFinding {
        scanner: String,
        target: String,
        title: String,
        sev: Severity,
    }

    impl Reportable for CustomFinding {
        fn scanner(&self) -> &str {
            &self.scanner
        }
        fn target(&self) -> &str {
            &self.target
        }
        fn severity(&self) -> Severity {
            self.sev
        }
        fn title(&self) -> &str {
            &self.title
        }
        fn cwe_ids(&self) -> &[String] {
            &[]
        }
        fn cve_ids(&self) -> &[String] {
            &[]
        }
        fn tags(&self) -> &[String] {
            &[]
        }
    }

    let findings = vec![
        CustomFinding {
            scanner: "scan<ner>/\\".to_string(),
            target: "target".to_string(),
            title: "SQL Injection <script>alert(1)</script>".to_string(),
            sev: Severity::Critical,
        },
        CustomFinding {
            scanner: "scan\"ner\"".to_string(),
            target: "target".to_string(),
            title: "RCE $(whoami) `rm -rf /`".to_string(),
            sev: Severity::High,
        },
    ];

    let output = render_any(&findings, Format::Sarif, "test-tool").unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&output).expect("SARIF should be valid JSON");
    assert_eq!(parsed["version"], "2.1.0");
    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn adversarial_empty_findings() {
    let findings: Vec<Finding> = vec![];

    for format in [
        Format::Text,
        Format::Json,
        Format::Jsonl,
        Format::Sarif,
        Format::Markdown,
    ] {
        let output = render(&findings, format, "test-tool").unwrap();
        assert!(
            !output.is_empty() || format == Format::Jsonl || format == Format::Text,
            "Empty findings should produce output for {:?}",
            format
        );
    }
}

#[test]
fn adversarial_special_characters_in_fields() {
    let finding = Finding::new(
        "scanner\\with\\backslashes",
        "https://example.com/path?query=<script>alert(1)</script>",
        Severity::High,
        "Title with \"quotes\" and 'apostrophes'",
        "Detail with \nnewlines\n\tand\ttabs and \\ backslash",
    )
    .unwrap();

    for format in [Format::Json, Format::Jsonl, Format::Sarif] {
        let output = render(std::slice::from_ref(&finding), format, "test-tool").unwrap();
        if format != Format::Jsonl {
            let parsed: serde_json::Value =
                serde_json::from_str(&output).expect("Must be valid JSON");
            assert!(!parsed.get("error").is_some());
        }
    }
}

#[test]
fn adversarial_control_characters() {
    let finding = Finding::new(
        "scanner",
        "target",
        Severity::Medium,
        "Title\x00with\x01null\x02bytes",
        "Detail\r\nwith\rcarriage\nreturns",
    )
    .unwrap();

    let output = render(std::slice::from_ref(&finding), Format::Json, "test-tool").unwrap();
    assert!(output.contains("\\u0000"));
}

#[test]
fn adversarial_markdown_escaping() {
    let finding = Finding::builder("scan[n]**er**", "https://example.com", Severity::Critical)
        .title("Title with `backticks` and [link](url)")
        .detail("Table | Col1 | Col2\n--- | --- | ---")
        .tag("tag-with-`code`")
        .build()
        .unwrap();

    let output = render(&[finding], Format::Markdown, "tool*name*").unwrap();
    assert!(output.contains(r"\`backticks\`"));
    assert!(output.contains(r"\[link\]\(url\)"));
    assert!(output.contains(r"\| Col1 \| Col2"));
}

#[test]
fn adversarial_text_ansi_edge_cases() {
    let findings =
        vec![Finding::new("scanner", "target", Severity::Critical, "Critical", "").unwrap()];
    let output = render(&findings, Format::Text, "test").unwrap();
    assert!(output.contains("\x1b["));
    assert!(output.contains("CRIT"));
}

#[test]
fn adversarial_emit_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("output.txt");

    let content = "Test output with unicode: 日本語 🎉\n";
    let mut file = std::fs::File::create(&path).unwrap();
    let result = emit(content, &mut file);

    assert!(result.is_ok());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
}

#[test]
fn html_ansi_injection_test() {
    let finding = Finding::new(
        "scanner\x1b[31minjected\x1b[0m",
        "https://target.com/<h1>injected</h1>",
        Severity::High,
        "Title <script>alert(1)</script>",
        "Detail \x1b[32mcolor\x1b[0m",
    )
    .unwrap();

    let text_output = render(&[finding.clone()], Format::Text, "test").unwrap();
    assert!(!text_output.contains("\x1b[31m")); // ANSI stripped
    assert!(!text_output.contains("\x1b[32m")); // ANSI stripped

    let md_output = render(&[finding], Format::Markdown, "test").unwrap();
    println!("MD OUTPUT: {}", md_output);
    assert!(md_output.contains("\\<h1\\>")); // Escaped HTML
    println!("MD OUTPUT: {}", md_output);
    assert!(md_output.contains("\\<script\\>alert\\(1\\)\\</script\\>")); // Escaped HTML
}
