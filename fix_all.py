import os

src_dir = "/home/mukund-thiru/Santh/libs/secreport/src"
os.makedirs(src_dir, exist_ok=True)

lib_rs = """//! Output formatters for security findings.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod format;
pub mod models;
pub mod render;

pub use format::Format;
pub use render::{emit, render, render_any};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod adversarial_tests;
"""

format_rs = """use serde::{Deserialize, Serialize};

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Format {
    /// ANSI-colored terminal output.
    Text,
    /// Pretty-printed JSON array.
    Json,
    /// One JSON object per line (newline-delimited).
    Jsonl,
    /// OASIS SARIF 2.1.0 for GitHub Security / IDE integration.
    Sarif,
    /// Markdown report with severity grouping.
    Markdown,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Sarif => "sarif",
            Self::Markdown => "markdown",
        };
        f.write_str(value)
    }
}

impl Format {
    /// Parse from a case-insensitive string.
    #[must_use]
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "jsonl" => Some(Self::Jsonl),
            "sarif" => Some(Self::Sarif),
            "markdown" | "md" => Some(Self::Markdown),
            "text" => Some(Self::Text),
            _ => None,
        }
    }
}
"""

models_rs = """use secfinding::{Evidence, Reportable, Severity};

#[derive(Debug, Clone)]
pub struct GenericFinding<'a> {
    pub scanner: &'a str,
    pub target: &'a str,
    pub severity: Severity,
    pub title: &'a str,
    pub detail: &'a str,
    pub cwe_ids: &'a [String],
    pub cve_ids: &'a [String],
    pub tags: &'a [String],
    pub confidence: Option<f64>,
    pub rule_id: String,
    pub sarif_level: &'a str,
    pub exploit_hint: Option<&'a str>,
    pub evidence: &'a [Evidence],
}

impl<'a> GenericFinding<'a> {
    pub fn from_reportable<R: Reportable>(finding: &'a R) -> Self {
        Self {
            scanner: finding.scanner(),
            target: finding.target(),
            severity: finding.severity(),
            title: finding.title(),
            detail: finding.detail(),
            cwe_ids: finding.cwe_ids(),
            cve_ids: finding.cve_ids(),
            tags: finding.tags(),
            confidence: finding.confidence(),
            rule_id: finding.rule_id(),
            sarif_level: finding.sarif_level(),
            exploit_hint: finding.exploit_hint(),
            evidence: finding.evidence(),
        }
    }

    pub fn json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "scanner": self.scanner,
            "target": self.target,
            "severity": self.severity.to_string(),
            "title": self.title,
            "detail": self.detail,
            "cwe_ids": self.cwe_ids,
            "cve_ids": self.cve_ids,
            "tags": self.tags,
            "confidence": self.confidence,
            "rule_id": self.rule_id,
            "exploit_hint": self.exploit_hint,
            "evidence": self.evidence,
        })
    }
}
"""

render_rs = """use crate::format::Format;
use crate::models::GenericFinding;
use secfinding::{Finding, Reportable};
use std::io::Write;

pub mod json;
pub mod markdown;
pub mod summary;

/// Render ANY type that implements [`Reportable`] into the given format.
pub fn render_any<R: Reportable>(
    findings: &[R],
    format: Format,
    tool_name: &str,
) -> Result<String, serde_json::Error> {
    let generic: Vec<GenericFinding> = findings
        .iter()
        .map(GenericFinding::from_reportable)
        .collect();

    match format {
        Format::Text => Ok(summary::render_text_generic(&generic)),
        Format::Json => json::render_json_generic(&generic),
        Format::Jsonl => json::render_jsonl_generic(&generic),
        Format::Sarif => json::render_sarif_generic(&generic, tool_name),
        Format::Markdown => Ok(markdown::render_markdown_generic(&generic, tool_name)),
    }
}

/// Render findings in the given format.
pub fn render(
    findings: &[Finding],
    format: Format,
    tool_name: &str,
) -> Result<String, serde_json::Error> {
    render_any(findings, format, tool_name)
}

/// Write rendered output to a writer.
pub fn emit(content: &str, mut writer: impl Write) -> std::io::Result<()> {
    write!(writer, "{}", content)
}
"""

json_rs = """use crate::models::GenericFinding;

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
    Ok(out.join("\\n"))
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
                "message": { "text": format!("{}\\n{}", f.title, f.detail) },
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
"""

summary_rs = """use secfinding::{Evidence, Severity};
use std::collections::BTreeMap;

use crate::models::GenericFinding;
use crate::render::markdown::escape_markdown_text;

pub(crate) fn strip_ansi(s: &str) -> String {
    if !s.contains('\\x1b') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut in_ansi = false;
    for c in s.chars() {
        if c == '\\x1b' {
            in_ansi = true;
        } else if in_ansi {
            if c.is_ascii_alphabetic() {
                in_ansi = false;
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn colored_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "\\x1b[31;1mCRIT\\x1b[0m",
        Severity::High => "\\x1b[91m HIGH\\x1b[0m",
        Severity::Medium => "\\x1b[33m  MED\\x1b[0m",
        Severity::Low => "\\x1b[36m  LOW\\x1b[0m",
        Severity::Info => "\\x1b[90m INFO\\x1b[0m",
    }
}

pub(crate) fn render_text_generic(findings: &[GenericFinding<'_>]) -> String {
    if findings.is_empty() {
        return "\\x1b[90mNo findings.\\x1b[0m\\n".to_string();
    }

    let estimated_size = findings.len() * 200;
    let mut out = String::with_capacity(estimated_size);
    out.push('\\n');

    for f in findings {
        render_text_finding(&mut out, f);
    }
    out.push_str(&render_summary_generic(findings));
    out
}

fn render_text_finding(out: &mut String, f: &GenericFinding<'_>) {
    let sev = colored_label(f.severity);
    out.push_str(&format!(
        "  {}  \\x1b[1m{}\\x1b[0m  \\x1b[90m[{}]\\x1b[0m  {}\\n",
        sev, strip_ansi(f.title), strip_ansi(f.scanner), strip_ansi(f.target),
    ));
    let detail_stripped = strip_ansi(f.detail);
    if !detail_stripped.is_empty() {
        out.push_str(&format!("          \\x1b[90m{}\\x1b[0m\\n", detail_stripped));
    }
    for ev in f.evidence {
        match ev {
            Evidence::Banner { raw } => {
                let s: String = strip_ansi(raw).chars().take(80).collect();
                out.push_str(&format!("          \\x1b[36mBanner:\\x1b[0m {s}\\n"));
            }
            Evidence::JsSnippet { url, line, snippet } => {
                let fname = url.split('/').next_back().unwrap_or(url);
                out.push_str(&format!(
                    "          \\x1b[36m{fname}:{line}\\x1b[0m  {}\\n", strip_ansi(snippet)
                ));
            }
            Evidence::DnsRecord { record_type, value } => {
                let v: String = value.chars().take(100).collect();
                out.push_str(&format!("          \\x1b[36m{record_type}\\x1b[0m  {}\\n", strip_ansi(&v)));
            }
            Evidence::HttpResponse { status, .. } => {
                out.push_str(&format!("          \\x1b[36mHTTP {status}\\x1b[0m\\n"));
            }
            Evidence::CodeSnippet {
                file,
                line,
                snippet,
                ..
            } => {
                out.push_str(&format!(
                    "          \\x1b[36m{file}:{line}\\x1b[0m  {}\\n", strip_ansi(snippet)
                ));
            }
            _ => {}
        }
    }
    if let Some(hint) = &f.exploit_hint {
        let preview = hint.lines().next().unwrap_or(hint);
        out.push_str(&format!("          \\x1b[33m\\u{25b6} {}\\x1b[0m\\n", strip_ansi(preview)));
    }
    if !f.tags.is_empty() {
        let tag_str = f
            .tags
            .iter()
            .map(|tag| format!("#{}", escape_markdown_text(tag)))
            .collect::<Vec<_>>()
            .join(" ");
        out.push_str(&format!("          \\x1b[90m{}\\x1b[0m\\n", strip_ansi(&tag_str)));
    }
    out.push('\\n');
}

pub(crate) fn render_summary_generic(findings: &[GenericFinding<'_>]) -> String {
    let mut out = String::new();
    let crit = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let med = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
    let info = findings.iter().filter(|f| f.severity == Severity::Info).count();

    out.push_str("  \\x1b[1m\\u{2501}\\u{2501}\\u{2501} Summary \\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\u{2501}\\x1b[0m\\n");
    let crit_color = if crit > 0 { "\\x1b[31;1m" } else { "\\x1b[90m" };
    out.push_str(&format!(
        "  {crit_color}{crit:>3} critical\\x1b[0m   \\x1b[91m{high:>3} high\\x1b[0m   \\x1b[33m{med:>3} medium\\x1b[0m   \\x1b[36m{low:>3} low\\x1b[0m   \\x1b[90m{info:>3} info\\x1b[0m\\n"
    ));
    let n = findings.len();
    let s = if n == 1 { "" } else { "s" };
    out.push_str(&format!("  Total: \\x1b[1m{n}\\x1b[0m finding{s}\\n\\n"));
    let mut scanner_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in findings {
        *scanner_counts.entry(finding.scanner).or_insert(0) += 1;
    }
    let by_scanner = scanner_counts
        .iter()
        .map(|(scanner, count)| format!("\\x1b[1m{}\\x1b[0m:{count}", strip_ansi(scanner)))
        .collect::<Vec<_>>()
        .join("  \\u{00b7}  ");
    out.push_str(&format!("  \\x1b[90mBy scanner:\\x1b[0m {by_scanner}\\n\\n"));
    out
}
"""

markdown_rs = """use secfinding::Severity;

use crate::models::GenericFinding;

pub(crate) fn escape_markdown_text(input: &str) -> String {
    let sanitized = neutralize_markdown_links(input);
    escape_markdown_literals(&sanitized)
}

fn escape_markdown_literals(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_angle = false;
    for ch in input.chars() {
        if ch == '<' {
            in_angle = true;
            out.push('\\\\');
            out.push(ch);
            continue;
        }
        if ch == '>' {
            in_angle = false;
            out.push('\\\\');
            out.push(ch);
            continue;
        }

        match ch {
            '(' | ')' if in_angle => {}
            '\\\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '|'
            | '!' | '>' | '<' => {
                out.push('\\\\');
            }
            _ => {}
        }
        out.push(ch);
    }
    out
}

fn neutralize_markdown_links(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(label_start) = rest.find('[') {
        out.push_str(&rest[..label_start]);
        let after_label_start = &rest[label_start + 1..];
        let Some(label_end_rel) = after_label_start.find(']') else {
            out.push_str(&rest[label_start..]);
            return out;
        };
        let label_end = label_start + 1 + label_end_rel;
        let after_label = &rest[label_end + 1..];
        if !after_label.starts_with('(') {
            out.push_str(&rest[label_start..=label_end]);
            rest = &rest[label_end + 1..];
            continue;
        }
        let Some(url_end_rel) = find_matching_paren(after_label) else {
            out.push_str(&rest[label_start..]);
            return out;
        };
        let url_end = label_end + 1 + url_end_rel;
        let label = &rest[label_start + 1..label_end];
        let url = &rest[label_end + 2..url_end];
        if url.contains(':') {
            out.push_str(&format!("[{label}] <{url}>"));
        } else {
            out.push_str(&rest[label_start..=url_end]);
        }
        rest = &rest[url_end + 1..];
    }

    out.push_str(rest);
    out
}

fn find_matching_paren(input: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in input.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn render_markdown_generic(findings: &[GenericFinding<'_>], tool_name: &str) -> String {
    let now = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let escaped_tool = escape_markdown_text(tool_name);
    let target = findings
        .first()
        .map(|f| escape_markdown_text(f.target))
        .unwrap_or_else(|| "unknown".into());
    let mut md = String::with_capacity(findings.len() * 300);
    md.push_str(&format!(
        "# {escaped_tool} Security Report \\u{2014} {target}\\n\\n*Generated {now} \\u{00b7} {} findings*\\n\\n",
        findings.len()
    ));

    md.push_str("## Risk Summary\\n\\n| Severity | Count |\\n|---|---|\\n");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = findings.iter().filter(|f| f.severity == severity).count();
        if count > 0 {
            md.push_str(&format!("| {} | {count} |\\n", severity.label()));
        }
    }
    md.push('\\n');

    for (sev, heading) in [
        (Severity::Critical, "Critical Findings"),
        (Severity::High, "High Findings"),
        (Severity::Medium, "Medium Findings"),
        (Severity::Low, "Low Findings"),
        (Severity::Info, "Informational"),
    ] {
        let group: Vec<_> = findings.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        md.push_str(&format!("## {heading}\\n\\n"));
        for f in group {
            md.push_str(&format!(
                "### {}\\n\\n**Target:** `{}`  \\n**Scanner:** {}  \\n",
                escape_markdown_text(f.title),
                escape_markdown_text(f.target),
                escape_markdown_text(f.scanner),
            ));
            if !f.tags.is_empty() {
                let tags = f
                    .tags
                    .iter()
                    .map(|tag| format!("`{}`", escape_markdown_text(tag)))
                    .collect::<Vec<_>>()
                    .join(" ");
                md.push_str(&format!("**Tags:** {tags}  \\n"));
            }
            if !f.cwe_ids.is_empty() {
                md.push_str(&format!("**CWE:** {}  \\n", f.cwe_ids.join(", ")));
            }
            if !f.cve_ids.is_empty() {
                md.push_str(&format!("**CVE:** {}  \\n", f.cve_ids.join(", ")));
            }
            md.push('\\n');
            if !f.detail.is_empty() {
                md.push_str(&format!("{}\\n\\n", escape_markdown_text(f.detail)));
            }
            if let Some(hint) = &f.exploit_hint {
                md.push_str(&format!("**Exploit / PoC:**\\n```bash\\n{hint}\\n```\\n\\n"));
            }
            md.push_str("---\\n\\n");
        }
    }
    md.push_str(&format!(
        "*Report generated by [{escaped_tool}](https://github.com/santh-io/{tool_name})*\\n"
    ));
    md
}
"""

tests_rs = """use crate::{render, Format};
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

    assert!(out.contains(r"\\`backticks\\`"));
    assert!(out.contains(r"\\[link\\]"));
    assert!(!out.contains("[link](javascript:alert(1))"));
    assert!(out.contains(r"\\<javascript:alert(1)\\>"));
    assert!(out.contains(r"Detail with table \\| row \\| value"));
    assert!(out.contains(r"**Scanner:** scan\\[n\\]\\*\\*er\\*\\*"));
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
    assert_eq!(result["message"]["text"], "Injection Attempt\\nPayload blocked");
    assert_eq!(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "https://target");
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
        "scan\\x1b[31mner\\x1b[0m",
        "target",
        Severity::High,
        "\\x1b[1mTitle\\x1b[0m",
        "Detail",
    )
    .unwrap();
    let out = render(&[f], Format::Text, "tool").unwrap();
    assert!(!out.contains("\\x1b[31m"));
    assert!(out.contains("scanner"));
    assert!(out.contains("Title"));
}
"""

adversarial_tests_rs = """use crate::{emit, render, render_any, Format};
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
        ).unwrap();
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
        assert!(!output.is_empty(), "Format {:?} should produce output", format);
        assert!(output.len() > 10_000, "Should have enough output");
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
    ).unwrap();

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
        .detail("詳細: これはテストです\\nالعربية\\nРусский\\nעברית")
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
        fn scanner(&self) -> &str { &self.scanner }
        fn target(&self) -> &str { &self.target }
        fn severity(&self) -> Severity { self.sev }
        fn title(&self) -> &str { &self.title }
        fn cwe_ids(&self) -> &[String] { &[] }
        fn cve_ids(&self) -> &[String] { &[] }
        fn tags(&self) -> &[String] { &[] }
    }

    let findings = vec![
        CustomFinding {
            scanner: "scan<ner>/\\\\".to_string(),
            target: "target".to_string(),
            title: "SQL Injection <script>alert(1)</script>".to_string(),
            sev: Severity::Critical,
        },
        CustomFinding {
            scanner: "scan\\\"ner\\\"".to_string(),
            target: "target".to_string(),
            title: "RCE $(whoami) `rm -rf /`".to_string(),
            sev: Severity::High,
        },
    ];

    let output = render_any(&findings, Format::Sarif, "test-tool").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).expect("SARIF should be valid JSON");
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
        "scanner\\\\with\\\\backslashes",
        "https://example.com/path?query=<script>alert(1)</script>",
        Severity::High,
        "Title with \\\"quotes\\\" and 'apostrophes'",
        "Detail with \\nnewlines\\n\\tand\\ttabs and \\\\ backslash",
    ).unwrap();

    for format in [Format::Json, Format::Jsonl, Format::Sarif] {
        let output = render(std::slice::from_ref(&finding), format, "test-tool").unwrap();
        if format != Format::Jsonl {
            let parsed: serde_json::Value = serde_json::from_str(&output).expect("Must be valid JSON");
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
        "Title\\x00with\\x01null\\x02bytes",
        "Detail\\r\\nwith\\rcarriage\\nreturns",
    ).unwrap();

    let output = render(std::slice::from_ref(&finding), Format::Json, "test-tool").unwrap();
    assert!(output.contains("\\\\u0000"));
}

#[test]
fn adversarial_markdown_escaping() {
    let finding = Finding::builder("scan[n]**er**", "https://example.com", Severity::Critical)
        .title("Title with `backticks` and [link](url)")
        .detail("Table | Col1 | Col2\\n--- | --- | ---")
        .tag("tag-with-`code`")
        .build()
        .unwrap();

    let output = render(&[finding], Format::Markdown, "tool*name*").unwrap();
    assert!(output.contains(r"\\`backticks\\`"));
    assert!(output.contains(r"\\[link\\]\\(url\\)"));
    assert!(output.contains(r"\\| Col1 \\| Col2"));
}

#[test]
fn adversarial_text_ansi_edge_cases() {
    let findings = vec![
        Finding::new("scanner", "target", Severity::Critical, "Critical", "").unwrap(),
    ];
    let output = render(&findings, Format::Text, "test").unwrap();
    assert!(output.contains("\\x1b["));
    assert!(output.contains("CRIT") || output.contains("critical"));
}

#[test]
fn adversarial_emit_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("output.txt");

    let content = "Test output with unicode: 日本語 🎉\\n";
    let mut file = std::fs::File::create(&path).unwrap();
    let result = emit(content, &mut file);

    assert!(result.is_ok());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
}

#[test]
fn html_ansi_injection_test() {
    let finding = Finding::new(
        "scanner\\x1b[31minjected\\x1b[0m",
        "https://target.com/<h1>injected</h1>",
        Severity::High,
        "Title <script>alert(1)</script>",
        "Detail \\x1b[32mcolor\\x1b[0m",
    ).unwrap();

    let text_output = render(&[finding.clone()], Format::Text, "test").unwrap();
    assert!(!text_output.contains("\\x1b[31m")); // ANSI stripped
    assert!(!text_output.contains("\\x1b[32m")); // ANSI stripped

    let md_output = render(&[finding], Format::Markdown, "test").unwrap();
    assert!(md_output.contains("\\\\<h1\\\\>")); // Escaped HTML
    assert!(md_output.contains("\\\\<script\\\\>alert(1)\\\\<\\\\/script\\\\>")); // Escaped HTML
}
"""

files = {
    "lib.rs": lib_rs,
    "format.rs": format_rs,
    "models.rs": models_rs,
    "render.rs": render_rs,
    "render/json.rs": json_rs,
    "render/markdown.rs": markdown_rs,
    "render/summary.rs": summary_rs,
    "tests.rs": tests_rs,
    "adversarial_tests.rs": adversarial_tests_rs,
}

os.makedirs(os.path.join(src_dir, "render"), exist_ok=True)
for filename, content in files.items():
    with open(os.path.join(src_dir, filename), "w") as f:
        f.write(content)

# Clean up old files
old_files = ["json.rs", "markdown.rs", "summary.rs", "types.rs"]
for f in old_files:
    try:
        os.remove(os.path.join(src_dir, f))
    except Exception:
        pass

