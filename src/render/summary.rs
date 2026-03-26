use secfinding::{Evidence, Severity};
use std::collections::BTreeMap;

use crate::models::GenericFinding;
use crate::render::markdown::escape_markdown_text;

pub(crate) fn strip_ansi(s: &str) -> String {
    if !s.contains('\x1b') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut in_ansi = false;
    for c in s.chars() {
        if c == '\x1b' {
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
        Severity::Critical => "\x1b[31;1mCRIT\x1b[0m",
        Severity::High => "\x1b[91m HIGH\x1b[0m",
        Severity::Medium => "\x1b[33m  MED\x1b[0m",
        Severity::Low => "\x1b[36m  LOW\x1b[0m",
        Severity::Info => "\x1b[90m INFO\x1b[0m",
    }
}

pub(crate) fn render_text_generic(findings: &[GenericFinding<'_>]) -> String {
    if findings.is_empty() {
        return "\x1b[90mNo findings.\x1b[0m\n".to_string();
    }

    let estimated_size = findings.len() * 200;
    let mut out = String::with_capacity(estimated_size);
    out.push('\n');

    for f in findings {
        render_text_finding(&mut out, f);
    }
    out.push_str(&render_summary_generic(findings));
    out
}

fn render_text_finding(out: &mut String, f: &GenericFinding<'_>) {
    let sev = colored_label(f.severity);
    out.push_str(&format!(
        "  {}  \x1b[1m{}\x1b[0m  \x1b[90m[{}]\x1b[0m  {}\n",
        sev,
        strip_ansi(f.title),
        strip_ansi(f.scanner),
        strip_ansi(f.target),
    ));
    let detail_stripped = strip_ansi(f.detail);
    if !detail_stripped.is_empty() {
        out.push_str(&format!("          \x1b[90m{}\x1b[0m\n", detail_stripped));
    }
    for ev in f.evidence {
        match ev {
            Evidence::Banner { raw } => {
                let s: String = strip_ansi(raw).chars().take(80).collect();
                out.push_str(&format!("          \x1b[36mBanner:\x1b[0m {s}\n"));
            }
            Evidence::JsSnippet { url, line, snippet } => {
                let fname = url.split('/').next_back().unwrap_or(url);
                out.push_str(&format!(
                    "          \x1b[36m{fname}:{line}\x1b[0m  {}\n",
                    strip_ansi(snippet)
                ));
            }
            Evidence::DnsRecord { record_type, value } => {
                let v: String = value.chars().take(100).collect();
                out.push_str(&format!(
                    "          \x1b[36m{record_type}\x1b[0m  {}\n",
                    strip_ansi(&v)
                ));
            }
            Evidence::HttpResponse { status, .. } => {
                out.push_str(&format!("          \x1b[36mHTTP {status}\x1b[0m\n"));
            }
            Evidence::CodeSnippet {
                file,
                line,
                snippet,
                ..
            } => {
                out.push_str(&format!(
                    "          \x1b[36m{file}:{line}\x1b[0m  {}\n",
                    strip_ansi(snippet)
                ));
            }
            _ => {}
        }
    }
    if let Some(hint) = &f.exploit_hint {
        let preview = hint.lines().next().unwrap_or(hint);
        out.push_str(&format!(
            "          \x1b[33m\u{25b6} {}\x1b[0m\n",
            strip_ansi(preview)
        ));
    }
    if !f.tags.is_empty() {
        let tag_str = f
            .tags
            .iter()
            .map(|tag| format!("#{}", escape_markdown_text(tag)))
            .collect::<Vec<_>>()
            .join(" ");
        out.push_str(&format!(
            "          \x1b[90m{}\x1b[0m\n",
            strip_ansi(&tag_str)
        ));
    }
    out.push('\n');
}

pub(crate) fn render_summary_generic(findings: &[GenericFinding<'_>]) -> String {
    let mut out = String::new();
    let crit = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let med = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    out.push_str("  \x1b[1m\u{2501}\u{2501}\u{2501} Summary \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\x1b[0m\n");
    let crit_color = if crit > 0 { "\x1b[31;1m" } else { "\x1b[90m" };
    out.push_str(&format!(
        "  {crit_color}{crit:>3} critical\x1b[0m   \x1b[91m{high:>3} high\x1b[0m   \x1b[33m{med:>3} medium\x1b[0m   \x1b[36m{low:>3} low\x1b[0m   \x1b[90m{info:>3} info\x1b[0m\n"
    ));
    let n = findings.len();
    let s = if n == 1 { "" } else { "s" };
    out.push_str(&format!("  Total: \x1b[1m{n}\x1b[0m finding{s}\n\n"));
    let mut scanner_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in findings {
        *scanner_counts.entry(finding.scanner).or_insert(0) += 1;
    }
    let by_scanner = scanner_counts
        .iter()
        .map(|(scanner, count)| format!("\x1b[1m{}\x1b[0m:{count}", strip_ansi(scanner)))
        .collect::<Vec<_>>()
        .join("  \u{00b7}  ");
    out.push_str(&format!("  \x1b[90mBy scanner:\x1b[0m {by_scanner}\n\n"));
    out
}
