use secfinding::Severity;

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
            out.push('\\');
            out.push(ch);
            continue;
        }
        if ch == '>' {
            in_angle = false;
            out.push('\\');
            out.push(ch);
            continue;
        }

        match ch {
            '(' | ')' if in_angle => {}
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '|'
            | '!' | '>' | '<' => {
                out.push('\\');
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
        "# {escaped_tool} Security Report \u{2014} {target}\n\n*Generated {now} \u{00b7} {} findings*\n\n",
        findings.len()
    ));

    md.push_str("## Risk Summary\n\n| Severity | Count |\n|---|---|\n");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = findings.iter().filter(|f| f.severity == severity).count();
        if count > 0 {
            md.push_str(&format!("| {} | {count} |\n", severity.label()));
        }
    }
    md.push('\n');

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
        md.push_str(&format!("## {heading}\n\n"));
        for f in group {
            md.push_str(&format!(
                "### {}\n\n**Target:** `{}`  \n**Scanner:** {}  \n",
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
                md.push_str(&format!("**Tags:** {tags}  \n"));
            }
            if !f.cwe_ids.is_empty() {
                md.push_str(&format!("**CWE:** {}  \n", f.cwe_ids.join(", ")));
            }
            if !f.cve_ids.is_empty() {
                md.push_str(&format!("**CVE:** {}  \n", f.cve_ids.join(", ")));
            }
            md.push('\n');
            if !f.detail.is_empty() {
                md.push_str(&format!("{}\n\n", escape_markdown_text(f.detail)));
            }
            if let Some(hint) = &f.exploit_hint {
                md.push_str(&format!("**Exploit / PoC:**\n```bash\n{hint}\n```\n\n"));
            }
            md.push_str("---\n\n");
        }
    }
    md.push_str(&format!(
        "*Report generated by [{escaped_tool}](https://github.com/santh-io/{tool_name})*\n"
    ));
    md
}
