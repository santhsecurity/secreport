use crate::format::Format;
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
        .map(GenericFinding::try_from_reportable)
        .collect::<Result<_, _>>()?;

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
