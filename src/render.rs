use crate::format::Format;
use crate::models::GenericFinding;
use secfinding::{Finding, Reportable};
use std::io::Write;

pub mod json;
pub mod markdown;
pub mod summary;

/// Render ANY type that implements [`Reportable`] into the given format.
///
/// This is the most flexible rendering function - it works with any type that
/// implements the `Reportable` trait from the `secfinding` crate. For rendering
/// native [`Finding`] types, see [`render`].
///
/// # Parameters
///
/// - `findings`: A slice of findings that implement `Reportable`
/// - `format`: The output format to use
/// - `tool_name`: Name of the tool generating the report (used in SARIF/Markdown headers)
///
/// # Returns
///
/// - `Ok(String)` containing the rendered output
/// - `Err(serde_json::Error)` if conversion or serialization fails
///
/// # Example
///
/// ```
/// use secfinding::{Finding, Severity};
/// use secreport::format::Format;
/// use secreport::render::render_any;
///
/// let finding = Finding::builder("my-scanner", "example.com", Severity::High)
///     .title("Test Finding")
///     .rule_id("TEST-001")
///     .build();
///
/// let output = render_any(&[finding], Format::Json, "my-scanner").unwrap();
/// assert!(output.contains("Test Finding"));
/// ```
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

/// Render native [`Finding`] types in the given format.
///
/// This is a convenience wrapper around [`render_any`] specifically for
/// the native `Finding` type from the `secfinding` crate.
///
/// # Parameters
///
/// - `findings`: A slice of [`Finding`] objects
/// - `format`: The output format to use
/// - `tool_name`: Name of the tool generating the report
///
/// # Returns
///
/// - `Ok(String)` containing the rendered output
/// - `Err(serde_json::Error)` if serialization fails
///
/// # Example
///
/// ```
/// use secfinding::{Finding, Severity};
/// use secreport::format::Format;
/// use secreport::render::render;
///
/// let findings = vec![
///     Finding::builder("scanner", "target.com", Severity::Critical)
///         .title("Critical Vulnerability")
///         .rule_id("CRIT-001")
///         .build(),
/// ];
///
/// let markdown = render(&findings, Format::Markdown, "security-scanner").unwrap();
/// assert!(markdown.contains("Critical Vulnerability"));
/// ```
pub fn render(
    findings: &[Finding],
    format: Format,
    tool_name: &str,
) -> Result<String, serde_json::Error> {
    render_any(findings, format, tool_name)
}

/// Write rendered output to a writer.
///
/// This function writes the rendered content to any type implementing
/// `std::io::Write`, such as files or stdout.
///
/// # Parameters
///
/// - `content`: The rendered content to write
/// - `writer`: Any type implementing `Write`
///
/// # Returns
///
/// - `Ok(())` on success
/// - `Err(std::io::Error)` if writing fails
///
/// # Example
///
/// ```
/// use secreport::render::emit;
///
/// let content = "Security Report\n===============";
/// let mut output = Vec::new();
///
/// emit(content, &mut output).unwrap();
/// assert_eq!(String::from_utf8(output).unwrap(), content);
/// ```
///
/// Writing to stdout:
///
/// ```
/// use secreport::render::emit;
/// use std::io;
///
/// # fn example() -> io::Result<()> {
/// emit("Report complete!\n", io::stdout())?;
/// # Ok(())
/// # }
/// ```
pub fn emit(content: &str, mut writer: impl Write) -> std::io::Result<()> {
    write!(writer, "{}", content)
}
