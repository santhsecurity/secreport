use serde::{Deserialize, Serialize};

/// Output format selection.
///
/// This enum defines the available output formats for rendering security findings.
/// Use [`Format::from_str_loose`] to parse format strings case-insensitively.
///
/// # Example
///
/// ```
/// use secreport::format::Format;
///
/// // Parse from string
/// let format = Format::from_str_loose("json").unwrap();
/// assert_eq!(format, Format::Json);
///
/// // Display as string
/// assert_eq!(format.to_string(), "json");
/// ```
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
    ///
    /// Recognizes the following formats:
    /// - `"json"` → [`Format::Json`]
    /// - `"jsonl"` → [`Format::Jsonl`]
    /// - `"sarif"` → [`Format::Sarif`]
    /// - `"markdown"` or `"md"` → [`Format::Markdown`]
    /// - `"text"` → [`Format::Text`]
    ///
    /// # Parameters
    ///
    /// - `s`: The format string to parse (case-insensitive)
    ///
    /// # Returns
    ///
    /// - `Some(Format)` if the string matches a known format
    /// - `None` if the string is unrecognized
    ///
    /// # Example
    ///
    /// ```
    /// use secreport::format::Format;
    ///
    // Case-insensitive parsing
    /// assert_eq!(Format::from_str_loose("JSON"), Some(Format::Json));
    /// assert_eq!(Format::from_str_loose("Jsonl"), Some(Format::Jsonl));
    /// assert_eq!(Format::from_str_loose("SARIF"), Some(Format::Sarif));
    /// assert_eq!(Format::from_str_loose("md"), Some(Format::Markdown));
    /// assert_eq!(Format::from_str_loose("unknown"), None);
    /// ```
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
