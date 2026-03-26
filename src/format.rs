use serde::{Deserialize, Serialize};

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
