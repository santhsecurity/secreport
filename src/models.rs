use secfinding::{Evidence, Reportable, Severity};

/// A generic security finding that can be rendered in multiple output formats.
///
/// This struct provides a unified representation of security findings from
/// various scanners, enabling consistent rendering to JSON, JSONL, SARIF,
/// Markdown, and text formats.
///
/// # Example
///
/// ```
/// use secfinding::Severity;
/// use secreport::models::GenericFinding;
///
/// let finding = GenericFinding::builder("test-scanner", "https://example.com", Severity::High)
///     .title("SQL Injection")
///     .detail("User input is not properly sanitized")
///     .rule_id("SQLI-001")
///     .build();
///
/// assert_eq!(finding.scanner, "test-scanner");
/// assert_eq!(finding.target, "https://example.com");
/// assert_eq!(finding.severity, Severity::High);
/// ```
#[derive(Debug, Clone)]
pub struct GenericFinding<'a> {
    /// Name of the scanner that detected this finding.
    pub scanner: &'a str,
    /// Target URL, domain, or resource that was scanned.
    pub target: &'a str,
    /// Severity level of the finding.
    pub severity: Severity,
    /// Brief title or name of the finding.
    pub title: &'a str,
    /// Detailed description of the vulnerability or issue.
    pub detail: &'a str,
    /// List of CWE (Common Weakness Enumeration) IDs associated with this finding.
    pub cwe_ids: &'a [String],
    /// List of CVE (Common Vulnerabilities and Exposures) IDs associated with this finding.
    pub cve_ids: &'a [String],
    /// List of tags for categorization.
    pub tags: &'a [String],
    /// Confidence score between 0.0 and 1.0 (optional).
    pub confidence: Option<f64>,
    /// Unique identifier for the rule that triggered this finding.
    pub rule_id: String,
    /// SARIF level string (e.g., "error", "warning", "note").
    pub sarif_level: &'a str,
    /// Optional exploit hint or proof-of-concept.
    pub exploit_hint: Option<&'a str>,
    /// Evidence collected for this finding (e.g., banners, code snippets).
    pub evidence: &'a [Evidence],
}

impl<'a> GenericFinding<'a> {
    /// Creates a builder for constructing a `GenericFinding`.
    ///
    /// # Parameters
    ///
    /// - `scanner`: Name of the scanner that detected the finding
    /// - `target`: Target URL, domain, or resource
    /// - `severity`: Severity level of the finding
    ///
    /// # Returns
    ///
    /// A `GenericFindingBuilder` that can be used to set additional fields.
    ///
    /// # Example
    ///
    /// ```
    /// use secfinding::Severity;
    /// use secreport::models::GenericFinding;
    ///
    /// let finding = GenericFinding::builder("nuclei", "example.com", Severity::Critical)
    ///     .title("Remote Code Execution")
    ///     .detail("Unauthenticated RCE in application")
    ///     .rule_id("RCE-001")
    ///     .build();
    /// ```
    #[must_use]
    pub fn builder(
        scanner: &'a str,
        target: &'a str,
        severity: Severity,
    ) -> GenericFindingBuilder<'a> {
        GenericFindingBuilder {
            scanner,
            target,
            severity,
            title: "",
            detail: "",
            cwe_ids: &[],
            cve_ids: &[],
            tags: &[],
            confidence: None,
            rule_id: String::new(),
            sarif_level: severity.sarif_level(),
            exploit_hint: None,
            evidence: &[],
        }
    }

    /// Attempts to convert a type implementing `Reportable` into a `GenericFinding`.
    ///
    /// This method validates the finding data and returns an error if validation fails
    /// (e.g., invalid severity or non-finite confidence value).
    ///
    /// # Parameters
    ///
    /// - `finding`: A reference to any type implementing the `Reportable` trait
    ///
    /// # Returns
    ///
    /// - `Ok(GenericFinding)` if conversion and validation succeed
    /// - `Err(serde_json::Error)` if validation fails
    ///
    /// # Example
    ///
    /// ```
    /// use secfinding::{Finding, Evidence, Severity};
    /// use secreport::models::GenericFinding;
    ///
    /// let finding = Finding::builder("scanner", "target", Severity::High)
    ///     .title("Test Finding")
    ///     .rule_id("TEST-001")
    ///     .build();
    ///
    /// let generic = GenericFinding::try_from_reportable(&finding);
    /// assert!(generic.is_ok());
    /// ```
    pub fn try_from_reportable<R: Reportable>(finding: &'a R) -> Result<Self, serde_json::Error> {
        let generic = Self {
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
        };
        generic.validate()?;
        Ok(generic)
    }

    /// Converts this finding to a JSON value.
    ///
    /// # Returns
    ///
    /// A `serde_json::Value` containing all the finding's fields.
    ///
    /// # Example
    ///
    /// ```
    /// use secfinding::Severity;
    /// use secreport::models::GenericFinding;
    ///
    /// let finding = GenericFinding::builder("scanner", "target", Severity::Medium)
    ///     .title("Test")
    ///     .rule_id("TEST-001")
    ///     .build();
    ///
    /// let json = finding.json_value();
    /// assert_eq!(json["scanner"], "scanner");
    /// assert_eq!(json["severity"], "Medium");
    /// ```
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

    fn validate(&self) -> Result<(), serde_json::Error> {
        if secfinding::Severity::from_str_loose(&self.severity.to_string()).is_none() {
            return Err(validation_error("invalid finding severity"));
        }
        if self.confidence.is_some_and(|value| !value.is_finite()) {
            return Err(validation_error("confidence must be finite"));
        }
        Ok(())
    }
}

/// Builder for constructing [`GenericFinding`] instances.
///
/// Use [`GenericFinding::builder`] to create a new builder instance.
///
/// # Example
///
/// ```
/// use secfinding::Severity;
/// use secreport::models::GenericFinding;
///
/// let finding = GenericFinding::builder("scanner", "example.com", Severity::High)
///     .title("XSS Vulnerability")
///     .detail("Cross-site scripting in search parameter")
///     .cwe_ids(&["CWE-79".to_string()])
///     .tags(&["web", "xss"])
///     .confidence(Some(0.95))
///     .rule_id("XSS-001")
///     .build();
/// ```
pub struct GenericFindingBuilder<'a> {
    scanner: &'a str,
    target: &'a str,
    severity: Severity,
    title: &'a str,
    detail: &'a str,
    cwe_ids: &'a [String],
    cve_ids: &'a [String],
    tags: &'a [String],
    confidence: Option<f64>,
    rule_id: String,
    sarif_level: &'a str,
    exploit_hint: Option<&'a str>,
    evidence: &'a [Evidence],
}

impl<'a> GenericFindingBuilder<'a> {
    /// Sets the title of the finding.
    ///
    /// # Parameters
    ///
    /// - `title`: Brief title or name of the finding
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining
    #[must_use]
    pub fn title(mut self, title: &'a str) -> Self {
        self.title = title;
        self
    }

    /// Sets the detailed description of the finding.
    ///
    /// # Parameters
    ///
    /// - `detail`: Detailed description of the vulnerability
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining
    #[must_use]
    pub fn detail(mut self, detail: &'a str) -> Self {
        self.detail = detail;
        self
    }

    /// Sets the CWE IDs for the finding.
    ///
    /// # Parameters
    ///
    /// - `cwe_ids`: List of CWE (Common Weakness Enumeration) IDs
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining
    #[must_use]
    pub fn cwe_ids(mut self, cwe_ids: &'a [String]) -> Self {
        self.cwe_ids = cwe_ids;
        self
    }

    /// Sets the CVE IDs for the finding.
    ///
    /// # Parameters
    ///
    /// - `cve_ids`: List of CVE (Common Vulnerabilities and Exposures) IDs
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining
    #[must_use]
    pub fn cve_ids(mut self, cve_ids: &'a [String]) -> Self {
        self.cve_ids = cve_ids;
        self
    }

    /// Sets the tags for the finding.
    ///
    /// # Parameters
    ///
    /// - `tags`: List of categorization tags
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining
    #[must_use]
    pub fn tags(mut self, tags: &'a [String]) -> Self {
        self.tags = tags;
        self
    }

    /// Sets the confidence score for the finding.
    ///
    /// # Parameters
    ///
    /// - `confidence`: Optional confidence value between 0.0 and 1.0
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining
    #[must_use]
    pub fn confidence(mut self, confidence: Option<f64>) -> Self {
        self.confidence = confidence;
        self
    }

    /// Sets the rule ID for the finding.
    ///
    /// # Parameters
    ///
    /// - `rule_id`: Unique identifier for the rule that triggered this finding
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining
    #[must_use]
    pub fn rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = rule_id.into();
        self
    }

    /// Sets the SARIF level for the finding.
    ///
    /// # Parameters
    ///
    /// - `sarif_level`: SARIF level string (e.g., "error", "warning", "note")
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining
    #[must_use]
    pub fn sarif_level(mut self, sarif_level: &'a str) -> Self {
        self.sarif_level = sarif_level;
        self
    }

    /// Sets the exploit hint for the finding.
    ///
    /// # Parameters
    ///
    /// - `exploit_hint`: Optional exploit hint or proof-of-concept
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining
    #[must_use]
    pub fn exploit_hint(mut self, exploit_hint: Option<&'a str>) -> Self {
        self.exploit_hint = exploit_hint;
        self
    }

    /// Sets the evidence for the finding.
    ///
    /// # Parameters
    ///
    /// - `evidence`: List of evidence items (banners, code snippets, etc.)
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining
    #[must_use]
    pub fn evidence(mut self, evidence: &'a [Evidence]) -> Self {
        self.evidence = evidence;
        self
    }

    /// Builds and returns the `GenericFinding` instance.
    ///
    /// # Returns
    ///
    /// A fully constructed `GenericFinding` with all configured fields
    ///
    /// # Example
    ///
    /// ```
    /// use secfinding::Severity;
    /// use secreport::models::GenericFinding;
    ///
    /// let finding = GenericFinding::builder("scanner", "target", Severity::Info)
    ///     .title("Information Disclosure")
    ///     .rule_id("INFO-001")
    ///     .build();
    ///
    /// assert_eq!(finding.title, "Information Disclosure");
    /// assert_eq!(finding.rule_id, "INFO-001");
    /// ```
    #[must_use]
    pub fn build(self) -> GenericFinding<'a> {
        GenericFinding {
            scanner: self.scanner,
            target: self.target,
            severity: self.severity,
            title: self.title,
            detail: self.detail,
            cwe_ids: self.cwe_ids,
            cve_ids: self.cve_ids,
            tags: self.tags,
            confidence: self.confidence,
            rule_id: self.rule_id,
            sarif_level: self.sarif_level,
            exploit_hint: self.exploit_hint,
            evidence: self.evidence,
        }
    }
}

fn validation_error(message: &str) -> serde_json::Error {
    serde_json::Error::io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.to_string(),
    ))
}
