use secfinding::{Evidence, Reportable, Severity};

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
    #[must_use]
    pub fn title(mut self, title: &'a str) -> Self {
        self.title = title;
        self
    }

    #[must_use]
    pub fn detail(mut self, detail: &'a str) -> Self {
        self.detail = detail;
        self
    }

    #[must_use]
    pub fn cwe_ids(mut self, cwe_ids: &'a [String]) -> Self {
        self.cwe_ids = cwe_ids;
        self
    }

    #[must_use]
    pub fn cve_ids(mut self, cve_ids: &'a [String]) -> Self {
        self.cve_ids = cve_ids;
        self
    }

    #[must_use]
    pub fn tags(mut self, tags: &'a [String]) -> Self {
        self.tags = tags;
        self
    }

    #[must_use]
    pub fn confidence(mut self, confidence: Option<f64>) -> Self {
        self.confidence = confidence;
        self
    }

    #[must_use]
    pub fn rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = rule_id.into();
        self
    }

    #[must_use]
    pub fn sarif_level(mut self, sarif_level: &'a str) -> Self {
        self.sarif_level = sarif_level;
        self
    }

    #[must_use]
    pub fn exploit_hint(mut self, exploit_hint: Option<&'a str>) -> Self {
        self.exploit_hint = exploit_hint;
        self
    }

    #[must_use]
    pub fn evidence(mut self, evidence: &'a [Evidence]) -> Self {
        self.evidence = evidence;
        self
    }

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
