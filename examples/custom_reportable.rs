use secfinding::{Reportable, Severity};
use secreport::{render_any, Format};

struct ApiFinding {
    endpoint: String,
    title: String,
    severity: Severity,
}

impl Reportable for ApiFinding {
    fn scanner(&self) -> &str {
        "api-audit"
    }
    fn target(&self) -> &str {
        &self.endpoint
    }
    fn severity(&self) -> Severity {
        self.severity
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn detail(&self) -> &str {
        "Custom type rendered through secreport::render_any."
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
    fn confidence(&self) -> Option<f64> {
        Some(0.87)
    }
}

fn main() {
    let findings = vec![
        ApiFinding {
            endpoint: "https://example.com/profile".into(),
            title: "Reflected XSS".into(),
            severity: Severity::High,
        },
        ApiFinding {
            endpoint: "https://example.com/admin".into(),
            title: "Missing authorization".into(),
            severity: Severity::Critical,
        },
    ];

    println!(
        "{}",
        render_any(&findings, Format::Text, "api-audit").unwrap()
    );
    println!(
        "{}",
        render_any(&findings, Format::Sarif, "api-audit").unwrap()
    );
}
