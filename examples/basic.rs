//! Generate reports in multiple formats.
//!
//! Run: cargo run --example basic

use secfinding::{Finding, Severity};
use secreport::{render, render_any, Format};

fn main() {
    let findings = vec![
        Finding::builder("my-scanner", "https://example.com", Severity::Critical)
            .title("SQL Injection")
            .detail("User input reaches database query without sanitization")
            .tag("sqli")
            .tag("owasp-a03")
            .cve("CVE-2024-12345")
            .build()
            .unwrap(),
        Finding::new(
            "my-scanner",
            "https://example.com",
            Severity::Low,
            "Server Version Exposed",
            "X-Powered-By header leaks version",
        )
        .unwrap(),
    ];

    // Text output (colored terminal)
    println!("=== TEXT ===");
    println!("{}", render(&findings, Format::Text, "my-scanner").unwrap());

    // SARIF output (for GitHub Security)
    println!("=== SARIF ===");
    println!(
        "{}",
        render(&findings, Format::Sarif, "my-scanner").unwrap()
    );

    // Custom types work too via render_any
    struct CustomFinding {
        title: String,
    }
    impl secfinding::Reportable for CustomFinding {
        fn scanner(&self) -> &str {
            "custom"
        }
        fn target(&self) -> &str {
            "custom-target"
        }
        fn severity(&self) -> Severity {
            Severity::Medium
        }
        fn title(&self) -> &str {
            &self.title
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
    }

    let custom = vec![CustomFinding {
        title: "Custom Issue".into(),
    }];
    println!("=== CUSTOM TYPE SARIF ===");
    println!(
        "{}",
        render_any(&custom, Format::Sarif, "custom-tool").unwrap()
    );
}
