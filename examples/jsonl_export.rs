//! Example showing JSONL export of security findings.
//!
//! Run: cargo run --example jsonl_export

use secfinding::{Finding, Severity};
use secreport::{render, Format};

fn main() {
    let findings = vec![
        Finding::builder("my-scanner", "https://example.com/1", Severity::High)
            .title("XSS Detected")
            .build()
            .unwrap(),
        Finding::builder("my-scanner", "https://example.com/2", Severity::Low)
            .title("Missing Headers")
            .build()
            .unwrap(),
    ];

    println!("=== JSONL Output ===");
    println!(
        "{}",
        render(&findings, Format::Jsonl, "my-scanner").unwrap()
    );
}
