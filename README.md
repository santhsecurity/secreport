# secreport

Render security findings into SARIF, JSON, JSONL, Markdown, or colored terminal output. Works with any type that implements the `Reportable` trait from secfinding. You don't need to use our Finding type.

```rust
use secfinding::{Finding, Severity};
use secreport::{render, Format};

let findings = vec![
    Finding::new("scanner", "https://target.com", Severity::High, "SQLi", "Unsanitized input"),
];
let sarif = render(&findings, Format::Sarif, "my-tool");
```

## Bring your own types

If you have your own finding struct, implement `Reportable` and use `render_any`:

```rust
use secfinding::{Reportable, Severity};
use secreport::{render_any, Format};

struct MyFinding { title: String }

impl Reportable for MyFinding {
    fn scanner(&self) -> &str { "my-tool" }
    fn target(&self) -> &str { "target" }
    fn severity(&self) -> Severity { Severity::High }
    fn title(&self) -> &str { &self.title }
}

let findings = vec![MyFinding { title: "XSS".into() }];
let json = render_any(&findings, Format::Json, "my-tool");
```

## Formats

| Format | Use case |
|--------|----------|
| Text | Terminal output with ANSI colors and severity counts |
| Json | Machine consumption, API responses |
| Jsonl | Streaming, one finding per line |
| Sarif | GitHub Security tab, IDE integration |
| Markdown | Reports, documentation, email |

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/secreport.svg)](https://crates.io/crates/secreport)
[![docs.rs](https://docs.rs/secreport/badge.svg)](https://docs.rs/secreport)
