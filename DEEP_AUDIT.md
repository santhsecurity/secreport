# TOKIO-LEVEL DEEP AUDIT — `secreport`

**Crate:** `libs/scanner/secreport` (single crate)  
**Role:** Security finding report generator — JSON, JSONL, SARIF, Markdown, plain text.  
**Audit date:** 2026-03-26  
**Standard:** Honest assessment of spec compliance, scalability, API ergonomics, and format coverage.

---

## Executive summary

| Question | Verdict |
|----------|---------|
| SARIF 2.1.0 spec compliance | **Mostly yes for minimal structural validity** — satisfies core `sarifLog` / `run` / `tool` / `result` shape; **weak for real-world SARIF consumers** (no `rules`, no evidence mapping, optional provenance fields absent). |
| 10K findings without OOM | **Likely yes on typical hosts** — covered by an in-crate stress test; design is **not streaming** and holds the full serialized report in memory. |
| `Reportable` for tool authors | **Practical for small/medium tools** — clear `render_any` path; **repetitive boilerplate** for empty CWE/CVE/tag slices; **SARIF drops evidence**. |
| Missing formats | **HTML, CSV/TSV, JIRA (and friends), GitLab/Sonar-style exports, PDF** are not present; only the five `Format` variants. |

**Overall grade:** **B** — Solid for internal CLI and JSON-focused pipelines; SARIF is “JSON that looks like SARIF” more than “SARIF tuned for GitHub/CodeQL-class ingestion.”

---

## 1. Does SARIF output comply with SARIF 2.1.0?

### 1.1 What the crate actually emits

SARIF is built as a `serde_json::json!` document in `render_sarif_generic`:

```20:55:libs/scanner/secreport/src/render/json.rs
pub(crate) fn render_sarif_generic(
    findings: &[GenericFinding<'_>],
    tool_name: &str,
) -> Result<String, serde_json::Error> {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": f.sarif_level,
                "message": { "text": format!("{}\n{}", f.title, f.detail) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.target }
                    }
                }],
                "properties": {
                    "tags": f.tags,
                    "severity": f.severity.to_string(),
                    "confidence": f.confidence,
                    "cwe_ids": f.cwe_ids,
                    "cve_ids": f.cve_ids,
                    "exploit_hint": f.exploit_hint,
                }
            })
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": tool_name } },
            "results": results,
        }]
    }))
}
```

### 1.2 Spec-aligned strengths

- **`version`:** `"2.1.0"` — correct.
- **`runs` + `tool.driver.name`:** matches the minimum *toolComponent* requirement (name present).
- **Each result** includes **`ruleId`**, **`message` with `text`**, and **`locations` → `physicalLocation` → `artifactLocation` → `uri`**, which is a valid minimal location graph.
- **`level`:** when driven by `Severity::sarif_level()`, values are only `error`, `warning`, or `note` — valid SARIF result levels.

```57:65:libs/scanner/secfinding/src/severity.rs
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low | Self::Info => "note",
        }
    }
```

- **`$schema`:** optional in SARIF; including it is fine (points at the 2.1.0 schema URL).

### 1.3 Spec / ecosystem gaps (not necessarily JSON Schema failures)

These are the main reasons to answer **“compliant at the skeleton level, incomplete for strict product QA.”**

| Gap | Why it matters |
|-----|----------------|
| **No `tool.driver.rules` (and no `ruleIndex`)** | Many SARIF consumers (notably GitHub code scanning) expect a **rule catalog** whose `id` matches each result’s `ruleId`, with names/help URIs. The log is still structurally SARIF-like, but **rule metadata is missing**. |
| **Evidence not represented** | `Reportable::evidence()` is converted for JSON/JSONL via `GenericFinding::json_value`, but **SARIF results never include** `codeFlows`, `attachments`, `relatedLocations`, etc. Security tools that rely on SARIF for dedupe or reviewer context lose that edge. |
| **No tool provenance** | `semanticVersion`, `version`, `informationUri`, `rules` URIs — all **optional** in the spec but **expected** in mature integrations. |
| **No region / line / column** | Only a URI is set. That is allowed, but **imprecise** compared to what IDEs and PR annotations usually want (`region.startLine`, …). |
| **Overridable `sarif_level`** | `Reportable::sarif_level()` can return arbitrary strings; secreport does **not** validate against SARIF’s `level` enum. A buggy impl can emit invalid SARIF. |
| **No CI schema validation** | Unit tests assert shape and JSON parseability (see `sarif_schema_and_result_shape` in `src/tests.rs`); the repo does **not** run an official SARIF 2.1 JSON Schema validator in automation. |

### 1.4 Bottom line on question (1)

- **As minimal SARIF 2.1.0 JSON:** likely **valid** for a schema that requires only the core objects and permitted property names (subject to property bag typing in the real schema — arrays/strings in `properties` are commonly accepted).
- **As SARIF that enterprise tooling treats as first-class:** **partial** — add `tool.driver.rules`, optional `fullName`/`version`, regions, and evidence mapping for a stronger “yes.”

---

## 2. Reports at 10K findings — OOM risk?

### 2.1 Evidence in this repo

`adversarial_10k_findings` builds **10,000** `Finding` values and runs **all** formats (including SARIF), asserting non-empty output and correct counts:

```5:58:libs/scanner/secreport/src/adversarial_tests.rs
fn adversarial_10k_findings() {
    let mut findings = Vec::new();
    for i in 0..10_000 {
        let finding = Finding::new(
            "stress-scanner",
            format!("https://target-{}.example.com", i),
            // ...
        )
        .unwrap();
        findings.push(finding);
    }

    for format in [
        Format::Text,
        Format::Json,
        Format::Jsonl,
        Format::Sarif,
        Format::Markdown,
    ] {
        let output = render(&findings, format, "stress-test").unwrap();
        // ...
    }
}
```

So **for the stated 10K scenario, the project’s own tests expect success** on a normal test runner host.

### 2.2 Memory model (why OOM can still happen elsewhere)

The pipeline **materializes everything in RAM**:

```11:27:libs/scanner/secreport/src/render.rs
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
```

- **`GenericFinding` vec:** one entry per finding (mostly references into `R`).
- **SARIF:** a **`Vec<serde_json::Value>`** with one subtree per result, then **`to_string_pretty`** → **one huge `String`**.
- **JSONL:** lines are collected then **`join("\n")`** → again **one `String`** for the whole report.
- **Pretty-printed JSON:** adds whitespace overhead versus compact serialization.

**Conclusion:** **10K findings:** aligned with tested behavior; **OOM is unlikely** on desktop/CI with moderate strings. **Very large N**, **huge per-finding text**, or **embedded memory limits** (WASM, tiny containers) can still fail — there is **no streaming writer API**.

---

## 3. Is `Reportable` practical for tool developers?

### 3.1 Strengths

- **Single integration point:** `secreport::render_any` + `secfinding::Reportable` gives JSON, JSONL, SARIF, Markdown, and text from **any** finding type.
- **Sensible defaults** in `secfinding` for `detail`, `confidence`, `rule_id`, `sarif_level`, `exploit_hint`, `evidence` (see `reportable.rs` in `secfinding`).
- **Examples** (`examples/custom_reportable.rs`) mirror real custom-type usage.

### 3.2 Pain points

- **Mandatory trio:** `cwe_ids`, `cve_ids`, and `tags` have **no default** implementations (Rust cannot safely default `fn foo(&self) -> &[String]` without `'static` empty slices on the trait itself). Every integrator writes three **“return `&[]`”** methods — noisy for tools that do not use those fields.
- **`rule_id() -> String`:** default builds a slug from scanner + title — fine, but **allocates**; hot paths with millions of findings may care.
- **SARIF story is thinner than JSON:** evidence, CWE/CVE end up in a **custom `properties`** bag rather than standard SARIF structures; tags/severity duplication may not match consumer expectations.
- **Validation:** `GenericFinding::try_from_reportable` checks severity string and finite confidence only — **not** SARIF-specific constraints (URI shape, level enum, rule id charset).

### 3.3 Verdict

**Good for teams that want one trait and multiple outputs quickly.** Less ideal for **SARIF-first** or **evidence-heavy** products without extending the SARIF mapper.

---

## 4. What output formats are missing?

Implemented today (`format.rs`): **Text**, **Json**, **Jsonl**, **Sarif**, **Markdown**.

Common gaps (including those you named):

| Format | Notes |
|--------|--------|
| **HTML** | Not present — would help dashboards, email, hosted reports. |
| **CSV / TSV** | Not present — spreadsheet and SIEM ingestion. |
| **JIRA** | No dedicated exporter (CSV/issue JSON, or rendered issue description). |
| **GitHub / GitLab flavored issue bodies** | Could be derived from Markdown, but no dedicated templates. |
| **GitLab SAST** | Not present. |
| **SonarQube generic issue / SARIF bridge formats** | Not present (only vanilla SARIF-ish). |
| **XML** | Not present (some enterprise gates still want it). |
| **PDF** | Not present (usually out of scope for a small formatter crate). |

---

## 5. Recommendations (priority order)

1. **SARIF quality:** Populate **`tool.driver.rules`** (stable `id`, `name`, `shortDescription`, optional `helpUri`) aligned with each distinct `ruleId`; add **`region`** when line/column data exists on `Evidence` or future fields.
2. **Evidence:** Map `Evidence` to SARIF **`relatedLocations`** or **`codeFlows`** where possible instead of only JSON.
3. **Scale:** Offer **`emit_*` APIs** that write to `impl Write` **without** building the full `String` (streaming JSONL line-by-line; compact JSON generator; optional non-pretty SARIF).
4. **Trait ergonomics:** Consider a **`ReportableMinimal`** / macro / blanket helper that implements the empty-slice trio for simple types, or use a small struct of callbacks.
5. **Validation:** Add optional **SARIF JSON Schema** check in tests (or a `dev-dependency` validator) to catch regressions.

---

## 6. File map (quick reference)

| Area | Path |
|------|------|
| Format enum | `src/format.rs` |
| `render` / `render_any` / `emit` | `src/render.rs` |
| SARIF + JSON + JSONL | `src/render/json.rs` |
| Markdown / text building blocks | `src/render/markdown.rs`, `src/render/summary.rs` |
| Normalization + validation | `src/models.rs` |
| Stress + SARIF JSON tests | `src/adversarial_tests.rs`, `src/tests.rs` |
