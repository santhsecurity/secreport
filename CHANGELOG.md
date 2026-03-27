# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-03-26

### Added

- Comprehensive documentation for all public APIs:
  - Added module-level documentation with usage examples
  - Documented all public functions with descriptions, parameters, return values, and code examples
  - Added doc comments for `GenericFinding` struct and all its fields
  - Added documentation for `GenericFindingBuilder` and all builder methods
  - Enhanced `Format::from_str_loose` documentation with examples
  - Documented `render`, `render_any`, and `emit` functions with usage examples

### Changed

- Improved API discoverability through detailed rustdoc comments

## [0.1.0] - 2025-03-XX

### Added

- Initial release of `secreport`
- Support for multiple output formats: JSON, JSONL, SARIF, Markdown, and text
- `GenericFinding` type for unified security finding representation
- Builder pattern for constructing findings
- `Format` enum for format selection
- Render functions for converting findings to various formats
