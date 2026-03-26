//! Output formatters for security findings.

#![forbid(unsafe_code)]

pub mod format;
pub mod models;
pub mod render;

pub use format::Format;
pub use render::{emit, render, render_any};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod adversarial_tests;

#[cfg(test)]
mod generated_tests;
