//! Rust-specific template validation
//!
//! This module focuses on Rust-specific checks not covered by the enhanced validator.
//! The enhanced validator already handles:
//! - fn main() entry point
//! - JSON library (serde_json) checking
//! - Error handling (Result, ?)
//!
//! This module adds Rust-specific checks:
//! - unwrap() usage (can panic)
//! - Memory safety patterns
//! - Rust idiom violations

use super::TemplateDiagnostic;
use anyhow::Result;

/// Validate Rust template code
pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check Rust-specific patterns
    diagnostics.extend(check_rust_patterns(code));

    Ok(diagnostics)
}

/// Check for Rust-specific code patterns
fn check_rust_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for excessive unwrap() usage
    let unwrap_count = code.matches(".unwrap()").count();
    if unwrap_count > 3 {
        diagnostics.push(TemplateDiagnostic::warning(
            "rust.excessive_unwrap",
            format!(
                "Found {} .unwrap() calls. Consider using ? operator or proper error handling \
                     to avoid panics in production templates.",
                unwrap_count
            ),
        ));
    } else if unwrap_count > 0 {
        // Find first unwrap location
        for (line_num, line) in code.lines().enumerate() {
            if line.contains(".unwrap()") && !line.trim().starts_with("//") {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "rust.unwrap_usage",
                        "unwrap() can panic. Consider using ? operator or match for graceful error handling.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for expect() without meaningful messages
    for (line_num, line) in code.lines().enumerate() {
        if line.contains(".expect(\"") {
            // Check if expect message is useful
            let re = regex::Regex::new(r#"\.expect\("([^"]+)"\)"#).unwrap();
            if let Some(caps) = re.captures(line) {
                let msg = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if msg.len() < 5 || msg == "error" || msg == "failed" {
                    diagnostics.push(
                        TemplateDiagnostic::info(
                            "rust.vague_expect",
                            "expect() message should be descriptive. Include what operation failed.",
                        )
                        .with_location(line_num + 1, None),
                    );
                    break;
                }
            }
        }
    }

    // Check for clone() in loops (potential performance issue)
    let mut in_loop = false;
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("for ") || line.contains("while ") || line.contains("loop {") {
            in_loop = true;
        }
        if in_loop && line.contains("}") && !line.contains("{") {
            in_loop = false;
        }
        if in_loop && line.contains(".clone()") && !line.trim().starts_with("//") {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "rust.clone_in_loop",
                    "clone() in loop detected. Consider borrowing or using iterators to avoid allocations.",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    // Check for mut references with potential aliasing
    let mut_ref_count = code.matches("&mut ").count();
    if mut_ref_count > 5 {
        diagnostics.push(TemplateDiagnostic::info(
            "rust.many_mut_refs",
            "Many mutable references detected. Ensure no aliasing issues exist.",
        ));
    }

    // Check for String::from vs .to_string() consistency
    let string_from_count = code.matches("String::from(").count();
    let to_string_count = code.matches(".to_string()").count();
    if string_from_count > 0 && to_string_count > 0 && string_from_count + to_string_count > 5 {
        diagnostics.push(TemplateDiagnostic::info(
            "rust.string_conversion_style",
            "Mixed String::from() and .to_string() usage. Consider using one style consistently.",
        ));
    }

    // Check for vec![] in function signatures (inefficient)
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("fn ") && line.contains("Vec<") && line.contains("= vec![]") {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "rust.vec_default_param",
                    "Default Vec in function. Consider Option<Vec<_>> or impl IntoIterator.",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwrap_detection() {
        let code = "let x = foo().unwrap();";
        let diags = check_rust_patterns(code);
        assert!(!diags.is_empty());
    }

    #[test]
    fn test_excessive_unwrap() {
        let code = "x.unwrap(); y.unwrap(); z.unwrap(); a.unwrap(); b.unwrap();";
        let diags = check_rust_patterns(code);
        assert!(diags.iter().any(|d| d.code == "rust.excessive_unwrap"));
    }

    #[test]
    fn test_clone_in_loop() {
        let code = "for item in items {\n    let x = item.clone();\n}";
        let diags = check_rust_patterns(code);
        assert!(diags.iter().any(|d| d.code == "rust.clone_in_loop"));
    }
}
