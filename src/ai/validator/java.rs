//! Java-specific template validation
//!
//! This module focuses on Java-specific checks not covered by the enhanced validator.
//! The enhanced validator already handles:
//! - public static void main entry point
//! - JSON library checking
//! - Error handling (try/catch)
//!
//! This module adds Java-specific checks:
//! - Resource management (try-with-resources)
//! - Common Java pitfalls
//! - Security issues

use super::TemplateDiagnostic;
use anyhow::Result;

/// Validate Java template code
pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check Java-specific patterns
    diagnostics.extend(check_java_patterns(code));

    Ok(diagnostics)
}

/// Check for Java-specific code patterns
fn check_java_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for resources not using try-with-resources
    let resource_types = [
        "Socket",
        "InputStream",
        "OutputStream",
        "Connection",
        "Statement",
        "ResultSet",
    ];
    for res_type in resource_types {
        let pattern = format!("{} ", res_type);
        if code.contains(&pattern) {
            // Check if using try-with-resources
            let try_with_re = regex::Regex::new(&format!(r"try\s*\([^)]*{}", res_type)).unwrap();
            if !try_with_re.is_match(code) && code.contains(".close()") {
                diagnostics.push(TemplateDiagnostic::info(
                    "java.no_try_with_resources",
                    format!(
                        "{} not using try-with-resources. Consider: try ({} x = ...) {{ }}",
                        res_type, res_type
                    ),
                ));
                break;
            }
        }
    }

    // Check for string comparison with ==
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("== \"") || line.contains("!= \"") {
            if !line.trim().starts_with("//") {
                diagnostics.push(
                    TemplateDiagnostic::warning(
                        "java.string_comparison",
                        "String comparison with == detected. Use .equals() for string content comparison.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for empty catch blocks
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("catch") {
            // Check next few lines for empty block
            let remaining: Vec<&str> = code.lines().skip(line_num + 1).take(3).collect();
            let next_content = remaining.join(" ");
            if next_content.contains("{ }") || next_content.contains("{}") {
                diagnostics.push(
                    TemplateDiagnostic::warning(
                        "java.empty_catch",
                        "Empty catch block detected. At minimum, log the exception.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for System.out.println (should use JSON output)
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("System.out.println") && !line.trim().starts_with("//") {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "java.println_output",
                    "System.out.println detected. Ensure output is valid JSON format.",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    // Check for synchronized in single-threaded context
    if code.contains("synchronized") && !code.contains("Thread") && !code.contains("Executor") {
        diagnostics.push(TemplateDiagnostic::info(
            "java.unnecessary_sync",
            "synchronized keyword found but no threading detected. May be unnecessary overhead.",
        ));
    }

    // Check for concatenation in loops
    let mut in_loop = false;
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("for ") || line.contains("while ") {
            in_loop = true;
        }
        if in_loop && line.contains("}") {
            in_loop = false;
        }
        if in_loop && line.contains("+=") && line.contains("\"") {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "java.string_concat_loop",
                    "String concatenation in loop. Use StringBuilder for better performance.",
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
    fn test_string_comparison() {
        let code = "if (str == \"test\") {}";
        let diags = check_java_patterns(code);
        assert!(diags.iter().any(|d| d.code == "java.string_comparison"));
    }

    #[test]
    fn test_empty_catch_detection() {
        let code = "try { x(); } catch (Exception e) { }";
        let diags = check_java_patterns(code);
        assert!(diags.iter().any(|d| d.code == "java.empty_catch"));
    }
}
