//! Ruby-specific template validation
//!
//! This module focuses on Ruby-specific checks not covered by the enhanced validator.
//! The enhanced validator already handles:
//! - JSON library checking
//! - Error handling (begin/rescue)
//! - Network imports
//!
//! This module adds Ruby-specific checks:
//! - Ruby idiom violations
//! - Security patterns
//! - Output formatting

use super::TemplateDiagnostic;
use anyhow::Result;

/// Validate Ruby template code
pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check Ruby-specific patterns
    diagnostics.extend(check_ruby_patterns(code));

    Ok(diagnostics)
}

/// Check for Ruby-specific code patterns
fn check_ruby_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for puts without JSON (common Ruby output)
    for (line_num, line) in code.lines().enumerate() {
        if line.trim().starts_with("puts ") && !line.contains(".to_json") && !line.contains("JSON")
        {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "ruby.puts_without_json",
                    "puts without .to_json detected. Ensure output is valid JSON format.",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    // Check for backticks command execution
    for (line_num, line) in code.lines().enumerate() {
        if line.contains('`') && !line.trim().starts_with('#') {
            // Count backticks
            let backtick_count = line.matches('`').count();
            if backtick_count >= 2 {
                diagnostics.push(
                    TemplateDiagnostic::warning(
                        "ruby.backtick_command",
                        "Backtick command execution detected. Ensure input is sanitized to prevent injection.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for eval usage
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("eval(") && !line.trim().starts_with('#') {
            diagnostics.push(
                TemplateDiagnostic::error(
                    "ruby.eval_usage",
                    "eval() is dangerous and can lead to code injection. Avoid if possible.",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    // Check for rescue without specific exception
    for (line_num, line) in code.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "rescue" || trimmed.starts_with("rescue =>") {
            if !trimmed.contains("StandardError") && !trimmed.contains("Exception") {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "ruby.bare_rescue",
                        "Bare rescue catches StandardError. Consider specifying exception types.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for string interpolation in system calls
    for (line_num, line) in code.lines().enumerate() {
        if (line.contains("system(") || line.contains("exec(") || line.contains("%x("))
            && line.contains("#{")
        {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "ruby.interpolation_in_system",
                    "String interpolation in system call. Use array form: system('cmd', arg) for safety.",
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
    fn test_eval_detection() {
        let code = "result = eval(user_input)";
        let diags = check_ruby_patterns(code);
        assert!(diags.iter().any(|d| d.code == "ruby.eval_usage"));
    }

    #[test]
    fn test_backtick_detection() {
        let code = "output = `ls -la`";
        let diags = check_ruby_patterns(code);
        assert!(diags.iter().any(|d| d.code == "ruby.backtick_command"));
    }
}
