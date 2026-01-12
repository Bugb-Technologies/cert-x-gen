//! JavaScript/Node.js-specific template validation
//!
//! This module focuses on JavaScript-specific checks not covered by the enhanced validator.
//! The enhanced validator already handles:
//! - JSON import/output checking
//! - Entry point checking
//! - Network imports
//! - Error handling
//!
//! This module adds JavaScript-specific checks:
//! - console.log analysis
//! - Node.js specific patterns
//! - Common JavaScript pitfalls

use super::TemplateDiagnostic;
use anyhow::Result;

/// Validate JavaScript template code
pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check JavaScript-specific patterns
    diagnostics.extend(check_console_output(code));
    diagnostics.extend(check_js_patterns(code));

    Ok(diagnostics)
}

/// Check for console output patterns
fn check_console_output(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    let mut found_console_warning = false;

    for (line_num, line) in code.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*") {
            continue;
        }

        // Check console.log without JSON.stringify
        if trimmed.contains("console.log(") && !found_console_warning {
            let is_json = trimmed.contains("JSON.stringify") || trimmed.contains("JSON.parse");

            if !is_json {
                // Check if it's debug output
                let is_debug = trimmed.contains("[DEBUG]")
                    || trimmed.contains("debug:")
                    || trimmed.contains("DEBUG:");

                if is_debug {
                    diagnostics.push(
                        TemplateDiagnostic::warning(
                            "javascript.debug_console",
                            format!(
                                "Debug console.log found. Remove before production. Code: {}",
                                trimmed
                            ),
                        )
                        .with_location(line_num + 1, None),
                    );
                } else {
                    diagnostics.push(
                        TemplateDiagnostic::info(
                            "javascript.console_without_json",
                            format!(
                                "console.log without JSON.stringify detected. Ensure valid JSON output. \
                                 Code: {}",
                                trimmed
                            ),
                        )
                        .with_location(line_num + 1, None),
                    );
                }
                found_console_warning = true;
            }
        }

        // Check for console.error (might interfere with JSON output)
        if trimmed.contains("console.error(") {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "javascript.console_error",
                    "console.error() writes to stderr. Ensure this doesn't interfere with JSON output.",
                )
                .with_location(line_num + 1, None),
            );
            break; // Only warn once
        }
    }

    diagnostics
}

/// Check for JavaScript-specific patterns and pitfalls
fn check_js_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for == instead of ===
    for (line_num, line) in code.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }

        // Check for loose equality (but not in strings or comments)
        if line.contains(" == ") && !line.contains(" === ") {
            // Avoid false positives in strings
            if !line.contains("\" == \"") && !line.contains("' == '") {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "javascript.loose_equality",
                        "Loose equality (==) detected. Consider using strict equality (===).",
                    )
                    .with_location(line_num + 1, None),
                );
                break; // Only warn once
            }
        }
    }

    // Check for var (prefer const/let)
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("var ") && !line.trim().starts_with("//") {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "javascript.var_usage",
                    "Consider using 'const' or 'let' instead of 'var' for block scoping.",
                )
                .with_location(line_num + 1, None),
            );
            break; // Only warn once
        }
    }

    // Check for callback hell (deeply nested callbacks)
    let mut callback_depth: u32 = 0;
    for (line_num, line) in code.lines().enumerate() {
        // Count callback nesting
        if line.contains("function(") || line.contains("=> {") {
            callback_depth += 1;
            if callback_depth > 3 {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "javascript.callback_nesting",
                        "Deep callback nesting detected. Consider using async/await or Promises.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
        if line.contains("});") || line.contains("})") {
            callback_depth = callback_depth.saturating_sub(1);
        }
    }

    // Check for synchronous file operations in what looks like async code
    if code.contains("async ") || code.contains("await ") {
        let sync_patterns = ["readFileSync", "writeFileSync", "existsSync", "mkdirSync"];
        for pattern in sync_patterns {
            if code.contains(pattern) {
                if let Some(line_num) = code.lines().position(|l| l.contains(pattern)) {
                    diagnostics.push(
                        TemplateDiagnostic::warning(
                            "javascript.sync_in_async",
                            format!(
                                "'{}' used in async code. Consider using async version for better performance.",
                                pattern
                            ),
                        )
                        .with_location(line_num + 1, None),
                    );
                    break;
                }
            }
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_output_check() {
        // Non-JSON console.log
        let code = "console.log('hello');";
        let diags = check_console_output(code);
        assert!(!diags.is_empty());

        // JSON console.log
        let code = "console.log(JSON.stringify(data));";
        let diags = check_console_output(code);
        // Should only have info, not warning
        assert!(diags.iter().all(|d| d.code != "javascript.debug_console"));
    }

    #[test]
    fn test_loose_equality_detection() {
        let code = "if (x == null) {}";
        let diags = check_js_patterns(code);
        assert!(diags.iter().any(|d| d.code == "javascript.loose_equality"));
    }

    #[test]
    fn test_var_usage_detection() {
        let code = "var x = 1;";
        let diags = check_js_patterns(code);
        assert!(diags.iter().any(|d| d.code == "javascript.var_usage"));
    }
}
