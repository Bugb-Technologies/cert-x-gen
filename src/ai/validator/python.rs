//! Python-specific template validation
//!
//! This module focuses on Python-specific checks not covered by the enhanced validator.
//! The enhanced validator already handles:
//! - JSON import checking
//! - Entry point (main function) checking  
//! - Network imports
//! - Error handling
//!
//! This module adds Python-specific checks:
//! - print() statement analysis
//! - Python-specific code patterns
//! - Indentation issues

use super::TemplateDiagnostic;
use anyhow::Result;

/// Validate Python template code
pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check for Python-specific patterns
    diagnostics.extend(check_print_statements(code));
    diagnostics.extend(check_python_patterns(code));

    Ok(diagnostics)
}

/// Check for print statements that might break JSON output
fn check_print_statements(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    let mut found_print_warning = false;

    for (line_num, line) in code.lines().enumerate() {
        let trimmed = line.trim();
        
        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }

        // Check for print() statements
        if trimmed.contains("print(") {
            // Check if it's properly JSON formatted
            let is_json_print = trimmed.contains("json.dumps")
                || trimmed.contains("json.dump")
                || trimmed.contains("json.loads")
                || trimmed.contains("print(json")
                || trimmed.contains("print({")  // Might be dict literal
                || trimmed.contains("print(f'{");  // f-string JSON

            if !is_json_print && !found_print_warning {
                // Check if it looks like debug output
                let is_debug = trimmed.contains("print(\"[")
                    || trimmed.contains("print('[")
                    || trimmed.contains("print(f\"[")
                    || trimmed.contains("DEBUG")
                    || trimmed.contains("debug");

                if is_debug {
                    diagnostics.push(
                        TemplateDiagnostic::warning(
                            "python.debug_print",
                            format!(
                                "Debug print statement found. Remove or comment out before production. \
                                 Code: {}",
                                trimmed
                            ),
                        )
                        .with_location(line_num + 1, None),
                    );
                } else {
                    diagnostics.push(
                        TemplateDiagnostic::info(
                            "python.print_without_json",
                            format!(
                                "print() without json.dumps() detected. Ensure output is valid JSON. \
                                 Code: {}",
                                trimmed
                            ),
                        )
                        .with_location(line_num + 1, None),
                    );
                }
                found_print_warning = true;
            }
        }
    }

    diagnostics
}

/// Check for Python-specific code patterns
fn check_python_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for bare except (catches everything including KeyboardInterrupt)
    for (line_num, line) in code.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "except:" || trimmed.starts_with("except: ") {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "python.bare_except",
                    "Bare 'except:' catches all exceptions including KeyboardInterrupt. \
                     Use 'except Exception:' instead.",
                )
                .with_location(line_num + 1, None),
            );
        }
    }

    // Check for mutable default arguments
    let mutable_default = regex::Regex::new(r"def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|\{[^}]+\}|\[[^\]]+\])").unwrap();
    for (line_num, line) in code.lines().enumerate() {
        if mutable_default.is_match(line) {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "python.mutable_default",
                    "Mutable default argument detected. This can cause unexpected behavior. \
                     Use None and create the mutable object inside the function.",
                )
                .with_location(line_num + 1, None),
            );
        }
    }

    // Check for global keyword usage (code smell)
    if code.contains("global ") {
        for (line_num, line) in code.lines().enumerate() {
            if line.trim().starts_with("global ") {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "python.global_usage",
                        "Global variable usage detected. Consider passing variables as arguments instead.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for f-string with potential injection
    for (line_num, line) in code.lines().enumerate() {
        // Look for f-strings used with os.system or similar
        if line.contains("os.system(f\"") || line.contains("os.system(f'") 
            || line.contains("subprocess.run(f\"") || line.contains("subprocess.run(f'")
            || line.contains("subprocess.call(f\"") {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "python.fstring_injection",
                    "f-string in command execution detected. This could lead to command injection. \
                     Use shlex.quote() for arguments or subprocess with list arguments.",
                )
                .with_location(line_num + 1, None),
            );
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_statement_check() {
        // Non-JSON print
        let code = "print('hello world')";
        let diags = check_print_statements(code);
        assert!(!diags.is_empty());

        // JSON print - should be fine
        let code = "print(json.dumps(findings))";
        let diags = check_print_statements(code);
        assert!(diags.is_empty());
    }

    #[test]
    fn test_bare_except_detection() {
        let code = "try:\n    x = 1\nexcept:\n    pass";
        let diags = check_python_patterns(code);
        assert!(diags.iter().any(|d| d.code == "python.bare_except"));
    }

    #[test]
    fn test_mutable_default_detection() {
        let code = "def foo(items=[]):\n    pass";
        let diags = check_python_patterns(code);
        assert!(diags.iter().any(|d| d.code == "python.mutable_default"));
    }
}
