//! PHP-specific template validation
//!
//! This module focuses on PHP-specific checks not covered by the enhanced validator.
//! The enhanced validator already handles:
//! - <?php tag checking
//! - json_encode checking
//! - Error handling (try/catch)
//!
//! This module adds PHP-specific checks:
//! - Security patterns
//! - PHP best practices
//! - Output formatting

use super::TemplateDiagnostic;
use anyhow::Result;

/// Validate PHP template code
pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check PHP-specific patterns
    diagnostics.extend(check_php_patterns(code));

    Ok(diagnostics)
}

/// Check for PHP-specific code patterns
fn check_php_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for dangerous functions
    let dangerous_funcs = vec![
        ("eval(", "eval() is dangerous - avoid if possible"),
        (
            "unserialize(",
            "unserialize() with untrusted data is a security risk",
        ),
        (
            "assert(",
            "assert() can execute code - avoid with user input",
        ),
        (
            "create_function(",
            "create_function() is deprecated and dangerous",
        ),
        (
            "preg_replace(/e",
            "preg_replace /e modifier is deprecated and dangerous",
        ),
    ];

    for (func, msg) in dangerous_funcs {
        for (line_num, line) in code.lines().enumerate() {
            if line.contains(func)
                && !line.trim().starts_with("//")
                && !line.trim().starts_with("#")
            {
                diagnostics.push(
                    TemplateDiagnostic::error("php.dangerous_function", msg)
                        .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for SQL injection patterns
    for (line_num, line) in code.lines().enumerate() {
        if (line.contains("mysql_query")
            || line.contains("mysqli_query")
            || line.contains("->query"))
            && (line.contains("$_GET") || line.contains("$_POST") || line.contains("$_REQUEST"))
        {
            diagnostics.push(
                TemplateDiagnostic::error(
                    "php.sql_injection",
                    "Direct use of user input in SQL query. Use prepared statements.",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    // Check for XSS patterns
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("echo") && (line.contains("$_GET") || line.contains("$_POST")) {
            if !line.contains("htmlspecialchars") && !line.contains("htmlentities") {
                diagnostics.push(
                    TemplateDiagnostic::warning(
                        "php.xss_risk",
                        "Echoing user input without sanitization. Use htmlspecialchars().",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for echo without json_encode
    for (line_num, line) in code.lines().enumerate() {
        if line.trim().starts_with("echo ") && !line.contains("json_encode") {
            if !line.trim().starts_with("//") {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "php.echo_without_json",
                        "echo without json_encode. Ensure output is valid JSON format.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for error display in production
    if code.contains("display_errors") && code.contains("On") {
        diagnostics.push(TemplateDiagnostic::warning(
            "php.display_errors",
            "display_errors should be Off in production to prevent information leakage.",
        ));
    }

    // Check for short open tag
    if code.contains("<?=") || (code.contains("<?") && !code.contains("<?php")) {
        diagnostics.push(TemplateDiagnostic::info(
            "php.short_open_tag",
            "Short open tags (<? or <?=) may not work on all PHP installations. Use <?php.",
        ));
    }

    // Check for deprecated mysql_ functions
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("mysql_") && !line.contains("mysqli_") {
            diagnostics.push(
                TemplateDiagnostic::error(
                    "php.deprecated_mysql",
                    "mysql_* functions are removed in PHP 7+. Use mysqli_* or PDO.",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    // Check for variable variables (confusing and potential security issue)
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("$$") {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "php.variable_variable",
                    "Variable variables ($$var) are confusing and can be a security risk. Consider using arrays.",
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
    fn test_dangerous_function_detection() {
        let code = "<?php eval($_GET['code']);";
        let diags = check_php_patterns(code);
        assert!(diags.iter().any(|d| d.code == "php.dangerous_function"));
    }

    #[test]
    fn test_sql_injection_detection() {
        let code = "<?php mysqli_query($conn, \"SELECT * FROM users WHERE id=\" . $_GET['id']);";
        let diags = check_php_patterns(code);
        assert!(diags.iter().any(|d| d.code == "php.sql_injection"));
    }

    #[test]
    fn test_deprecated_mysql() {
        let code = "<?php mysql_connect('host', 'user', 'pass');";
        let diags = check_php_patterns(code);
        assert!(diags.iter().any(|d| d.code == "php.deprecated_mysql"));
    }
}
