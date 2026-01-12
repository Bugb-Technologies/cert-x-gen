//! Perl-specific template validation
//!
//! This module focuses on Perl-specific checks not covered by the enhanced validator.
//! The enhanced validator already handles:
//! - JSON library checking
//! - Error handling (eval/die)
//! - use strict/warnings
//!
//! This module adds Perl-specific checks:
//! - Perl best practices
//! - Security patterns
//! - Output formatting

use super::TemplateDiagnostic;
use anyhow::Result;

/// Validate Perl template code
pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check Perl-specific patterns
    diagnostics.extend(check_perl_patterns(code));

    Ok(diagnostics)
}

/// Check for Perl-specific code patterns
fn check_perl_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for use strict and use warnings
    if !code.contains("use strict") {
        diagnostics.push(
            TemplateDiagnostic::warning(
                "perl.no_strict",
                "Add 'use strict;' at the top of the script for better error checking.",
            )
            .with_location(1, None),
        );
    }

    if !code.contains("use warnings") {
        diagnostics.push(
            TemplateDiagnostic::info(
                "perl.no_warnings",
                "Consider adding 'use warnings;' for additional runtime checks.",
            )
            .with_location(1, None),
        );
    }

    // Check for two-argument open (security risk)
    for (line_num, line) in code.lines().enumerate() {
        // Pattern: open(FH, "file") instead of open(FH, '<', "file")
        if let Ok(re) = regex::Regex::new(r#"open\s*\(\s*\$?\w+\s*,\s*['"<>|+]?[^,'"]+['"]?\s*\)"#) {
            if re.is_match(line) && !line.contains(", '<',") && !line.contains(", '>',") {
                diagnostics.push(
                    TemplateDiagnostic::warning(
                        "perl.two_arg_open",
                        "Two-argument open() is a security risk. Use three-argument form: open(my $fh, '<', $file)",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for print without json output
    for (line_num, line) in code.lines().enumerate() {
        if line.trim().starts_with("print ") && !line.contains("encode_json") && !line.contains("to_json") {
            if !line.contains("{") && !line.trim().starts_with('#') {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "perl.print_without_json",
                        "print without JSON encoding. Ensure output is valid JSON format.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for backticks/qx with variables (injection risk)
    for (line_num, line) in code.lines().enumerate() {
        if (line.contains('`') || line.contains("qx(") || line.contains("qx{"))
            && line.contains('$')
            && !line.trim().starts_with('#')
        {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "perl.command_injection",
                    "Variable in backticks/qx detected. Sanitize input to prevent command injection.",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    // Check for regex without /x modifier on complex patterns
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("=~") || line.contains("!~") {
            // Simple heuristic: regex with more than 30 chars without /x
            if let Ok(re) = regex::Regex::new(r#"[=!]~\s*[ms]?/[^/]{30,}/[^x]*$"#) {
                if re.is_match(line) {
                    diagnostics.push(
                        TemplateDiagnostic::info(
                            "perl.complex_regex",
                            "Complex regex without /x modifier. Consider using /x for readability.",
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
    fn test_strict_detection() {
        let code = "#!/usr/bin/perl\nprint 'hello';";
        let diags = check_perl_patterns(code);
        assert!(diags.iter().any(|d| d.code == "perl.no_strict"));
    }

    #[test]
    fn test_command_injection_detection() {
        let code = "my $output = `cat $filename`";
        let diags = check_perl_patterns(code);
        assert!(diags.iter().any(|d| d.code == "perl.command_injection"));
    }
}
