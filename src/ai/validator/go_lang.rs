//! Go-specific template validation
//!
//! This module focuses on Go-specific checks not covered by the enhanced validator.
//! The enhanced validator already handles:
//! - package main declaration
//! - func main() entry point
//! - JSON import checking
//! - Error handling patterns
//!
//! This module adds Go-specific checks:
//! - Go idiom violations
//! - Common Go mistakes
//! - Goroutine/channel patterns

use super::TemplateDiagnostic;
use anyhow::Result;

/// Validate Go template code
pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check Go-specific patterns
    diagnostics.extend(check_go_patterns(code));
    diagnostics.extend(check_goroutine_patterns(code));

    Ok(diagnostics)
}

/// Check for Go-specific code patterns
fn check_go_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for panic() usage (should use error returns in templates)
    for (line_num, line) in code.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }

        if trimmed.contains("panic(") && !trimmed.contains("recover") {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "go.panic_usage",
                    "panic() detected. Templates should handle errors gracefully and return \
                     error values instead of panicking.",
                )
                .with_location(line_num + 1, None),
            );
            break; // Only warn once
        }
    }

    // Check for naked returns (can be confusing)
    let naked_return_re = regex::Regex::new(r"^\s*return\s*$").unwrap();
    for (line_num, line) in code.lines().enumerate() {
        if naked_return_re.is_match(line) {
            // Check if function has named returns
            // This is a simple heuristic, not perfect
            diagnostics.push(
                TemplateDiagnostic::info(
                    "go.naked_return",
                    "Naked return detected. Consider explicit returns for clarity.",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    // Check for fmt.Print instead of fmt.Println for JSON
    for (line_num, line) in code.lines().enumerate() {
        if line.contains("fmt.Print(") && !line.contains("fmt.Printf") && !line.contains("fmt.Println") {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "go.fmt_print",
                    "fmt.Print() doesn't add newline. For JSON output, consider fmt.Println().",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    // Check for ignored errors (common mistake)
    for (line_num, line) in code.lines().enumerate() {
        // Pattern: _, _ := someFunc() or simply ignoring second return
        if line.contains(", _ =") || line.contains(", _ :=") {
            let trimmed = line.trim();
            // Skip if it's intentionally ignoring non-error values
            if !trimmed.contains("err") {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "go.ignored_value",
                        "Value explicitly ignored with '_'. Ensure this is intentional, \
                         especially for error returns.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for string concatenation in loops (inefficient)
    if code.contains("for ") && code.contains("+ ") {
        // Simple heuristic for string concat in loops
        let mut in_loop = false;
        for (line_num, line) in code.lines().enumerate() {
            if line.contains("for ") {
                in_loop = true;
            }
            if in_loop && line.contains("}") {
                in_loop = false;
            }
            if in_loop && (line.contains("= ") || line.contains("+= ")) 
                && line.contains("+ ") 
                && !line.contains("//") {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "go.string_concat_loop",
                        "String concatenation in loop detected. Consider using strings.Builder \
                         for better performance.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    diagnostics
}

/// Check for goroutine-related patterns
fn check_goroutine_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for goroutines without proper synchronization
    if code.contains("go ") && code.contains("go func") {
        let has_sync = code.contains("sync.") 
            || code.contains("WaitGroup")
            || code.contains("chan ")
            || code.contains("<-")
            || code.contains("context."); 

        if !has_sync {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "go.goroutine_no_sync",
                    "Goroutine detected without apparent synchronization. \
                     Ensure goroutines complete before program exit. \
                     Use sync.WaitGroup, channels, or context.",
                )
            );
        }
    }

    // Check for unbuffered channels in loops (potential deadlock)
    if code.contains("make(chan") && !code.contains("make(chan ") {
        // Simple heuristic - more complex analysis would need AST
        diagnostics.push(
            TemplateDiagnostic::info(
                "go.unbuffered_channel",
                "Channel creation detected. Ensure buffered channels are used appropriately \
                 to prevent deadlocks.",
            )
        );
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_detection() {
        let code = "func main() {\n    panic(\"error\")\n}";
        let diags = check_go_patterns(code);
        assert!(diags.iter().any(|d| d.code == "go.panic_usage"));
    }

    #[test]
    fn test_goroutine_sync_warning() {
        // Goroutine without sync
        let code = "go func() { doWork() }()";
        let diags = check_goroutine_patterns(code);
        assert!(diags.iter().any(|d| d.code == "go.goroutine_no_sync"));

        // Goroutine with WaitGroup
        let code = "var wg sync.WaitGroup\ngo func() { defer wg.Done() }()";
        let diags = check_goroutine_patterns(code);
        assert!(!diags.iter().any(|d| d.code == "go.goroutine_no_sync"));
    }
}
