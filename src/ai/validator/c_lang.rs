//! C-specific template validation
//!
//! This module focuses on C-specific checks not covered by the enhanced validator.
//! The enhanced validator already handles:
//! - int main() entry point
//! - JSON library checking
//! - Error handling patterns
//! - Unsafe function detection
//!
//! This module adds C-specific checks:
//! - Buffer overflow risks
//! - Memory management issues
//! - Common C security pitfalls

use super::TemplateDiagnostic;
use anyhow::Result;

/// Validate C template code
pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check C-specific patterns
    diagnostics.extend(check_c_security(code));
    diagnostics.extend(check_c_patterns(code));

    Ok(diagnostics)
}

/// Check for C security issues
fn check_c_security(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for dangerous functions (more detailed than enhanced validator)
    let dangerous_functions = vec![
        ("gets(", "gets() is dangerous - use fgets() instead"),
        ("sprintf(", "sprintf() can overflow - use snprintf() instead"),
        ("strcpy(", "strcpy() can overflow - use strncpy() or strlcpy()"),
        ("strcat(", "strcat() can overflow - use strncat() or strlcat()"),
        ("scanf(\"%s\"", "scanf %s can overflow - use %Ns with buffer size"),
        ("vsprintf(", "vsprintf() can overflow - use vsnprintf()"),
    ];

    for (func, msg) in dangerous_functions {
        for (line_num, line) in code.lines().enumerate() {
            if line.contains(func) && !line.trim().starts_with("//") && !line.trim().starts_with("/*") {
                diagnostics.push(
                    TemplateDiagnostic::error(
                        "c.dangerous_function",
                        msg,
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for format string vulnerabilities
    for (line_num, line) in code.lines().enumerate() {
        // printf(variable) without format string
        if let Ok(re) = regex::Regex::new(r"printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)") {
            if re.is_match(line) {
                diagnostics.push(
                    TemplateDiagnostic::error(
                        "c.format_string",
                        "printf() with variable as format string - format string vulnerability. \
                         Use printf(\"%s\", var) instead.",
                    )
                    .with_location(line_num + 1, None),
                );
            }
        }
    }

    // Check for signed/unsigned comparison
    if code.contains("< 0") && code.contains("size_t") {
        diagnostics.push(
            TemplateDiagnostic::info(
                "c.signed_unsigned",
                "Code uses size_t with signed comparison. size_t is unsigned and never < 0.",
            )
        );
    }

    diagnostics
}

/// Check for C-specific code patterns
fn check_c_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for malloc without free (simple heuristic)
    let malloc_count = code.matches("malloc(").count() + code.matches("calloc(").count();
    let free_count = code.matches("free(").count();
    
    if malloc_count > free_count + 1 {
        diagnostics.push(
            TemplateDiagnostic::warning(
                "c.potential_memory_leak",
                format!(
                    "Found {} allocations but only {} free() calls. Check for memory leaks.",
                    malloc_count, free_count
                ),
            )
        );
    }

    // Check for null pointer checks after malloc
    if code.contains("malloc(") || code.contains("calloc(") {
        let has_null_check = code.contains("== NULL") || code.contains("!= NULL") 
            || code.contains("if (") || code.contains("if(");
        
        if !has_null_check {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "c.no_malloc_check",
                    "Memory allocation without NULL check. malloc()/calloc() can fail.",
                )
            );
        }
    }

    // Check for return value of functions not checked
    let unchecked_functions = vec!["fopen(", "socket(", "connect(", "bind(", "listen("];
    for func in unchecked_functions {
        for (line_num, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains(func) && !trimmed.contains("if") && !trimmed.contains("=") {
                diagnostics.push(
                    TemplateDiagnostic::warning(
                        "c.unchecked_return",
                        format!("Return value of {} not checked. These functions can fail.", func),
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    // Check for magic numbers
    for (line_num, line) in code.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("#") {
            continue;
        }
        // Check for buffer sizes as magic numbers
        if let Ok(re) = regex::Regex::new(r"\[\s*\d{3,}\s*\]") {
            if re.is_match(line) && !line.contains("#define") && !line.contains("const") {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "c.magic_buffer_size",
                        "Large magic number buffer size. Consider using #define for buffer sizes.",
                    )
                    .with_location(line_num + 1, None),
                );
                break;
            }
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_function_detection() {
        let code = "char buf[10];\ngets(buf);";
        let diags = check_c_security(code);
        assert!(diags.iter().any(|d| d.code == "c.dangerous_function"));
    }

    #[test]
    fn test_memory_leak_detection() {
        let code = "void* p1 = malloc(10);\nvoid* p2 = malloc(20);\nvoid* p3 = malloc(30);\nfree(p1);";
        let diags = check_c_patterns(code);
        assert!(diags.iter().any(|d| d.code == "c.potential_memory_leak"));
    }

    #[test]
    fn test_format_string() {
        let code = "printf(user_input)";
        let diags = check_c_security(code);
        assert!(diags.iter().any(|d| d.code == "c.format_string"));
    }
}
