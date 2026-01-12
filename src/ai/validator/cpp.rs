//! C++-specific template validation
//!
//! This module focuses on C++-specific checks not covered by the enhanced validator.
//! The enhanced validator already handles:
//! - int main() entry point
//! - JSON library checking
//! - Error handling (try/catch)
//!
//! This module adds C++-specific checks:
//! - Modern C++ best practices
//! - Memory management (smart pointers)
//! - C++ specific security issues

use super::TemplateDiagnostic;
use anyhow::Result;

/// Validate C++ template code
pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check C++-specific patterns
    diagnostics.extend(check_cpp_patterns(code));

    Ok(diagnostics)
}

/// Check for C++-specific code patterns
fn check_cpp_patterns(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for raw new/delete (prefer smart pointers)
    let new_count = code.matches(" new ").count();
    let delete_count = code.matches("delete ").count() + code.matches("delete[").count();

    if new_count > 0 && !code.contains("unique_ptr") && !code.contains("shared_ptr") {
        diagnostics.push(
            TemplateDiagnostic::warning(
                "cpp.raw_new",
                "Raw 'new' detected without smart pointers. Consider using std::unique_ptr or std::make_unique.",
            )
        );
    }

    if new_count > delete_count + 1 {
        diagnostics.push(
            TemplateDiagnostic::warning(
                "cpp.potential_memory_leak",
                format!(
                    "Found {} 'new' but only {} 'delete'. Check for memory leaks or use smart pointers.",
                    new_count, delete_count
                ),
            )
        );
    }

    // Check for C-style casts
    let c_cast_re = regex::Regex::new(r"\(\s*(int|char|float|double|void)\s*\*?\s*\)").unwrap();
    for (line_num, line) in code.lines().enumerate() {
        if c_cast_re.is_match(line) && !line.trim().starts_with("//") {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "cpp.c_style_cast",
                    "C-style cast detected. Prefer static_cast, dynamic_cast, or reinterpret_cast.",
                )
                .with_location(line_num + 1, None),
            );
            break;
        }
    }

    // Check for NULL instead of nullptr
    if code.contains("NULL") && !code.contains("nullptr") {
        diagnostics.push(TemplateDiagnostic::info(
            "cpp.use_nullptr",
            "Use 'nullptr' instead of 'NULL' for type safety in modern C++.",
        ));
    }

    // Check for using namespace std in headers (bad practice)
    if code.contains("using namespace std") {
        diagnostics.push(
            TemplateDiagnostic::info(
                "cpp.using_namespace_std",
                "'using namespace std' pollutes global namespace. Use std:: prefix or specific using declarations.",
            )
        );
    }

    // Check for exception safety
    if code.contains("throw ") && !code.contains("noexcept") {
        // Check if there are any noexcept specifications
        let has_exception_spec = code.contains("noexcept") || code.contains("throw()");
        if !has_exception_spec && code.contains("~") {
            diagnostics.push(TemplateDiagnostic::info(
                "cpp.destructor_throw",
                "Exceptions used but no noexcept. Ensure destructors are noexcept.",
            ));
        }
    }

    // Check for auto with complex types
    if code.contains("auto ") {
        let auto_count = code.matches("auto ").count();
        if auto_count > 10 {
            diagnostics.push(TemplateDiagnostic::info(
                "cpp.excessive_auto",
                "Heavy use of 'auto'. Consider explicit types for better code readability.",
            ));
        }
    }

    // Check for iostream and cstdio mixing
    if (code.contains("iostream") || code.contains("cout") || code.contains("cin"))
        && (code.contains("cstdio") || code.contains("printf") || code.contains("scanf"))
    {
        if !code.contains("sync_with_stdio") {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "cpp.mixed_io",
                    "Mixing iostream and cstdio. Consider std::ios_base::sync_with_stdio(false) for consistency.",
                )
            );
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_new_detection() {
        let code = "int* p = new int(5);";
        let diags = check_cpp_patterns(code);
        assert!(diags.iter().any(|d| d.code == "cpp.raw_new"));
    }

    #[test]
    fn test_nullptr_suggestion() {
        let code = "int* p = NULL;";
        let diags = check_cpp_patterns(code);
        assert!(diags.iter().any(|d| d.code == "cpp.use_nullptr"));
    }
}
