//! Shell script-specific template validation

use super::TemplateDiagnostic;
use anyhow::Result;

pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Check for shebang
    if let Some(first_line) = code.lines().next() {
        if !first_line.starts_with("#!") {
            diagnostics.push(TemplateDiagnostic::warning(
                "shell.missing_shebang",
                "Shell script should start with shebang (#!/bin/bash or #!/bin/sh)",
            ));
        }
    }

    // Check for CERT-X-GEN JSON contract structure
    diagnostics.extend(check_json_contract(code));

    // Check for problematic output statements
    diagnostics.extend(check_output_statements(code));

    // Check for ANSI colors/escape codes (will break JSON)
    diagnostics.extend(check_ansi_colors(code));

    // Check for error handling
    if !code.contains("set -e") && !code.contains("set -o errexit") {
        diagnostics.push(TemplateDiagnostic::info(
            "shell.no_error_handling",
            "Consider using 'set -e' for better error handling",
        ));
    }

    // Check for target host usage
    if !code.contains("CERT_X_GEN_TARGET_HOST") {
        diagnostics.push(TemplateDiagnostic::warning(
            "shell.missing_target_host",
            "Shell template should use CERT_X_GEN_TARGET_HOST environment variable",
        ));
    }

    // Check for template metadata variables
    diagnostics.extend(check_metadata_variables(code));

    Ok(diagnostics)
}

/// Check for CERT-X-GEN JSON contract structure
fn check_json_contract(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Must have "findings" field in JSON output
    if !code.contains("\"findings\"") && !code.contains("'findings'") {
        diagnostics.push(TemplateDiagnostic::error(
            "shell.missing_findings_field",
            "Shell template must output JSON with 'findings' field. \
             Expected format: {\"findings\": [...], \"metadata\": {...}}",
        ));
    }

    // Must have "metadata" field in JSON output
    if !code.contains("\"metadata\"") && !code.contains("'metadata'") {
        diagnostics.push(TemplateDiagnostic::error(
            "shell.missing_metadata_field",
            "Shell template must output JSON with 'metadata' field. \
             Expected format: {\"findings\": [...], \"metadata\": {...}}",
        ));
    }

    // Should use cat <<EOF or similar for JSON output
    let has_heredoc = code.contains("cat <<EOF") || code.contains("cat << EOF") 
        || code.contains("cat <<'EOF'") || code.contains("cat <<\"EOF\"");
    
    if !has_heredoc && !code.contains("jq") {
        diagnostics.push(TemplateDiagnostic::warning(
            "shell.no_heredoc_json",
            "Shell templates should use 'cat <<EOF' heredoc for clean JSON output. \
             This prevents mixing human-readable output with JSON.",
        ));
    }

    // Check if JSON output is at the end (last significant code block)
    let lines: Vec<&str> = code.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .collect();
    
    if let Some(last_lines) = lines.last_chunk::<20>() {
        let end_block = last_lines.join("\n");
        if !end_block.contains("cat <<") && !end_block.contains("echo '{") {
            diagnostics.push(TemplateDiagnostic::warning(
                "shell.json_not_at_end",
                "JSON output should be at the end of the script. \
                 Ensure no other output comes after the JSON block.",
            ));
        }
    }

    diagnostics
}

/// Check for problematic output statements that break JSON
fn check_output_statements(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    // Patterns that indicate human-readable output
    let problematic_patterns = vec![
        ("echo -e", "echo with escape sequences (colors) detected"),
        ("printf.*\\\\033", "ANSI escape sequences detected"),
        ("log_finding", "log_finding function may output human text instead of collecting JSON"),
        ("print_remediation", "print_remediation may output text before JSON"),
        ("usage()", "usage() function called may output help text"),
    ];

    for (pattern_str, msg) in problematic_patterns {
        if let Ok(re) = regex::Regex::new(pattern_str) {
            if re.is_match(code) {
                // Find first occurrence line
                for (line_num, line) in code.lines().enumerate() {
                    if re.is_match(line) {
                        diagnostics.push(
                            TemplateDiagnostic::warning(
                                "shell.human_readable_output",
                                format!("{}: This may output text that breaks JSON parsing", msg),
                            )
                            .with_location(line_num + 1, None),
                        );
                        break; // Only report first occurrence
                    }
                }
            }
        }
    }

    // Check for direct echo/print statements outside heredoc
    let mut in_heredoc = false;
    for (line_num, line) in code.lines().enumerate() {
        let trimmed = line.trim();
        
        // Track heredoc boundaries
        if trimmed.contains("cat <<") {
            in_heredoc = true;
            continue;
        }
        if in_heredoc && trimmed == "EOF" {
            in_heredoc = false;
            continue;
        }
        
        // Check for echo/printf outside heredoc (but allow in functions that build JSON)
        if !in_heredoc && !trimmed.starts_with('#') {
            if (trimmed.starts_with("echo ") || trimmed.contains("printf ")) 
                && !trimmed.contains("FINDINGS=") 
                && !trimmed.contains("$(") 
                && !line.contains("add_finding") {
                
                // Skip if it's clearly building JSON
                if !trimmed.contains("\"findings\"") 
                    && !trimmed.contains("\"metadata\"")
                    && !trimmed.contains("template_id") {
                    
                    diagnostics.push(
                        TemplateDiagnostic::warning(
                            "shell.echo_outside_json",
                            "Echo/printf statement outside JSON heredoc detected. \
                             This will output text before/after JSON and cause parsing errors. \
                             Collect findings in variables instead.",
                        )
                        .with_location(line_num + 1, None),
                    );
                }
            }
        }
    }

    diagnostics
}

/// Check for ANSI color codes that break JSON
fn check_ansi_colors(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    // Check for color variable definitions
    let color_patterns = vec![
        ("RED=", "RED color variable"),
        ("GREEN=", "GREEN color variable"),
        ("YELLOW=", "YELLOW color variable"),
        ("NC=", "NC (no color) variable"),
        ("\\033[", "ANSI escape code"),
        ("\\e[", "ANSI escape code"),
    ];

    for (pattern, name) in color_patterns {
        if code.contains(pattern) {
            if let Some(line_num) = code.lines().position(|l| l.contains(pattern)) {
                diagnostics.push(
                    TemplateDiagnostic::error(
                        "shell.ansi_colors",
                        format!("{} detected. ANSI color codes will break JSON output. \
                                Remove all color formatting from shell templates.", name),
                    )
                    .with_location(line_num + 1, None),
                );
                break; // Only report once
            }
        }
    }

    // Check for ASCII art / box drawing
    if code.contains("╔") || code.contains("║") || code.contains("═") {
        if let Some(line_num) = code.lines().position(|l| 
            l.contains("╔") || l.contains("║") || l.contains("═")
        ) {
            diagnostics.push(
                TemplateDiagnostic::error(
                    "shell.ascii_art",
                    "ASCII art/box drawing characters detected. \
                     These will be output to stdout and break JSON parsing. \
                     Remove all decorative output.",
                )
                .with_location(line_num + 1, None),
            );
        }
    }

    diagnostics
}

/// Check for required metadata variables
fn check_metadata_variables(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();

    let required_vars = vec![
        ("TEMPLATE_ID", "Template ID is required for findings"),
        ("TEMPLATE_NAME", "Template name is required for metadata"),
        ("SEVERITY", "Severity is required for findings"),
    ];

    for (var, msg) in required_vars {
        if !code.contains(var) {
            diagnostics.push(TemplateDiagnostic::warning(
                format!("shell.missing_{}", var.to_lowercase()),
                msg,
            ));
        }
    }

    // Check if metadata is used in JSON output
    if code.contains("\"metadata\"") {
        if !code.contains("${TEMPLATE_ID}") && !code.contains("$TEMPLATE_ID") {
            diagnostics.push(TemplateDiagnostic::warning(
                "shell.metadata_not_used",
                "Metadata field defined but TEMPLATE_ID not interpolated in JSON output",
            ));
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_ansi_colors() {
        let code = r#"#!/bin/bash
RED='\033[0;31m'
echo -e "${RED}Error${NC}"
"#;
        let diags = validate(code).unwrap();
        assert!(diags.iter().any(|d| d.code == "shell.ansi_colors"));
    }

    #[test]
    fn test_detects_missing_json_contract() {
        let code = r#"#!/bin/bash
echo "Some output"
"#;
        let diags = validate(code).unwrap();
        assert!(diags.iter().any(|d| d.code.contains("missing_findings_field")));
    }

    #[test]
    fn test_valid_json_output() {
        let code = r#"#!/bin/bash
set -e
HOST="${CERT_X_GEN_TARGET_HOST}"
TEMPLATE_ID="test"
TEMPLATE_NAME="Test"
SEVERITY="high"

cat <<EOF
{
  "findings": [],
  "metadata": {
    "id": "${TEMPLATE_ID}",
    "name": "${TEMPLATE_NAME}",
    "severity": "${SEVERITY}",
    "language": "shell"
  }
}
EOF
"#;
        let diags = validate(code).unwrap();
        // Should have minimal warnings
        let errors: Vec<_> = diags.iter().filter(|d| d.severity == super::super::DiagnosticSeverity::Error).collect();
        assert!(errors.is_empty(), "Should have no errors for valid template");
    }

    #[test]
    fn test_detects_echo_outside_json() {
        let code = r#"#!/bin/bash
echo "Testing endpoint..."
cat <<EOF
{"findings": []}
EOF
"#;
        let diags = validate(code).unwrap();
        assert!(diags.iter().any(|d| d.code == "shell.echo_outside_json"));
    }
}
