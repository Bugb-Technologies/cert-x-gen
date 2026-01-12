//! Finding output schema validation
//!
//! This module validates that template code produces output conforming to the
//! CERT-X-GEN Finding JSON schema. It checks for required fields and proper structure.

use super::TemplateDiagnostic;
use anyhow::Result;

/// Required fields in a Finding object
pub const FINDING_REQUIRED_FIELDS: &[&str] = &[
    "template_id",
    "template_name", 
    "severity",
    "host",
    "matched_at",
];

/// Optional but recommended fields
#[allow(dead_code)]
pub const FINDING_RECOMMENDED_FIELDS: &[&str] = &[
    "description",
    "matched_value",
    "timestamp",
    "tags",
];

/// Valid severity values
pub const VALID_SEVERITIES: &[&str] = &[
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "informational",
];

/// Validator for Finding output schema
#[derive(Debug)]
pub struct FindingSchemaValidator;

impl FindingSchemaValidator {
    /// Create a new FindingSchemaValidator instance
    pub fn new() -> Self {
        Self
    }

    /// Validate that code appears to produce valid Finding JSON
    pub fn validate(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        let mut diagnostics = Vec::new();

        // Check for findings array/list structure
        diagnostics.extend(self.check_findings_structure(code));

        // Check for required fields
        diagnostics.extend(self.check_required_fields(code));

        // Check for proper severity usage
        diagnostics.extend(self.check_severity_values(code));

        // Check for timestamp format
        diagnostics.extend(self.check_timestamp_format(code));

        Ok(diagnostics)
    }

    /// Check for findings array structure
    fn check_findings_structure(&self, code: &str) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        // Look for patterns indicating findings array
        let has_findings_array = code.contains("\"findings\"")
            || code.contains("'findings'")
            || code.contains("findings:")  // YAML style
            || code.contains("findings =")
            || code.contains("findings=")
            || code.contains("Findings")
            || code.contains("FINDINGS");

        if !has_findings_array {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "schema.no_findings_array",
                    "No 'findings' array detected. CERT-X-GEN expects output with a 'findings' array. \
                     Structure: {\"findings\": [{...}], \"metadata\": {...}}",
                )
            );
        }

        diagnostics
    }

    /// Check for required Finding fields in the code
    fn check_required_fields(&self, code: &str) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();
        let code_lower = code.to_lowercase();

        // Check for each required field
        for field in FINDING_REQUIRED_FIELDS {
            // Look for various ways the field might appear
            let field_patterns = vec![
                format!("\"{}\"", field),
                format!("'{}'", field),
                format!("{} =", field),
                format!("{}:", field),
                field.to_uppercase(),
            ];

            let has_field = field_patterns.iter().any(|p| code_lower.contains(&p.to_lowercase()));

            if !has_field {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        format!("schema.missing_{}", field),
                        format!(
                            "Required Finding field '{}' not found in template. \
                             Ensure findings include this field.",
                            field
                        ),
                    )
                );
            }
        }

        diagnostics
    }

    /// Check for proper severity value usage
    fn check_severity_values(&self, code: &str) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        // Look for severity assignments with invalid values
        let severity_patterns = vec![
            r#""severity"\s*:\s*"([^"]+)""#,
            r#"'severity'\s*:\s*'([^']+)'"#,
            r#"severity\s*=\s*"([^"]+)""#,
            r#"severity\s*=\s*'([^']+)'"#,
            r#"SEVERITY\s*=\s*"([^"]+)""#,
        ];

        for pattern_str in severity_patterns {
            if let Ok(re) = regex::Regex::new(pattern_str) {
                for caps in re.captures_iter(code) {
                    if let Some(severity) = caps.get(1) {
                        let sev = severity.as_str().to_lowercase();
                        if !VALID_SEVERITIES.contains(&sev.as_str()) {
                            // Find line number
                            let line_num = code.lines()
                                .enumerate()
                                .find(|(_, line)| line.contains(severity.as_str()))
                                .map(|(i, _)| i + 1);

                            let mut diag = TemplateDiagnostic::warning(
                                "schema.invalid_severity",
                                format!(
                                    "Invalid severity value '{}'. Valid values: {}",
                                    severity.as_str(),
                                    VALID_SEVERITIES.join(", ")
                                ),
                            );

                            if let Some(line) = line_num {
                                diag = diag.with_location(line, None);
                            }

                            diagnostics.push(diag);
                        }
                    }
                }
            }
        }

        diagnostics
    }

    /// Check for proper timestamp format
    fn check_timestamp_format(&self, code: &str) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        // Look for timestamp field
        if code.contains("timestamp") || code.contains("TIMESTAMP") {
            // Check for ISO 8601 format patterns
            let has_iso_format = code.contains("isoformat()")  // Python
                || code.contains("toISOString()")  // JavaScript
                || code.contains("RFC3339")  // Go/Rust
                || code.contains("ISO8601")
                || code.contains("%Y-%m-%dT%H:%M:%S")  // strftime
                || code.contains("datetime.now")
                || code.contains("new Date()");

            if !has_iso_format {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "schema.timestamp_format",
                        "Timestamp field found but no ISO 8601 formatting detected. \
                         Use ISO 8601 format (e.g., 2024-01-15T10:30:00Z) for timestamps.",
                    )
                );
            }
        }

        diagnostics
    }
}

impl Default for FindingSchemaValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_findings_structure_detection() {
        let validator = FindingSchemaValidator::new();

        // Has findings
        let code = r#"{"findings": [], "metadata": {}}"#;
        let diags = validator.check_findings_structure(code);
        assert!(diags.is_empty());

        // Missing findings
        let code = "print('hello')";
        let diags = validator.check_findings_structure(code);
        assert!(!diags.is_empty());
    }

    #[test]
    fn test_severity_validation() {
        let validator = FindingSchemaValidator::new();

        // Valid severity
        let code = r#""severity": "high""#;
        let diags = validator.check_severity_values(code);
        assert!(diags.is_empty());

        // Invalid severity
        let code = r#""severity": "super_critical""#;
        let diags = validator.check_severity_values(code);
        assert!(!diags.is_empty());
    }
}
