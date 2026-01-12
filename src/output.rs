//! Output formatting and reporting for scan results

use crate::error::{Error, Result};
use crate::types::{ScanResults, Severity};
use serde_json;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Output formatter trait
pub trait OutputFormatter: Send + Sync {
    /// Get format name
    fn name(&self) -> &str;

    /// Format scan results
    fn format(&self, results: &ScanResults) -> Result<String>;

    /// Write formatted results to file
    fn write_to_file(&self, results: &ScanResults, path: &Path) -> Result<()> {
        let output = self.format(results)?;
        let mut file = File::create(path).map_err(|e| Error::Io(e))?;
        file.write_all(output.as_bytes())
            .map_err(|e| Error::Io(e))?;
        Ok(())
    }
}

/// JSON output formatter
#[derive(Debug)]
pub struct JsonFormatter {
    pretty: bool,
}

impl JsonFormatter {
    /// Create a new JSON formatter
    pub fn new(pretty: bool) -> Self {
        Self { pretty }
    }
}

impl OutputFormatter for JsonFormatter {
    fn name(&self) -> &str {
        "json"
    }

    fn format(&self, results: &ScanResults) -> Result<String> {
        if self.pretty {
            serde_json::to_string_pretty(results).map_err(|e| Error::Serialization(e.to_string()))
        } else {
            serde_json::to_string(results).map_err(|e| Error::Serialization(e.to_string()))
        }
    }
}

/// CSV output formatter
#[derive(Debug)]
pub struct CsvFormatter;

impl CsvFormatter {
    /// Create a new CSV formatter
    pub fn new() -> Self {
        Self
    }
}

impl Default for CsvFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputFormatter for CsvFormatter {
    fn name(&self) -> &str {
        "csv"
    }

    fn format(&self, results: &ScanResults) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str("Finding ID,Target,Template ID,Severity,Confidence,Title,Description,CVE IDs,Timestamp\n");

        // Findings
        for finding in &results.findings {
            let cve_ids = finding.cve_ids.join(";");
            let line = format!(
                "{},{},{},{},{},{},{},{},{}\n",
                finding.id,
                finding.target,
                finding.template_id,
                finding.severity,
                finding.confidence,
                Self::escape_csv(&finding.title),
                Self::escape_csv(&finding.description),
                cve_ids,
                finding.timestamp
            );
            output.push_str(&line);
        }

        Ok(output)
    }
}

impl CsvFormatter {
    fn escape_csv(s: &str) -> String {
        if s.contains(',') || s.contains('"') || s.contains('\n') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
}

/// Markdown output formatter
#[derive(Debug)]
pub struct MarkdownFormatter;

impl MarkdownFormatter {
    /// Create a new Markdown formatter
    pub fn new() -> Self {
        Self
    }
}

impl Default for MarkdownFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputFormatter for MarkdownFormatter {
    fn name(&self) -> &str {
        "markdown"
    }

    fn format(&self, results: &ScanResults) -> Result<String> {
        let mut output = String::new();

        // Title
        output.push_str("# CERT-X-GEN Security Scan Report\n\n");

        // Summary
        output.push_str("## Summary\n\n");
        output.push_str(&format!("- **Scan ID**: {}\n", results.scan_id));
        output.push_str(&format!("- **Started**: {}\n", results.started_at));
        if let Some(completed) = results.completed_at {
            output.push_str(&format!("- **Completed**: {}\n", completed));
        }
        output.push_str(&format!(
            "- **Targets Scanned**: {}\n",
            results.statistics.targets_scanned
        ));
        output.push_str(&format!(
            "- **Templates Executed**: {}\n",
            results.statistics.templates_executed
        ));
        output.push_str(&format!(
            "- **Total Findings**: {}\n\n",
            results.findings.len()
        ));

        // Findings by severity
        output.push_str("### Findings by Severity\n\n");
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let count = results
                .statistics
                .findings_by_severity
                .get(&severity)
                .unwrap_or(&0);
            output.push_str(&format!("- **{}**: {}\n", severity, count));
        }
        output.push_str("\n");

        // Findings
        if !results.findings.is_empty() {
            output.push_str("## Findings\n\n");

            for finding in &results.findings {
                output.push_str(&format!("### {} - {}\n\n", finding.severity, finding.title));
                output.push_str(&format!("- **Target**: {}\n", finding.target));
                output.push_str(&format!("- **Template**: {}\n", finding.template_id));
                output.push_str(&format!("- **Severity**: {}\n", finding.severity));
                output.push_str(&format!("- **Confidence**: {}%\n", finding.confidence));

                if !finding.cve_ids.is_empty() {
                    output.push_str(&format!("- **CVE IDs**: {}\n", finding.cve_ids.join(", ")));
                }

                output.push_str(&format!("\n**Description**: {}\n\n", finding.description));

                if let Some(ref remediation) = finding.remediation {
                    output.push_str(&format!("**Remediation**: {}\n\n", remediation));
                }

                output.push_str("---\n\n");
            }
        }

        Ok(output)
    }
}

/// SARIF output formatter (for CI/CD integration)
#[derive(Debug)]
pub struct SarifFormatter;

impl SarifFormatter {
    /// Create a new SARIF formatter
    pub fn new() -> Self {
        Self
    }
}

impl Default for SarifFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputFormatter for SarifFormatter {
    fn name(&self) -> &str {
        "sarif"
    }

    fn format(&self, results: &ScanResults) -> Result<String> {
        let mut sarif = serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CERT-X-GEN",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://cert-x-gen.io"
                    }
                },
                "results": []
            }]
        });

        let sarif_results = results
            .findings
            .iter()
            .map(|finding| {
                serde_json::json!({
                    "ruleId": finding.template_id,
                    "level": Self::severity_to_sarif_level(&finding.severity),
                    "message": {
                        "text": finding.description
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.target
                            }
                        }
                    }],
                    "properties": {
                        "severity": finding.severity.to_string(),
                        "confidence": finding.confidence,
                        "cveIds": finding.cve_ids,
                        "cweIds": finding.cwe_ids
                    }
                })
            })
            .collect::<Vec<_>>();

        sarif["runs"][0]["results"] = serde_json::json!(sarif_results);

        serde_json::to_string_pretty(&sarif).map_err(|e| Error::Serialization(e.to_string()))
    }
}

impl SarifFormatter {
    fn severity_to_sarif_level(severity: &Severity) -> &str {
        match severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }
}

/// Output manager for handling multiple output formats
#[allow(missing_debug_implementations)]
pub struct OutputManager {
    formatters: Vec<Box<dyn OutputFormatter>>,
}

impl OutputManager {
    /// Create a new output manager
    pub fn new() -> Self {
        Self {
            formatters: vec![
                Box::new(JsonFormatter::new(true)),
                Box::new(CsvFormatter::new()),
                Box::new(MarkdownFormatter::new()),
                Box::new(SarifFormatter::new()),
            ],
        }
    }

    /// Get formatter by name
    pub fn get_formatter(&self, name: &str) -> Option<&dyn OutputFormatter> {
        self.formatters
            .iter()
            .find(|f| f.name() == name)
            .map(|f| f.as_ref())
    }

    /// Write results in multiple formats
    pub fn write_results(
        &self,
        results: &ScanResults,
        base_path: &Path,
        formats: &[String],
    ) -> Result<()> {
        for format in formats {
            if let Some(formatter) = self.get_formatter(format) {
                let file_path = base_path.with_extension(format);
                tracing::info!("Writing {} output to {}", format, file_path.display());
                formatter.write_to_file(results, &file_path)?;
            } else {
                tracing::warn!("Unknown output format: {}", format);
            }
        }
        Ok(())
    }

    /// Stream results to console
    pub fn stream_finding(&self, finding: &crate::types::Finding) {
        use console::style;

        let severity_color = match finding.severity {
            Severity::Critical => style(finding.severity.to_string()).red().bold(),
            Severity::High => style(finding.severity.to_string()).red(),
            Severity::Medium => style(finding.severity.to_string()).yellow(),
            Severity::Low => style(finding.severity.to_string()).blue(),
            Severity::Info => style(finding.severity.to_string()).cyan(),
        };

        println!(
            "{} {} {} - {}",
            style("✓").green(),
            severity_color,
            style(&finding.target).dim(),
            style(&finding.title).bold()
        );
    }
}

impl Default for OutputManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn create_test_results() -> ScanResults {
        ScanResults::new(Uuid::new_v4())
    }

    #[test]
    fn test_json_formatter() {
        let formatter = JsonFormatter::new(true);
        let results = create_test_results();
        assert!(formatter.format(&results).is_ok());
    }

    #[test]
    fn test_csv_formatter() {
        let formatter = CsvFormatter::new();
        let results = create_test_results();
        let output = formatter.format(&results).unwrap();
        assert!(output.contains("Finding ID"));
    }

    #[test]
    fn test_markdown_formatter() {
        let formatter = MarkdownFormatter::new();
        let results = create_test_results();
        let output = formatter.format(&results).unwrap();
        assert!(output.contains("# CERT-X-GEN"));
    }

    #[test]
    fn test_sarif_formatter() {
        let formatter = SarifFormatter::new();
        let results = create_test_results();
        let output = formatter.format(&results).unwrap();
        assert!(output.contains("sarif-schema"));
    }
}
