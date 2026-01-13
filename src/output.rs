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

/// HTML output formatter
#[derive(Debug)]
pub struct HtmlFormatter;

impl HtmlFormatter {
    /// Create a new HTML formatter
    pub fn new() -> Self {
        Self
    }
}

impl Default for HtmlFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputFormatter for HtmlFormatter {
    fn name(&self) -> &str {
        "html"
    }

    fn format(&self, results: &ScanResults) -> Result<String> {
        let mut html = String::new();

        // HTML header (Monochrome + Teal)
        html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CERT-X-GEN Security Scan Report</title>
    <style>
/* =========================
    Monochrome + Teal
   ========================= */
:root {
  --font-ui: -apple-system, system-ui, sans-serif;
  --font-mono: Menlo, Monaco, "Courier New", monospace;

  --bg-app: #121212;
  --bg-panel: #1a1a1a;
  --bg-panel-2: #222222;
  --bg-panel-3: #0d0d0d;

  --fg: #ffffff;
  --fg-muted: #b3b3b3;
  --fg-subtle: #808080;
  --fg-ghost: #5c5c5c;
  --fg-ghost-2: #404040;

  --teal: #14b8a6;
  --teal-light: #2dd4bf;
  --teal-dark: #0d9488;
  --teal-muted: #5eead4;

  --border: #2a2a2a;
  --border-2: #333333;

  --shadow-sm: 0 1px 3px rgba(0,0,0,0.4);
  --shadow-md: 0 8px 24px rgba(0,0,0,0.5);

  --r-sm: 8px;
  --r-md: 12px;
  --r-lg: 16px;

  --s-1: 6px;
  --s-2: 10px;
  --s-3: 14px;
  --s-4: 18px;
  --s-5: 24px;
  --s-6: 32px;
}

* { box-sizing: border-box; }

html, body {
  margin: 0;
  padding: 0;
  background: radial-gradient(ellipse 1200px 600px at 15% 0%, rgba(20,184,166,0.08), transparent 50%),
              radial-gradient(ellipse 800px 400px at 85% 5%, rgba(20,184,166,0.05), transparent 50%),
              var(--bg-app);
  color: var(--fg);
  font-family: var(--font-ui);
  font-size: 14px;
  line-height: 1.5;
}

a { color: var(--teal-light); text-decoration: none; }
a:hover { text-decoration: underline; }

.container {
  max-width: 1100px;
  margin: 0 auto;
  padding: var(--s-6) var(--s-5) 56px;
}

/* =========================
   Header
   ========================= */
.report-hero {
  background: linear-gradient(135deg, rgba(20,184,166,0.12) 0%, rgba(20,184,166,0.03) 100%),
              var(--bg-panel);
  border: 1px solid rgba(20,184,166,0.2);
  border-radius: var(--r-lg);
  box-shadow: var(--shadow-md);
  padding: var(--s-6);
  position: relative;
  overflow: hidden;
}

.report-hero::before {
  content: "";
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(20,184,166,0.4), transparent);
}

.report-title {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 26px;
  line-height: 34px;
  font-weight: 600;
  margin: 0;
  color: var(--fg);
}

.report-subtitle {
  margin: 8px 0 0;
  color: var(--fg-subtle);
  font-size: 13px;
  font-family: var(--font-mono);
}

.meta-row {
  margin-top: 16px;
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.meta-pill {
  background: rgba(255,255,255,0.04);
  border: 1px solid var(--border-2);
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 12px;
  color: var(--fg-muted);
}

/* =========================
   Stats Grid
   ========================= */
.grid {
  display: grid;
  gap: var(--s-4);
}

.grid.stats {
  grid-template-columns: repeat(4, 1fr);
  margin-top: var(--s-5);
}

.card {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--r-md);
  padding: var(--s-5);
  text-align: center;
}

.stat-value {
  font-size: 36px;
  font-weight: 700;
  color: var(--fg);
  margin: 0;
}

.stat-label {
  margin-top: 6px;
  color: var(--fg-ghost);
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* =========================
   Severity Grid (Monochrome)
   ========================= */
.grid.severity {
  grid-template-columns: repeat(5, 1fr);
  margin-top: var(--s-4);
}

.sev {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--r-md);
  padding: var(--s-4) var(--s-3);
  text-align: center;
  position: relative;
}

.sev .sev-count {
  font-size: 28px;
  font-weight: 800;
  color: var(--fg);
  margin: 0;
}

.sev .sev-label {
  margin-top: 4px;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Teal accent for any severity with findings, grey for zero */
.sev .sev-count { color: var(--fg-ghost); }
.sev .sev-label { color: var(--fg-ghost); }

.sev.has-findings .sev-count { color: var(--teal); }
.sev.has-findings .sev-label { color: var(--teal-muted); }
.sev.has-findings { border-color: rgba(20,184,166,0.3); background: rgba(20,184,166,0.05); }

/* =========================
   Section
   ========================= */
.section {
  margin-top: var(--s-6);
}

.section-title {
  margin: 0 0 var(--s-3);
  font-size: 16px;
  font-weight: 600;
  color: var(--fg);
  display: flex;
  align-items: center;
  gap: 8px;
}

.hr {
  height: 1px;
  background: var(--border);
  margin: 0 0 var(--s-4);
}

/* =========================
   Finding Card
   ========================= */
.finding {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--r-md);
  overflow: hidden;
  margin-bottom: var(--s-4);
}

.finding-head {
  padding: var(--s-4) var(--s-5);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--s-4);
  border-bottom: 1px solid var(--border);
  background: rgba(255,255,255,0.01);
}

.finding-title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
  color: var(--fg);
}

.badge {
  font-size: 10px;
  letter-spacing: 0.8px;
  font-weight: 700;
  padding: 6px 12px;
  border-radius: 4px;
  text-transform: uppercase;
  flex-shrink: 0;
}

/* All badges use teal or grey */
.badge.critical { 
  background: rgba(20,184,166,0.15); 
  color: var(--teal-light); 
  border: 1px solid rgba(20,184,166,0.3);
}
.badge.high { 
  background: rgba(255,255,255,0.06); 
  color: var(--fg-muted); 
  border: 1px solid var(--border-2);
}
.badge.medium { 
  background: rgba(255,255,255,0.04); 
  color: var(--fg-subtle); 
  border: 1px solid var(--border);
}
.badge.low { 
  background: rgba(255,255,255,0.03); 
  color: var(--fg-ghost); 
  border: 1px solid var(--border);
}
.badge.info { 
  background: rgba(255,255,255,0.02); 
  color: var(--fg-ghost); 
  border: 1px solid var(--border);
}

.finding-body {
  padding: var(--s-5);
}

.kv-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--s-4);
  margin-bottom: var(--s-4);
}

.kv .k { 
  color: var(--fg-ghost); 
  font-size: 11px; 
  text-transform: uppercase; 
  letter-spacing: 0.5px; 
}
.kv .v { 
  margin-top: 4px; 
  font-weight: 500; 
  color: var(--fg); 
  font-size: 13px; 
}

.desc {
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: var(--r-sm);
  padding: var(--s-4);
  color: var(--fg-muted);
  font-size: 13px;
  line-height: 1.6;
}

.desc strong { color: var(--fg); }

/* Evidence Block */
.evidence {
  margin-top: var(--s-4);
  background: var(--bg-panel-3);
  border: 1px solid var(--border);
  border-radius: var(--r-sm);
  overflow: hidden;
}

.evidence-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 14px;
  background: rgba(255,255,255,0.03);
  border-bottom: 1px solid var(--border);
  color: var(--fg-ghost);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.evidence pre {
  margin: 0;
  padding: 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.6;
  color: var(--fg-muted);
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 300px;
}

/* Tags */
.tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: var(--s-3);
}

.tag {
  background: rgba(20,184,166,0.1);
  border: 1px solid rgba(20,184,166,0.2);
  color: var(--teal-muted);
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
}

/* References */
.refs {
  margin-top: var(--s-3);
  padding-top: var(--s-3);
  border-top: 1px solid var(--border);
}

.refs-title {
  color: var(--fg-ghost);
  font-size: 11px;
  margin-bottom: 6px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.refs a {
  display: block;
  font-size: 12px;
  margin-top: 4px;
  word-break: break-all;
  color: var(--teal-light);
}

/* No Findings */
.no-findings {
  text-align: center;
  padding: 60px 20px;
  color: var(--fg-subtle);
}

.no-findings .icon { font-size: 48px; margin-bottom: 16px; opacity: 0.5; }
.no-findings h3 { color: var(--fg-muted); margin-bottom: 8px; font-weight: 500; }

/* Footer */
.footer {
  margin-top: var(--s-6);
  color: var(--fg-ghost);
  text-align: center;
  font-size: 12px;
  padding-top: var(--s-5);
  border-top: 1px solid var(--border);
}

/* Responsive */
@media (max-width: 900px) {
  .grid.stats { grid-template-columns: repeat(2, 1fr); }
  .grid.severity { grid-template-columns: repeat(3, 1fr); }
  .kv-grid { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 540px) {
  .report-title { font-size: 20px; }
  .grid.stats, .grid.severity { grid-template-columns: 1fr 1fr; }
  .kv-grid { grid-template-columns: 1fr; }
  .finding-head { flex-direction: column; align-items: flex-start; gap: 10px; }
}
    </style>
</head>
<body>
    <div class="container">
"#);

        // Header / Hero
        html.push_str(&format!(r#"
        <div class="report-hero">
            <h1 class="report-title">🛡️ CERT-X-GEN Security Scan Report</h1>
            <p class="report-subtitle">Scan ID: {}</p>
            <div class="meta-row">
                <span class="meta-pill">📅 {}</span>
                <span class="meta-pill">⏱️ {:.2}s duration</span>
                <span class="meta-pill">🔧 v{}</span>
            </div>
        </div>
"#, 
            results.scan_id,
            results.started_at.format("%Y-%m-%d %H:%M:%S UTC"),
            results.statistics.duration.as_secs_f64(),
            env!("CARGO_PKG_VERSION")
        ));

        // Stats Grid
        html.push_str(&format!(r#"
        <div class="grid stats">
            <div class="card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Targets Scanned</div>
            </div>
            <div class="card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Templates Executed</div>
            </div>
            <div class="card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="card">
                <div class="stat-value">{:.2}s</div>
                <div class="stat-label">Duration</div>
            </div>
        </div>
"#, 
            results.statistics.targets_scanned,
            results.statistics.templates_executed,
            results.findings.len(),
            results.statistics.duration.as_secs_f64()
        ));

        // Severity Grid
        let critical = results.statistics.findings_by_severity.get(&Severity::Critical).unwrap_or(&0);
        let high = results.statistics.findings_by_severity.get(&Severity::High).unwrap_or(&0);
        let medium = results.statistics.findings_by_severity.get(&Severity::Medium).unwrap_or(&0);
        let low = results.statistics.findings_by_severity.get(&Severity::Low).unwrap_or(&0);
        let info = results.statistics.findings_by_severity.get(&Severity::Info).unwrap_or(&0);

        // Add "has-findings" class for teal highlighting
        let critical_class = if *critical > 0 { "sev critical has-findings" } else { "sev critical" };
        let high_class = if *high > 0 { "sev high has-findings" } else { "sev high" };
        let medium_class = if *medium > 0 { "sev medium has-findings" } else { "sev medium" };
        let low_class = if *low > 0 { "sev low has-findings" } else { "sev low" };
        let info_class = if *info > 0 { "sev info has-findings" } else { "sev info" };

        html.push_str(&format!(r#"
        <div class="grid severity">
            <div class="{}">
                <div class="sev-count">{}</div>
                <div class="sev-label">Critical</div>
            </div>
            <div class="{}">
                <div class="sev-count">{}</div>
                <div class="sev-label">High</div>
            </div>
            <div class="{}">
                <div class="sev-count">{}</div>
                <div class="sev-label">Medium</div>
            </div>
            <div class="{}">
                <div class="sev-count">{}</div>
                <div class="sev-label">Low</div>
            </div>
            <div class="{}">
                <div class="sev-count">{}</div>
                <div class="sev-label">Info</div>
            </div>
        </div>
"#, critical_class, critical, high_class, high, medium_class, medium, low_class, low, info_class, info));

        // Findings Section
        html.push_str(r#"
        <div class="section">
            <h2 class="section-title">📋 Findings</h2>
            <div class="hr"></div>
"#);

        if results.findings.is_empty() {
            html.push_str(r#"
            <div class="no-findings">
                <div class="icon">✅</div>
                <h3>No vulnerabilities found</h3>
                <p>The scan completed successfully with no security issues detected.</p>
            </div>
"#);
        } else {
            for finding in &results.findings {
                let severity_class = finding.severity.to_string().to_lowercase();
                
                // Build evidence section
                let evidence_html = if let Some(ref response) = finding.evidence.response {
                    let truncated = if response.len() > 1000 {
                        format!("{}...\n[truncated]", &response[..1000])
                    } else {
                        response.to_string()
                    };
                    format!(r#"
                    <div class="evidence">
                        <div class="evidence-head">
                            <span>Evidence</span>
                            <span>Raw output</span>
                        </div>
                        <pre>{}</pre>
                    </div>"#, Self::escape_html(&truncated))
                } else {
                    String::new()
                };

                // Build tags section
                let tags_html = if !finding.tags.is_empty() {
                    let tags: String = finding.tags.iter()
                        .map(|t| format!(r#"<span class="tag">{}</span>"#, Self::escape_html(t)))
                        .collect::<Vec<_>>()
                        .join("");
                    format!(r#"<div class="tags">{}</div>"#, tags)
                } else {
                    String::new()
                };

                // Build references section
                let refs_html = if !finding.references.is_empty() {
                    let refs: String = finding.references.iter()
                        .map(|r| format!(r#"<a href="{}" target="_blank">{}</a>"#, 
                            Self::escape_html(r), Self::escape_html(r)))
                        .collect::<Vec<_>>()
                        .join("");
                    format!(r#"
                    <div class="refs">
                        <div class="refs-title">References</div>
                        {}
                    </div>"#, refs)
                } else {
                    String::new()
                };

                // Build CWE/CVE info
                let vuln_ids: Vec<String> = finding.cwe_ids.iter()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .chain(finding.cve_ids.iter().map(|s| s.to_string()))
                    .collect();
                let vuln_html = if !vuln_ids.is_empty() {
                    format!(r#"
                        <div class="kv">
                            <div class="k">Vulnerability IDs</div>
                            <div class="v">{}</div>
                        </div>"#, vuln_ids.join(", "))
                } else {
                    String::new()
                };

                html.push_str(&format!(r#"
            <article class="finding">
                <div class="finding-head">
                    <h3 class="finding-title">{}</h3>
                    <span class="badge {}">{}</span>
                </div>
                <div class="finding-body">
                    <div class="kv-grid">
                        <div class="kv">
                            <div class="k">Target</div>
                            <div class="v">{}</div>
                        </div>
                        <div class="kv">
                            <div class="k">Template</div>
                            <div class="v">{}</div>
                        </div>
                        <div class="kv">
                            <div class="k">Confidence</div>
                            <div class="v">{}%</div>
                        </div>
                        <div class="kv">
                            <div class="k">Timestamp</div>
                            <div class="v">{}</div>
                        </div>
                        {}
                    </div>
                    <div class="desc">
                        <strong>Description:</strong> {}
                    </div>
                    {}
                    {}
                    {}
                </div>
            </article>
"#,
                    Self::escape_html(&finding.title),
                    severity_class,
                    finding.severity,
                    Self::escape_html(&finding.target),
                    Self::escape_html(&finding.template_id),
                    finding.confidence,
                    finding.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    vuln_html,
                    Self::escape_html(&finding.description),
                    tags_html,
                    evidence_html,
                    refs_html
                ));
            }
        }

        html.push_str(r#"
        </div>
"#);

        // Footer
        html.push_str(&format!(r#"
        <div class="footer">
            Generated by CERT-X-GEN v{} | {}
        </div>
    </div>
</body>
</html>
"#, env!("CARGO_PKG_VERSION"), results.started_at.format("%Y-%m-%d %H:%M:%S UTC")));

        Ok(html)
    }
}

impl HtmlFormatter {
    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
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
                Box::new(HtmlFormatter::new()),
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

    #[test]
    fn test_html_formatter() {
        let formatter = HtmlFormatter::new();
        let results = create_test_results();
        let output = formatter.format(&results).unwrap();
        assert!(output.contains("<!DOCTYPE html>"));
        assert!(output.contains("CERT-X-GEN Security Scan Report"));
    }
}
