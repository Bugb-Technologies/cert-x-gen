//! Common utilities for template engines

#![allow(missing_docs)]

use crate::error::{Error, Result};
use crate::types::{Context, Finding, Severity, Target, TemplateLanguage, TemplateMetadata};
use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

// ============================================================================
// METADATA PARSING FROM COMMENT HEADERS
// ============================================================================

/// A single context variable declaration parsed from `@context_vars`.
///
/// Format in header: `name:required` or `name[]:optional`
/// The `[]` suffix indicates the variable is a JSON array at runtime.
#[derive(Debug, Clone, Default)]
pub struct ContextVarSpec {
    /// Variable name as it appears in the CERT_X_GEN_CONTEXT JSON dict
    pub name: String,
    /// True when the name ends with `[]` — value is a JSON array
    pub is_array: bool,
    /// True = template cannot operate without this variable
    pub required: bool,
}

impl ContextVarSpec {
    /// Parse a single spec token such as `auth_token:required` or `endpoints[]:optional`
    pub fn parse(token: &str) -> Option<Self> {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }
        let (raw_name, qualifier) = if let Some(pos) = token.find(':') {
            let (n, q) = token.split_at(pos);
            (n.trim(), q.trim_start_matches(':').trim())
        } else {
            (token, "optional")
        };
        let is_array = raw_name.ends_with("[]");
        let name = raw_name.trim_end_matches("[]").to_string();
        if name.is_empty() {
            return None;
        }
        let required = matches!(qualifier.to_lowercase().as_str(), "required" | "req" | "r");
        Some(Self {
            name,
            is_array,
            required,
        })
    }
}

/// Parsed metadata extracted from template comment headers
#[derive(Debug, Clone, Default)]
pub struct ParsedMetadata {
    pub id: Option<String>,
    pub name: Option<String>,
    pub author: Option<String>,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub cwe: Vec<String>,
    pub cvss: Option<f32>,
    pub references: Vec<String>,
    pub confidence: Option<u8>,
    pub version: Option<String>,

    // --- Parameterisation & routing fields (Task 3a) ---
    /// Context variables the template needs via `--context` / `CERT_X_GEN_CONTEXT`.
    /// Declared as: `# @context_vars: auth_token:required, endpoints[]:required, user_id:optional`
    pub context_vars: Vec<ContextVarSpec>,

    /// Coarse vulnerability class for pipeline routing (maps to Bravos `VulnClass`).
    /// Declared as: `# @vuln_class: idor`
    pub vuln_class: Option<String>,

    /// Fine-grained hypothesis routing tags consumed by Bravos `TemplateMatcher`.
    /// Declared as: `# @hypothesis_tags: idor, bola, horizontal-access`
    pub hypothesis_tags: Vec<String>,

    /// Batch group — the context-shape this template belongs to.
    /// Declared as: `# @batch_group: auth-context`
    pub batch_group: Option<String>,

    /// Whether the template can self-acquire missing context via probing.
    /// Declared as: `# @auto_probe: true`
    pub auto_probe: bool,

    /// The template exits non-zero on purpose; cxg must keep its stdout.
    /// Declared as: `# @allow_nonzero_exit: true`
    pub allow_nonzero_exit: bool,
}

impl ParsedMetadata {
    /// Check if any metadata was found
    pub fn has_metadata(&self) -> bool {
        self.id.is_some()
            || self.name.is_some()
            || self.author.is_some()
            || self.severity.is_some()
            || self.description.is_some()
            || !self.tags.is_empty()
    }

    /// Check if all required fields are present
    pub fn has_required_fields(&self) -> bool {
        self.id.is_some()
            && self.name.is_some()
            && self.author.is_some()
            && self.severity.is_some()
            && self.description.is_some()
            && !self.tags.is_empty()
    }

    /// Get list of missing required fields
    pub fn missing_required_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.id.is_none() {
            missing.push("@id");
        }
        if self.name.is_none() {
            missing.push("@name");
        }
        if self.author.is_none() {
            missing.push("@author");
        }
        if self.severity.is_none() {
            missing.push("@severity");
        }
        if self.description.is_none() {
            missing.push("@description");
        }
        if self.tags.is_empty() {
            missing.push("@tags");
        }
        missing
    }
}

/// Parse metadata from template comment headers
///
/// Looks for @field: annotations in the first 50 lines of the file.
/// Supports all comment styles: #, //, /*, *, //!
///
/// # Example
/// ```ignore
/// # @id: mongodb-unauthenticated
/// # @name: MongoDB Unauthenticated Access
/// # @author: CERT-X-GEN Security Team
/// # @severity: critical
/// # @description: Detects MongoDB without authentication
/// # @tags: mongodb, database, unauthenticated
/// ```
pub fn parse_metadata_from_comments(content: &str) -> ParsedMetadata {
    let mut metadata = ParsedMetadata::default();

    // Only scan first 50 lines for metadata
    let header_lines: Vec<&str> = content.lines().take(50).collect();
    let header_content = header_lines.join("\n");

    // Extract each field
    metadata.id = extract_metadata_field(&header_content, "id");
    metadata.name = extract_metadata_field(&header_content, "name");
    metadata.author = extract_metadata_field(&header_content, "author");
    metadata.severity = extract_metadata_field(&header_content, "severity");
    metadata.description = extract_metadata_field(&header_content, "description");
    metadata.version = extract_metadata_field(&header_content, "version");

    // Parse tags (comma-separated)
    if let Some(tags_str) = extract_metadata_field(&header_content, "tags") {
        metadata.tags = parse_comma_separated(&tags_str);
    }

    // Parse CWE (can be comma-separated or single)
    if let Some(cwe_str) = extract_metadata_field(&header_content, "cwe") {
        metadata.cwe = parse_comma_separated(&cwe_str);
    }

    // Parse references (can be comma-separated or single URL)
    if let Some(refs_str) = extract_metadata_field(&header_content, "references") {
        metadata.references = parse_comma_separated(&refs_str);
    }

    // Parse CVSS score
    if let Some(cvss_str) = extract_metadata_field(&header_content, "cvss") {
        metadata.cvss = cvss_str.parse::<f32>().ok();
    }

    // Parse confidence
    if let Some(conf_str) = extract_metadata_field(&header_content, "confidence") {
        metadata.confidence = conf_str.parse::<u8>().ok();
    }

    // If no @tags found, try fallback extraction from code
    if metadata.tags.is_empty() {
        metadata.tags = extract_tags_from_code(content);
    }

    // --- Parameterisation & routing fields ---

    // @context_vars: auth_token:required, endpoints[]:required, user_id:optional
    if let Some(cv_str) = extract_metadata_field(&header_content, "context_vars") {
        metadata.context_vars = cv_str
            .split(',')
            .filter_map(ContextVarSpec::parse)
            .collect();
    }

    // @vuln_class: idor
    metadata.vuln_class = extract_metadata_field(&header_content, "vuln_class");

    // @hypothesis_tags: idor, bola, horizontal-access
    if let Some(ht_str) = extract_metadata_field(&header_content, "hypothesis_tags") {
        metadata.hypothesis_tags = ht_str
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
    }

    // @batch_group: auth-context
    metadata.batch_group = extract_metadata_field(&header_content, "batch_group");

    // @auto_probe: true
    if let Some(ap_str) = extract_metadata_field(&header_content, "auto_probe") {
        metadata.auto_probe = matches!(ap_str.to_lowercase().as_str(), "true" | "yes" | "1");
    }

    // @allow_nonzero_exit: true
    if let Some(v) = extract_metadata_field(&header_content, "allow_nonzero_exit") {
        metadata.allow_nonzero_exit = matches!(v.to_lowercase().as_str(), "true" | "yes" | "1");
    }

    metadata
}

/// Extract a single metadata field value from content
///
/// Handles various comment styles:
/// - `# @field: value`
/// - `// @field: value`
/// - `//! @field: value`
/// - `* @field: value`
/// - `@field: value`
fn extract_metadata_field(content: &str, field: &str) -> Option<String> {
    // Pattern matches @field: followed by value, with optional comment prefixes
    // Handles: # @id: value, // @id: value, * @id: value, //! @id: value
    let pattern = format!(
        r"(?m)^[\s]*(?:#|//!?|\*)?[\s]*@{}[\s]*:[\s]*(.+?)[\s]*$",
        regex::escape(field)
    );

    let re = Regex::new(&pattern).ok()?;

    re.captures(content)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Parse comma-separated values into a vector
fn parse_comma_separated(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Fallback: Extract tags from code patterns (language-specific)
///
/// This is used when @tags header is not present.
/// Attempts to find tags defined in code like:
/// - Python: self.tags = ["a", "b"] or tags = ["a", "b"]
/// - JavaScript: tags: ['a', 'b']
/// - Go: Tags: []string{"a", "b"}
/// - etc.
fn extract_tags_from_code(content: &str) -> Vec<String> {
    let mut tags = HashSet::new();

    // Pattern 1: Python/Ruby style - self.tags = [...] or tags = [...]
    // Matches: self.tags = ["mongodb", "database"] or tags = ['redis', 'cache']
    if let Some(caps) = Regex::new(r#"(?:self\.)?tags\s*=\s*\[([^\]]+)\]"#)
        .ok()
        .and_then(|re| re.captures(content))
    {
        if let Some(m) = caps.get(1) {
            tags.extend(parse_array_literal(m.as_str()));
        }
    }

    // Pattern 2: JavaScript/JSON style - tags: [...]
    // Matches: tags: ['mongodb', 'database']
    if let Some(caps) = Regex::new(r#"tags\s*:\s*\[([^\]]+)\]"#)
        .ok()
        .and_then(|re| re.captures(content))
    {
        if let Some(m) = caps.get(1) {
            tags.extend(parse_array_literal(m.as_str()));
        }
    }

    // Pattern 3: Go style - Tags: []string{...}
    // Matches: Tags: []string{"redis", "database"}
    if let Some(caps) = Regex::new(r#"Tags\s*:\s*\[\]string\{([^}]+)\}"#)
        .ok()
        .and_then(|re| re.captures(content))
    {
        if let Some(m) = caps.get(1) {
            tags.extend(parse_array_literal(m.as_str()));
        }
    }

    // Pattern 4: Java style - Arrays.asList(...) or List.of(...)
    // Matches: Arrays.asList("mongodb", "database")
    if let Some(caps) = Regex::new(r#"(?:Arrays\.asList|List\.of)\s*\(([^)]+)\)"#)
        .ok()
        .and_then(|re| re.captures(content))
    {
        if let Some(m) = caps.get(1) {
            tags.extend(parse_array_literal(m.as_str()));
        }
    }

    // Pattern 5: Perl style - tags => [...]
    // Matches: tags => ['skeleton', 'example']
    if let Some(caps) = Regex::new(r#"tags\s*=>\s*\[([^\]]+)\]"#)
        .ok()
        .and_then(|re| re.captures(content))
    {
        if let Some(m) = caps.get(1) {
            tags.extend(parse_array_literal(m.as_str()));
        }
    }

    // Pattern 6: Shell style - TAGS="..." or TAGS='...'
    // Matches: TAGS="mongodb,database,auth"
    if let Some(caps) = Regex::new(r#"TAGS\s*=\s*["']([^"']+)["']"#)
        .ok()
        .and_then(|re| re.captures(content))
    {
        if let Some(m) = caps.get(1) {
            tags.extend(parse_comma_separated(m.as_str()));
        }
    }

    tags.into_iter().collect()
}

/// Parse array literal content like "mongodb", "database" or 'redis', 'cache'
fn parse_array_literal(content: &str) -> Vec<String> {
    // Match quoted strings (single or double quotes)
    let re = Regex::new(r#"["']([^"']+)["']"#).unwrap();

    re.captures_iter(content)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str().trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse severity string to Severity enum
fn parse_severity_string(severity: &str) -> Severity {
    match severity.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" | "informational" => Severity::Info,
        _ => Severity::Medium, // Default fallback
    }
}

/// Build environment variables for template execution
pub fn build_env_vars(target: &Target, context: &Context) -> Result<HashMap<String, String>> {
    let mut env_vars = HashMap::new();

    // Required environment variables
    env_vars.insert("CERT_X_GEN_MODE".to_string(), "engine".to_string());
    env_vars.insert("CERT_X_GEN_TARGET_HOST".to_string(), target.address.clone());
    env_vars.insert(
        "CERT_X_GEN_TARGET_PORT".to_string(),
        target.port.unwrap_or(80).to_string(),
    );
    // Target kind lets a template distinguish a local CLI/binary target
    // (CERT_X_GEN_TARGET_HOST is a filesystem path) from a network host
    // (it is a hostname/IP) without re-parsing. Additive: templates that
    // ignore it are unaffected. Network targets report "http"/"https"/etc.
    env_vars.insert(
        "CERT_X_GEN_TARGET_KIND".to_string(),
        target.protocol.to_string(),
    );

    // Port configuration
    if !context.additional_ports.is_empty() {
        let ports_str = context
            .additional_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        env_vars.insert("CERT_X_GEN_ADD_PORTS".to_string(), ports_str);
    }

    if let Some(ref override_ports) = context.override_ports {
        let ports_str = override_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        env_vars.insert("CERT_X_GEN_OVERRIDE_PORTS".to_string(), ports_str);
    }

    // Context variables
    if !context.variables.is_empty() {
        let context_json = serde_json::to_string(&context.variables)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        env_vars.insert("CERT_X_GEN_CONTEXT".to_string(), context_json);
    }

    Ok(env_vars)
}

/// Parse JSON output from templates into Finding structs
pub fn parse_findings(stdout: &str, target: &Target, template_id: &str) -> Result<Vec<Finding>> {
    if stdout.trim().is_empty() {
        return Ok(Vec::new());
    }

    // Try to parse as Vec<Finding> first (full format)
    if let Ok(findings) = serde_json::from_str::<Vec<Finding>>(stdout) {
        return Ok(findings);
    }

    // Try to parse as wrapped format: {"findings": [...], "metadata": {...}}
    if let Ok(wrapped) = serde_json::from_str::<serde_json::Value>(stdout) {
        if let Some(findings_array) = wrapped.get("findings").and_then(|v| v.as_array()) {
            // Try to parse findings as Vec<Finding>
            if let Ok(findings) = serde_json::from_value::<Vec<Finding>>(serde_json::Value::Array(
                findings_array.clone(),
            )) {
                return Ok(findings);
            }
            // Otherwise, parse as simplified format
            let simple_findings = findings_array.clone();
            return parse_simple_findings(&simple_findings, target, template_id);
        }
    }

    // Otherwise, parse as simplified format array and convert
    let simple_findings: Vec<serde_json::Value> =
        serde_json::from_str(stdout).map_err(Error::JsonParse)?;

    parse_simple_findings(&simple_findings, target, template_id)
}

fn parse_simple_findings(
    simple_findings: &[serde_json::Value],
    target: &Target,
    template_id: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for simple in simple_findings {
        let finding = Finding {
            id: uuid::Uuid::new_v4(),
            target: target.address.clone(),
            template_id: simple
                .get("template_id")
                .and_then(|v| v.as_str())
                .unwrap_or(template_id)
                .to_string(),
            severity: match simple
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("medium")
            {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            },
            confidence: simple
                .get("confidence")
                .and_then(|v| v.as_u64())
                .unwrap_or(50) as u8,
            title: simple
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string(),
            description: simple
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            evidence: if let Some(evidence_obj) = simple.get("evidence") {
                crate::types::Evidence {
                    request: evidence_obj
                        .get("request")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    response: evidence_obj
                        .get("response")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    matched_patterns: evidence_obj
                        .get("matched_patterns")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                    data: evidence_obj
                        .get("data")
                        .and_then(|v| v.as_object())
                        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                        .unwrap_or_default(),
                    timestamp: chrono::Utc::now(),
                }
            } else {
                crate::types::Evidence {
                    request: None,
                    response: None,
                    matched_patterns: Vec::new(),
                    data: HashMap::new(),
                    timestamp: chrono::Utc::now(),
                }
            },
            cve_ids: Vec::new(),
            cwe_ids: vec![simple
                .get("cwe")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()],
            cvss_score: simple
                .get("cvss_score")
                .and_then(|v| v.as_f64())
                .map(|v| v as f32),
            remediation: simple
                .get("remediation")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            references: if let Some(arr) = simple.get("references").and_then(|v| v.as_array()) {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            } else {
                Vec::new()
            },
            tags: Vec::new(),
            timestamp: chrono::Utc::now(),
        };
        findings.push(finding);
    }

    Ok(findings)
}

/// Create template metadata from file path
///
/// This function reads the template file and extracts metadata from comment headers.
/// It looks for @field: annotations in the first 50 lines.
/// Falls back to filename-based defaults if no metadata is found.
pub fn create_metadata(path: &Path, language: TemplateLanguage) -> TemplateMetadata {
    // Read file content for metadata parsing
    let content = std::fs::read_to_string(path).unwrap_or_default();

    // Parse metadata from comment headers
    let parsed = parse_metadata_from_comments(&content);

    // Check if metadata was found before moving fields
    let has_metadata = parsed.has_metadata();

    // Fallback: derive ID from filename
    let fallback_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Use parsed values or fallbacks
    let id = parsed.id.unwrap_or_else(|| fallback_id.clone());
    let name = parsed
        .name
        .unwrap_or_else(|| fallback_id.replace(['-', '_'], " "));
    let author_name = parsed.author.unwrap_or_else(|| "Unknown".to_string());
    let severity = parsed
        .severity
        .map(|s| parse_severity_string(&s))
        .unwrap_or(Severity::Medium);
    let description = parsed
        .description
        .unwrap_or_else(|| format!("{} template: {}", language, fallback_id));

    // Tags: use parsed tags, ensure language tag is always included
    let mut tags = parsed.tags;
    let lang_tag = language.to_string().to_lowercase();
    if !tags.contains(&lang_tag) {
        tags.push(lang_tag);
    }
    // If no tags were found at all, just use language tag
    if tags.is_empty() {
        tags.push(language.to_string().to_lowercase());
    }

    // Log if metadata was found
    if has_metadata {
        tracing::debug!(
            "Parsed metadata from {}: id={}, tags={:?}",
            path.display(),
            id,
            tags
        );
    }

    TemplateMetadata {
        id,
        name,
        author: crate::types::AuthorInfo {
            name: author_name,
            email: None,
            github: None,
        },
        severity,
        description,
        cve_ids: Vec::new(),
        cwe_ids: parsed.cwe,
        cvss_score: parsed.cvss,
        tags,
        language,
        file_path: path.to_path_buf(),
        created: chrono::Utc::now(),
        updated: chrono::Utc::now(),
        version: parsed.version.unwrap_or_else(|| "1.0.0".to_string()),
        confidence: parsed.confidence.or(Some(50)),
        context_vars: parsed
            .context_vars
            .iter()
            .map(|cv| {
                let name = if cv.is_array {
                    format!("{}[]", cv.name)
                } else {
                    cv.name.clone()
                };
                let qualifier = if cv.required { "required" } else { "optional" };
                format!("{}:{}", name, qualifier)
            })
            .collect(),
        vuln_class: parsed.vuln_class,
        hypothesis_tags: parsed.hypothesis_tags,
        batch_group: parsed.batch_group,
        auto_probe: parsed.auto_probe,
        allow_nonzero_exit: parsed.allow_nonzero_exit,
    }
}

/// Get ports to scan from context
pub fn get_ports_to_scan(context: &Context) -> Vec<u16> {
    // Check for override first
    if let Some(ref override_ports) = context.override_ports {
        return override_ports.clone();
    }

    // Then check for additional ports
    let mut defaults = vec![80, 443];
    if !context.additional_ports.is_empty() {
        defaults.extend(context.additional_ports.clone());
    }

    defaults.sort();
    defaults.dedup();
    defaults
}

/// Execute a command with environment variables and return stdout
pub async fn execute_command(
    command: &str,
    args: &[String],
    env_vars: &HashMap<String, String>,
) -> Result<String> {
    let mut cmd = Command::new(command);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Kill the child if this future is dropped. Template execution is wrapped in
    // `tokio::time::timeout` (src/executor.rs), and dropping the timed-out future
    // only stops *awaiting* the child -- without this the process outlives its own
    // timeout and keeps running unsupervised.
    cmd.kill_on_drop(true);

    // Set environment variables
    for (key, value) in env_vars {
        cmd.env(key, value);
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| Error::Execution(format!("Failed to execute command: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Execution(format!("Command failed: {}", stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.to_string())
}

/// Check if a compiler/interpreter is available
pub async fn check_tool_available(tool: &str) -> bool {
    // Go uses "version" instead of "--version"
    let version_arg = if tool == "go" { "version" } else { "--version" };

    let output = Command::new(tool).arg(version_arg).output().await;

    output.is_ok() && output.unwrap().status.success()
}

/// Get cache directory for a language
pub fn get_cache_dir(language: &str) -> std::path::PathBuf {
    std::path::PathBuf::from("/tmp/cert-x-gen-cache").join(language)
}

/// Generate cache key from file path and content
pub fn generate_cache_key(path: &Path) -> Result<String> {
    use std::collections::hash_map::DefaultHasher;
    use std::fs;
    use std::hash::{Hash, Hasher};

    let metadata = fs::metadata(path).map_err(Error::Io)?;

    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    metadata.len().hash(&mut hasher);
    metadata
        .modified()
        .unwrap_or(std::time::UNIX_EPOCH)
        .hash(&mut hasher);

    Ok(format!("{:x}", hasher.finish()))
}

// ============================================================================
// Probe contract: exit-tolerant execution and template-declared status
// ============================================================================

/// Full outcome of a child process, including the non-zero cases.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    /// Captured stdout (kept even when the process failed)
    pub stdout: String,
    /// Captured stderr (kept even when the process succeeded)
    pub stderr: String,
    /// Exit code, when the process exited normally. `None` when it was killed
    /// by a signal.
    pub exit_code: Option<i32>,
    /// True when the process exited with status 0
    pub success: bool,
}

/// Execute a command and return the full outcome, without treating a non-zero
/// exit as an error.
///
/// [`execute_command`] discards stdout whenever the child exits non-zero. For a
/// probe template whose whole job is to provoke a crash in a target, that
/// throws the evidence away: the finding, the sanitizer report and the exit
/// code all go with it. This variant keeps them and lets the caller decide.
pub async fn execute_command_full(
    command: &str,
    args: &[String],
    env_vars: &HashMap<String, String>,
) -> Result<ExecOutcome> {
    let mut cmd = Command::new(command);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Same rationale as execute_command: a dropped timeout must kill the child.
    cmd.kill_on_drop(true);

    for (key, value) in env_vars {
        cmd.env(key, value);
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| Error::Execution(format!("Failed to execute command: {}", e)))?;

    Ok(ExecOutcome {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code(),
        success: output.status.success(),
    })
}

/// A template's self-declared verdict, read from the JSON wrapper's metadata.
///
/// ```json
/// {"findings": [], "metadata": {"status": "refuted", "detail": "exit=0"}}
/// ```
///
/// Purely additive: `parse_findings` already accepts and ignores `metadata`.
#[derive(Debug, Clone, Default)]
pub struct TemplateReport {
    /// Status the template declared, if it declared a recognised one
    pub status: Option<crate::types::ExecutionStatus>,
    /// A `metadata.status` value cxg did not recognise, kept verbatim so an
    /// operator sees the typo instead of silently getting cxg's own guess.
    pub unrecognised_status: Option<String>,
    /// Short reason the template gave
    pub detail: Option<String>,
    /// Exit code of the template process, when the engine observed it
    pub exit_code: Option<i32>,
}

/// Extract a template-declared status from its JSON output.
///
/// Non-JSON output, or JSON with no `metadata.status`, yields an empty report
/// and cxg falls back to inferring the status from the finding count.
pub fn parse_template_report(stdout: &str) -> TemplateReport {
    let mut report = TemplateReport::default();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout) else {
        return report;
    };
    let Some(meta) = value.get("metadata") else {
        return report;
    };
    if let Some(raw) = meta.get("status").and_then(|v| v.as_str()) {
        match crate::types::ExecutionStatus::parse(raw) {
            Some(status) => report.status = Some(status),
            None => {
                tracing::warn!(
                    "Template declared an unrecognised metadata.status '{}'; \
                     falling back to cxg's inferred status",
                    raw
                );
                report.unrecognised_status = Some(raw.to_string());
            }
        }
    }
    if let Some(d) = meta.get("detail").and_then(|v| v.as_str()) {
        report.detail = Some(d.to_string());
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Context, Protocol, Target};

    #[test]
    fn build_env_vars_reports_target_kind_for_network_targets() {
        let target = Target::with_port("example.com", 8443, Protocol::Https);
        let env = build_env_vars(&target, &Context::default()).unwrap();

        assert_eq!(env.get("CERT_X_GEN_TARGET_HOST").unwrap(), "example.com");
        assert_eq!(env.get("CERT_X_GEN_TARGET_PORT").unwrap(), "8443");
        assert_eq!(env.get("CERT_X_GEN_TARGET_KIND").unwrap(), "https");
    }

    #[test]
    fn build_env_vars_reports_cli_kind_and_carries_the_path_as_host() {
        let target = Target::new("/opt/build/toy", Protocol::Cli);
        let env = build_env_vars(&target, &Context::default()).unwrap();

        assert_eq!(env.get("CERT_X_GEN_TARGET_HOST").unwrap(), "/opt/build/toy");
        assert_eq!(env.get("CERT_X_GEN_TARGET_KIND").unwrap(), "cli");
        // PORT is meaningless for a CLI target but is still emitted, so the
        // contract stays uniform. Templates must ignore it when KIND=cli.
        assert_eq!(env.get("CERT_X_GEN_TARGET_PORT").unwrap(), "80");
    }

    #[test]
    fn parses_allow_nonzero_exit_from_the_header() {
        let yes = "#!/bin/bash\n# @id: probe\n# @allow_nonzero_exit: true\n";
        assert!(parse_metadata_from_comments(yes).allow_nonzero_exit);

        let no = "#!/bin/bash\n# @id: probe\n";
        assert!(!parse_metadata_from_comments(no).allow_nonzero_exit);

        let explicit_false = "#!/bin/bash\n# @id: probe\n# @allow_nonzero_exit: false\n";
        assert!(!parse_metadata_from_comments(explicit_false).allow_nonzero_exit);
    }

    #[test]
    fn template_report_reads_a_declared_status_and_detail() {
        let report = parse_template_report(
            r#"{"findings":[],"metadata":{"status":"refuted","detail":"exit=0"}}"#,
        );
        assert_eq!(report.status, Some(crate::types::ExecutionStatus::Refuted));
        assert_eq!(report.detail.as_deref(), Some("exit=0"));
        assert_eq!(report.unrecognised_status, None);
    }

    /// A status cxg cannot parse must be surfaced, not silently replaced by
    /// cxg's own guess -- that is the exact failure the ledger exists to stop.
    #[test]
    fn template_report_keeps_an_unrecognised_status_verbatim() {
        let report =
            parse_template_report(r#"{"findings":[],"metadata":{"status":"refuuted"}}"#);
        assert_eq!(report.status, None);
        assert_eq!(report.unrecognised_status.as_deref(), Some("refuuted"));
    }

    #[test]
    fn template_report_is_empty_for_output_that_declares_nothing() {
        assert!(parse_template_report("not json at all").status.is_none());
        assert!(parse_template_report(r#"{"findings":[]}"#).status.is_none());
        assert!(parse_template_report(r#"{"findings":[],"metadata":{}}"#)
            .status
            .is_none());
    }

    /// `execute_command` discards stdout on a non-zero exit; `execute_command_full`
    /// is the variant that keeps the evidence a crashing probe produces.
    #[tokio::test]
    async fn execute_command_full_keeps_stdout_on_a_nonzero_exit() {
        let args = vec!["-c".to_string(), "echo evidence; exit 3".to_string()];

        let outcome = execute_command_full("sh", &args, &HashMap::new())
            .await
            .unwrap();
        assert_eq!(outcome.stdout.trim(), "evidence");
        assert_eq!(outcome.exit_code, Some(3));
        assert!(!outcome.success);

        // The contrast, on the same command.
        assert!(execute_command("sh", &args, &HashMap::new()).await.is_err());
    }

    /// A template that outruns its timeout must not outlive it. `execute_command`
    /// sets `kill_on_drop`, so dropping the timed-out future kills the child;
    /// without it the child keeps running and completes its side effects.
    #[tokio::test]
    async fn execute_command_kills_the_child_when_the_caller_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("survived");
        let script = format!(
            "sleep 5; echo alive > {}",
            marker.display()
        );
        let args = vec!["-c".to_string(), script];

        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            execute_command("sh", &args, &HashMap::new()),
        )
        .await;
        assert!(timed_out.is_err(), "the command should have outrun the timeout");

        // Well past the child's own sleep: if it were still alive it would have
        // written the marker by now.
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        assert!(
            !marker.exists(),
            "child survived the dropped timeout and wrote {}",
            marker.display()
        );
    }
}
