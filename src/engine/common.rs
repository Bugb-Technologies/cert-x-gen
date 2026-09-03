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
    /// Oracles the template relies on to decide something is wrong.
    /// Declared as: `# @oracles: asan, signal, exit`
    pub oracles: Vec<String>,
    /// Target kinds the template accepts. Empty means no declaration, and a
    /// template with no declaration runs everywhere -- today's behaviour.
    /// Declared as: `# @target_kinds: cli`
    pub target_kinds: Vec<String>,
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

    // @oracles: asan, signal, exit
    if let Some(v) = extract_metadata_field(&header_content, "oracles") {
        metadata.oracles = parse_comma_separated(&v);
    }

    // @target_kinds: cli
    if let Some(v) = extract_metadata_field(&header_content, "target_kinds") {
        metadata.target_kinds = parse_comma_separated(&v);
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

    // --- Structured probe input. Each variable is emitted only when the
    // operator supplied the corresponding flag, so a scan that passes none of
    // them produces exactly the environment it always did.
    if !context.probe_argv.is_empty() {
        let argv_json = serde_json::to_string(&context.probe_argv)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        env_vars.insert("CERT_X_GEN_ARGV".to_string(), argv_json);
    }
    if let Some(ref p) = context.probe_stdin_file {
        env_vars.insert(
            "CERT_X_GEN_STDIN_FILE".to_string(),
            p.to_string_lossy().to_string(),
        );
    }
    if let Some(ref p) = context.probe_input_dir {
        env_vars.insert(
            "CERT_X_GEN_INPUT_DIR".to_string(),
            p.to_string_lossy().to_string(),
        );
    }
    // Tell the template what the build can actually reveal, so a probe never
    // has to guess whether "nothing happened" means "nothing is wrong".
    if matches!(target.protocol, crate::types::Protocol::Cli) {
        let detected = detect_instrumentation(Path::new(&target.address));
        env_vars.insert(
            "CERT_X_GEN_TARGET_INSTRUMENTATION".to_string(),
            if detected.is_empty() {
                "none".to_string()
            } else {
                detected.join(",")
            },
        );
    }

    if !context.probe_env.is_empty() {
        // A repeated key takes its last value, matching shell assignment.
        let map: std::collections::BTreeMap<&str, &str> = context
            .probe_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let env_json =
            serde_json::to_string(&map).map_err(|e| Error::Serialization(e.to_string()))?;
        env_vars.insert("CERT_X_GEN_TARGET_ENV".to_string(), env_json);
    }

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

/// Read the CWE list a shell template attached to a finding.
///
/// Templates write the canonical `cwe_ids` field -- the name used by
/// `types.rs` and by cxg's own JSON output -- but the original parser read
/// only the singular string key `cwe`, so a template emitting `cwe_ids` had
/// its CWEs silently dropped. Both spellings are accepted here, and each may
/// be a single string or an array of them.
///
/// When neither key is present the result is an empty vector. The original
/// parser produced `vec![""]`, so every finding from every shell template
/// carried one bogus empty CWE id downstream.
fn parse_cwe_ids(simple: &serde_json::Value) -> Vec<String> {
    let mut ids = Vec::new();
    for key in ["cwe_ids", "cwe"] {
        match simple.get(key) {
            Some(serde_json::Value::Array(arr)) => {
                ids.extend(arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()));
            }
            Some(serde_json::Value::String(s)) => ids.push(s.clone()),
            _ => {}
        }
    }
    let mut seen = HashSet::new();
    ids.retain(|id| !id.trim().is_empty() && seen.insert(id.clone()));
    ids
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
            cwe_ids: parse_cwe_ids(simple),
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
        oracles: parsed.oracles,
        target_kinds: parsed.target_kinds,
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
// Instrumentation preflight
// ============================================================================

/// Symbols a build carries when it was compiled with the corresponding
/// instrumentation, and the label cxg reports for each.
///
/// This is the cheap, honest version of OSS-Fuzz's `bad_build_check`: before
/// concluding "no defect", establish that the build could have shown one.
const INSTRUMENTATION_MARKERS: &[(&str, &str)] = &[
    ("__asan_init", "asan"),
    ("__asan_report_load1", "asan"),
    ("__ubsan_handle", "ubsan"),
    ("__msan_init", "msan"),
    ("__tsan_init", "tsan"),
    ("__sanitizer_cov", "sancov"),
    ("LLVMFuzzerTestOneInput", "libfuzzer"),
    ("__llvm_profile", "profile"),
];

/// Byte sequences that mean the build carries DWARF debug info, and so can
/// report a file and a line rather than a bare address.
///
/// `.debug_info` is the ELF section name; `__debug_info` is the Mach-O one. A
/// sibling `.dSYM` bundle is checked separately -- that is where `dsymutil`
/// puts macOS debug info, outside the executable entirely.
const DEBUG_INFO_MARKERS: &[&str] = &[".debug_info", "__debug_info", ".debug_line"];

/// Magic numbers that begin a real compiled object: ELF, every Mach-O flavour
/// (32/64-bit, both endiannesses, and the universal "fat" wrapper), PE/COFF,
/// and a static archive.
///
/// Only a file that starts with one of these can *carry* instrumentation, so
/// only such a file is worth scanning for markers. See [`is_object_file`].
const OBJECT_MAGICS: &[&[u8]] = &[
    b"\x7fELF",                    // ELF (Linux, BSD)
    &[0xFE, 0xED, 0xFA, 0xCE],     // Mach-O 32-bit, big endian
    &[0xFE, 0xED, 0xFA, 0xCF],     // Mach-O 64-bit, big endian
    &[0xCE, 0xFA, 0xED, 0xFE],     // Mach-O 32-bit, little endian
    &[0xCF, 0xFA, 0xED, 0xFE],     // Mach-O 64-bit, little endian
    &[0xCA, 0xFE, 0xBA, 0xBE],     // Mach-O universal binary
    &[0xBE, 0xBA, 0xFE, 0xCA],     // Mach-O universal binary, byte-swapped
    b"MZ",                         // PE/COFF (the DOS stub)
    b"!<arch>\n",                  // static archive (.a)
];

/// How many leading bytes are read to decide whether a file is an object.
const OBJECT_MAGIC_PEEK: usize = 8;

/// Is this file a compiled object, judged by its leading bytes?
///
/// The instrumentation markers are *symbol names*, and a symbol name only
/// means something inside a compiled object. A shebang script, a source file
/// or a JS bundle that merely mentions `__asan_init` -- in a comment, a corpus
/// entry, or its own documentation -- is not instrumented, and reading it as
/// instrumented is the dangerous direction: the preflight would pass and cxg
/// would report a refutation the build could never have earned.
///
/// A text file cannot carry a sanitizer runtime, so nothing is lost by
/// refusing to scan it.
fn is_object_file(header: &[u8]) -> bool {
    OBJECT_MAGICS.iter().any(|magic| header.starts_with(magic))
}

/// How much of the file is read at a time while scanning for markers.
const SCAN_CHUNK: usize = 1 << 20;

/// Oracles that only work if the *build* carries the matching instrumentation,
/// mapped to the instrumentation label [`detect_instrumentation`] reports.
///
/// Everything outside this list -- `signal`, `exit`, `assert`, `timeout`,
/// `diff`, `property`, `detector` -- works on any build, so a template that
/// declares one of those always has a way to reach a verdict.
const BUILD_DEPENDENT_ORACLES: &[(&str, &str)] = &[
    ("asan", "asan"),
    ("ubsan", "ubsan"),
    ("msan", "msan"),
    ("tsan", "tsan"),
];

/// Does a template's `@target_kinds` declaration accept this target?
///
/// **An empty declaration accepts everything.** That is deliberate and load
/// bearing: every template written before this annotation existed has an empty
/// declaration, and gating them would silently stop the whole public registry
/// from running against new target kinds.
pub fn target_kind_accepted(declared: &[String], kind: &str) -> bool {
    if declared.is_empty() {
        return true;
    }
    let kind = kind.to_lowercase();
    // http and https are the same kind of target to a template author.
    const WEB: &[&str] = &["http", "https", "web"];
    let kind_is_web = WEB.contains(&kind.as_str());

    declared.iter().any(|d| {
        let d = d.trim().to_lowercase();
        d == "any" || d == "*" || d == kind || (kind_is_web && WEB.contains(&d.as_str()))
    })
}

/// Which of a template's declared oracles the build cannot support.
///
/// Returns `None` when the template can still reach a verdict: either it
/// declared no oracles, or it declared at least one that does not depend on
/// the build, or the build carries the instrumentation it asked for. Returns
/// the missing build-dependent oracles otherwise -- a template that can only
/// decide via ASan, run against a build with no ASan, cannot produce a verdict
/// worth having.
pub fn unsupported_oracles(declared: &[String], instrumentation: &[String]) -> Option<Vec<String>> {
    if declared.is_empty() {
        return None;
    }
    let declared: Vec<String> = declared.iter().map(|o| o.trim().to_lowercase()).collect();

    let has_build_independent = declared
        .iter()
        .any(|o| !BUILD_DEPENDENT_ORACLES.iter().any(|(name, _)| name == o));
    if has_build_independent {
        return None;
    }

    let missing: Vec<String> = declared
        .iter()
        .filter(|o| {
            BUILD_DEPENDENT_ORACLES
                .iter()
                .find(|(name, _)| name == *o)
                .is_some_and(|(_, label)| !instrumentation.iter().any(|i| i == label))
        })
        .cloned()
        .collect();

    if missing.len() == declared.len() {
        Some(missing)
    } else {
        None
    }
}

/// Inspect a local executable and report which instrumentation it carries.
///
/// Returns e.g. `["asan", "debug-info"]`. An **empty** vec is the important
/// case: it means the binary carries none of the markers cxg knows how to
/// read, and therefore that a "no findings" result from it is not evidence of
/// absence. `--require-instrumentation` turns that into an honest `skipped`
/// instead of a false refutation.
///
/// Detection is a byte-level scan of the file: the markers appear in the
/// symbol table (or the dynamic symbol table, for a stripped binary that links
/// a sanitizer runtime), so no external tool is needed and the result is the
/// same on ELF and Mach-O.
///
/// The scan only runs on a **compiled object** ([`is_object_file`]). Anything
/// else -- a shebang script, a JS bundle, a source file, a corpus entry --
/// reports `none` however many marker strings it contains. Those strings are
/// symbol names in an object and prose everywhere else, and reading prose as
/// instrumentation fails in the dangerous direction: the preflight passes and
/// cxg reports a refutation the build could never have earned. Within an
/// object the scan stays a heuristic in the safe direction only -- a byte
/// sequence that is not really a symbol makes cxg *run* the probe rather than
/// skip it.
pub fn detect_instrumentation(path: &Path) -> Vec<String> {
    if let Some(cached) = instrumentation_cache_get(path) {
        return cached;
    }
    let detected = detect_instrumentation_uncached(path);
    instrumentation_cache_put(path, &detected);
    detected
}

fn detect_instrumentation_uncached(path: &Path) -> Vec<String> {
    use std::collections::BTreeSet;
    use std::io::{Read, Seek};

    let mut found: BTreeSet<String> = BTreeSet::new();

    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };

    // Only a compiled object can carry instrumentation. Deciding this from the
    // file's magic *before* scanning is what stops a script that mentions
    // `__asan_init` in a comment from reading as an ASan build -- a false
    // all-clear, which is exactly what the preflight exists to prevent.
    let mut header = [0u8; OBJECT_MAGIC_PEEK];
    let mut header_len = 0usize;
    while header_len < header.len() {
        match file.read(&mut header[header_len..]) {
            Ok(0) => break,
            Ok(n) => header_len += n,
            Err(_) => return Vec::new(),
        }
    }
    if !is_object_file(&header[..header_len]) {
        tracing::debug!(
            "Target {:?} is not a compiled object; reporting no instrumentation",
            path
        );
        return Vec::new();
    }
    if file.seek(std::io::SeekFrom::Start(0)).is_err() {
        return Vec::new();
    }

    // Debug info can live outside the executable: dsymutil writes a sibling
    // `<binary>.dSYM` bundle, so it is found even for a binary that is
    // otherwise stripped.
    let mut dsym = path.as_os_str().to_os_string();
    dsym.push(".dSYM");
    if Path::new(&dsym).exists() {
        found.insert("debug-info".to_string());
    }

    // The longest marker, minus one, is how much of each chunk must be carried
    // into the next so a marker straddling a chunk boundary is still seen.
    let overlap = INSTRUMENTATION_MARKERS
        .iter()
        .map(|(m, _)| m.len())
        .chain(DEBUG_INFO_MARKERS.iter().map(|m| m.len()))
        .max()
        .unwrap_or(1)
        .saturating_sub(1);

    let mut buf = vec![0u8; SCAN_CHUNK + overlap];
    let mut carried = 0usize;
    loop {
        let read = match file.read(&mut buf[carried..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let filled = carried + read;
        let window = &buf[..filled];

        for (marker, label) in INSTRUMENTATION_MARKERS {
            if !found.contains(*label) && contains_bytes(window, marker.as_bytes()) {
                found.insert((*label).to_string());
            }
        }
        if !found.contains("debug-info")
            && DEBUG_INFO_MARKERS
                .iter()
                .any(|m| contains_bytes(window, m.as_bytes()))
        {
            found.insert("debug-info".to_string());
        }

        if filled <= overlap {
            break;
        }
        let tail = filled - overlap;
        buf.copy_within(tail..filled, 0);
        carried = overlap;
    }

    found.into_iter().collect()
}

/// Substring search over raw bytes.
///
/// Anchors on the needle's first byte before comparing, so scanning a
/// multi-megabyte binary for a handful of markers stays cheap.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let first = needle[0];
    let last_start = haystack.len() - needle.len();
    let mut cursor = 0usize;
    while cursor <= last_start {
        let Some(offset) = haystack[cursor..=last_start].iter().position(|&b| b == first) else {
            return false;
        };
        let start = cursor + offset;
        if &haystack[start..start + needle.len()] == needle {
            return true;
        }
        cursor = start + 1;
    }
    false
}

/// Cache key: a binary is only re-scanned if it changed on disk.
type InstrumentationKey = (std::path::PathBuf, u64, Option<std::time::SystemTime>);

fn instrumentation_cache() -> &'static std::sync::Mutex<HashMap<InstrumentationKey, Vec<String>>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<HashMap<InstrumentationKey, Vec<String>>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn instrumentation_key(path: &Path) -> Option<InstrumentationKey> {
    let meta = std::fs::metadata(path).ok()?;
    Some((path.to_path_buf(), meta.len(), meta.modified().ok()))
}

fn instrumentation_cache_get(path: &Path) -> Option<Vec<String>> {
    let key = instrumentation_key(path)?;
    instrumentation_cache().lock().ok()?.get(&key).cloned()
}

fn instrumentation_cache_put(path: &Path, detected: &[String]) {
    let Some(key) = instrumentation_key(path) else {
        return;
    };
    if let Ok(mut cache) = instrumentation_cache().lock() {
        cache.insert(key, detected.to_vec());
    }
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
    fn build_env_vars_delivers_the_probe_input_when_it_was_supplied() {
        let target = Target::new("/opt/build/toy", Protocol::Cli);
        let context = Context {
            probe_argv: vec!["--label".to_string(), "AAAA".to_string()],
            probe_stdin_file: Some("/tmp/case.bin".into()),
            probe_input_dir: Some("/tmp/corpus".into()),
            probe_env: vec![(
                "ASAN_OPTIONS".to_string(),
                "abort_on_error=1".to_string(),
            )],
            ..Context::default()
        };

        let env = build_env_vars(&target, &context).unwrap();
        assert_eq!(env.get("CERT_X_GEN_ARGV").unwrap(), r#"["--label","AAAA"]"#);
        assert_eq!(env.get("CERT_X_GEN_STDIN_FILE").unwrap(), "/tmp/case.bin");
        assert_eq!(env.get("CERT_X_GEN_INPUT_DIR").unwrap(), "/tmp/corpus");
        assert_eq!(
            env.get("CERT_X_GEN_TARGET_ENV").unwrap(),
            r#"{"ASAN_OPTIONS":"abort_on_error=1"}"#
        );
    }

    /// The additive claim at the wire level: a scan that passes no probe flags
    /// produces exactly the environment it produced before they existed.
    #[test]
    fn build_env_vars_omits_every_probe_variable_when_none_was_supplied() {
        let target = Target::with_port("example.com", 8443, Protocol::Https);
        let env = build_env_vars(&target, &Context::default()).unwrap();

        for name in [
            "CERT_X_GEN_ARGV",
            "CERT_X_GEN_STDIN_FILE",
            "CERT_X_GEN_INPUT_DIR",
            "CERT_X_GEN_TARGET_ENV",
        ] {
            assert!(!env.contains_key(name), "{name} leaked into a network scan");
        }
    }

    #[test]
    fn parses_oracles_and_target_kinds_from_the_header() {
        let header = "#!/bin/bash\n# @id: probe\n# @oracles: asan, signal, exit\n# @target_kinds: cli\n";
        let parsed = parse_metadata_from_comments(header);
        assert_eq!(parsed.oracles, vec!["asan", "signal", "exit"]);
        assert_eq!(parsed.target_kinds, vec!["cli"]);

        let bare = parse_metadata_from_comments("#!/bin/bash\n# @id: probe\n");
        assert!(bare.oracles.is_empty());
        assert!(bare.target_kinds.is_empty());
    }

    /// The load-bearing default: no declaration means every kind, so the
    /// existing template registry keeps running against every target.
    #[test]
    fn an_absent_target_kind_declaration_accepts_every_kind() {
        assert!(target_kind_accepted(&[], "cli"));
        assert!(target_kind_accepted(&[], "https"));
    }

    #[test]
    fn a_declared_target_kind_accepts_only_what_it_named() {
        let cli = vec!["cli".to_string()];
        assert!(target_kind_accepted(&cli, "cli"));
        assert!(!target_kind_accepted(&cli, "https"));
        assert!(!target_kind_accepted(&cli, "tcp"));

        // http and https are one kind to a template author.
        let web = vec!["http".to_string()];
        assert!(target_kind_accepted(&web, "https"));
        assert!(target_kind_accepted(&web, "http"));
        assert!(!target_kind_accepted(&web, "cli"));

        assert!(target_kind_accepted(&["any".to_string()], "cli"));
        assert!(target_kind_accepted(&["CLI".to_string()], "cli"));
    }

    #[test]
    fn a_sanitizer_only_template_is_unsupported_on_a_build_without_that_sanitizer() {
        let asan_only = vec!["asan".to_string()];
        assert_eq!(
            unsupported_oracles(&asan_only, &[]),
            Some(vec!["asan".to_string()])
        );
        assert_eq!(
            unsupported_oracles(&asan_only, &["asan".to_string(), "debug-info".to_string()]),
            None
        );
    }

    /// A template that also declares a build-independent oracle can still
    /// reach a verdict, so it is never gated.
    #[test]
    fn a_template_with_a_fallback_oracle_is_always_supported() {
        let mixed = vec!["asan".to_string(), "signal".to_string(), "exit".to_string()];
        assert_eq!(unsupported_oracles(&mixed, &[]), None);

        assert_eq!(unsupported_oracles(&[], &[]), None);
        assert_eq!(unsupported_oracles(&["signal".to_string()], &[]), None);
    }

    #[test]
    fn detects_a_sanitizer_marker_and_reports_nothing_without_one() {
        let dir = tempfile::tempdir().unwrap();

        let instrumented = dir.path().join("with_asan");
        std::fs::write(&instrumented, b"\x7fELF....__asan_init....rest").unwrap();
        assert_eq!(detect_instrumentation(&instrumented), vec!["asan"]);

        let bare = dir.path().join("no_markers");
        std::fs::write(&bare, b"\x7fELF....just some bytes....").unwrap();
        assert!(
            detect_instrumentation(&bare).is_empty(),
            "an empty result is the signal that a refutation would not be evidence"
        );
    }

    #[test]
    fn detects_each_known_instrumentation_label() {
        let dir = tempfile::tempdir().unwrap();
        for (marker, label) in [
            ("__ubsan_handle_add_overflow", "ubsan"),
            ("__msan_init", "msan"),
            ("__tsan_init", "tsan"),
            ("__sanitizer_cov_trace_pc", "sancov"),
            ("LLVMFuzzerTestOneInput", "libfuzzer"),
            ("__llvm_profile_write_file", "profile"),
        ] {
            let path = dir.path().join(label);
            // A real object, because only an object is scanned at all.
            let mut body = b"\x7fELF\x02\x01\x01\x00".to_vec();
            body.extend_from_slice(marker.as_bytes());
            std::fs::write(&path, &body).unwrap();
            assert_eq!(
                detect_instrumentation(&path),
                vec![label.to_string()],
                "marker {marker} should report {label}"
            );
        }
    }

    #[test]
    fn detects_debug_info_from_a_dwarf_section_name() {
        let dir = tempfile::tempdir().unwrap();

        let elf = dir.path().join("elf_with_dwarf");
        std::fs::write(&elf, b"\x7fELF....debug_info....").unwrap();
        assert_eq!(detect_instrumentation(&elf), vec!["debug-info"]);

        let macho = dir.path().join("macho_with_dwarf");
        std::fs::write(&macho, b"\xcf\xfa\xed\xfe....__debug_info....").unwrap();
        assert_eq!(detect_instrumentation(&macho), vec!["debug-info"]);
    }

    /// dsymutil puts macOS debug info in a sibling bundle, outside the
    /// executable, so a stripped-looking binary can still resolve file:line.
    #[test]
    fn detects_debug_info_from_a_sibling_dsym_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("toy");
        std::fs::write(&bin, b"\xcf\xfa\xed\xfeno markers here").unwrap();
        assert!(detect_instrumentation(&bin).is_empty());

        std::fs::create_dir(dir.path().join("toy.dSYM")).unwrap();
        // The cache is keyed on the binary's own size and mtime, so touch it
        // to force a re-read now that its sibling exists.
        std::fs::write(&bin, b"\xcf\xfa\xed\xfeno markers here either").unwrap();
        assert_eq!(detect_instrumentation(&bin), vec!["debug-info"]);
    }

    /// The scan reads the file in chunks, carrying an overlap so a marker
    /// lying across a chunk boundary is still found.
    #[test]
    fn finds_a_marker_that_straddles_a_read_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big");

        let marker = b"__asan_init";
        // Place the marker so it starts a few bytes before the first boundary.
        let prefix_len = SCAN_CHUNK - 4;
        let mut bytes = vec![b'.'; prefix_len];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes.extend_from_slice(marker);
        bytes.extend(std::iter::repeat_n(b'.', SCAN_CHUNK));
        std::fs::write(&path, &bytes).unwrap();

        assert_eq!(detect_instrumentation(&path), vec!["asan"]);
    }

    /// s14 item 2. A script that merely *mentions* a sanitizer symbol -- in a
    /// comment, its own documentation, or a corpus entry -- is not an
    /// instrumented build. Reading it as one is a false all-clear: the
    /// preflight passes and cxg reports a refutation the build could not have
    /// earned. This is the exact shape s14 found against a Node CLI bundle.
    #[test]
    fn a_script_that_mentions_a_marker_carries_no_instrumentation() {
        let dir = tempfile::tempdir().unwrap();

        let script = dir.path().join("interp-cli.js");
        std::fs::write(
            &script,
            b"#!/usr/bin/env node\n// Detected symbols include __asan_init and __ubsan_handle_type_mismatch.\n",
        )
        .unwrap();
        assert!(
            detect_instrumentation(&script).is_empty(),
            "a shebang script is never an instrumented build, whatever it says"
        );

        // Same bytes, this time inside a compiled object: still detected.
        let object = dir.path().join("with_asan.o");
        std::fs::write(
            &object,
            b"\x7fELF\x02\x01\x01\x00__asan_init __ubsan_handle_type_mismatch",
        )
        .unwrap();
        assert_eq!(detect_instrumentation(&object), vec!["asan", "ubsan"]);
    }

    /// The same rule for a plain source file and for a Python console-script
    /// wrapper -- the two other shapes a `cli://` target took in s14.
    #[test]
    fn only_a_compiled_object_is_scanned_for_markers() {
        let dir = tempfile::tempdir().unwrap();

        for (name, body) in [
            ("source.c", "/* calls __asan_init at startup */\nint main(void){return 0;}\n"),
            ("bugb", "#!/usr/bin/env python3\n# __asan_init, __llvm_profile, .debug_info\nimport sys\n"),
            ("notes.txt", "the marker is __tsan_init\n"),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, body).unwrap();
            assert!(
                detect_instrumentation(&path).is_empty(),
                "{name} is not a compiled object and must report no instrumentation"
            );
        }
    }

    #[test]
    fn object_magic_covers_elf_macho_pe_and_archives() {
        assert!(is_object_file(b"\x7fELF\x02\x01"));
        assert!(is_object_file(&[0xcf, 0xfa, 0xed, 0xfe, 0x0c]));
        assert!(is_object_file(&[0xce, 0xfa, 0xed, 0xfe]));
        assert!(is_object_file(&[0xfe, 0xed, 0xfa, 0xcf]));
        assert!(is_object_file(&[0xca, 0xfe, 0xba, 0xbe]));
        assert!(is_object_file(b"MZ\x90\x00"));
        assert!(is_object_file(b"!<arch>\n"));

        assert!(!is_object_file(b"#!/bin/bash\n"));
        assert!(!is_object_file(b"import sys"));
        assert!(!is_object_file(b""));
        assert!(!is_object_file(b"\x7fEL"));
    }

    #[test]
    fn a_missing_binary_reports_no_instrumentation_rather_than_panicking() {
        assert!(detect_instrumentation(Path::new("/definitely/not/here")).is_empty());
    }

    #[test]
    fn build_env_vars_reports_instrumentation_only_for_cli_targets() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("toy_asan");
        std::fs::write(&bin, b"\x7fELF__asan_init and .debug_info").unwrap();

        let cli = Target::new(bin.to_string_lossy().to_string(), Protocol::Cli);
        let env = build_env_vars(&cli, &Context::default()).unwrap();
        assert_eq!(
            env.get("CERT_X_GEN_TARGET_INSTRUMENTATION").unwrap(),
            "asan,debug-info"
        );

        let bare = dir.path().join("toy_stripped");
        std::fs::write(&bare, b"nothing to see").unwrap();
        let cli = Target::new(bare.to_string_lossy().to_string(), Protocol::Cli);
        let env = build_env_vars(&cli, &Context::default()).unwrap();
        assert_eq!(env.get("CERT_X_GEN_TARGET_INSTRUMENTATION").unwrap(), "none");

        let net = Target::with_port("example.com", 443, Protocol::Https);
        let env = build_env_vars(&net, &Context::default()).unwrap();
        assert!(!env.contains_key("CERT_X_GEN_TARGET_INSTRUMENTATION"));
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
    // -----------------------------------------------------------------
    // s12 6.2 -- CWE ids from a shell template's finding JSON
    // -----------------------------------------------------------------

    fn cwes_of(json: &str) -> Vec<String> {
        let values: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
        let target = Target::new("example.com", Protocol::Https);
        let findings = parse_simple_findings(&values, &target, "t").unwrap();
        findings[0].cwe_ids.clone()
    }

    /// A template writing the canonical `cwe_ids` array keeps its CWEs. The
    /// parser used to read only `cwe`, so these were silently dropped.
    #[test]
    fn a_template_emitting_cwe_ids_keeps_its_cwes() {
        assert_eq!(
            cwes_of(r#"[{"title":"t","cwe_ids":["CWE-787","CWE-125"]}]"#),
            vec!["CWE-787".to_string(), "CWE-125".to_string()]
        );
    }

    /// The singular `cwe` string still works, so no existing template breaks.
    #[test]
    fn the_singular_cwe_key_is_still_accepted() {
        assert_eq!(
            cwes_of(r#"[{"title":"t","cwe":"CWE-89"}]"#),
            vec!["CWE-89".to_string()]
        );
    }

    /// No CWE key at all means no CWE. The parser used to inject `vec![""]`,
    /// so every finding from every shell template carried an empty CWE id.
    #[test]
    fn no_cwe_key_injects_no_empty_cwe() {
        assert!(cwes_of(r#"[{"title":"t"}]"#).is_empty());
    }

    /// ...and an explicitly empty or blank value is not an id either.
    #[test]
    fn a_blank_cwe_value_is_not_an_id() {
        assert!(cwes_of(r#"[{"title":"t","cwe":"","cwe_ids":["  "]}]"#).is_empty());
    }

    /// Both spellings together are merged without duplicates, in the order
    /// they were read.
    #[test]
    fn both_cwe_spellings_are_merged_without_duplicates() {
        assert_eq!(
            cwes_of(r#"[{"title":"t","cwe_ids":["CWE-787"],"cwe":"CWE-787"}]"#),
            vec!["CWE-787".to_string()]
        );
    }
}
