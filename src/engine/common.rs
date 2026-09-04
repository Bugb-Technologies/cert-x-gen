//! Common utilities for template engines

#![allow(missing_docs)]

use crate::error::{Error, Result};
use crate::types::{Context, Finding, Severity, Target, TemplateLanguage, TemplateMetadata};
use regex::Regex;
use std::collections::BTreeSet;
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
    /// Declared as: `# @oracles: asan, signal, exit` (also: `exception`)
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
        let detected = instrumentation_for(Path::new(&target.address), context);
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

/// Symbols a **Rust** build carries when `-C overflow-checks=on` compiled the
/// integer checks in, and the label cxg reports for them.
///
/// This is the Rust integer class, and it needs its own table for two reasons.
///
/// It needs to exist at all because **Rust has no UBSan**:
/// `-Zsanitizer=undefined` is not in rustc's vocabulary on any target, so
/// `ubsan` is unreachable on every Rust build there will ever be. The
/// equivalent check is `-C overflow-checks=on`, which turns the wrap into a
/// panic -- and compile it out and the same program returns the same wrong
/// number and exits 0, which is exactly the silent false negative the
/// preflight exists to refuse. It is therefore build-dependent in precisely
/// the way a sanitizer is, and [`BUILD_DEPENDENT_ORACLES`] maps the `overflow`
/// oracle onto this label.
///
/// It needs to be **matched as a substring** rather than a prefix because
/// these are Rust items, so the symbol is mangled and the name is buried:
/// `__RNvNtNtCs..._4core9panicking11panic_const24panic_const_mul_overflow`
/// under v0, `_ZN4core9panicking11panic_const24panic_const_mul_overflowE`
/// under the legacy scheme. A substring is still a fact about the symbol
/// table, which is the property that matters -- prose cannot get in there.
///
/// The six listed are exactly the ones the flag gates, verified by compiling
/// the same source both ways: `panic_const_div_overflow`,
/// `panic_const_div_by_zero` and `panic_const_rem_by_zero` are emitted either
/// way, because those are hard errors rather than overflow checks, and
/// including them would report every Rust build as carrying the check.
///
/// The failure direction is **under**-reporting, which is the safe one: a
/// build with the check on but no fallible arithmetic left after const-folding
/// carries no such symbol and reads as uninstrumented, so a template gated on
/// `overflow` skips rather than claims. Toolchains older than the
/// `panic_const` family (pre-1.79) route the panic through a shared function
/// with a string argument and likewise read as uninstrumented.
const RUST_OVERFLOW_CHECK_MARKERS: &[&str] = &[
    "panic_const_add_overflow",
    "panic_const_sub_overflow",
    "panic_const_mul_overflow",
    "panic_const_neg_overflow",
    "panic_const_shl_overflow",
    "panic_const_shr_overflow",
];

/// The label [`RUST_OVERFLOW_CHECK_MARKERS`] reports, and the instrumentation
/// `cxg build --instrument` records for `-C overflow-checks=on`.
pub const RUST_OVERFLOW_CHECKS_LABEL: &str = "rust-overflow-checks";

/// Section names that mean the build carries DWARF debug info, and so can
/// report a file and a line rather than a bare address.
///
/// `.debug_info` is the ELF section name; `__debug_info` is the Mach-O one.
/// Two other homes are checked separately, because macOS puts the DWARF
/// outside the executable: a sibling `.dSYM` bundle, which is where `dsymutil`
/// writes it, and the `N_OSO` stab entries rustc leaves pointing at the `.o`
/// files it kept it in.
const DEBUG_INFO_MARKERS: &[&str] = &[".debug_info", "__debug_info", ".debug_line"];

/// Magic numbers that begin a real compiled object: ELF, every Mach-O flavour
/// (32/64-bit, both endiannesses, and the universal "fat" wrapper), PE/COFF,
/// and a static archive.
///
/// Only a file that starts with one of these can *carry* instrumentation, so
/// only such a file is worth handing to an object parser. See
/// [`is_object_file`].
const OBJECT_MAGICS: &[&[u8]] = &[
    b"\x7fELF",                // ELF (Linux, BSD)
    &[0xFE, 0xED, 0xFA, 0xCE], // Mach-O 32-bit, big endian
    &[0xFE, 0xED, 0xFA, 0xCF], // Mach-O 64-bit, big endian
    &[0xCE, 0xFA, 0xED, 0xFE], // Mach-O 32-bit, little endian
    &[0xCF, 0xFA, 0xED, 0xFE], // Mach-O 64-bit, little endian
    &[0xCA, 0xFE, 0xBA, 0xBE], // Mach-O universal binary
    &[0xBE, 0xBA, 0xFE, 0xCA], // Mach-O universal binary, byte-swapped
    b"MZ",                     // PE/COFF (the DOS stub)
    b"!<arch>\n",              // static archive (.a)
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
/// refusing to parse it. This is the cheap pre-check only: the parse in
/// [`detect_instrumentation`] is what actually decides, and a file that gets
/// past the magic but is not a readable object still reports nothing.
fn is_object_file(header: &[u8]) -> bool {
    OBJECT_MAGICS.iter().any(|magic| header.starts_with(magic))
}

/// Oracles that only work if the *build* carries the matching instrumentation,
/// mapped to the instrumentation label [`detect_instrumentation`] reports.
///
/// Everything outside this list -- `signal`, `exit`, `assert`, `timeout`,
/// `diff`, `property`, `detector` -- works on any build, so a template that
/// declares one of those always has a way to reach a verdict.
///
/// `overflow` is here because **Rust has no UBSan**: `-Zsanitizer=undefined`
/// does not exist on any target, and the Rust equivalent for the integer class
/// is `-C overflow-checks=on`, which turns the wrap into a panic. That panic
/// is an oracle exactly as much as an ASan report is, and exactly as
/// build-dependent -- compile the check out and the same program returns the
/// same wrong number and exits 0. Listing it here is what stops a template's
/// overflow branch from claiming a verdict on a build where the check was
/// never compiled in. The alternative -- reaching for a build-INDEPENDENT
/// oracle such as `exception` -- would make
/// [`oracles_are_build_independent`] true for the whole template and let it
/// run, and refute, on an uninstrumented build, quietly undoing the preflight.
const BUILD_DEPENDENT_ORACLES: &[(&str, &str)] = &[
    ("asan", "asan"),
    ("ubsan", "ubsan"),
    ("msan", "msan"),
    ("tsan", "tsan"),
    ("overflow", "rust-overflow-checks"),
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

/// An unhandled language-level exception cxg recognised in a target's output.
///
/// Fieldless on purpose: it names *what was seen*, and everything else about
/// the execution already has a home in the ledger row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionKind {
    /// `Traceback (most recent call last):` -- CPython.
    PythonTraceback,
    /// A rejected promise nobody handled -- Node.
    NodeUnhandledRejection,
    /// An exception that escaped to the top level -- Node.
    NodeUncaughtException,
    /// `Exception in thread "main" ...` -- the JVM.
    JavaUncaughtException,
    /// `panic: ...` plus a goroutine dump -- Go.
    GoPanic,
    /// `thread '...' panicked at ...` -- Rust.
    RustPanic,
}

impl ExceptionKind {
    /// Stable machine-readable label, as it appears in the ledger detail.
    pub fn label(self) -> &'static str {
        match self {
            ExceptionKind::PythonTraceback => "python-traceback",
            ExceptionKind::NodeUnhandledRejection => "node-unhandled-rejection",
            ExceptionKind::NodeUncaughtException => "node-uncaught-exception",
            ExceptionKind::JavaUncaughtException => "java-uncaught-exception",
            ExceptionKind::GoPanic => "go-panic",
            ExceptionKind::RustPanic => "rust-panic",
        }
    }
}

/// Substrings that identify a Node stack as an escaped exception rather than
/// an ordinary error message the program chose to print.
const NODE_UNHANDLED_REJECTION_MARKERS: &[&str] = &[
    "UnhandledPromiseRejection",
    "node:internal/process/promises",
    "fromPromise",
];
const NODE_UNCAUGHT_MARKERS: &[&str] = &[
    "triggerUncaughtException",
    "node:internal/process/execution",
    "node:internal/modules",
];

/// Did an unhandled language-level exception escape the target?
///
/// This is the one oracle cxg implements itself, and it exists because neither
/// `exit` nor `signal` can express what an interpreted target does when it
/// falls over: a Python traceback or a Node stack exits **1** with no crash
/// signal, so `signal` is silent and `exit` fires on every deliberate non-zero
/// exit too -- including the correct ones (s14 report §5). The discrimination
/// is a per-language string match, and doing it once here beats every template
/// re-implementing it slightly differently.
///
/// Deliberately keyed on the **output alone**, never on the exit status: an
/// escaped exception is an escaped exception whatever the runtime exits with,
/// and a non-zero exit on its own is exactly what this must not be confused
/// with.
pub fn detect_unhandled_exception(output: &str) -> Option<ExceptionKind> {
    if output.is_empty() {
        return None;
    }

    // Python: the traceback header, at the start of its own line so a mention
    // of the phrase in prose is not a crash.
    if has_line_starting_with(output, "Traceback (most recent call last):") {
        return Some(ExceptionKind::PythonTraceback);
    }

    // Node: the runtime's own frames are what separate an escaped exception
    // from an error message the program printed and exited on.
    if NODE_UNHANDLED_REJECTION_MARKERS
        .iter()
        .any(|m| output.contains(m))
    {
        return Some(ExceptionKind::NodeUnhandledRejection);
    }
    if NODE_UNCAUGHT_MARKERS.iter().any(|m| output.contains(m))
        || (output.contains("node:internal/") && has_line_starting_with(output, "at "))
    {
        return Some(ExceptionKind::NodeUncaughtException);
    }

    if has_line_starting_with(output, "Exception in thread \"") {
        return Some(ExceptionKind::JavaUncaughtException);
    }
    if has_line_starting_with(output, "panic: ") && output.contains("goroutine ") {
        return Some(ExceptionKind::GoPanic);
    }
    if has_line_starting_with(output, "thread '") && output.contains("panicked at") {
        return Some(ExceptionKind::RustPanic);
    }

    None
}

/// Is `needle` at the start of any line, ignoring that line's indentation?
///
/// Stack traces are indented; the markers that identify them are not prose.
fn has_line_starting_with(haystack: &str, needle: &str) -> bool {
    haystack
        .lines()
        .any(|line| line.trim_start().starts_with(needle))
}

/// Take at most `max` characters, never splitting a UTF-8 character.
///
/// Interpreted CLIs print box drawing and ANSI escapes, so byte-slicing their
/// output is how a template ends up emitting invalid JSON (s14 report
/// §4.1(e)). cxg does its own truncation on character boundaries.
pub fn truncate_chars(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((byte_idx, _)) => format!("{}...", &text[..byte_idx]),
        None => text.to_string(),
    }
}

/// Can this template reach a verdict on a build that carries no
/// instrumentation at all?
///
/// True only when the template **declared** oracles and every one of them is
/// build-independent (`exit`, `signal`, `timeout`, `exception`, `assert`,
/// `diff`, `property`, `detector`). Such a template needs nothing from the
/// build, so `--require-instrumentation` has no reason to refuse it -- which
/// is what lets an interpreted CLI, whose instrumentation is always `none`,
/// be tested at all (s14 report §4.1(a)).
///
/// An **absent** declaration is false, deliberately: a template that never
/// said how it decides may well be reading a sanitizer report, and the whole
/// point of the flag is to refuse to guess. A template that wants through
/// says so.
pub fn oracles_are_build_independent(declared: &[String]) -> bool {
    !declared.is_empty()
        && declared.iter().all(|o| {
            let o = o.trim().to_lowercase();
            !BUILD_DEPENDENT_ORACLES.iter().any(|(name, _)| *name == o)
        })
}

/// What instrumentation this target carries, preferring **provenance** over
/// inspection.
///
/// When cxg built the binary itself -- `cxg build --instrument`, whose manifest
/// the operator handed back with `cxg scan --instrumented-manifest` -- it does
/// not have to re-derive the answer from the artefact. It passed the flags, it
/// read the produced binary back before it was willing to call the build
/// instrumented, and that record is strictly better evidence than a second
/// sniff of the same file: it survives stripping, it survives a binary copied
/// away from the build tree, and it can record a build fact no scan of the
/// artefact could recover.
///
/// Falls back to [`detect_instrumentation`] for every binary cxg did not
/// build, which is the overwhelmingly common case and the one that must keep
/// behaving exactly as it did before this existed. A manifest naming some
/// *other* binary changes nothing here.
pub fn instrumentation_for(path: &Path, context: &Context) -> Vec<String> {
    if !context.instrumentation_provenance.is_empty() {
        let key = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .to_string();
        if let Some(recorded) = context.instrumentation_provenance.get(&key) {
            tracing::debug!(
                "Target {:?} instrumentation comes from a build manifest: {}",
                path,
                recorded.join(",")
            );
            return recorded.clone();
        }
    }
    detect_instrumentation(path)
}

/// Inspect a local executable and report which instrumentation it carries.
///
/// Returns e.g. `["asan", "debug-info"]`. An **empty** vec is the important
/// case: it means the binary carries none of the markers cxg knows how to
/// read, and therefore that a "no findings" result from it is not evidence of
/// absence. `--require-instrumentation` turns that into an honest `skipped`
/// instead of a false refutation.
///
/// Detection reads the **symbol table** -- and the dynamic symbol table, which
/// is where a stripped binary's reference to a shared sanitizer runtime
/// survives -- so no external tool is needed and the result is the same on ELF
/// and Mach-O.
///
/// It has to be the symbol table rather than the file's bytes, and cxg's own
/// binary is the proof. A byte scan cannot tell a linker reference from a
/// string constant that merely spells one, and cxg carries
/// [`INSTRUMENTATION_MARKERS`] as string literals: an ordinary `cargo build`
/// of cxg read as carrying asan, ubsan, msan, tsan, sancov, libfuzzer *and*
/// profile, on a build that links no sanitizer runtime at all. That is a false
/// ALL-CLEAR -- the preflight passes and cxg reports a refutation the build
/// could never have earned, which is the one failure
/// `--require-instrumentation` exists to prevent. It is not special to cxg:
/// any binary that names sanitizers in its own text -- a security scanner, a
/// fuzzing wrapper, a build tool's help output -- trips the same way. A symbol
/// table cannot contain prose.
///
/// The scan only runs on a **compiled object** ([`is_object_file`]), and a
/// file that does not parse as one reports nothing. Anything else -- a shebang
/// script, a JS bundle, a source file, a corpus entry -- reports `none`
/// however many marker strings it contains.
pub fn detect_instrumentation(path: &Path) -> Vec<String> {
    if let Some(cached) = instrumentation_cache_get(path) {
        return cached;
    }
    let detected = detect_instrumentation_uncached(path);
    instrumentation_cache_put(path, &detected);
    detected
}

fn detect_instrumentation_uncached(path: &Path) -> Vec<String> {
    use std::io::Read;

    let mut found: BTreeSet<String> = BTreeSet::new();

    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };

    // Only a compiled object can carry instrumentation. Deciding this from the
    // file's magic *before* parsing is what stops a script that mentions
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
    // Debug info can live outside the executable: dsymutil writes a sibling
    // `<binary>.dSYM` bundle, so it is found even for a binary that is
    // otherwise stripped.
    let mut dsym = path.as_os_str().to_os_string();
    dsym.push(".dSYM");
    if Path::new(&dsym).exists() {
        found.insert("debug-info".to_string());
    }

    // `ReadCache` reads the pieces the parser asks for rather than the whole
    // file, and does its own positioning: an instrumented binary is routinely
    // hundreds of megabytes, and its symbol table is a small part of that.
    let cache = object::ReadCache::new(file);
    scan_object_image(&cache, path, &mut found);

    found.into_iter().collect()
}

/// Record the instrumentation one file's object image carries.
///
/// A Mach-O universal binary is a wrapper around several real images. The
/// question being asked is about the file as a whole -- "could this build have
/// shown a defect" -- so every slice is scanned and the answers are unioned.
fn scan_object_image<'data, R: object::ReadRef<'data>>(
    data: R,
    path: &Path,
    found: &mut BTreeSet<String>,
) {
    use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};

    match object::FileKind::parse(data) {
        Ok(object::FileKind::MachOFat32) => {
            if let Ok(fat) = MachOFatFile32::parse(data) {
                for arch in fat.arches() {
                    if let Ok(slice) = arch.data(data) {
                        scan_thin_object(slice, path, found);
                    }
                }
            }
        }
        Ok(object::FileKind::MachOFat64) => {
            if let Ok(fat) = MachOFatFile64::parse(data) {
                for arch in fat.arches() {
                    if let Ok(slice) = arch.data(data) {
                        scan_thin_object(slice, path, found);
                    }
                }
            }
        }
        Ok(_) => scan_thin_object(data, path, found),
        Err(_) => {
            tracing::debug!(
                "Target {:?} does not parse as an object; reporting no instrumentation",
                path
            );
        }
    }
}

/// Record the instrumentation a single (non-universal) object image carries.
fn scan_thin_object<'data, R: object::ReadRef<'data>>(
    data: R,
    path: &Path,
    found: &mut BTreeSet<String>,
) {
    use object::{Object, ObjectSection, ObjectSymbol};

    let Ok(object) = object::File::parse(data) else {
        tracing::debug!(
            "Target {:?} does not parse as an object; reporting no instrumentation",
            path
        );
        return;
    };

    // Mach-O prefixes C symbols with an underscore and ELF does not, so the
    // comparison is on the underscore-stripped name; the marker matches as a
    // prefix so `__ubsan_handle` covers `__ubsan_handle_add_overflow`.
    let mut note = |name: &str| {
        let name = name.trim_start_matches('_');
        for (marker, label) in INSTRUMENTATION_MARKERS {
            if !found.contains(*label) && name.starts_with(marker.trim_start_matches('_')) {
                found.insert((*label).to_string());
            }
        }
        // Rust's overflow checks are mangled Rust items, so the marker is in
        // the middle of the symbol rather than at its start.
        if !found.contains(RUST_OVERFLOW_CHECKS_LABEL)
            && RUST_OVERFLOW_CHECK_MARKERS
                .iter()
                .any(|marker| name.contains(marker))
        {
            found.insert(RUST_OVERFLOW_CHECKS_LABEL.to_string());
        }
    };
    for symbol in object.symbols() {
        if let Ok(name) = symbol.name() {
            note(name);
        }
    }
    // A stripped binary keeps its DYNAMIC symbols, and that is where the
    // reference to a shared sanitizer runtime survives.
    for symbol in object.dynamic_symbols() {
        if let Ok(name) = symbol.name() {
            note(name);
        }
    }

    if found.contains("debug-info") {
        return;
    }
    // Debug info is a SECTION, for the same reason the markers are symbols: a
    // section table entry is a fact about the build, a byte sequence somewhere
    // in the file is not.
    for section in object.sections() {
        if let Ok(name) = section.name() {
            if DEBUG_INFO_MARKERS.contains(&name) {
                found.insert("debug-info".to_string());
                return;
            }
        }
    }
    // rustc on macOS leaves the DWARF in the `.o` files and records where each
    // one was with an `N_OSO` stab entry, so a Rust debug build has neither a
    // `__debug_info` section nor a `.dSYM` and still symbolicates to file and
    // line. `object_map()` is that stab list; a non-empty one is debug info by
    // reference, which is the capability the label names.
    if !object.object_map().objects().is_empty() {
        found.insert("debug-info".to_string());
    }
}

/// Cache key: a binary is only re-scanned if it changed on disk.
type InstrumentationKey = (std::path::PathBuf, u64, Option<std::time::SystemTime>);

fn instrumentation_cache() -> &'static std::sync::Mutex<HashMap<InstrumentationKey, Vec<String>>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<InstrumentationKey, Vec<String>>>> =
        std::sync::OnceLock::new();
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
    /// Output the template captured from the **target** and handed back for
    /// cxg's own oracles to read, from `metadata.target_output`. Absent for
    /// every template that does not offer it, which is every template written
    /// before the `exception` oracle existed.
    pub target_output: Option<String>,
    /// Status the **target** exited with, as the template observed it, from
    /// `metadata.target_exit_code`. Reported alongside an `exception` verdict
    /// so the operator can see the exception did not need a crash exit.
    pub target_exit_code: Option<i32>,
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
    if let Some(o) = meta.get("target_output").and_then(|v| v.as_str()) {
        report.target_output = Some(o.to_string());
    }
    if let Some(rc) = meta.get("target_exit_code").and_then(|v| v.as_i64()) {
        report.target_exit_code = Some(rc as i32);
    }
    report
}

/// Real object-file fixtures for the instrumentation preflight's tests.
///
/// Shared by this module's tests and `executor`'s, because both of them assert
/// on what a build carries and neither may do so against a made-up file.
///
/// Unix only: Windows has no `cc`, and the suite runs there.
#[cfg(all(test, unix))]
pub(crate) mod object_fixtures {
    use std::path::Path;

    /// Compile a tiny C source into a **real** object file and hand back its
    /// path.
    ///
    /// The detector reads a symbol table, so a fixture has to be a real
    /// object. A magic number followed by the marker spelled out in the file's
    /// bytes -- what these tests used to build -- is precisely the shape the
    /// detector now refuses to believe, and refusing it is the fix: cxg's own
    /// binary has that shape, and used to read as carrying all seven
    /// sanitizers.
    ///
    /// `cc` is not an extra dependency: cargo already needs a C toolchain to
    /// link this crate, the same argument `tests/fixtures/cli-baseline/build.sh`
    /// makes. Unix only, because Windows has no `cc` and the suite runs there.
    pub(crate) fn compile_c(
        dir: &Path,
        name: &str,
        source: &str,
        flags: &[&str],
    ) -> std::path::PathBuf {
        let src = dir.join(format!("{name}.c"));
        std::fs::write(&src, source).expect("writing the fixture source");

        let out = dir.join(name);
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let built = std::process::Command::new(&cc)
            .args(flags)
            .arg("-o")
            .arg(&out)
            .arg(&src)
            .output()
            .unwrap_or_else(|e| panic!("running {cc}: {e}"));

        assert!(
            built.status.success(),
            "compiling the {name} fixture failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&built.stdout),
            String::from_utf8_lossy(&built.stderr),
        );
        out
    }

    /// A C source that *references* one symbol, so the compiled object carries
    /// it as an undefined entry in its symbol table -- the same entry a build
    /// linked against a sanitizer runtime carries, and the thing the detector
    /// reads.
    pub(crate) fn references(symbol: &str) -> String {
        format!("extern void {symbol}(void);\nvoid (*const cxg_marker_ref)(void) = {symbol};\n")
    }

    /// Compile a tiny Rust source into a **real** executable and hand back its
    /// path.
    ///
    /// Rust's overflow checks are the one instrumentation label that only a
    /// Rust build can carry, so its fixture has to be a Rust build. `rustc` is
    /// not an extra dependency by any measure: it is compiling this test.
    pub(crate) fn compile_rust(
        dir: &Path,
        name: &str,
        source: &str,
        flags: &[&str],
    ) -> std::path::PathBuf {
        let src = dir.join(format!("{name}.rs"));
        std::fs::write(&src, source).expect("writing the fixture source");

        let out = dir.join(name);
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
        let built = std::process::Command::new(&rustc)
            .args(flags)
            .arg("-o")
            .arg(&out)
            .arg(&src)
            .output()
            .unwrap_or_else(|e| panic!("running {rustc}: {e}"));

        assert!(
            built.status.success(),
            "compiling the {name} fixture failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&built.stdout),
            String::from_utf8_lossy(&built.stderr),
        );
        out
    }

    /// A Rust source whose arithmetic **can** overflow, so the compiler has to
    /// emit the check when it is asked for.
    ///
    /// Every operand comes from the process's own argv, which no constant
    /// folding can see through: a program the optimiser can evaluate carries
    /// no check either way and would prove nothing.
    pub(crate) fn rust_fallible_arithmetic() -> String {
        "fn main() {\n\
         \x20   let n: i32 = std::env::args().count() as i32;\n\
         \x20   let m: i32 = std::env::args().skip(1).count() as i32;\n\
         \x20   println!(\"{} {} {}\", n + m, n - m, n * m);\n\
         }\n"
        .to_string()
    }

    /// A C source with no marker in it at all, sized by `padding` bytes of
    /// ballast so two otherwise identical fixtures differ on disk.
    pub(crate) fn no_markers(padding: usize) -> String {
        format!("const char cxg_ballast[{padding}] = {{1}};\nint main(void) {{ return 0; }}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Context, Protocol, Target};

    #[cfg(unix)]
    use super::object_fixtures::{
        compile_c, compile_rust, no_markers, references, rust_fallible_arithmetic,
    };

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
            probe_env: vec![("ASAN_OPTIONS".to_string(), "abort_on_error=1".to_string())],
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
        let header =
            "#!/bin/bash\n# @id: probe\n# @oracles: asan, signal, exit\n# @target_kinds: cli\n";
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

    /// s14 item 4 / §5. The oracle has to separate an exception that escaped
    /// from a non-zero exit the program chose, because both real defects s14
    /// found exited 1 with no crash signal.
    #[test]
    fn recognises_an_escaped_exception_in_each_runtime() {
        let python = "Traceback (most recent call last):\n  \
                      File \"/tmp/app.py\", line 12, in <module>\n    main()\n\
                      ValueError: synthetic\n";
        assert_eq!(
            detect_unhandled_exception(python),
            Some(ExceptionKind::PythonTraceback)
        );

        let node_rejection = "node:internal/process/promises:288\n            \
                              triggerUncaughtException(err, true /* fromPromise */);\n\
                              [UnhandledPromiseRejection: synthetic]\n";
        assert_eq!(
            detect_unhandled_exception(node_rejection),
            Some(ExceptionKind::NodeUnhandledRejection)
        );

        let node_uncaught = "file:///tmp/app.js:3\n  throw new Error('synthetic');\n  ^\n\
                             Error: synthetic\n    at file:///tmp/app.js:3:9\n\
                                 at ModuleJob.run (node:internal/modules/esm/module_job:271:25)\n";
        assert_eq!(
            detect_unhandled_exception(node_uncaught),
            Some(ExceptionKind::NodeUncaughtException)
        );

        let java = "Exception in thread \"main\" java.lang.IllegalStateException: synthetic\n\
                    \tat App.main(App.java:7)\n";
        assert_eq!(
            detect_unhandled_exception(java),
            Some(ExceptionKind::JavaUncaughtException)
        );

        let go = "panic: synthetic\n\ngoroutine 1 [running]:\nmain.main()\n";
        assert_eq!(detect_unhandled_exception(go), Some(ExceptionKind::GoPanic));

        let rust = "thread 'main' panicked at src/main.rs:4:5:\nsynthetic\n";
        assert_eq!(
            detect_unhandled_exception(rust),
            Some(ExceptionKind::RustPanic)
        );
    }

    /// The distinction the `exit` oracle cannot draw: these all exit non-zero
    /// and none of them is a defect.
    #[test]
    fn a_deliberate_error_exit_is_not_an_exception() {
        for output in [
            "error: no such file or directory: /tmp/nope\n",
            "usage: tool <command> [options]\n",
            "validation failed: 3 rules did not pass\n",
            "",
            // Prose that mentions a traceback is not a traceback.
            "This tool prints a Traceback (most recent call last): header when it crashes.\n",
        ] {
            assert_eq!(
                detect_unhandled_exception(output),
                None,
                "output {output:?} must not read as an escaped exception"
            );
        }
    }

    /// s14 §4.1(e): interpreted CLIs print box drawing and ANSI escapes, and a
    /// byte-level cut through one of those is how a template ends up emitting
    /// invalid JSON. cxg cuts on character boundaries.
    #[test]
    fn truncation_never_splits_a_character() {
        let text = "┌───┐ tidy output";
        assert_eq!(truncate_chars(text, 100), text);

        let cut = truncate_chars(text, 3);
        assert_eq!(cut, "┌──...");
        assert!(std::str::from_utf8(cut.as_bytes()).is_ok());
    }

    /// s14 item 1: which templates `--require-instrumentation` may let through
    /// against a build carrying nothing.
    #[test]
    fn build_independence_is_declared_never_assumed() {
        let s = |v: &[&str]| v.iter().map(|o| o.to_string()).collect::<Vec<_>>();

        // Every oracle works on any build: let it through.
        assert!(oracles_are_build_independent(&s(&["exit"])));
        assert!(oracles_are_build_independent(&s(&[
            "exit", "signal", "timeout"
        ])));
        assert!(oracles_are_build_independent(&s(&["exception"])));
        assert!(oracles_are_build_independent(&s(&[" EXIT ", "Timeout"])));

        // One sanitizer oracle is enough to keep the gate closed: the template
        // might be reading the report cxg knows is not there.
        assert!(!oracles_are_build_independent(&s(&["asan"])));
        assert!(!oracles_are_build_independent(&s(&["exit", "asan"])));
        assert!(!oracles_are_build_independent(&s(&[
            "ubsan", "msan", "tsan"
        ])));

        // Absent is not a promise.
        assert!(!oracles_are_build_independent(&[]));
    }

    #[cfg(unix)]
    #[test]
    fn detects_a_sanitizer_marker_and_reports_nothing_without_one() {
        let dir = tempfile::tempdir().unwrap();

        let instrumented = compile_c(dir.path(), "with_asan", &references("__asan_init"), &["-c"]);
        assert_eq!(detect_instrumentation(&instrumented), vec!["asan"]);

        let bare = compile_c(dir.path(), "no_markers", &no_markers(16), &["-c"]);
        assert!(
            detect_instrumentation(&bare).is_empty(),
            "an empty result is the signal that a refutation would not be evidence"
        );
    }

    #[cfg(unix)]
    #[test]
    fn detects_each_known_instrumentation_label() {
        let dir = tempfile::tempdir().unwrap();
        for (marker, label) in [
            ("__asan_init", "asan"),
            // The table's marker is the `__ubsan_handle` prefix; a real build
            // carries the per-check symbols underneath it.
            ("__ubsan_handle_add_overflow", "ubsan"),
            ("__msan_init", "msan"),
            ("__tsan_init", "tsan"),
            ("__sanitizer_cov_trace_pc", "sancov"),
            ("LLVMFuzzerTestOneInput", "libfuzzer"),
            ("__llvm_profile_write_file", "profile"),
        ] {
            let path = compile_c(dir.path(), label, &references(marker), &["-c"]);
            assert_eq!(
                detect_instrumentation(&path),
                vec![label.to_string()],
                "marker {marker} should report {label}"
            );
        }
    }

    /// A `-g` build carries the DWARF in its own section table, which is what
    /// the detector reads -- `.debug_info` on ELF, `__debug_info` on Mach-O.
    #[cfg(unix)]
    #[test]
    fn detects_debug_info_from_a_dwarf_section_name() {
        let dir = tempfile::tempdir().unwrap();

        let with_dwarf = compile_c(dir.path(), "with_dwarf", &no_markers(16), &["-c", "-g"]);
        assert_eq!(detect_instrumentation(&with_dwarf), vec!["debug-info"]);

        let without = compile_c(dir.path(), "without_dwarf", &no_markers(16), &["-c", "-g0"]);
        assert!(
            detect_instrumentation(&without).is_empty(),
            "a build compiled without -g carries no debug info to report"
        );
    }

    /// dsymutil puts macOS debug info in a sibling bundle, outside the
    /// executable, so a stripped-looking binary can still resolve file:line.
    #[cfg(unix)]
    #[test]
    fn detects_debug_info_from_a_sibling_dsym_bundle() {
        let dir = tempfile::tempdir().unwrap();

        // Two marker-free objects of different sizes: the cache is keyed on
        // the binary's own size and mtime, so the second one is what forces a
        // re-read now that the sibling bundle exists.
        let first = compile_c(dir.path(), "first", &no_markers(16), &["-c"]);
        let second = compile_c(dir.path(), "second", &no_markers(4096), &["-c"]);

        let bin = dir.path().join("toy");
        std::fs::copy(&first, &bin).unwrap();
        assert!(detect_instrumentation(&bin).is_empty());

        std::fs::create_dir(dir.path().join("toy.dSYM")).unwrap();
        std::fs::copy(&second, &bin).unwrap();
        assert_eq!(detect_instrumentation(&bin), vec!["debug-info"]);
    }

    /// rustc on macOS emits no `__debug_info` section and no `.dSYM`: it
    /// leaves the DWARF in the `.o` files and records where each one was with
    /// an `N_OSO` stab entry. Symbolication still works -- an ASan report off
    /// such a build carries file and line -- so the build *has* the capability
    /// `debug-info` names, and not reporting it under-reports the build.
    ///
    /// The C toolchain produces the same shape, which is what this pins: the
    /// linked binary's own section table has no DWARF, and the assertion holds
    /// with the sibling bundle deliberately removed so the stabs are the only
    /// evidence left.
    #[cfg(target_os = "macos")]
    #[test]
    fn detects_debug_info_from_macos_oso_stab_entries() {
        let dir = tempfile::tempdir().unwrap();
        let bin = compile_c(dir.path(), "linked", &no_markers(16), &["-g"]);

        // Modern clang runs dsymutil itself when it links from a temporary
        // object. Take the bundle away: the stabs are then the only debug
        // info left, which is exactly the Rust build's situation.
        let dsym = dir.path().join("linked.dSYM");
        if dsym.exists() {
            std::fs::remove_dir_all(&dsym).unwrap();
        }

        assert_eq!(detect_instrumentation(&bin), vec!["debug-info"]);
    }

    /// The symbol table lives wherever the linker put it, which on a real
    /// binary is megabytes into the file. Nothing about the detector may
    /// depend on a marker being near the start.
    #[cfg(unix)]
    #[test]
    fn finds_a_marker_far_into_a_large_object() {
        let dir = tempfile::tempdir().unwrap();

        let mut source = String::from("const char cxg_ballast[2097152] = {1};\n");
        source.push_str(&references("__asan_init"));
        let path = compile_c(dir.path(), "big", &source, &["-c"]);

        assert!(
            std::fs::metadata(&path).unwrap().len() > 1 << 20,
            "the fixture has to be big enough for its symbol table to be far in"
        );
        assert_eq!(detect_instrumentation(&path), vec!["asan"]);
    }

    /// A universal binary is a wrapper around several real images, and the
    /// question -- could this build have shown a defect -- is about the file
    /// the operator named. Every slice is read, and the answers are unioned.
    #[cfg(target_os = "macos")]
    #[test]
    fn reads_every_slice_of_a_universal_binary() {
        let dir = tempfile::tempdir().unwrap();

        // A different marker per slice, so the assertion is that *both* were
        // read and not merely that the first one was.
        let intel = compile_c(
            dir.path(),
            "slice_x86_64",
            &references("__asan_init"),
            &["-c", "-arch", "x86_64"],
        );
        let arm = compile_c(
            dir.path(),
            "slice_arm64",
            &references("__tsan_init"),
            &["-c", "-arch", "arm64"],
        );

        let fat = dir.path().join("universal");
        let joined = std::process::Command::new("lipo")
            .arg("-create")
            .arg("-output")
            .arg(&fat)
            .arg(&intel)
            .arg(&arm)
            .output()
            .expect("running lipo");
        assert!(
            joined.status.success(),
            "lipo failed: {}",
            String::from_utf8_lossy(&joined.stderr)
        );

        assert_eq!(detect_instrumentation(&fat), vec!["asan", "tsan"]);
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
    }

    /// The same two symbols as the script above, this time genuinely
    /// referenced by a compiled object: both are reported.
    #[cfg(unix)]
    #[test]
    fn the_same_markers_inside_a_real_object_are_detected() {
        let dir = tempfile::tempdir().unwrap();

        let mut source = references("__asan_init");
        source.push_str(
            "extern void __ubsan_handle_type_mismatch(void);\n\
             void (*const cxg_marker_ref2)(void) = __ubsan_handle_type_mismatch;\n",
        );
        let object = compile_c(dir.path(), "with_asan_ubsan", &source, &["-c"]);

        assert_eq!(detect_instrumentation(&object), vec!["asan", "ubsan"]);
    }

    /// An object whose *strings* spell every marker, and whose symbol table
    /// references none of them, carries no instrumentation. This is cxg's own
    /// binary in miniature, and the whole point of reading symbols: the byte
    /// scan this replaced reported an ordinary `cargo build` of cxg as
    /// carrying asan, ubsan, msan, tsan, sancov, libfuzzer and profile, and
    /// `--require-instrumentation` -- the flag whose entire purpose is to stop
    /// that -- let it through.
    #[cfg(unix)]
    #[test]
    fn an_object_that_only_names_the_markers_carries_no_instrumentation() {
        let dir = tempfile::tempdir().unwrap();

        let source = "const char *const cxg_marker_table[] = {\n\
             \"__asan_init\", \"__asan_report_load1\", \"__ubsan_handle\",\n\
             \"__msan_init\", \"__tsan_init\", \"__sanitizer_cov\",\n\
             \"LLVMFuzzerTestOneInput\", \"__llvm_profile\",\n\
             \".debug_info\", \"__debug_info\", \".debug_line\",\n\
             };\nint main(void) { return 0; }\n";
        let object = compile_c(dir.path(), "names_only", source, &["-c"]);

        assert!(
            detect_instrumentation(&object).is_empty(),
            "a marker in a string constant is prose, not a build capability"
        );
    }

    /// **The Rust integer class.** Rust has no UBSan, so the only thing that
    /// makes an integer overflow observable is `-C overflow-checks=on`, and
    /// the only honest way to gate a template's overflow branch is to know
    /// whether that flag was passed. It is a real, readable build fact: the
    /// check compiles in a call to `core::panicking::panic_const::*_overflow`,
    /// which is a symbol.
    ///
    /// Both directions, on the same source, because one alone proves nothing:
    /// a detector that always said yes would let a template refute on a build
    /// where the same program returns the same wrong number and exits 0.
    #[cfg(unix)]
    #[test]
    fn detects_rust_overflow_checks_only_when_the_flag_compiled_them_in() {
        let dir = tempfile::tempdir().unwrap();
        let source = rust_fallible_arithmetic();

        let with = compile_rust(
            dir.path(),
            "checks_on",
            &source,
            &["-C", "overflow-checks=on"],
        );
        assert!(
            detect_instrumentation(&with).contains(&RUST_OVERFLOW_CHECKS_LABEL.to_string()),
            "a build compiled with -C overflow-checks=on carries the check: {:?}",
            detect_instrumentation(&with)
        );

        let without = compile_rust(
            dir.path(),
            "checks_off",
            &source,
            &["-C", "overflow-checks=off"],
        );
        assert!(
            !detect_instrumentation(&without).contains(&RUST_OVERFLOW_CHECKS_LABEL.to_string()),
            "a build with the check compiled OUT must not report it -- that is the false \
             all-clear the preflight exists to refuse: {:?}",
            detect_instrumentation(&without)
        );
    }

    /// `overflow` is build-dependent, so a template that can only decide that
    /// way is refused on a build that compiled the check out -- and allowed on
    /// one that did not.
    #[test]
    fn the_overflow_oracle_is_gated_on_the_rust_overflow_check_label() {
        let declared = vec!["overflow".to_string()];
        assert_eq!(
            unsupported_oracles(&declared, &["asan".to_string()]),
            Some(vec!["overflow".to_string()]),
            "an ASan-only build cannot decide the integer class"
        );
        assert_eq!(
            unsupported_oracles(
                &declared,
                &["asan".to_string(), RUST_OVERFLOW_CHECKS_LABEL.to_string()]
            ),
            None
        );
        assert!(
            !oracles_are_build_independent(&declared),
            "overflow must not read as build-independent: that would let a template refute the \
             integer class on a build where the check was never compiled in"
        );
    }

    /// **Provenance beats inspection.** Where cxg built the binary itself it
    /// already read the artefact back, and that record is authoritative.
    #[test]
    fn a_build_manifest_is_believed_in_preference_to_re_inspecting_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("toy");
        std::fs::write(
            &binary,
            b"#!/bin/sh
exit 0
",
        )
        .unwrap();
        let key = binary.canonicalize().unwrap().to_string_lossy().to_string();

        // Inspection alone reports nothing for this file.
        assert!(detect_instrumentation(&binary).is_empty());

        let mut context = Context::default();
        context.instrumentation_provenance.insert(
            key,
            vec!["asan".to_string(), RUST_OVERFLOW_CHECKS_LABEL.to_string()],
        );
        assert_eq!(
            instrumentation_for(&binary, &context),
            vec!["asan".to_string(), RUST_OVERFLOW_CHECKS_LABEL.to_string()]
        );
    }

    /// The additive contract: a manifest naming some *other* binary changes
    /// nothing, and no manifest at all is exactly today's behaviour.
    #[test]
    fn provenance_applies_only_to_the_binary_its_manifest_names() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("toy");
        std::fs::write(
            &binary,
            b"#!/bin/sh
exit 0
",
        )
        .unwrap();

        let mut context = Context::default();
        assert_eq!(
            instrumentation_for(&binary, &context),
            detect_instrumentation(&binary),
            "with no manifest, provenance must not change a single answer"
        );

        context
            .instrumentation_provenance
            .insert("/some/other/binary".to_string(), vec!["asan".to_string()]);
        assert!(
            instrumentation_for(&binary, &context).is_empty(),
            "a manifest for another binary must not vouch for this one"
        );
    }

    /// End to end at the wire level: a manifest reaches the template as
    /// `CERT_X_GEN_TARGET_INSTRUMENTATION`, which is what a gated branch reads.
    #[test]
    fn build_env_vars_reports_the_instrumentation_a_manifest_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("toy");
        std::fs::write(
            &binary,
            b"#!/bin/sh
exit 0
",
        )
        .unwrap();
        let key = binary.canonicalize().unwrap().to_string_lossy().to_string();

        let target = Target::new(binary.to_string_lossy().to_string(), Protocol::Cli);
        let mut context = Context::default();
        assert_eq!(
            build_env_vars(&target, &context)
                .unwrap()
                .get("CERT_X_GEN_TARGET_INSTRUMENTATION")
                .unwrap(),
            "none"
        );

        context
            .instrumentation_provenance
            .insert(key, vec!["asan".to_string(), "debug-info".to_string()]);
        assert_eq!(
            build_env_vars(&target, &context)
                .unwrap()
                .get("CERT_X_GEN_TARGET_INSTRUMENTATION")
                .unwrap(),
            "asan,debug-info"
        );
    }

    /// The same rule for a plain source file and for a Python console-script
    /// wrapper -- the two other shapes a `cli://` target took in s14.
    #[test]
    fn only_a_compiled_object_is_scanned_for_markers() {
        let dir = tempfile::tempdir().unwrap();

        for (name, body) in [
            (
                "source.c",
                "/* calls __asan_init at startup */\nint main(void){return 0;}\n",
            ),
            (
                "bugb",
                "#!/usr/bin/env python3\n# __asan_init, __llvm_profile, .debug_info\nimport sys\n",
            ),
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

        let bare = dir.path().join("toy_stripped");
        std::fs::write(&bare, b"nothing to see").unwrap();
        let cli = Target::new(bare.to_string_lossy().to_string(), Protocol::Cli);
        let env = build_env_vars(&cli, &Context::default()).unwrap();
        assert_eq!(
            env.get("CERT_X_GEN_TARGET_INSTRUMENTATION").unwrap(),
            "none"
        );

        let net = Target::with_port("example.com", 443, Protocol::Https);
        let env = build_env_vars(&net, &Context::default()).unwrap();
        assert!(!env.contains_key("CERT_X_GEN_TARGET_INSTRUMENTATION"));
    }

    /// The value a template reads is what the build actually carries, taken
    /// from a real object rather than from a file that merely spells the
    /// markers out.
    #[cfg(unix)]
    #[test]
    fn build_env_vars_reports_the_instrumentation_a_real_build_carries() {
        let dir = tempfile::tempdir().unwrap();
        let bin = compile_c(
            dir.path(),
            "toy_asan",
            &references("__asan_init"),
            &["-c", "-g"],
        );

        let cli = Target::new(bin.to_string_lossy().to_string(), Protocol::Cli);
        let env = build_env_vars(&cli, &Context::default()).unwrap();
        assert_eq!(
            env.get("CERT_X_GEN_TARGET_INSTRUMENTATION").unwrap(),
            "asan,debug-info"
        );
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
        let report = parse_template_report(r#"{"findings":[],"metadata":{"status":"refuuted"}}"#);
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
        let script = format!("sleep 5; echo alive > {}", marker.display());
        let args = vec!["-c".to_string(), script];

        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            execute_command("sh", &args, &HashMap::new()),
        )
        .await;
        assert!(
            timed_out.is_err(),
            "the command should have outrun the timeout"
        );

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
