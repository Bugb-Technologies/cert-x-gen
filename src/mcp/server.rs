//! CXG MCP Server implementation
//!
//! Provides 12 tools for AI agents:
//! - cxg_search: Search templates by query/filters
//! - cxg_template_list: List templates with optional filters
//! - cxg_template_info: Get detailed info on a specific template
//! - cxg_scan: Run security scans against targets
//! - cxg_template_validate: Validate template code (12-language checker)
//! - cxg_template_create: Scaffold a new template with boilerplate
//! - cxg_template_write: Validate + save a completed template atomically
//! - cxg_template_get_notes: Get the AI generation guide for a language
//! - cxg_ai_generate: Generate a template from natural language (dual-mode)
//! - cxg_template_test: Test a specific template against a target
//! - cxg_template_stats: Get template collection statistics
//! - cxg_template_update: Pull latest templates from remote repository

use crate::config::Config;
use crate::core::CertXGen;
use crate::search::{SearchArgs, SearchFormat, SearchSort, TemplateSearchEngine};
use crate::template::TemplateFilter;
use crate::types::{Protocol, Severity, Target, TemplateLanguage};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─── Request types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchRequest {
    /// Search query text (searches name, description, tags)
    pub query: Option<String>,
    /// Filter by language: yaml, python, rust, shell, javascript, c, cpp, java, go, ruby, perl, php
    pub language: Option<String>,
    /// Filter by severity: critical, high, medium, low, info
    pub severity: Option<String>,
    /// Filter by tags (comma-separated)
    pub tags: Option<String>,
    /// Maximum results to return (default: 20)
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TemplateListRequest {
    /// Filter by programming language
    pub language: Option<String>,
    /// Filter by severity level
    pub severity: Option<String>,
    /// Filter by tags (comma-separated)
    pub tags: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TemplateInfoRequest {
    /// Template ID to look up
    pub template_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScanRequest {
    /// Target: URL, IP, domain, CIDR (e.g. "https://example.com")
    pub scope: String,
    /// Template IDs to run (comma-separated). Omit for all.
    pub templates: Option<String>,
    /// Filter by tags (comma-separated)
    pub tags: Option<String>,
    /// Filter by severity
    pub severity: Option<String>,
    /// Timeout per template in seconds (default: 30)
    pub timeout: Option<u64>,
    /// Additional ports (comma-separated)
    pub ports: Option<String>,
    /// JSON context for parameterised templates. Injected as CERT_X_GEN_CONTEXT env var.
    /// Example: {"auth_token":"Bearer eyJ...","user_id":"6","endpoints":["/api/users/6"]}
    pub context: Option<String>,
    /// Run only templates in this batch group (e.g. "auth-context", "endpoint-params")
    pub batch_group: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TemplateValidateRequest {
    /// Template source code to validate
    pub code: String,
    /// Language of the template: python, yaml, rust, shell, javascript, c, cpp, java, go, ruby, perl, php
    pub language: String,
    /// Optional filename (helps detect language mismatches)
    pub filename: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TemplateCreateRequest {
    /// Unique template ID (kebab-case, e.g. "graphql-introspection")
    pub id: String,
    /// Programming language for the template
    pub language: String,
    /// Human-readable name (auto-generated from ID if omitted)
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TemplateWriteRequest {
    /// Unique template ID (kebab-case, e.g. "jwt-none-alg-check")
    pub id: String,
    /// Programming language: python, yaml, rust, shell, javascript, c, cpp, java, go, ruby, perl, php
    pub language: String,
    /// Complete template source code (must pass validation before saving)
    pub code: String,
    /// Overwrite if a template with this ID already exists (default: false)
    pub overwrite: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TemplateNotesRequest {
    /// Programming language to get guidance for: python, yaml, rust, shell, javascript, c, cpp, java, go, ruby, perl, php
    pub language: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AiGenerateRequest {
    /// Natural language description of what to detect.
    /// Examples: "detect Redis without authentication", "find JWT none algorithm", "check for exposed Memcached"
    pub prompt: String,
    /// Programming language for the template (default: yaml)
    pub language: Option<String>,
    /// LLM provider override: anthropic, openai, deepseek, ollama.
    /// If omitted, uses the configured default provider.
    pub provider: Option<String>,
    /// Model name override (e.g. claude-sonnet-4-20250514, gpt-4o).
    /// If omitted, uses the provider default.
    pub model: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TemplateTestRequest {
    /// Template ID to test
    pub template_id: String,
    /// Target to test against (URL, IP, hostname)
    pub target: String,
    /// Timeout in seconds (default: 30)
    pub timeout: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TemplateStatsRequest {
    /// Optional: only count templates for this language
    pub language: Option<String>,
}

// No params needed for update, but rmcp needs a struct
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TemplateUpdateRequest {
    /// Force update even if already up-to-date
    pub force: Option<bool>,
}

// ─── Response types ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct TemplateEntry {
    id: String,
    name: String,
    language: String,
    severity: String,
    description: String,
    tags: Vec<String>,
    cwe: Vec<String>,
    confidence: Option<u8>,
}

#[derive(Debug, Serialize)]
struct TemplateDetail {
    id: String,
    name: String,
    language: String,
    severity: String,
    description: String,
    tags: Vec<String>,
    cwe: Vec<String>,
    cve: Vec<String>,
    cvss: Option<f32>,
    confidence: Option<u8>,
    author: String,
    version: String,
    file_path: String,
    // Parameterisation & routing fields
    context_vars: Vec<String>,
    vuln_class: Option<String>,
    hypothesis_tags: Vec<String>,
    batch_group: Option<String>,
    auto_probe: bool,
}

#[derive(Debug, Serialize)]
struct ScanFinding {
    target: String,
    template_id: String,
    severity: String,
    confidence: u8,
    title: String,
    description: String,
    cwe: Vec<String>,
    cve: Vec<String>,
    evidence_patterns: Vec<String>,
    remediation: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanOutput {
    scan_id: String,
    targets_scanned: usize,
    templates_executed: usize,
    total_findings: usize,
    findings: Vec<ScanFinding>,
    errors: Vec<String>,
    duration_secs: f64,
}

#[derive(Debug, Serialize)]
struct DiagnosticEntry {
    severity: String,
    code: String,
    message: String,
    line: Option<usize>,
    column: Option<usize>,
    suggestion: Option<String>,
}

// ─── MCP Server ──────────────────────────────────────────────────────────────

/// CERT-X-GEN MCP Server — exposes scanning capabilities via Model Context Protocol
#[derive(Debug, Clone)]
pub struct CxgMcpServer {
    tool_router: ToolRouter<Self>,
}

impl Default for CxgMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl CxgMcpServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    async fn load_templates() -> Result<Vec<Box<dyn crate::template::Template>>, String> {
        // Spawn on a new thread with its own runtime because TemplateLoader
        // returns non-Send futures internally. The result (Vec<Box<dyn Template>>)
        // IS Send+Sync so this works fine across the channel.
        Self::run_non_send(|| async {
            let config = Config::default();
            let engine = CertXGen::new(config)
                .await
                .map_err(|e| format!("Failed to init engine: {}", e))?;
            engine
                .load_templates()
                .await
                .map_err(|e| format!("Failed to load templates: {}", e))
        })
        .await
    }

    /// Run an async closure that may contain non-Send futures on a dedicated thread.
    /// The closure's return type must be Send so it can cross the channel.
    async fn run_non_send<F, Fut, T>(f: F) -> Result<T, String>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T, String>>,
        T: Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
            let result = rt.block_on(f());
            let _ = tx.send(result);
        });
        rx.await.map_err(|e| format!("Channel error: {}", e))?
    }

    fn parse_language(s: &str) -> Option<TemplateLanguage> {
        match s.to_lowercase().as_str() {
            "yaml" | "yml" => Some(TemplateLanguage::Yaml),
            "python" | "py" => Some(TemplateLanguage::Python),
            "rust" | "rs" => Some(TemplateLanguage::Rust),
            "shell" | "sh" | "bash" => Some(TemplateLanguage::Shell),
            "javascript" | "js" => Some(TemplateLanguage::JavaScript),
            "c" => Some(TemplateLanguage::C),
            "cpp" | "c++" => Some(TemplateLanguage::Cpp),
            "java" => Some(TemplateLanguage::Java),
            "go" | "golang" => Some(TemplateLanguage::Go),
            "ruby" | "rb" => Some(TemplateLanguage::Ruby),
            "perl" | "pl" => Some(TemplateLanguage::Perl),
            "php" => Some(TemplateLanguage::Php),
            _ => None,
        }
    }

    fn parse_severity(s: &str) -> Option<Severity> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" => Some(Severity::Info),
            _ => None,
        }
    }

    fn parse_target(scope: &str) -> Target {
        if let Ok(url) = url::Url::parse(scope) {
            if let Some(host) = url.host_str() {
                let protocol = match url.scheme().to_lowercase().as_str() {
                    "http" => Protocol::Http,
                    "https" => Protocol::Https,
                    "tcp" => Protocol::Tcp,
                    other => Protocol::Custom(other.to_string()),
                };
                let mut target = Target::new(host, protocol);
                if let Some(port) = url.port() {
                    target.port = Some(port);
                }
                return target;
            }
        }
        if let Some((host, port_str)) = scope.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                let protocol = match port {
                    80 | 8000 | 8080 => Protocol::Http,
                    443 | 8443 => Protocol::Https,
                    _ => Protocol::Https,
                };
                return Target::with_port(host, port, protocol);
            }
        }
        Target::new(scope, Protocol::Https)
    }

    fn lang_to_ext(lang: &TemplateLanguage) -> &'static str {
        match lang {
            TemplateLanguage::Python => "py",
            TemplateLanguage::Rust => "rs",
            TemplateLanguage::Shell => "sh",
            TemplateLanguage::JavaScript => "js",
            TemplateLanguage::C => "c",
            TemplateLanguage::Cpp => "cpp",
            TemplateLanguage::Java => "java",
            TemplateLanguage::Go => "go",
            TemplateLanguage::Ruby => "rb",
            TemplateLanguage::Perl => "pl",
            TemplateLanguage::Php => "php",
            TemplateLanguage::Yaml => "yaml",
        }
    }
}

// ─── Tool implementations ────────────────────────────────────────────────────

#[tool_router]
impl CxgMcpServer {
    #[tool(
        description = "Search security scanning templates by query, language, severity, or tags. Returns matching templates with relevance scores."
    )]
    async fn cxg_search(
        &self,
        Parameters(req): Parameters<SearchRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let templates = Self::load_templates()
            .await
            .map_err(|e| ErrorData::internal_error(e, None))?;

        let search_engine = TemplateSearchEngine::new(templates);
        let search_args = SearchArgs {
            query: req.query,
            language: req.language.as_deref().and_then(Self::parse_language),
            severity: req.severity.as_deref().and_then(Self::parse_severity),
            tags: req.tags,
            author: None,
            cwe: None,
            content: false,
            case_sensitive: false,
            regex: false,
            limit: req.limit.unwrap_or(20),
            format: SearchFormat::Json,
            detailed: false,
            sort: SearchSort::Relevance,
            reverse: false,
            ids_only: false,
            stats: false,
        };

        let (results, stats) = search_engine.search(&search_args);
        let output: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id, "name": r.name,
                    "language": format!("{}", r.language),
                    "severity": format!("{}", r.severity),
                    "description": r.description, "tags": r.tags,
                    "cwe": r.cwe, "relevance": r.relevance_score,
                })
            })
            .collect();

        let json = serde_json::json!({
            "total_available": stats.total_templates,
            "matching": stats.matching_templates,
            "results": output,
        });
        Ok(CallToolResult::success(vec![Content::text(
            json.to_string(),
        )]))
    }

    #[tool(
        description = "List available security scanning templates with optional filters by language, severity, or tags."
    )]
    async fn cxg_template_list(
        &self,
        Parameters(req): Parameters<TemplateListRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let templates = Self::load_templates()
            .await
            .map_err(|e| ErrorData::internal_error(e, None))?;

        let filtered: Vec<&Box<dyn crate::template::Template>> = templates
            .iter()
            .filter(|t| {
                let m = t.metadata();
                if let Some(ref lang) = req.language {
                    if let Some(parsed) = Self::parse_language(lang) {
                        if m.language != parsed {
                            return false;
                        }
                    }
                }
                if let Some(ref sev) = req.severity {
                    let severities: Vec<&str> = sev.split(',').map(|s| s.trim()).collect();
                    if !severities
                        .iter()
                        .any(|s| Self::parse_severity(s) == Some(m.severity))
                    {
                        return false;
                    }
                }
                if let Some(ref tags) = req.tags {
                    let filter_tags: Vec<&str> = tags.split(',').map(|s| s.trim()).collect();
                    if !filter_tags
                        .iter()
                        .any(|ft| m.tags.iter().any(|t| t.eq_ignore_ascii_case(ft)))
                    {
                        return false;
                    }
                }
                true
            })
            .collect();

        let entries: Vec<TemplateEntry> = filtered
            .iter()
            .map(|t| {
                let m = t.metadata();
                TemplateEntry {
                    id: m.id.clone(),
                    name: m.name.clone(),
                    language: m.language.to_string(),
                    severity: m.severity.to_string(),
                    description: if m.description.len() > 120 {
                        format!("{}...", &m.description[..120])
                    } else {
                        m.description.clone()
                    },
                    tags: m.tags.clone(),
                    cwe: m.cwe_ids.clone(),
                    confidence: m.confidence,
                }
            })
            .collect();

        let json = serde_json::json!({ "total": entries.len(), "templates": entries });
        Ok(CallToolResult::success(vec![Content::text(
            json.to_string(),
        )]))
    }

    #[tool(
        description = "Get detailed info about a specific template by ID. Returns full metadata, CWEs, CVEs, author, and description."
    )]
    async fn cxg_template_info(
        &self,
        Parameters(req): Parameters<TemplateInfoRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let templates = Self::load_templates()
            .await
            .map_err(|e| ErrorData::internal_error(e, None))?;

        let found = templates.iter().find(|t| {
            let m = t.metadata();
            m.id.eq_ignore_ascii_case(&req.template_id)
                || m.name.eq_ignore_ascii_case(&req.template_id)
        });

        match found {
            Some(template) => {
                let m = template.metadata();
                let detail = TemplateDetail {
                    id: m.id.clone(),
                    name: m.name.clone(),
                    language: m.language.to_string(),
                    severity: m.severity.to_string(),
                    description: m.description.clone(),
                    tags: m.tags.clone(),
                    cwe: m.cwe_ids.clone(),
                    cve: m.cve_ids.clone(),
                    cvss: m.cvss_score,
                    confidence: m.confidence,
                    author: m.author.name.clone(),
                    version: m.version.clone(),
                    file_path: m.file_path.to_string_lossy().to_string(),
                    context_vars: m.context_vars.clone(),
                    vuln_class: m.vuln_class.clone(),
                    hypothesis_tags: m.hypothesis_tags.clone(),
                    batch_group: m.batch_group.clone(),
                    auto_probe: m.auto_probe,
                };
                let json = serde_json::to_string_pretty(&detail)
                    .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            None => {
                let suggestions: Vec<String> = templates
                    .iter()
                    .filter(|t| {
                        let id = t.metadata().id.to_lowercase();
                        let q = req.template_id.to_lowercase();
                        id.contains(&q) || q.contains(&id)
                    })
                    .take(5)
                    .map(|t| t.metadata().id.clone())
                    .collect();
                let json = serde_json::json!({
                    "error": format!("Template '{}' not found", req.template_id),
                    "suggestions": suggestions,
                    "hint": "Use cxg_search or cxg_template_list to find available templates"
                });
                Ok(CallToolResult::success(vec![Content::text(
                    json.to_string(),
                )]))
            }
        }
    }

    #[tool(
        description = "Run a security scan against a target. Executes vulnerability detection templates and returns findings with evidence and remediation. Pass 'context' as a JSON object to inject auth tokens and endpoint lists into parameterised templates (e.g. auth-context batch group). Use 'batch_group' to run only templates sharing a context shape."
    )]
    async fn cxg_scan(
        &self,
        Parameters(req): Parameters<ScanRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let timeout = req.timeout;
        let scope = req.scope.clone();
        let template_ids = req.templates.clone();
        let tags = req.tags.clone();
        let severity = req.severity.clone();
        let ports = req.ports.clone();
        let context_json = req.context.clone();
        let batch_group = req.batch_group.clone();

        let output = Self::run_non_send(move || async move {
            let mut config = Config::default();
            if let Some(t) = timeout {
                config.network.timeout_secs = t;
                config.templates.timeout_secs = t;
            }

            let engine = CertXGen::new(config).await
                .map_err(|e| format!("Engine init failed: {}", e))?;
            let templates = engine.load_templates().await
                .map_err(|e| format!("Template load failed: {}", e))?;

            if templates.is_empty() {
                return Err("No templates available. Run cxg_template_update first.".to_string());
            }

            let targets: Vec<Target> = scope.split(',').map(|s| Self::parse_target(s.trim())).collect();
            let additional_ports: Vec<u16> = ports.as_deref()
                .map(|p| p.split(',').filter_map(|s| s.trim().parse().ok()).collect())
                .unwrap_or_default();

            let mut job = engine.create_scan_job(targets, templates);
            let mut filter = TemplateFilter::new();
            if let Some(ref ids) = template_ids {
                filter.ids = ids.split(',').map(|s| s.trim().to_string()).collect();
            }
            if let Some(ref t) = tags {
                filter.tags = t.split(',').map(|s| s.trim().to_string()).collect();
            }
            if let Some(ref s) = severity {
                filter.severities = s.split(',').filter_map(|sv| Self::parse_severity(sv.trim())).collect();
            }
            if let Some(ref bg) = batch_group {
                filter.batch_group = Some(bg.clone());
            }
            job.filter_templates(&filter);
            if !additional_ports.is_empty() {
                job.context.additional_ports = additional_ports;
            }
            // Inject context variables — same logic as CLI --context flag
            if let Some(ref json_str) = context_json {
                match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(json_str) {
                    Ok(map) => {
                        for (key, value) in map {
                            let str_value = match value {
                                serde_json::Value::String(s) => s,
                                other => other.to_string(),
                            };
                            job.context.variables.insert(key, str_value);
                        }
                    }
                    Err(e) => {
                        return Err(format!("Invalid context JSON: {}. Expected object like {{\"auth_token\":\"Bearer eyJ...\"}}", e));
                    }
                }
            }

            let template_count = job.templates.len();
            let target_count = job.targets.len();
            let start = std::time::Instant::now();

            let results = engine.execute_scan(job).await
                .map_err(|e| format!("Scan failed: {}", e))?;
            let duration = start.elapsed();

            let findings: Vec<ScanFinding> = results.findings.iter().map(|f| ScanFinding {
                target: f.target.clone(), template_id: f.template_id.clone(),
                severity: f.severity.to_string(), confidence: f.confidence,
                title: f.title.clone(), description: f.description.clone(),
                cwe: f.cwe_ids.clone(), cve: f.cve_ids.clone(),
                evidence_patterns: f.evidence.matched_patterns.clone(),
                remediation: f.remediation.clone(),
            }).collect();

            Ok(ScanOutput {
                scan_id: results.scan_id.to_string(),
                targets_scanned: target_count, templates_executed: template_count,
                total_findings: findings.len(), findings,
                errors: results.errors, duration_secs: duration.as_secs_f64(),
            })
        }).await.map_err(|e| ErrorData::internal_error(e, None))?;

        let json = serde_json::to_string_pretty(&output)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    // ─── New tools ───────────────────────────────────────────────────────────

    #[tool(
        description = "Validate template source code. Runs 12-language syntax checker, pattern analysis, and schema validation. Returns diagnostics with severity, line numbers, and fix suggestions."
    )]
    async fn cxg_template_validate(
        &self,
        Parameters(req): Parameters<TemplateValidateRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        use crate::ai::validator::{DiagnosticSeverity, TemplateValidator};

        let language = Self::parse_language(&req.language).ok_or_else(|| {
            ErrorData::invalid_params(
                format!("Unknown language '{}'. Supported: yaml, python, rust, shell, javascript, c, cpp, java, go, ruby, perl, php", req.language),
                None,
            )
        })?;

        let validator = TemplateValidator::new();
        let filename = req
            .filename
            .as_ref()
            .map(|f| std::path::Path::new(f.as_str()));

        let diagnostics = validator
            .validate_with_diagnostics(&req.code, language, filename)
            .map_err(|e| ErrorData::internal_error(format!("Validation failed: {}", e), None))?;

        let entries: Vec<DiagnosticEntry> = diagnostics
            .iter()
            .map(|d| DiagnosticEntry {
                severity: match d.severity {
                    DiagnosticSeverity::Error => "error".to_string(),
                    DiagnosticSeverity::Warning => "warning".to_string(),
                    DiagnosticSeverity::Info => "info".to_string(),
                },
                code: d.code.clone(),
                message: d.message.clone(),
                line: d.line,
                column: d.column,
                suggestion: None,
            })
            .collect();

        let errors = entries.iter().filter(|d| d.severity == "error").count();
        let warnings = entries.iter().filter(|d| d.severity == "warning").count();

        let json = serde_json::json!({
            "valid": errors == 0,
            "errors": errors,
            "warnings": warnings,
            "total_diagnostics": entries.len(),
            "diagnostics": entries,
        });
        Ok(CallToolResult::success(vec![Content::text(
            json.to_string(),
        )]))
    }

    #[tool(
        description = "Create a new template from scaffold with proper metadata headers. Returns the boilerplate code for the specified language. The agent can then customize the detection logic."
    )]
    async fn cxg_template_create(
        &self,
        Parameters(req): Parameters<TemplateCreateRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let language = Self::parse_language(&req.language).ok_or_else(|| {
            ErrorData::invalid_params(
                format!("Unknown language '{}'. Supported: yaml, python, rust, shell, javascript, c, cpp, java, go, ruby, perl, php", req.language),
                None,
            )
        })?;

        let ext = Self::lang_to_ext(&language);
        let skeleton_name = format!(
            "{}-template-skeleton.{}",
            match language {
                TemplateLanguage::Python => "python",
                TemplateLanguage::Rust => "rust",
                TemplateLanguage::Shell => "shell",
                TemplateLanguage::JavaScript => "javascript",
                TemplateLanguage::C => "c",
                TemplateLanguage::Cpp => "cpp",
                TemplateLanguage::Java => "java",
                TemplateLanguage::Go => "go",
                TemplateLanguage::Ruby => "ruby",
                TemplateLanguage::Perl => "perl",
                TemplateLanguage::Php => "php",
                TemplateLanguage::Yaml => "yaml",
            },
            ext
        );

        // Search skeleton in known locations
        let skeleton_paths = [
            PathBuf::from("templates/skeleton").join(&skeleton_name),
            dirs::home_dir()
                .unwrap_or_default()
                .join(".cert-x-gen/templates/official/templates/skeleton")
                .join(&skeleton_name),
        ];

        let skeleton_content = skeleton_paths
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok());

        let template_name = req.name.unwrap_or_else(|| {
            req.id
                .split('-')
                .map(|word| {
                    let mut chars = word.chars();
                    match chars.next() {
                        Some(c) => c.to_uppercase().chain(chars).collect(),
                        None => String::new(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        });

        let code = match skeleton_content {
            Some(skeleton) => skeleton
                .replace("template-skeleton", &req.id)
                .replace("Template Skeleton", &template_name),
            None => {
                // Generate minimal boilerplate if no skeleton found
                self.generate_minimal_scaffold(&req.id, &template_name, &language)
            }
        };

        let filename = format!("{}.{}", req.id, ext);
        let json = serde_json::json!({
            "template_id": req.id,
            "language": format!("{}", language),
            "filename": filename,
            "code": code,
            "hint": "Customize the detection logic, then use cxg_template_validate to check it, or cxg_template_write to validate and save in one step."
        });
        Ok(CallToolResult::success(vec![Content::text(
            json.to_string(),
        )]))
    }

    #[tool(
        description = "Validate and save a completed template atomically. Runs the full 12-language validator first — if any errors are found the file is NOT written and diagnostics are returned for the agent to fix. On success, saves to ~/.cert-x-gen/templates/agent-created/<id>.<ext> and returns the saved path. Use this after cxg_template_create + writing detection logic. Prefer this over cxg_template_validate + manual save to guarantee no broken template ever touches disk."
    )]
    async fn cxg_template_write(
        &self,
        Parameters(req): Parameters<TemplateWriteRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        use crate::ai::validator::{DiagnosticSeverity, TemplateValidator};

        let language = Self::parse_language(&req.language).ok_or_else(|| {
            ErrorData::invalid_params(
                format!("Unknown language '{}'. Supported: yaml, python, rust, shell, javascript, c, cpp, java, go, ruby, perl, php", req.language),
                None,
            )
        })?;

        // --- Step 1: validate ---
        let validator = TemplateValidator::new();
        let ext = Self::lang_to_ext(&language);
        let filename = format!("{}.{}", req.id, ext);
        let filepath = std::path::Path::new(&filename);

        let diagnostics = validator
            .validate_with_diagnostics(&req.code, language, Some(filepath))
            .map_err(|e| ErrorData::internal_error(format!("Validation failed: {}", e), None))?;

        let errors: Vec<_> = diagnostics
            .iter()
            .filter(|d| matches!(d.severity, DiagnosticSeverity::Error))
            .collect();
        let warnings: Vec<_> = diagnostics
            .iter()
            .filter(|d| matches!(d.severity, DiagnosticSeverity::Warning))
            .collect();

        // Block save if there are errors
        if !errors.is_empty() {
            let diag_entries: Vec<serde_json::Value> = diagnostics
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "severity": match d.severity {
                            DiagnosticSeverity::Error   => "error",
                            DiagnosticSeverity::Warning => "warning",
                            DiagnosticSeverity::Info    => "info",
                        },
                        "code":    d.code,
                        "message": d.message,
                        "line":    d.line,
                        "column":  d.column,
                    })
                })
                .collect();

            let json = serde_json::json!({
                "saved": false,
                "reason": "Template has validation errors — fix them and retry cxg_template_write",
                "errors":   errors.len(),
                "warnings": warnings.len(),
                "diagnostics": diag_entries,
            });
            return Ok(CallToolResult::success(vec![Content::text(
                json.to_string(),
            )]));
        }

        // --- Step 2: resolve save path ---
        let save_dir = dirs::home_dir()
            .ok_or_else(|| {
                ErrorData::internal_error("Cannot determine home directory".to_string(), None)
            })?
            .join(".cert-x-gen")
            .join("templates")
            .join("agent-created");

        std::fs::create_dir_all(&save_dir).map_err(|e| {
            ErrorData::internal_error(format!("Cannot create save directory: {}", e), None)
        })?;

        let save_path = save_dir.join(&filename);

        // Overwrite guard
        if save_path.exists() && !req.overwrite.unwrap_or(false) {
            let json = serde_json::json!({
                "saved": false,
                "reason": format!("Template '{}' already exists at {}. Pass overwrite: true to replace it.", req.id, save_path.display()),
                "path": save_path.to_string_lossy(),
            });
            return Ok(CallToolResult::success(vec![Content::text(
                json.to_string(),
            )]));
        }

        // --- Step 3: write ---
        std::fs::write(&save_path, &req.code).map_err(|e| {
            ErrorData::internal_error(format!("Failed to write template: {}", e), None)
        })?;

        let json = serde_json::json!({
            "saved": true,
            "template_id": req.id,
            "language": format!("{}", language),
            "path": save_path.to_string_lossy(),
            "warnings": warnings.len(),
            "hint": if warnings.is_empty() {
                "Template saved. Use cxg_template_test to verify it detects correctly against a live target."
            } else {
                "Template saved with warnings. Review diagnostics — warnings won't break execution but may indicate quality issues."
            },
            "diagnostics": diagnostics.iter()
                .filter(|d| matches!(d.severity, DiagnosticSeverity::Warning))
                .map(|d| serde_json::json!({
                    "severity": "warning",
                    "code": d.code,
                    "message": d.message,
                    "line": d.line,
                }))
                .collect::<Vec<_>>(),
        });
        Ok(CallToolResult::success(vec![Content::text(
            json.to_string(),
        )]))
    }

    #[tool(
        description = "Get the AI generation guide for a specific template language. Returns the full guidance document covering metadata format, required fields, runtime environment variables (CERT_X_GEN_TARGET_HOST, CERT_X_GEN_CONTEXT, etc.), output JSON contract, validation rules, and a complete working example. Call this before cxg_template_create to understand what a correct template looks like in your chosen language."
    )]
    async fn cxg_template_get_notes(
        &self,
        Parameters(req): Parameters<TemplateNotesRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let language = Self::parse_language(&req.language).ok_or_else(|| {
            ErrorData::invalid_params(
                format!("Unknown language '{}'. Supported: yaml, python, rust, shell, javascript, c, cpp, java, go, ruby, perl, php", req.language),
                None,
            )
        })?;

        let lang_name = match language {
            TemplateLanguage::Python => "python",
            TemplateLanguage::Rust => "rust",
            TemplateLanguage::Shell => "shell",
            TemplateLanguage::JavaScript => "javascript",
            TemplateLanguage::C => "c",
            TemplateLanguage::Cpp => "cpp",
            TemplateLanguage::Java => "java",
            TemplateLanguage::Go => "go",
            TemplateLanguage::Ruby => "ruby",
            TemplateLanguage::Perl => "perl",
            TemplateLanguage::Php => "php",
            TemplateLanguage::Yaml => "yaml",
        };

        let notes_filename = format!("{}-template-ai-notes.md", lang_name);
        let notes_paths = [
            PathBuf::from("templates/skeleton").join(&notes_filename),
            dirs::home_dir()
                .unwrap_or_default()
                .join(".cert-x-gen/templates/official/templates/skeleton")
                .join(&notes_filename),
        ];

        let notes = notes_paths.iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
            .ok_or_else(|| ErrorData::internal_error(
                format!("AI notes for '{}' not found. Run cxg_template_update to fetch the latest templates.", lang_name),
                None,
            ))?;

        let json = serde_json::json!({
            "language": lang_name,
            "notes_file": notes_filename,
            "content": notes,
            "hint": "Read these notes carefully before writing template code. Then call cxg_template_create to get the skeleton, fill in the detection logic, and use cxg_template_write to validate and save.",
        });
        Ok(CallToolResult::success(vec![Content::text(
            json.to_string(),
        )]))
    }

    #[tool(
        description = "Generate a security template from a natural language prompt. Dual-mode: if an LLM provider is configured with an API key, generates the template internally and returns the code ready to save with cxg_template_write. If no provider is configured, returns the generation prompt + skeleton + ai-notes for the calling agent to generate directly — the agent should then call cxg_template_write with the result."
    )]
    async fn cxg_ai_generate(
        &self,
        Parameters(req): Parameters<AiGenerateRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        use crate::ai::manager::AIManager;
        use crate::ai::prompt::PromptBuilder;
        use crate::types::TemplateLanguage;

        let language = req
            .language
            .as_deref()
            .and_then(Self::parse_language)
            .unwrap_or(TemplateLanguage::Yaml);

        let lang_name = match language {
            TemplateLanguage::Python => "python",
            TemplateLanguage::Rust => "rust",
            TemplateLanguage::Shell => "shell",
            TemplateLanguage::JavaScript => "javascript",
            TemplateLanguage::C => "c",
            TemplateLanguage::Cpp => "cpp",
            TemplateLanguage::Java => "java",
            TemplateLanguage::Go => "go",
            TemplateLanguage::Ruby => "ruby",
            TemplateLanguage::Perl => "perl",
            TemplateLanguage::Php => "php",
            TemplateLanguage::Yaml => "yaml",
        };

        let _prompt = req.prompt.clone();
        let provider = req.provider.clone();

        // --- Check whether a provider is usable ---
        let manager_result: Result<_, String> =
            Self::run_non_send(move || async move { AIManager::new().map_err(|e| e.to_string()) })
                .await;

        let api_available = match &manager_result {
            Ok(manager) => {
                let p = provider
                    .as_deref()
                    .unwrap_or_else(|| manager.config().default_provider_name());
                manager.config().is_provider_enabled(p)
                    && manager
                        .config()
                        .get_provider(p)
                        .and_then(|pc| pc.api_key.as_ref())
                        .map(|k| !k.is_empty() && !k.starts_with("${"))
                        .unwrap_or(false)
            }
            Err(_) => false,
        };

        if api_available {
            // ── API mode: generate internally ──────────────────────────────
            let prompt2 = req.prompt.clone();
            let provider2 = req.provider.clone();

            let result = Self::run_non_send(move || async move {
                let manager =
                    AIManager::new().map_err(|e| format!("AIManager init failed: {}", e))?;
                let code = manager
                    .generate_template(&prompt2, language, provider2.as_deref())
                    .await
                    .map_err(|e| format!("Generation failed: {}", e))?;
                Ok::<String, String>(code)
            })
            .await
            .map_err(|e| ErrorData::internal_error(e, None))?;

            // Suggest a save ID from the prompt
            let save_id = req
                .prompt
                .to_lowercase()
                .split_whitespace()
                .take(5)
                .collect::<Vec<_>>()
                .join("-")
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '-')
                .collect::<String>();

            let json = serde_json::json!({
                "mode": "api",
                "language": lang_name,
                "code": result,
                "suggested_id": save_id,
                "hint": "Template generated. Call cxg_template_write with this code to validate and save it, then cxg_template_test to verify it detects correctly.",
            });
            return Ok(CallToolResult::success(vec![Content::text(
                json.to_string(),
            )]));
        }

        // ── Agent mode: no API key — return prompt + skeleton + notes ──────
        // Build the same generation prompt the CLI uses
        let builder = PromptBuilder::new();
        let generation_prompt = builder.build_generation_prompt(&req.prompt, language);

        // Load skeleton
        let skeleton_name = format!(
            "{}-template-skeleton.{}",
            lang_name,
            Self::lang_to_ext(&language)
        );
        let skeleton_paths = [
            PathBuf::from("templates/skeleton").join(&skeleton_name),
            dirs::home_dir()
                .unwrap_or_default()
                .join(".cert-x-gen/templates/official/templates/skeleton")
                .join(&skeleton_name),
        ];
        let skeleton = skeleton_paths
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default();

        // Load notes
        let notes_name = format!("{}-template-ai-notes.md", lang_name);
        let notes_paths = [
            PathBuf::from("templates/skeleton").join(&notes_name),
            dirs::home_dir()
                .unwrap_or_default()
                .join(".cert-x-gen/templates/official/templates/skeleton")
                .join(&notes_name),
        ];
        let notes = notes_paths
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default();

        let save_id = req
            .prompt
            .to_lowercase()
            .split_whitespace()
            .take(5)
            .collect::<Vec<_>>()
            .join("-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();

        let json = serde_json::json!({
            "mode": "agent",
            "message": "No LLM API key configured. Use the prompt, skeleton, and notes below to generate the template directly, then call cxg_template_write to validate and save it.",
            "language": lang_name,
            "suggested_id": save_id,
            "generation_prompt": generation_prompt,
            "skeleton": skeleton,
            "notes": notes,
            "save_hint": format!("After generating, call cxg_template_write with id='{}', language='{}', code=<generated code>", save_id, lang_name),
        });
        Ok(CallToolResult::success(vec![Content::text(
            json.to_string(),
        )]))
    }

    #[tool(
        description = "Test a specific template against a target. More targeted than cxg_scan — runs a single template and returns detailed results."
    )]
    async fn cxg_template_test(
        &self,
        Parameters(req): Parameters<TemplateTestRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let template_id = req.template_id.clone();
        let target_str = req.target.clone();
        let timeout = req.timeout;

        let result = Self::run_non_send(move || async move {
            let mut config = Config::default();
            if let Some(t) = timeout {
                config.network.timeout_secs = t;
                config.templates.timeout_secs = t;
            }

            let engine = CertXGen::new(config)
                .await
                .map_err(|e| format!("Engine init failed: {}", e))?;
            let templates = engine
                .load_templates()
                .await
                .map_err(|e| format!("Template load failed: {}", e))?;

            // Check template exists
            if !templates
                .iter()
                .any(|t| t.metadata().id.eq_ignore_ascii_case(&template_id))
            {
                let suggestions: Vec<String> = templates
                    .iter()
                    .filter(|t| {
                        t.metadata()
                            .id
                            .to_lowercase()
                            .contains(&template_id.to_lowercase())
                    })
                    .take(5)
                    .map(|t| t.metadata().id.clone())
                    .collect();
                return Err(serde_json::json!({
                    "error": format!("Template '{}' not found", template_id),
                    "suggestions": suggestions,
                })
                .to_string());
            }

            let target = Self::parse_target(&target_str);
            let mut job = engine.create_scan_job(vec![target], templates);
            let mut filter = TemplateFilter::new();
            filter.ids = vec![template_id.clone()];
            job.filter_templates(&filter);

            let start = std::time::Instant::now();
            let results = engine
                .execute_scan(job)
                .await
                .map_err(|e| format!("Test failed: {}", e))?;
            let duration = start.elapsed();

            let findings: Vec<ScanFinding> = results
                .findings
                .iter()
                .map(|f| ScanFinding {
                    target: f.target.clone(),
                    template_id: f.template_id.clone(),
                    severity: f.severity.to_string(),
                    confidence: f.confidence,
                    title: f.title.clone(),
                    description: f.description.clone(),
                    cwe: f.cwe_ids.clone(),
                    cve: f.cve_ids.clone(),
                    evidence_patterns: f.evidence.matched_patterns.clone(),
                    remediation: f.remediation.clone(),
                })
                .collect();

            Ok(serde_json::json!({
                "template_id": template_id,
                "target": target_str,
                "findings_count": findings.len(),
                "findings": findings,
                "errors": results.errors,
                "duration_secs": duration.as_secs_f64(),
            }))
        })
        .await;

        match result {
            Ok(json) => Ok(CallToolResult::success(vec![Content::text(
                json.to_string(),
            )])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    #[tool(
        description = "Get template collection statistics — total count, breakdown by language and severity. Useful for understanding what checks are available."
    )]
    async fn cxg_template_stats(
        &self,
        Parameters(req): Parameters<TemplateStatsRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let templates = Self::load_templates()
            .await
            .map_err(|e| ErrorData::internal_error(e, None))?;

        let mut by_language: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut by_severity: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut all_tags: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for t in &templates {
            let m = t.metadata();

            // Apply language filter if specified
            if let Some(ref lang) = req.language {
                if let Some(parsed) = Self::parse_language(lang) {
                    if m.language != parsed {
                        continue;
                    }
                }
            }

            *by_language.entry(m.language.to_string()).or_insert(0) += 1;
            *by_severity.entry(m.severity.to_string()).or_insert(0) += 1;
            for tag in &m.tags {
                *all_tags.entry(tag.clone()).or_insert(0) += 1;
            }
        }

        // Sort tags by frequency
        let mut top_tags: Vec<_> = all_tags.into_iter().collect();
        top_tags.sort_by(|a, b| b.1.cmp(&a.1));
        let top_tags: Vec<_> = top_tags.into_iter().take(20).collect();

        let total = by_language.values().sum::<usize>();

        let json = serde_json::json!({
            "total_templates": total,
            "by_language": by_language,
            "by_severity": by_severity,
            "top_tags": top_tags,
        });
        Ok(CallToolResult::success(vec![Content::text(
            json.to_string(),
        )]))
    }

    #[tool(
        description = "Update templates from remote repository. Downloads latest security checks. Run this if cxg_scan reports no templates available."
    )]
    async fn cxg_template_update(
        &self,
        Parameters(_req): Parameters<TemplateUpdateRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        use crate::template::AutoUpdater;

        let mut updater = AutoUpdater::new()
            .map_err(|e| ErrorData::internal_error(format!("Updater init failed: {}", e), None))?;

        if updater.needs_initial_install() {
            updater
                .auto_install()
                .map_err(|e| ErrorData::internal_error(format!("Install failed: {}", e), None))?;

            let stats = updater.get_stats();
            let json = serde_json::json!({
                "action": "initial_install",
                "success": true,
                "summary": stats.summary(),
                "total_templates": stats.total,
                "by_language": stats.by_language,
            });
            Ok(CallToolResult::success(vec![Content::text(
                json.to_string(),
            )]))
        } else {
            updater
                .perform_update()
                .map_err(|e| ErrorData::internal_error(format!("Update failed: {}", e), None))?;

            let stats = updater.get_stats();
            let json = serde_json::json!({
                "action": "update",
                "success": true,
                "summary": stats.summary(),
                "total_templates": stats.total,
                "by_language": stats.by_language,
            });
            Ok(CallToolResult::success(vec![Content::text(
                json.to_string(),
            )]))
        }
    }
}

// ─── Scaffold helper ─────────────────────────────────────────────────────────

impl CxgMcpServer {
    fn generate_minimal_scaffold(
        &self,
        id: &str,
        name: &str,
        language: &TemplateLanguage,
    ) -> String {
        match language {
            TemplateLanguage::Python => format!(r#"#!/usr/bin/env python3
# id: {id}
# name: {name}
# author: AI Agent
# severity: medium
# description: {name} detection template
# tags: custom
# language: python
# confidence: 70

import requests
import json
import sys

def scan(target: str) -> list:
    """Scan target for {name}."""
    findings = []

    try:
        url = target if target.startswith("http") else f"https://{{target}}"
        response = requests.get(url, timeout=10, verify=False)

        # TODO: Add detection logic here
        # Example:
        # if "vulnerable_pattern" in response.text:
        #     findings.append({{
        #         "title": "{name}",
        #         "severity": "medium",
        #         "confidence": 80,
        #         "description": "Detected {name}",
        #         "evidence": {{"matched": "vulnerable_pattern"}},
        #     }})

    except Exception as e:
        print(f"Error: {{e}}", file=sys.stderr)

    return findings

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    results = scan(target)
    print(json.dumps(results, indent=2))
"#),
            TemplateLanguage::Yaml => format!(r#"id: {id}
info:
  name: {name}
  author: AI Agent
  severity: medium
  description: |
    {name} detection template.
  tags:
    - custom

http:
  - method: GET
    path:
      - "/{{{{BaseURL}}}}"
    matchers:
      - type: word
        words:
          - "TODO_MATCH_PATTERN"
        condition: and
"#),
            _ => format!("// id: {id}\n// name: {name}\n// language: {}\n// TODO: Implement detection logic\n",
                language),
        }
    }
}

// ─── ServerHandler ───────────────────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for CxgMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "CERT-X-GEN: Multi-language security scanning engine. \
                 Search, validate, create, write, test, and run vulnerability scanning templates \
                 across 12 programming languages with 77+ built-in security checks. \
                 Tools: cxg_search, cxg_template_list, cxg_template_info, cxg_scan, \
                 cxg_template_validate, cxg_template_create, cxg_template_write, \
                 cxg_template_get_notes, cxg_ai_generate, cxg_template_test, \
                 cxg_template_stats, cxg_template_update."
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}
