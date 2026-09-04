//! Core type definitions for CERT-X-GEN

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

impl Severity {
    /// Get numeric score for severity
    pub fn score(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Template programming language
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TemplateLanguage {
    /// YAML declarative templates
    Yaml,
    /// Python procedural templates
    Python,
    /// Rust compiled templates
    Rust,
    /// Shell script templates
    Shell,
    /// JavaScript templates
    JavaScript,
    /// C compiled templates
    C,
    /// C++ compiled templates
    Cpp,
    /// Java compiled templates
    Java,
    /// Go compiled templates
    Go,
    /// Ruby interpreted templates
    Ruby,
    /// Perl interpreted templates
    Perl,
    /// PHP interpreted templates
    Php,
}

impl std::fmt::Display for TemplateLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateLanguage::Yaml => write!(f, "yaml"),
            TemplateLanguage::Python => write!(f, "python"),
            TemplateLanguage::Rust => write!(f, "rust"),
            TemplateLanguage::Shell => write!(f, "shell"),
            TemplateLanguage::JavaScript => write!(f, "javascript"),
            TemplateLanguage::C => write!(f, "c"),
            TemplateLanguage::Cpp => write!(f, "cpp"),
            TemplateLanguage::Java => write!(f, "java"),
            TemplateLanguage::Go => write!(f, "go"),
            TemplateLanguage::Ruby => write!(f, "ruby"),
            TemplateLanguage::Perl => write!(f, "perl"),
            TemplateLanguage::Php => write!(f, "php"),
        }
    }
}

/// Supported network protocols
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP protocol
    Http,
    /// HTTPS protocol
    Https,
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
    /// DNS protocol
    Dns,
    /// SSH protocol
    Ssh,
    /// FTP protocol
    Ftp,
    /// SMTP protocol
    Smtp,
    /// SMB protocol
    Smb,
    /// RDP protocol
    Rdp,
    /// Custom protocol with name
    Custom(String),
    /// Local CLI/binary target. `Target::address` carries a filesystem path to a
    /// locally-built executable rather than a network host. Additive: existing
    /// network protocols are unchanged, and the `CERT_X_GEN_TARGET_HOST` env
    /// contract still holds (for a Cli target the "host" is the binary path).
    Cli,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Http => write!(f, "http"),
            Protocol::Https => write!(f, "https"),
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Dns => write!(f, "dns"),
            Protocol::Ssh => write!(f, "ssh"),
            Protocol::Ftp => write!(f, "ftp"),
            Protocol::Smtp => write!(f, "smtp"),
            Protocol::Smb => write!(f, "smb"),
            Protocol::Rdp => write!(f, "rdp"),
            Protocol::Custom(name) => write!(f, "{}", name),
            Protocol::Cli => write!(f, "cli"),
        }
    }
}

/// Scan target specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// Unique target ID
    pub id: Uuid,
    /// Target address (IP or hostname)
    pub address: String,
    /// Target port (optional)
    pub port: Option<u16>,
    /// Protocol to use
    pub protocol: Protocol,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Target {
    /// Create a new target
    pub fn new<S: Into<String>>(address: S, protocol: Protocol) -> Self {
        Self {
            id: Uuid::new_v4(),
            address: address.into(),
            port: None,
            protocol,
            metadata: HashMap::new(),
        }
    }

    /// Create target with port
    pub fn with_port<S: Into<String>>(address: S, port: u16, protocol: Protocol) -> Self {
        Self {
            id: Uuid::new_v4(),
            address: address.into(),
            port: Some(port),
            protocol,
            metadata: HashMap::new(),
        }
    }

    /// Get full URL or address:port
    pub fn url(&self) -> String {
        match &self.protocol {
            Protocol::Http | Protocol::Https => {
                let scheme = if self.protocol == Protocol::Https {
                    "https"
                } else {
                    "http"
                };
                if let Some(port) = self.port {
                    format!("{}://{}:{}", scheme, self.address, port)
                } else {
                    format!("{}://{}", scheme, self.address)
                }
            }
            _ => {
                if let Some(port) = self.port {
                    format!("{}:{}", self.address, port)
                } else {
                    self.address.clone()
                }
            }
        }
    }

    /// Get socket address if possible
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        if let Ok(ip) = self.address.parse::<IpAddr>() {
            Some(SocketAddr::new(ip, self.port.unwrap_or(0)))
        } else {
            None
        }
    }

    /// Create variants with both HTTP and HTTPS for flexible testing
    /// This allows a single HTTP template to test both protocols
    pub fn with_both_schemes(&self) -> Vec<Target> {
        if matches!(self.protocol, Protocol::Http | Protocol::Https) {
            vec![
                Target {
                    protocol: Protocol::Http,
                    ..self.clone()
                },
                Target {
                    protocol: Protocol::Https,
                    ..self.clone()
                },
            ]
        } else {
            vec![self.clone()]
        }
    }

    /// Smart scheme selection based on port
    pub fn infer_scheme(&self) -> Protocol {
        match self.port {
            Some(443) | Some(8443) => Protocol::Https,
            Some(80) | Some(8080) | Some(8000) => Protocol::Http,
            _ => self.protocol.clone(),
        }
    }
}

/// Execution context for templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    /// Scan ID
    pub scan_id: Uuid,
    /// Aggressive mode enabled
    pub aggressive_mode: bool,
    /// Stealth mode enabled
    pub stealth_mode: bool,
    /// Maximum retries
    pub max_retries: u32,
    /// Timeout duration
    pub timeout: Duration,
    /// Custom variables
    pub variables: HashMap<String, String>,
    /// Rate limit (requests per second)
    pub rate_limit: Option<u32>,
    /// Additional ports to scan (added to template defaults)
    pub additional_ports: Vec<u16>,
    /// Override ports (replaces template defaults if set)
    pub override_ports: Option<Vec<u16>>,
    /// Custom HTTP headers
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Cookies for authenticated scans
    #[serde(default)]
    pub cookies: Vec<(String, String)>,

    // --- Structured probe input. All additive and all absent unless the
    // corresponding flag was passed, so a network scan's template environment
    // is byte-identical to what it was before these existed.
    /// Argument vector cxg hands the template to feed the target under test.
    /// Exposed as `CERT_X_GEN_ARGV` (JSON array). Empty means not supplied.
    #[serde(default)]
    pub probe_argv: Vec<String>,
    /// File whose bytes the template should feed to the target's stdin.
    /// Exposed as `CERT_X_GEN_STDIN_FILE`.
    #[serde(default)]
    pub probe_stdin_file: Option<PathBuf>,
    /// Directory of seed inputs (corpus) the template may iterate. cxg does
    /// not mutate or minimise it. Exposed as `CERT_X_GEN_INPUT_DIR`.
    #[serde(default)]
    pub probe_input_dir: Option<PathBuf>,
    /// Environment the template should set on the *target* process, not on
    /// itself. Exposed as `CERT_X_GEN_TARGET_ENV` (JSON object).
    #[serde(default)]
    pub probe_env: Vec<(String, String)>,
    /// Refuse to run against a `cli://` target whose build carries no
    /// detectable instrumentation, rather than reporting a "no findings"
    /// result that reads as a refutation but is not evidence.
    #[serde(default)]
    pub require_instrumentation: bool,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            scan_id: Uuid::new_v4(),
            aggressive_mode: false,
            stealth_mode: false,
            max_retries: 1,
            timeout: Duration::from_secs(30),
            variables: HashMap::new(),
            rate_limit: None,
            additional_ports: Vec::new(),
            override_ports: None,
            headers: Vec::new(),
            cookies: Vec::new(),
            probe_argv: Vec::new(),
            probe_stdin_file: None,
            probe_input_dir: None,
            probe_env: Vec::new(),
            require_instrumentation: false,
        }
    }
}

/// Evidence for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// HTTP request (if applicable)
    pub request: Option<String>,
    /// HTTP response (if applicable)
    pub response: Option<String>,
    /// Matched patterns
    pub matched_patterns: Vec<String>,
    /// Custom evidence data
    pub data: HashMap<String, serde_json::Value>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl Evidence {
    /// Create new evidence
    pub fn new() -> Self {
        Self {
            request: None,
            response: None,
            matched_patterns: Vec::new(),
            data: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    /// Add matched pattern
    pub fn add_match(&mut self, pattern: String) {
        self.matched_patterns.push(pattern);
    }

    /// Add custom data
    pub fn add_data<K: Into<String>>(&mut self, key: K, value: serde_json::Value) {
        self.data.insert(key.into(), value);
    }
}

impl Default for Evidence {
    fn default() -> Self {
        Self::new()
    }
}

/// Security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding ID
    pub id: Uuid,
    /// Target that was scanned
    pub target: String,
    /// Template ID that generated this finding
    pub template_id: String,
    /// Severity level
    pub severity: Severity,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Finding title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Evidence
    pub evidence: Evidence,
    /// CVE IDs
    pub cve_ids: Vec<String>,
    /// CWE IDs
    pub cwe_ids: Vec<String>,
    /// CVSS score
    pub cvss_score: Option<f32>,
    /// Remediation advice
    pub remediation: Option<String>,
    /// References
    pub references: Vec<String>,
    /// Tags
    pub tags: Vec<String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    /// Create a new finding
    pub fn new<S: Into<String>>(
        target: S,
        template_id: S,
        severity: Severity,
        title: S,
        description: S,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            target: target.into(),
            template_id: template_id.into(),
            severity,
            confidence: 90,
            title: title.into(),
            description: description.into(),
            evidence: Evidence::new(),
            cve_ids: Vec::new(),
            cwe_ids: Vec::new(),
            cvss_score: None,
            remediation: None,
            references: Vec::new(),
            tags: Vec::new(),
            timestamp: Utc::now(),
        }
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }

    /// Set evidence
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence = evidence;
        self
    }

    /// Add CVE ID
    pub fn add_cve<S: Into<String>>(mut self, cve_id: S) -> Self {
        self.cve_ids.push(cve_id.into());
        self
    }

    /// Add CWE ID
    pub fn add_cwe<S: Into<String>>(mut self, cwe_id: S) -> Self {
        self.cwe_ids.push(cwe_id.into());
        self
    }

    /// Set CVSS score
    pub fn with_cvss_score(mut self, score: f32) -> Self {
        self.cvss_score = Some(score);
        self
    }
}

/// Outcome of one (template, target) execution.
///
/// cxg has always surfaced *findings*. It has never surfaced "this template
/// ran, exercised the target, and concluded there is no defect" -- which made a
/// genuine refutation indistinguishable from a template that silently did
/// nothing. This enum is that missing channel; [`ExecutionRecord`] carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionStatus {
    /// Template ran and produced at least one finding.
    Confirmed,
    /// Template ran, exercised the target, and concluded no defect.
    Refuted,
    /// Template ran but could not reach a conclusion (setup failure, bad build).
    Errored,
    /// Template declined this target (wrong kind, missing precondition, a build
    /// that could not have revealed the defect).
    Skipped,
    /// Template exceeded its wall-clock budget.
    #[serde(rename = "timed-out")]
    TimedOut,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ExecutionStatus::Confirmed => "confirmed",
            ExecutionStatus::Refuted => "refuted",
            ExecutionStatus::Errored => "errored",
            ExecutionStatus::Skipped => "skipped",
            ExecutionStatus::TimedOut => "timed-out",
        };
        f.write_str(s)
    }
}

impl ExecutionStatus {
    /// Parse a template-declared status string (case-insensitive).
    ///
    /// Returns `None` for anything outside the vocabulary; callers must treat
    /// that as an unrecognised declaration rather than silently ignoring it.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "confirmed" | "confirm" => Some(ExecutionStatus::Confirmed),
            "refuted" | "refute" | "not-reproduced" => Some(ExecutionStatus::Refuted),
            "errored" | "error" => Some(ExecutionStatus::Errored),
            "skipped" | "skip" => Some(ExecutionStatus::Skipped),
            "timed-out" | "timedout" | "timeout" => Some(ExecutionStatus::TimedOut),
            _ => None,
        }
    }

    /// Every status, in report order. Used by the terminal summary.
    pub const ALL: [ExecutionStatus; 5] = [
        ExecutionStatus::Confirmed,
        ExecutionStatus::Refuted,
        ExecutionStatus::Skipped,
        ExecutionStatus::Errored,
        ExecutionStatus::TimedOut,
    ];
}

/// One row of the per-(template, target) execution ledger.
///
/// Emitted for every template cxg attempted against every target, including
/// the ones that produced no findings. `ScanResults.findings` says what was
/// confirmed; this says what was *refuted*, *skipped* or *errored*, which a
/// scan reporting zero findings otherwise cannot distinguish.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    /// Target address (host, or binary path for a `cli://` target)
    pub target: String,
    /// Target kind, i.e. the target's protocol (`http`, `cli`, ...)
    #[serde(default)]
    pub target_kind: String,
    /// Template ID
    pub template_id: String,
    /// What cxg observed, or what the template declared
    pub status: ExecutionStatus,
    /// True when `status` came from the template's own JSON metadata rather
    /// than being inferred by cxg from the finding count. An operator can
    /// always tell a template's considered verdict from cxg's default guess.
    #[serde(default)]
    pub declared_by_template: bool,
    /// Number of findings this execution produced
    pub findings: usize,
    /// Template process exit code, when the engine observed one
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Short human-readable reason, template-supplied or cxg-supplied
    #[serde(default)]
    pub detail: Option<String>,
    /// Wall-clock duration in milliseconds
    #[serde(default)]
    pub duration_ms: u64,
}

/// Scan statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStatistics {
    /// Total targets scanned
    pub targets_scanned: usize,
    /// Total templates executed
    pub templates_executed: usize,
    /// Findings by severity
    pub findings_by_severity: HashMap<Severity, usize>,
    /// Total network requests
    pub network_requests: usize,
    /// Total data transferred (bytes)
    pub data_transferred: u64,
    /// Scan duration
    pub duration: Duration,
    /// Success rate
    pub success_rate: f64,
}

/// Scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// Scan ID
    pub scan_id: Uuid,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// Completion time
    pub completed_at: Option<DateTime<Utc>>,
    /// Findings
    pub findings: Vec<Finding>,
    /// Statistics
    pub statistics: ScanStatistics,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Per-(template, target) execution ledger. Additive: absent in result
    /// files written by older versions, defaulted to empty on deserialisation.
    #[serde(default)]
    pub executions: Vec<ExecutionRecord>,
}

impl ScanResults {
    /// Create new scan results
    pub fn new(scan_id: Uuid) -> Self {
        Self {
            scan_id,
            started_at: Utc::now(),
            completed_at: None,
            findings: Vec::new(),
            statistics: ScanStatistics::default(),
            errors: Vec::new(),
            executions: Vec::new(),
        }
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        *self
            .statistics
            .findings_by_severity
            .entry(finding.severity)
            .or_insert(0) += 1;
        self.findings.push(finding);
    }

    /// Mark scan as complete
    pub fn complete(&mut self) {
        self.completed_at = Some(Utc::now());
        if let Some(completed) = self.completed_at {
            self.statistics.duration = (completed - self.started_at)
                .to_std()
                .unwrap_or(Duration::from_secs(0));
        }
    }

    /// Get critical findings
    pub fn critical_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect()
    }

    /// Get high severity findings
    pub fn high_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .collect()
    }
}

/// Template metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMetadata {
    /// Template ID
    pub id: String,
    /// Template name
    pub name: String,
    /// Author information
    pub author: AuthorInfo,
    /// Severity
    pub severity: Severity,
    /// Description
    pub description: String,
    /// CVE IDs
    #[serde(default)]
    pub cve_ids: Vec<String>,
    /// CWE IDs
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    /// CVSS score
    pub cvss_score: Option<f32>,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Template language
    pub language: TemplateLanguage,
    /// Template file path
    #[serde(default)]
    pub file_path: PathBuf,
    /// Created date
    #[serde(default = "default_datetime")]
    pub created: DateTime<Utc>,
    /// Last updated
    #[serde(default = "default_datetime")]
    pub updated: DateTime<Utc>,
    /// Version
    #[serde(default = "default_version")]
    pub version: String,
    /// Confidence (0-100)
    pub confidence: Option<u8>,

    // --- Parameterisation & routing fields (Task 3a) ---
    /// Context variables required/optional at runtime, parsed from `@context_vars`.
    /// Each entry: `{ name, is_array, required }`.
    /// Serialised as a compact string vec: `["auth_token:required", "endpoints[]:required"]`
    #[serde(default)]
    pub context_vars: Vec<String>,

    /// Coarse vulnerability class for Bravos pipeline routing, from `@vuln_class`.
    #[serde(default)]
    pub vuln_class: Option<String>,

    /// Fine-grained hypothesis routing tags for Bravos `TemplateMatcher`, from `@hypothesis_tags`.
    #[serde(default)]
    pub hypothesis_tags: Vec<String>,

    /// Batch group identifier for running context-shape cohorts together, from `@batch_group`.
    #[serde(default)]
    pub batch_group: Option<String>,

    /// Whether the template can self-probe for missing context, from `@auto_probe`.
    #[serde(default)]
    pub auto_probe: bool,

    /// The template exits non-zero on purpose (a probe whose job is to provoke
    /// a crash); cxg keeps its stdout instead of treating the exit as a hard
    /// error. From `@allow_nonzero_exit`.
    #[serde(default)]
    pub allow_nonzero_exit: bool,

    /// Oracles the template relies on to decide something is wrong, from
    /// `@oracles`. Vocabulary: `asan` `ubsan` `msan` `tsan` `signal` `exit`
    /// `exception` `assert` `timeout` `diff` `property` `detector`. Knowing
    /// which one a template depends on lets cxg refuse to run it against a
    /// build that cannot support it.
    ///
    /// The template observes the target for all of these but one: `exception`
    /// is implemented by cxg, which matches the target output the template
    /// hands back in `metadata.target_output` against the per-language shape
    /// of an escaped exception. A template declares it the same way as any
    /// other; nothing changes for a template that does not.
    #[serde(default)]
    pub oracles: Vec<String>,

    /// Target kinds the template accepts, from `@target_kinds` (e.g. `cli`,
    /// `http`). **Empty means no declaration, and a template with no
    /// declaration runs against every kind** -- which is every template
    /// written before this annotation existed.
    #[serde(default)]
    pub target_kinds: Vec<String>,
}

/// Author information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorInfo {
    /// Author name
    pub name: String,
    /// Author email
    pub email: Option<String>,
    /// GitHub username
    pub github: Option<String>,
}

// Default functions for serde
fn default_datetime() -> DateTime<Utc> {
    Utc::now()
}

fn default_version() -> String {
    "1.0".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_status_round_trips_through_json() {
        for status in ExecutionStatus::ALL {
            let json = serde_json::to_string(&status).unwrap();
            // The wire form is exactly the Display form, so a consumer reading
            // the JSON and a human reading the terminal see the same word.
            assert_eq!(json, format!("\"{}\"", status));
            let back: ExecutionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn execution_status_parses_the_declared_vocabulary() {
        assert_eq!(
            ExecutionStatus::parse("REFUTED"),
            Some(ExecutionStatus::Refuted)
        );
        assert_eq!(
            ExecutionStatus::parse(" not-reproduced "),
            Some(ExecutionStatus::Refuted)
        );
        assert_eq!(
            ExecutionStatus::parse("timeout"),
            Some(ExecutionStatus::TimedOut)
        );
        assert_eq!(ExecutionStatus::parse("refuuted"), None);
        assert_eq!(ExecutionStatus::parse(""), None);
    }

    /// A result file written before the ledger existed must still load.
    #[test]
    fn scan_results_without_an_executions_field_still_deserialise() {
        let legacy = r#"{
            "scan_id": "00000000-0000-0000-0000-000000000000",
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": null,
            "findings": [],
            "statistics": {
                "targets_scanned": 0,
                "templates_executed": 0,
                "findings_by_severity": {},
                "network_requests": 0,
                "data_transferred": 0,
                "duration": {"secs": 0, "nanos": 0},
                "success_rate": 0.0
            },
            "errors": []
        }"#;
        let results: ScanResults = serde_json::from_str(legacy).unwrap();
        assert!(results.executions.is_empty());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_target_url() {
        let target = Target::with_port("example.com", 443, Protocol::Https);
        assert_eq!(target.url(), "https://example.com:443");

        let target = Target::new("example.com", Protocol::Http);
        assert_eq!(target.url(), "http://example.com");
    }

    #[test]
    fn test_finding_creation() {
        let finding = Finding::new(
            "192.168.1.1",
            "CVE-2024-1234",
            Severity::Critical,
            "Test Finding",
            "Test description",
        );
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.confidence, 90);
    }
}
