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
    /// Passive mode enabled (no active probes)
    pub passive_mode: bool,
    /// Safe mode enabled (exclude dangerous checks)
    pub safe_mode: bool,
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
}

impl Default for Context {
    fn default() -> Self {
        Self {
            scan_id: Uuid::new_v4(),
            aggressive_mode: false,
            stealth_mode: false,
            passive_mode: false,
            safe_mode: false,
            max_retries: 1,
            timeout: Duration::from_secs(30),
            variables: HashMap::new(),
            rate_limit: None,
            additional_ports: Vec::new(),
            override_ports: None,
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
