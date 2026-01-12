//! Configuration management for CERT-X-GEN

use crate::error::{Error, Result};
use crate::template::PathResolver;
use crate::types::{Severity, TemplateLanguage};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Global configuration
    pub global: GlobalConfig,
    /// Template configuration
    pub templates: TemplateConfig,
    /// Network configuration
    pub network: NetworkConfig,
    /// Execution configuration
    pub execution: ExecutionConfig,
    /// Output configuration
    pub output: OutputConfig,
    /// Sandbox configuration
    pub sandbox: SandboxConfig,
    /// Metrics configuration
    pub metrics: MetricsConfig,
    /// Plugin configuration
    pub plugins: PluginConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            global: GlobalConfig::default(),
            templates: TemplateConfig::default(),
            network: NetworkConfig::default(),
            execution: ExecutionConfig::default(),
            output: OutputConfig::default(),
            sandbox: SandboxConfig::default(),
            metrics: MetricsConfig::default(),
            plugins: PluginConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("Failed to read config file: {}", e)))?;

        match path.extension().and_then(|s| s.to_str()) {
            Some("yaml") | Some("yml") => serde_yaml::from_str(&content)
                .map_err(|e| Error::config(format!("Invalid YAML config: {}", e))),
            Some("toml") => toml::from_str(&content)
                .map_err(|e| Error::config(format!("Invalid TOML config: {}", e))),
            Some("json") => serde_json::from_str(&content)
                .map_err(|e| Error::config(format!("Invalid JSON config: {}", e))),
            _ => Err(Error::config("Unsupported config file format")),
        }
    }

    /// Save configuration to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        let content = match path.extension().and_then(|s| s.to_str()) {
            Some("yaml") | Some("yml") => serde_yaml::to_string(self)
                .map_err(|e| Error::config(format!("Failed to serialize to YAML: {}", e)))?,
            Some("toml") => toml::to_string_pretty(self)
                .map_err(|e| Error::config(format!("Failed to serialize to TOML: {}", e)))?,
            Some("json") => serde_json::to_string_pretty(self)
                .map_err(|e| Error::config(format!("Failed to serialize to JSON: {}", e)))?,
            _ => return Err(Error::config("Unsupported config file format")),
        };

        std::fs::write(path, content)
            .map_err(|e| Error::config(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.execution.threads == 0 {
            return Err(Error::config("Thread count must be greater than 0"));
        }

        if self.execution.parallel_targets == 0 {
            return Err(Error::config("Parallel targets must be greater than 0"));
        }

        if self.network.timeout_secs == 0 {
            return Err(Error::config("Timeout must be greater than 0"));
        }

        Ok(())
    }
}

/// Global configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Verbosity level (0-3)
    pub verbosity: u8,
    /// Enable colored output
    pub color: bool,
    /// Log level
    pub log_level: String,
    /// Log file path
    pub log_file: Option<PathBuf>,
    /// Enable debug mode
    pub debug: bool,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            verbosity: 1,
            color: true,
            log_level: "info".to_string(),
            log_file: None,
            debug: false,
        }
    }
}

/// Helper function for serde default = true
fn default_true() -> bool {
    true
}

/// Template configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    /// Template directories (for backward compatibility)
    pub directories: Vec<PathBuf>,
    /// Use system-wide template discovery
    #[serde(default = "default_true")]
    pub use_system_templates: bool,
    /// Use user templates
    #[serde(default = "default_true")]
    pub use_user_templates: bool,
    /// Use local templates
    #[serde(default = "default_true")]
    pub use_local_templates: bool,
    /// Auto-update templates
    pub auto_update: bool,
    /// Template cache directory
    pub cache_dir: PathBuf,
    /// Enabled template languages
    pub enabled_languages: Vec<TemplateLanguage>,
    /// Template timeout (seconds)
    pub timeout_secs: u64,
}

impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            directories: vec![],  // Empty - will use discovery system
            use_system_templates: true,
            use_user_templates: true,
            use_local_templates: true,
            auto_update: false,
            cache_dir: PathResolver::cache_dir(),
            enabled_languages: vec![
                TemplateLanguage::Yaml,
                TemplateLanguage::Python,
                TemplateLanguage::Rust,
                TemplateLanguage::Shell,
            ],
            timeout_secs: 30,
        }
    }
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Request timeout (seconds)
    pub timeout_secs: u64,
    /// User agent string
    pub user_agent: String,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Maximum redirects
    pub max_redirects: usize,
    /// Connection pool size
    pub connection_pool_size: usize,
    /// Enable HTTP/2
    pub http2: bool,
    /// Proxy URL
    pub proxy: Option<String>,
    /// DNS servers
    pub dns_servers: Vec<String>,
    /// Rate limit (requests per second)
    pub rate_limit: Option<u32>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            user_agent: format!("cert-x-gen/{}", env!("CARGO_PKG_VERSION")),
            follow_redirects: true,
            max_redirects: 5,
            connection_pool_size: 100,
            http2: true,
            proxy: None,
            dns_servers: Vec::new(),
            rate_limit: Some(100),
        }
    }
}

/// Execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    /// Number of worker threads
    pub threads: usize,
    /// Parallel target scanning
    pub parallel_targets: usize,
    /// Parallel template execution per target
    pub parallel_templates: usize,
    /// Maximum retries
    pub max_retries: u32,
    /// Retry delay (seconds)
    pub retry_delay_secs: u64,
    /// Aggressive mode
    pub aggressive_mode: bool,
    /// Stealth mode
    pub stealth_mode: bool,
    /// Passive mode (no active probes)
    pub passive_mode: bool,
    /// Safe mode (exclude dangerous checks)
    pub safe_mode: bool,
    /// Enable caching
    pub cache_enabled: bool,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            threads: num_cpus::get(),
            parallel_targets: 50,
            parallel_templates: 10,
            max_retries: 1,
            retry_delay_secs: 1,
            aggressive_mode: false,
            stealth_mode: false,
            passive_mode: false,
            safe_mode: false,
            cache_enabled: true,
        }
    }
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output formats
    pub formats: Vec<String>,
    /// Output directory
    pub output_dir: PathBuf,
    /// Output file basename
    pub output_file: String,
    /// Stream output (real-time)
    pub stream: bool,
    /// Minimum severity to report
    pub min_severity: Severity,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            formats: vec!["json".to_string()],
            output_dir: PathBuf::from("results"),
            output_file: "scan-results".to_string(),
            stream: false,
            min_severity: Severity::Info,
        }
    }
}

/// Sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Enable sandbox
    pub enabled: bool,
    /// Memory limit (MB)
    pub memory_limit_mb: usize,
    /// CPU limit (percentage)
    pub cpu_limit_percent: usize,
    /// Network access control
    pub network_access: NetworkAccess,
    /// Filesystem access
    pub filesystem_access: FilesystemAccess,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            memory_limit_mb: 512,
            cpu_limit_percent: 80,
            network_access: NetworkAccess::Controlled,
            filesystem_access: FilesystemAccess::ReadOnly,
        }
    }
}

/// Network access levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAccess {
    /// No network access
    None,
    /// Controlled access (only to targets)
    Controlled,
    /// Full network access
    Full,
}

/// Filesystem access levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilesystemAccess {
    /// No filesystem access
    None,
    /// Read-only access
    ReadOnly,
    /// Full access
    Full,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,
    /// Metrics export port
    pub export_port: u16,
    /// Metrics export format
    pub export_format: MetricsFormat,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            export_port: 9090,
            export_format: MetricsFormat::Prometheus,
        }
    }
}

/// Metrics export formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricsFormat {
    /// Prometheus format
    Prometheus,
    /// JSON format
    Json,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Enable plugin system
    pub enabled: bool,
    /// Plugin directories
    pub directories: Vec<PathBuf>,
    /// Loaded plugins
    pub plugins: Vec<String>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directories: vec![PathBuf::from("plugins")],
            plugins: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.execution.threads, num_cpus::get());
        assert_eq!(config.network.timeout_secs, 10);
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        config.execution.threads = 0;
        assert!(config.validate().is_err());
    }
}
