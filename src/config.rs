//! Configuration management for CERT-X-GEN

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Template configuration. Omitted → `TemplateConfig::default()`.
    #[serde(default)]
    pub templates: TemplateConfig,
    /// Network configuration. Omitted → `NetworkConfig::default()`.
    #[serde(default)]
    pub network: NetworkConfig,
    /// Execution configuration. Omitted → `ExecutionConfig::default()`.
    #[serde(default)]
    pub execution: ExecutionConfig,
    /// Sandbox configuration. Omitted → `SandboxConfig::default()`.
    #[serde(default)]
    pub sandbox: SandboxConfig,
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
        if self.execution.parallel_targets == 0 {
            return Err(Error::config("Parallel targets must be greater than 0"));
        }

        if self.network.timeout_secs == 0 {
            return Err(Error::config("Timeout must be greater than 0"));
        }

        Ok(())
    }
}

/// Template configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TemplateConfig {
    /// Template directories (for backward compatibility)
    pub directories: Vec<PathBuf>,
    /// Template timeout (seconds)
    pub timeout_secs: u64,
}

impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            directories: vec![], // Empty - will use discovery system
            timeout_secs: 30,
        }
    }
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Request timeout (seconds)
    pub timeout_secs: u64,
    /// User agent string
    pub user_agent: String,
    /// Follow redirects.
    ///
    /// Not a config key: this is runtime plumbing for the `--follow-redirects`
    /// CLI flag, which unconditionally overwrites it (`main.rs`). Skipped from
    /// (de)serialization so a config file cannot set a value the flag ignores.
    #[serde(skip)]
    pub follow_redirects: bool,
    /// Maximum redirects
    pub max_redirects: usize,
    /// Connection pool size
    pub connection_pool_size: usize,
    /// Proxy URL
    pub proxy: Option<String>,
    /// Rate limit (requests per second)
    pub rate_limit: Option<u32>,
    /// Custom headers for HTTP requests
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Cookies for authenticated scans
    #[serde(default)]
    pub cookies: Vec<(String, String)>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            user_agent: format!("cert-x-gen/{}", env!("CARGO_PKG_VERSION")),
            follow_redirects: false,
            max_redirects: 5,
            connection_pool_size: 100,
            proxy: None,
            rate_limit: Some(100),
            headers: Vec::new(),
            cookies: Vec::new(),
        }
    }
}

/// Execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecutionConfig {
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
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            parallel_targets: 50,
            parallel_templates: 10,
            max_retries: 1,
            retry_delay_secs: 1,
            aggressive_mode: false,
            stealth_mode: false,
        }
    }
}

/// Sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.execution.parallel_targets, 50);
        assert_eq!(config.network.timeout_secs, 10);
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        config.execution.parallel_targets = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_partial_config_uses_defaults_for_omitted_sections() {
        // Only `network` is present, and only one of its keys. Every other
        // section — and every unspecified network key — must fall back to its
        // compiled-in default rather than erroring.
        let yaml = "network:\n  timeout_secs: 20\n";
        let config: Config = serde_yaml::from_str(yaml).expect("partial config should load");

        // Specified value wins.
        assert_eq!(config.network.timeout_secs, 20);
        // Unspecified network key falls back to NetworkConfig::default().
        assert_eq!(
            config.network.connection_pool_size,
            NetworkConfig::default().connection_pool_size
        );
        // Omitted sections equal their Default impls.
        assert_eq!(
            config.templates.timeout_secs,
            TemplateConfig::default().timeout_secs
        );
        assert_eq!(
            config.execution.parallel_targets,
            ExecutionConfig::default().parallel_targets
        );
        assert_eq!(config.sandbox.enabled, SandboxConfig::default().enabled);

        // A partial config still validates.
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_empty_config_is_all_defaults() {
        // An empty document is a valid config equal to Config::default().
        let config: Config = serde_yaml::from_str("{}").expect("empty config should load");
        assert_eq!(
            config.execution.parallel_targets,
            Config::default().execution.parallel_targets
        );
        assert!(config.validate().is_ok());
    }
}
