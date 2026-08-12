//! Configuration management for CERT-X-GEN

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level config sections this build no longer reads.
///
/// `sandbox` held `enabled`, `memory_limit_mb`, `cpu_limit_percent`,
/// `network_access` and `filesystem_access`. Nothing ever enforced any of
/// them — the values were deserialized and, outside one unit test, never read.
/// Unrelated to the `cxg sandbox` command, which manages per-language
/// dependency environments and is unaffected.
const OBSOLETE_SECTIONS: &[&str] = &["sandbox"];

/// Report an obsolete section on stderr.
///
/// Loud on purpose: someone whose config says `sandbox.enabled: true` believes
/// they are hardened. Dropping the keys silently would leave them believing it.
fn warn_obsolete_section(section: &str, path: &Path) {
    tracing::warn!(
        "config file {} contains an obsolete `{}` section that has no effect",
        path.display(),
        section
    );

    if section == "sandbox" {
        eprintln!(
            "\n\
              warning: {} contains a `sandbox:` section.\n\
             \n\
             These settings never took effect. `enabled`, `memory_limit_mb`,\n\
             `cpu_limit_percent`, `network_access` and `filesystem_access` were\n\
             parsed and then ignored — no code path has ever read them to confine\n\
             anything. A config setting them was not protected by them.\n\
             \n\
             Templates execute as ordinary child processes with the invoking user's\n\
             privileges and full network and filesystem access. Review templates\n\
             before running them.\n\
             \n\
             Remove the `sandbox:` section from {}. For real isolation, run cxg\n\
             itself inside a container or VM, as a non-privileged user.\n\
             \n\
             (The `cxg sandbox` command is unrelated and still works — it manages\n\
             per-language dependency environments, not execution confinement.)\n",
            path.display(),
            path.display()
        );
    } else {
        eprintln!(
            "\nwarning: {} contains an obsolete `{}:` section that has no effect. \
             Remove it.\n",
            path.display(),
            section
        );
    }
}

/// Top-level keys of a config document, or empty if it cannot be parsed as a map.
fn top_level_keys(content: &str, path: &Path) -> Vec<String> {
    match path.extension().and_then(|s| s.to_str()) {
        Some("yaml") | Some("yml") => serde_yaml::from_str::<serde_yaml::Value>(content)
            .ok()
            .and_then(|v| {
                v.as_mapping().map(|m| {
                    m.keys()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect()
                })
            })
            .unwrap_or_default(),
        Some("toml") => toml::from_str::<toml::Value>(content)
            .ok()
            .and_then(|v| {
                v.as_table()
                    .map(|t| t.keys().map(|k| k.to_string()).collect())
            })
            .unwrap_or_default(),
        Some("json") => serde_json::from_str::<serde_json::Value>(content)
            .ok()
            .and_then(|v| {
                v.as_object()
                    .map(|m| m.keys().map(|k| k.to_string()).collect())
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

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
}

impl Config {
    /// Load configuration from file.
    ///
    /// Obsolete sections are not an error: the file still loads, but each one
    /// is reported on stderr (see [`Config::obsolete_sections`]) so nobody is
    /// left believing a setting is doing something it never did.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("Failed to read config file: {}", e)))?;

        let config = Self::parse(&content, path)?;

        for section in Self::obsolete_sections(&content, path) {
            warn_obsolete_section(section, path);
        }

        Ok(config)
    }

    /// Parse configuration from a string, dispatching on the path's extension.
    fn parse(content: &str, path: &Path) -> Result<Self> {
        match path.extension().and_then(|s| s.to_str()) {
            Some("yaml") | Some("yml") => serde_yaml::from_str(content)
                .map_err(|e| Error::config(format!("Invalid YAML config: {}", e))),
            Some("toml") => toml::from_str(content)
                .map_err(|e| Error::config(format!("Invalid TOML config: {}", e))),
            Some("json") => serde_json::from_str(content)
                .map_err(|e| Error::config(format!("Invalid JSON config: {}", e))),
            _ => Err(Error::config("Unsupported config file format")),
        }
    }

    /// Top-level sections present in `content` that this build no longer reads.
    ///
    /// Unknown keys are ignored by the parser, so a config that still sets one
    /// loads cleanly — which is exactly why callers must surface these.
    pub fn obsolete_sections(content: &str, path: &Path) -> Vec<&'static str> {
        let keys = top_level_keys(content, path);
        OBSOLETE_SECTIONS
            .iter()
            .copied()
            .filter(|section| keys.iter().any(|key| key == section))
            .collect()
    }

    /// Load a configuration file and report which obsolete sections it contains.
    ///
    /// Same load semantics as [`Config::from_file`], but the caller gets the
    /// list back instead of only seeing it on stderr.
    pub fn from_file_reporting_obsolete<P: AsRef<Path>>(
        path: P,
    ) -> Result<(Self, Vec<&'static str>)> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("Failed to read config file: {}", e)))?;

        let config = Self::parse(&content, path)?;
        let obsolete = Self::obsolete_sections(&content, path);

        for section in &obsolete {
            warn_obsolete_section(section, path);
        }

        Ok((config, obsolete))
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

        // A partial config still validates.
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_legacy_sandbox_section_still_loads_and_is_reported() {
        // A config written against the old `sandbox` section must keep loading —
        // breaking the load would be a worse outcome than the dead keys were.
        let yaml = "network:\n  timeout_secs: 20\n\
                    sandbox:\n  enabled: true\n  memory_limit_mb: 512\n  \
                    cpu_limit_percent: 80\n  network_access: none\n  \
                    filesystem_access: readonly\n";
        let path = Path::new("cert-x-gen.yaml");

        let config = Config::parse(yaml, path).expect("legacy config must still load");
        assert_eq!(config.network.timeout_secs, 20);
        assert!(config.validate().is_ok());

        // ...but it must never load quietly.
        assert_eq!(Config::obsolete_sections(yaml, path), vec!["sandbox"]);
    }

    #[test]
    fn test_clean_config_reports_no_obsolete_sections() {
        let yaml = "network:\n  timeout_secs: 20\n";
        assert!(Config::obsolete_sections(yaml, Path::new("cert-x-gen.yaml")).is_empty());
    }

    #[test]
    fn test_obsolete_sections_detected_in_toml_and_json() {
        assert_eq!(
            Config::obsolete_sections("[sandbox]\nenabled = true\n", Path::new("c.toml")),
            vec!["sandbox"]
        );
        assert_eq!(
            Config::obsolete_sections(r#"{"sandbox": {"enabled": true}}"#, Path::new("c.json")),
            vec!["sandbox"]
        );
    }

    #[test]
    fn test_generated_config_has_no_sandbox_section() {
        // `cxg config generate` serializes Config::default(); it must not put the
        // section back into every new config file.
        let yaml = serde_yaml::to_string(&Config::default()).expect("serialize");
        assert!(
            !yaml.contains("sandbox"),
            "generated config still emits a sandbox section:\n{}",
            yaml
        );
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
