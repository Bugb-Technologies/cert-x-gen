//! AI configuration management
//!
//! Handles loading, saving, and managing AI provider configurations.
//! Configuration file location: `~/.cert-x-gen/ai-config.yaml`

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Main AI configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIConfig {
    /// Default LLM provider to use
    #[serde(default = "default_provider")]
    pub default_provider: String,

    /// Provider-specific configurations
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
}

/// Provider-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Whether this provider is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// API endpoint (for local or custom endpoints)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// API key (supports environment variable substitution)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// Model name to use
    pub model: String,

    /// Maximum tokens to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,

    /// Temperature for generation (0.0-2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,

    /// Request timeout in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

// Default value functions
fn default_provider() -> String {
    "ollama".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            default_provider: default_provider(),
            providers: Self::default_providers(),
        }
    }
}

impl AIConfig {
    /// Load configuration from default location
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if !config_path.exists() {
            // Create default configuration on first run
            let config = Self::default();
            config.save()?;
            return Ok(config);
        }

        let content = fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read AI config from {}", config_path.display()))?;

        let mut config: AIConfig =
            serde_yaml::from_str(&content).with_context(|| "Failed to parse AI configuration")?;

        // Expand environment variables in API keys
        config.expand_env_vars();

        Ok(config)
    }

    /// Save configuration to default location
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        let content =
            serde_yaml::to_string(self).with_context(|| "Failed to serialize AI configuration")?;

        fs::write(&config_path, content)
            .with_context(|| format!("Failed to write AI config to {}", config_path.display()))?;

        Ok(())
    }

    /// Get the configuration file path
    pub fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Failed to determine home directory")?;

        Ok(home.join(".cert-x-gen").join("ai-config.yaml"))
    }

    /// Expand environment variables in configuration
    fn expand_env_vars(&mut self) {
        for (name, provider) in self.providers.iter_mut() {
            // Clone the api_key to avoid borrow checker issues
            let api_key_template = provider.api_key.clone();

            if let Some(api_key) = api_key_template {
                if api_key.starts_with("${") && api_key.ends_with("}") {
                    let env_var = &api_key[2..api_key.len() - 1];
                    if let Ok(value) = std::env::var(env_var) {
                        if !value.is_empty() {
                            provider.api_key = Some(value);
                            // Auto-enable provider when API key is available
                            provider.enabled = true;
                            tracing::debug!(
                                "Auto-enabled provider '{}' from environment variable {}",
                                name,
                                env_var
                            );
                        }
                    }
                }
            }
        }
    }

    /// Get provider configuration by name
    pub fn get_provider(&self, name: &str) -> Option<&ProviderConfig> {
        self.providers.get(name)
    }

    /// Check if a provider is enabled
    pub fn is_provider_enabled(&self, name: &str) -> bool {
        self.get_provider(name).map(|p| p.enabled).unwrap_or(false)
    }

    /// Get the default provider name
    pub fn default_provider_name(&self) -> &str {
        &self.default_provider
    }

    /// Create default provider configurations
    fn default_providers() -> HashMap<String, ProviderConfig> {
        let mut providers = HashMap::new();

        // Ollama (local, no API key required)
        providers.insert(
            "ollama".to_string(),
            ProviderConfig {
                enabled: true,
                endpoint: Some("http://localhost:11434".to_string()),
                api_key: None,
                model: "codellama:13b".to_string(),
                max_tokens: Some(4000),
                temperature: Some(0.7),
                timeout_secs: Some(300),
            },
        );

        // OpenAI
        providers.insert(
            "openai".to_string(),
            ProviderConfig {
                enabled: false,
                endpoint: None,
                api_key: Some("${OPENAI_API_KEY}".to_string()),
                model: "gpt-4".to_string(),
                max_tokens: Some(4000),
                temperature: Some(0.7),
                timeout_secs: Some(60),
            },
        );

        // Anthropic
        providers.insert(
            "anthropic".to_string(),
            ProviderConfig {
                enabled: false,
                endpoint: None,
                api_key: Some("${ANTHROPIC_API_KEY}".to_string()),
                model: "claude-3-5-sonnet-20241022".to_string(),
                max_tokens: Some(4000),
                temperature: Some(0.7),
                timeout_secs: Some(60),
            },
        );

        // DeepSeek
        providers.insert(
            "deepseek".to_string(),
            ProviderConfig {
                enabled: false,
                endpoint: None,
                api_key: Some("${DEEPSEEK_API_KEY}".to_string()),
                model: "deepseek-coder".to_string(),
                max_tokens: Some(4000),
                temperature: Some(0.7),
                timeout_secs: Some(60),
            },
        );

        providers
    }

    /// Validate the configuration
    ///
    /// Checks for:
    /// - Valid provider references
    /// - Valid configuration values
    pub fn validate(&self) -> Result<()> {
        // Check that default provider exists
        if !self.providers.contains_key(&self.default_provider) {
            anyhow::bail!(
                "Default provider '{}' not found in providers list. Available: {}",
                self.default_provider,
                self.providers
                    .keys()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        // Validate provider configurations
        for (name, provider) in &self.providers {
            // Check max_tokens is reasonable
            if let Some(max_tokens) = provider.max_tokens {
                if max_tokens == 0 || max_tokens > 200_000 {
                    anyhow::bail!(
                        "Provider '{}' has invalid max_tokens: {}. Must be between 1 and 200,000",
                        name,
                        max_tokens
                    );
                }
            }

            // Check temperature is in valid range
            if let Some(temperature) = provider.temperature {
                if !(0.0..=2.0).contains(&temperature) {
                    anyhow::bail!(
                        "Provider '{}' has invalid temperature: {}. Must be between 0.0 and 2.0",
                        name,
                        temperature
                    );
                }
            }

            // Check timeout is reasonable
            if let Some(timeout) = provider.timeout_secs {
                if timeout == 0 || timeout > 600 {
                    anyhow::bail!(
                        "Provider '{}' has invalid timeout: {}s. Must be between 1 and 600 seconds",
                        name,
                        timeout
                    );
                }
            }
        }

        Ok(())
    }

    /// Update a provider's configuration
    pub fn update_provider(&mut self, name: &str, config: ProviderConfig) -> Result<()> {
        if !self.providers.contains_key(name) {
            anyhow::bail!("Provider '{}' not found", name);
        }

        self.providers.insert(name.to_string(), config);
        Ok(())
    }

    /// Enable a provider
    pub fn enable_provider(&mut self, name: &str) -> Result<()> {
        let provider = self
            .providers
            .get_mut(name)
            .context(format!("Provider '{}' not found", name))?;

        provider.enabled = true;
        Ok(())
    }

    /// Disable a provider
    pub fn disable_provider(&mut self, name: &str) -> Result<()> {
        let provider = self
            .providers
            .get_mut(name)
            .context(format!("Provider '{}' not found", name))?;

        provider.enabled = false;
        Ok(())
    }

    /// Set the default provider
    pub fn set_default_provider(&mut self, name: &str) -> Result<()> {
        if !self.providers.contains_key(name) {
            anyhow::bail!("Provider '{}' not found", name);
        }

        self.default_provider = name.to_string();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AIConfig::default();
        assert_eq!(config.default_provider, "ollama");
        assert!(config.providers.contains_key("ollama"));
        assert!(config.providers.contains_key("openai"));
    }

    #[test]
    fn test_serialization() {
        let config = AIConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("default_provider"));
        assert!(yaml.contains("ollama"));

        let deserialized: AIConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.default_provider, config.default_provider);
    }

    #[test]
    fn test_provider_access() {
        let config = AIConfig::default();

        assert!(config.is_provider_enabled("ollama"));
        assert!(!config.is_provider_enabled("openai")); // Disabled by default

        let ollama = config.get_provider("ollama").unwrap();
        assert_eq!(ollama.model, "codellama:13b");
    }

    #[test]
    fn test_validation() {
        let mut config = AIConfig::default();

        // Valid config should pass
        assert!(config.validate().is_ok());

        // Invalid default provider
        config.default_provider = "nonexistent".to_string();
        assert!(config.validate().is_err());
        config.default_provider = "ollama".to_string();

        // Invalid max_tokens
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.max_tokens = Some(0);
        }
        assert!(config.validate().is_err());
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.max_tokens = Some(4000);
        }

        // Should be valid again
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_provider_management() {
        let mut config = AIConfig::default();

        // Enable a disabled provider
        assert!(!config.is_provider_enabled("openai"));
        config.enable_provider("openai").unwrap();
        assert!(config.is_provider_enabled("openai"));

        // Disable it again
        config.disable_provider("openai").unwrap();
        assert!(!config.is_provider_enabled("openai"));

        // Try to enable non-existent provider
        assert!(config.enable_provider("nonexistent").is_err());
    }

    #[test]
    fn test_default_provider_management() {
        let mut config = AIConfig::default();

        assert_eq!(config.default_provider_name(), "ollama");

        // Change default provider
        config.set_default_provider("openai").unwrap();
        assert_eq!(config.default_provider_name(), "openai");

        // Try to set non-existent provider as default
        assert!(config.set_default_provider("nonexistent").is_err());
    }
}
