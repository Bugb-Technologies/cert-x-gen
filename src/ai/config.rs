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
    
    /// Fallback providers to try if default fails
    #[serde(default)]
    pub fallback_providers: Vec<String>,
    
    /// Provider-specific configurations
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
    
    /// Cost tracking configuration
    #[serde(default)]
    pub cost_tracking: CostTracking,
    
    /// Response caching configuration
    #[serde(default)]
    pub cache: CacheConfig,
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

/// Cost tracking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostTracking {
    /// Whether cost tracking is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    /// Warn if single request cost exceeds this (USD)
    #[serde(default = "default_cost_warn_threshold")]
    pub warn_threshold: f64,
    
    /// Maximum monthly spending (USD)
    #[serde(default = "default_max_monthly")]
    pub max_per_month: f64,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Whether caching is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    /// Cache TTL in hours
    #[serde(default = "default_cache_ttl")]
    pub ttl_hours: u32,
    
    /// Maximum cache size in megabytes
    #[serde(default = "default_cache_size")]
    pub max_size_mb: u32,
}

// Default value functions
fn default_provider() -> String {
    "ollama".to_string()
}

fn default_true() -> bool {
    true
}

fn default_cost_warn_threshold() -> f64 {
    1.0
}

fn default_max_monthly() -> f64 {
    50.0
}

fn default_cache_ttl() -> u32 {
    24
}

fn default_cache_size() -> u32 {
    100
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            default_provider: default_provider(),
            fallback_providers: vec!["ollama".to_string()],
            providers: Self::default_providers(),
            cost_tracking: CostTracking::default(),
            cache: CacheConfig::default(),
        }
    }
}

impl Default for CostTracking {
    fn default() -> Self {
        Self {
            enabled: true,
            warn_threshold: default_cost_warn_threshold(),
            max_per_month: default_max_monthly(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_hours: default_cache_ttl(),
            max_size_mb: default_cache_size(),
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
        
        let mut config: AIConfig = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse AI configuration")?;
        
        // Expand environment variables in API keys
        config.expand_env_vars();
        
        Ok(config)
    }
    
    /// Save configuration to default location
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        
        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
        }
        
        let content = serde_yaml::to_string(self)
            .with_context(|| "Failed to serialize AI configuration")?;
        
        fs::write(&config_path, content)
            .with_context(|| format!("Failed to write AI config to {}", config_path.display()))?;
        
        Ok(())
    }
    
    /// Get the configuration file path
    pub fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .context("Failed to determine home directory")?;
        
        Ok(home.join(".cert-x-gen").join("ai-config.yaml"))
    }
    
    /// Get the cache directory path
    pub fn cache_dir() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .context("Failed to determine home directory")?;
        
        Ok(home.join(".cert-x-gen").join("cache").join("ai-responses"))
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
                            tracing::debug!("Auto-enabled provider '{}' from environment variable {}", name, env_var);
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
        self.get_provider(name)
            .map(|p| p.enabled)
            .unwrap_or(false)
    }
    
    /// Get the default provider name
    pub fn default_provider_name(&self) -> &str {
        &self.default_provider
    }
    
    /// Get fallback providers in order
    pub fn fallback_providers(&self) -> &[String] {
        &self.fallback_providers
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
    /// - Proper fallback provider setup
    pub fn validate(&self) -> Result<()> {
        // Check that default provider exists
        if !self.providers.contains_key(&self.default_provider) {
            anyhow::bail!(
                "Default provider '{}' not found in providers list. Available: {}",
                self.default_provider,
                self.providers.keys().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
        
        // Check that all fallback providers exist
        for fallback in &self.fallback_providers {
            if !self.providers.contains_key(fallback) {
                anyhow::bail!(
                    "Fallback provider '{}' not found in providers list",
                    fallback
                );
            }
        }
        
        // Validate provider configurations
        for (name, provider) in &self.providers {
            // Check max_tokens is reasonable
            if let Some(max_tokens) = provider.max_tokens {
                if max_tokens == 0 || max_tokens > 200_000 {
                    anyhow::bail!(
                        "Provider '{}' has invalid max_tokens: {}. Must be between 1 and 200,000",
                        name, max_tokens
                    );
                }
            }
            
            // Check temperature is in valid range
            if let Some(temperature) = provider.temperature {
                if temperature < 0.0 || temperature > 2.0 {
                    anyhow::bail!(
                        "Provider '{}' has invalid temperature: {}. Must be between 0.0 and 2.0",
                        name, temperature
                    );
                }
            }
            
            // Check timeout is reasonable
            if let Some(timeout) = provider.timeout_secs {
                if timeout == 0 || timeout > 600 {
                    anyhow::bail!(
                        "Provider '{}' has invalid timeout: {}s. Must be between 1 and 600 seconds",
                        name, timeout
                    );
                }
            }
        }
        
        // Validate cost tracking
        if self.cost_tracking.warn_threshold < 0.0 {
            anyhow::bail!("Cost tracking warn_threshold must be non-negative");
        }
        
        if self.cost_tracking.max_per_month < 0.0 {
            anyhow::bail!("Cost tracking max_per_month must be non-negative");
        }
        
        // Validate cache config
        if self.cache.ttl_hours == 0 {
            anyhow::bail!("Cache TTL must be at least 1 hour");
        }
        
        if self.cache.max_size_mb == 0 {
            anyhow::bail!("Cache max size must be at least 1 MB");
        }
        
        Ok(())
    }
    
    /// Get the best available provider
    pub fn get_best_provider<F>(&self, check_availability: F) -> Option<String>
    where
        F: Fn(&str) -> bool,
    {
        if self.is_provider_enabled(&self.default_provider) 
            && check_availability(&self.default_provider) 
        {
            return Some(self.default_provider.clone());
        }
        
        for fallback in &self.fallback_providers {
            if self.is_provider_enabled(fallback) && check_availability(fallback) {
                return Some(fallback.clone());
            }
        }
        
        for (name, config) in &self.providers {
            if config.enabled && check_availability(name) {
                return Some(name.clone());
            }
        }
        
        None
    }
    
    /// Get all enabled providers
    pub fn get_enabled_providers(&self) -> Vec<String> {
        self.providers
            .iter()
            .filter(|(_, config)| config.enabled)
            .map(|(name, _)| name.clone())
            .collect()
    }
    
    /// Get providers in priority order
    pub fn get_providers_in_priority(&self) -> Vec<String> {
        let mut result = Vec::new();
        
        if self.providers.contains_key(&self.default_provider) {
            result.push(self.default_provider.clone());
        }
        
        for fallback in &self.fallback_providers {
            if !result.contains(fallback) && self.providers.contains_key(fallback) {
                result.push(fallback.clone());
            }
        }
        
        for (name, config) in &self.providers {
            if !result.contains(name) && config.enabled {
                result.push(name.clone());
            }
        }
        
        result
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
        let provider = self.providers.get_mut(name)
            .context(format!("Provider '{}' not found", name))?;
        
        provider.enabled = true;
        Ok(())
    }
    
    /// Disable a provider
    pub fn disable_provider(&mut self, name: &str) -> Result<()> {
        let provider = self.providers.get_mut(name)
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
    
    /// Add a fallback provider
    pub fn add_fallback_provider(&mut self, name: &str) -> Result<()> {
        if !self.providers.contains_key(name) {
            anyhow::bail!("Provider '{}' not found", name);
        }
        
        if !self.fallback_providers.contains(&name.to_string()) {
            self.fallback_providers.push(name.to_string());
        }
        
        Ok(())
    }
    
    /// Remove a fallback provider
    pub fn remove_fallback_provider(&mut self, name: &str) {
        self.fallback_providers.retain(|p| p != name);
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
        assert!(config.cost_tracking.enabled);
        assert!(config.cache.enabled);
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
}

/// Cost tracking data stored separately
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CostTrackingData {
    /// Total cost this month (USD)
    pub month_total: f64,
    
    /// Current month (YYYY-MM format)
    pub current_month: String,
    
    /// Cost per provider this month
    pub provider_costs: HashMap<String, f64>,
    
    /// Request count per provider
    pub provider_requests: HashMap<String, u32>,
}

impl CostTrackingData {
    /// Load cost tracking data
    pub fn load() -> Result<Self> {
        let data_path = Self::data_path()?;
        
        if !data_path.exists() {
            return Ok(Self::default());
        }
        
        let content = fs::read_to_string(&data_path)
            .with_context(|| format!("Failed to read cost tracking data from {}", data_path.display()))?;
        
        let mut data: CostTrackingData = serde_json::from_str(&content)
            .with_context(|| "Failed to parse cost tracking data")?;
        
        // Reset if it's a new month
        let current_month = chrono::Utc::now().format("%Y-%m").to_string();
        if data.current_month != current_month {
            data.month_total = 0.0;
            data.current_month = current_month;
            data.provider_costs.clear();
            data.provider_requests.clear();
            data.save()?;
        }
        
        Ok(data)
    }
    
    /// Save cost tracking data
    pub fn save(&self) -> Result<()> {
        let data_path = Self::data_path()?;
        
        // Ensure parent directory exists
        if let Some(parent) = data_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create data directory: {}", parent.display()))?;
        }
        
        let content = serde_json::to_string_pretty(self)
            .with_context(|| "Failed to serialize cost tracking data")?;
        
        fs::write(&data_path, content)
            .with_context(|| format!("Failed to write cost tracking data to {}", data_path.display()))?;
        
        Ok(())
    }
    
    /// Get the data file path
    fn data_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .context("Failed to determine home directory")?;
        
        Ok(home.join(".cert-x-gen").join("ai-cost-tracking.json"))
    }
    
    /// Record a cost
    pub fn record_cost(&mut self, provider: &str, cost: f64) -> Result<()> {
        // Ensure we're in the current month
        let current_month = chrono::Utc::now().format("%Y-%m").to_string();
        if self.current_month != current_month {
            self.month_total = 0.0;
            self.current_month = current_month;
            self.provider_costs.clear();
            self.provider_requests.clear();
        }
        
        // Add cost
        self.month_total += cost;
        *self.provider_costs.entry(provider.to_string()).or_insert(0.0) += cost;
        *self.provider_requests.entry(provider.to_string()).or_insert(0) += 1;
        
        // Save
        self.save()?;
        
        Ok(())
    }
    
    /// Check if monthly limit would be exceeded
    pub fn would_exceed_limit(&self, additional_cost: f64, max_per_month: f64) -> bool {
        self.month_total + additional_cost > max_per_month
    }
    
    /// Get cost for a specific provider
    pub fn get_provider_cost(&self, provider: &str) -> f64 {
        *self.provider_costs.get(provider).unwrap_or(&0.0)
    }
    
    /// Get request count for a specific provider
    pub fn get_provider_requests(&self, provider: &str) -> u32 {
        *self.provider_requests.get(provider).unwrap_or(&0)
    }
}

#[cfg(test)]
mod tests_cost_tracking {
    use super::*;
    
    #[test]
    fn test_validation() {
        let mut config = AIConfig::default();
        
        // Valid config should pass
        assert!(config.validate().is_ok());
        
        // Invalid default provider
        config.default_provider = "nonexistent".to_string();
        assert!(config.validate().is_err());
        config.default_provider = "ollama".to_string();
        
        // Invalid fallback provider
        config.fallback_providers.push("nonexistent".to_string());
        assert!(config.validate().is_err());
        config.fallback_providers = vec!["ollama".to_string()];
        
        // Invalid max_tokens - use block scope to drop mutable borrow
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.max_tokens = Some(0);
        }
        assert!(config.validate().is_err());
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.max_tokens = Some(300_000);
        }
        assert!(config.validate().is_err());
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.max_tokens = Some(4000);
        }
        
        // Invalid temperature - use block scope
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.temperature = Some(-0.1);
        }
        assert!(config.validate().is_err());
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.temperature = Some(2.5);
        }
        assert!(config.validate().is_err());
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.temperature = Some(0.7);
        }
        
        // Invalid timeout - use block scope
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.timeout_secs = Some(0);
        }
        assert!(config.validate().is_err());
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.timeout_secs = Some(700);
        }
        assert!(config.validate().is_err());
        {
            let provider = config.providers.get_mut("ollama").unwrap();
            provider.timeout_secs = Some(300);
        }
        
        // Should be valid again
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_get_best_provider() {
        let mut config = AIConfig::default();
        
        // All available - should return default (ollama)
        let best = config.get_best_provider(|_| true);
        assert_eq!(best, Some("ollama".to_string()));
        
        // Default unavailable but no other enabled providers - should return None
        let best = config.get_best_provider(|name| name != "ollama");
        assert!(best.is_none());
        
        // Enable another provider and add to fallbacks
        config.enable_provider("openai").unwrap();
        config.add_fallback_provider("openai").unwrap();
        
        // Now with default unavailable - should use fallback
        let best = config.get_best_provider(|name| name != "ollama");
        assert_eq!(best, Some("openai".to_string()));
        
        // None available - should return None
        let best = config.get_best_provider(|_| false);
        assert!(best.is_none());
    }
    
    #[test]
    fn test_get_enabled_providers() {
        let config = AIConfig::default();
        let enabled = config.get_enabled_providers();
        
        // Ollama is enabled by default
        assert!(enabled.contains(&"ollama".to_string()));
        
        // Others are disabled by default
        assert!(!enabled.contains(&"openai".to_string()));
    }
    
    #[test]
    fn test_get_providers_in_priority() {
        let config = AIConfig::default();
        let priority = config.get_providers_in_priority();
        
        // Default provider should be first
        assert_eq!(priority[0], "ollama");
        
        // Should not contain duplicates
        let unique: std::collections::HashSet<_> = priority.iter().collect();
        assert_eq!(unique.len(), priority.len());
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
    
    #[test]
    fn test_fallback_provider_management() {
        let mut config = AIConfig::default();
        
        // Add fallback
        config.add_fallback_provider("openai").unwrap();
        assert!(config.fallback_providers().contains(&"openai".to_string()));
        
        // Remove fallback
        config.remove_fallback_provider("openai");
        assert!(!config.fallback_providers().contains(&"openai".to_string()));
        
        // Try to add non-existent provider as fallback
        assert!(config.add_fallback_provider("nonexistent").is_err());
    }
    
    #[test]
    fn test_cost_tracking_data() {
        let mut data = CostTrackingData::default();
        data.current_month = chrono::Utc::now().format("%Y-%m").to_string();
        
        // Record some costs
        data.record_cost("openai", 0.05).unwrap();
        data.record_cost("anthropic", 0.03).unwrap();
        data.record_cost("openai", 0.02).unwrap();
        
        // Check totals
        assert_eq!(data.month_total, 0.10);
        assert_eq!(data.get_provider_cost("openai"), 0.07);
        assert_eq!(data.get_provider_cost("anthropic"), 0.03);
        assert_eq!(data.get_provider_requests("openai"), 2);
        assert_eq!(data.get_provider_requests("anthropic"), 1);
        
        // Check limit
        assert!(!data.would_exceed_limit(0.05, 1.0));
        assert!(data.would_exceed_limit(0.95, 1.0));
    }
    
    #[test]
    fn test_cost_tracking_month_rollover() {
        let mut data = CostTrackingData::default();
        data.current_month = "2024-10".to_string(); // Old month
        data.month_total = 10.0;
        data.provider_costs.insert("openai".to_string(), 10.0);
        
        // Record cost - should reset for new month
        data.record_cost("openai", 0.05).unwrap();
        
        assert_eq!(data.month_total, 0.05);
        assert_eq!(data.get_provider_cost("openai"), 0.05);
        assert_eq!(data.current_month, chrono::Utc::now().format("%Y-%m").to_string());
    }
}
