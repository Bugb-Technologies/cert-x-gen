//! LLM Provider Abstraction Layer
//!
//! This module defines the `LLMProvider` trait that all LLM providers must implement.
//! It provides a unified interface for interacting with different LLM services
//! (local and cloud-based).
//!
//! # Supported Providers
//!
//! - **Ollama**: Local LLM provider (no API key required) ✅
//! - **OpenAI**: GPT-4, GPT-3.5-turbo (requires API key) ✅
//! - **Anthropic**: Claude 3.5 Sonnet, Opus (requires API key) ✅
//! - **DeepSeek**: DeepSeek Coder (requires API key) ✅
//! - **Google AI**: Gemini Pro (requires API key) - Coming soon
//! - **Groq**: Fast inference (requires API key) - Coming soon
//!
//! # Architecture
//!
//! The provider system follows these principles:
//!
//! 1. **Async-first**: All generation operations are async
//! 2. **Unified interface**: Same trait for all providers
//! 3. **Graceful degradation**: Providers fail gracefully with helpful errors
//! 4. **Cost transparency**: Optional cost estimation for paid providers
//! 5. **Health checks**: Built-in availability checking
//!
//! # Example
//!
//! ```no_run
//! use cert_x_gen::ai::providers::{LLMProvider, GenerationOptions};
//! use std::time::Duration;
//!
//! async fn generate_with_provider<P: LLMProvider>(provider: &P) -> anyhow::Result<()> {
//!     // Check if provider is available
//!     if !provider.is_available() {
//!         anyhow::bail!("Provider {} is not available", provider.name());
//!     }
//!     
//!     // Configure generation options
//!     let options = GenerationOptions {
//!         max_tokens: Some(4000),
//!         temperature: Some(0.7),
//!         timeout: Some(Duration::from_secs(60)),
//!     };
//!     
//!     // Generate code
//!     let code = provider.generate(
//!         "Write a Python function to detect Redis without auth",
//!         options,
//!     ).await?;
//!     
//!     println!("Generated code:\n{}", code);
//!     Ok(())
//! }
//! ```

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// Provider implementations
pub mod anthropic;
pub mod deepseek;
pub mod ollama;
pub mod openai;

// Re-export for convenience
pub use anthropic::AnthropicProvider;
pub use deepseek::DeepSeekProvider;
pub use ollama::OllamaProvider;
pub use openai::OpenAIProvider;

/// Options for controlling LLM generation behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationOptions {
    /// Maximum number of tokens to generate
    ///
    /// Different providers have different limits:
    /// - Ollama: Depends on model
    /// - OpenAI GPT-4: 8192-128000 depending on variant
    /// - Claude 3.5 Sonnet: 200000
    /// - DeepSeek Coder: 16384
    pub max_tokens: Option<u32>,

    /// Sampling temperature (0.0-2.0)
    ///
    /// - 0.0: Deterministic, focused output
    /// - 0.7: Balanced creativity and consistency (recommended)
    /// - 1.0: More creative, varied output
    /// - 2.0: Very creative, potentially inconsistent
    pub temperature: Option<f32>,

    /// Request timeout
    ///
    /// Recommended timeouts:
    /// - Local providers (Ollama): 300s
    /// - Cloud providers: 60s
    pub timeout: Option<Duration>,
}

impl Default for GenerationOptions {
    fn default() -> Self {
        Self {
            max_tokens: Some(4000),
            temperature: Some(0.7),
            timeout: Some(Duration::from_secs(60)),
        }
    }
}

/// Provider health check status
///
/// Contains detailed information about a provider's health and availability.
/// Used by the `health_check()` method to provide comprehensive diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealthStatus {
    /// Provider name
    pub provider: String,

    /// Overall health status
    pub healthy: bool,

    /// Connection status (can reach the endpoint)
    pub connection: ConnectionStatus,

    /// Authentication status
    pub authentication: AuthStatus,

    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,

    /// Available models count
    pub models_available: Option<usize>,

    /// Available models (sample, max 5)
    pub models: Vec<ModelInfo>,

    /// Any error messages or warnings
    pub messages: Vec<String>,

    /// Additional provider-specific information
    pub metadata: std::collections::HashMap<String, String>,
}

/// Connection status for a provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    /// Successfully connected to the provider
    Connected,

    /// Failed to connect (network error, wrong endpoint, etc.)
    Failed,

    /// Connection not tested yet
    Untested,
}

impl ConnectionStatus {
    /// Check if the provider check result is successful

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Connected)
    }
}

/// Authentication status for a provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthStatus {
    /// Authentication succeeded
    Authenticated,

    /// Authentication failed (invalid API key, etc.)
    Failed,

    /// No authentication required (e.g., local providers)
    NotRequired,

    /// Authentication not configured (API key missing)
    NotConfigured,

    /// Authentication not tested yet
    Untested,
}

impl AuthStatus {
    /// Check if the provider check result is successful

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Authenticated | Self::NotRequired)
    }
}

impl ProviderHealthStatus {
    /// Create a new health status with defaults
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            healthy: false,
            connection: ConnectionStatus::Untested,
            authentication: AuthStatus::Untested,
            response_time_ms: None,
            models_available: None,
            models: Vec::new(),
            messages: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Mark as healthy if all checks passed
    pub fn update_health(&mut self) {
        self.healthy = self.connection.is_ok() && self.authentication.is_ok();
    }

    /// Add a message (warning or info)
    pub fn add_message(&mut self, message: impl Into<String>) {
        self.messages.push(message.into());
    }

    /// Add metadata
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
}

/// Information about an available LLM model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Unique model identifier (e.g., "codellama:13b", "gpt-4")
    pub id: String,

    /// Human-readable model name
    pub name: String,

    /// Provider name (e.g., "ollama", "openai")
    pub provider: String,

    /// Model size in bytes (for local models)
    pub size: Option<u64>,

    /// Model capabilities/features
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Context window size (max input tokens)
    pub context_window: Option<u32>,
}

impl ModelInfo {
    /// Create a new ModelInfo with basic details
    pub fn new(id: String, name: String, provider: String) -> Self {
        Self {
            id,
            name,
            provider,
            size: None,
            capabilities: Vec::new(),
            context_window: None,
        }
    }

    /// Builder method to set size
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Builder method to set context window
    pub fn with_context_window(mut self, tokens: u32) -> Self {
        self.context_window = Some(tokens);
        self
    }

    /// Builder method to add capability
    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities.push(capability.into());
        self
    }

    /// Format size as human-readable string
    pub fn size_human_readable(&self) -> String {
        match self.size {
            None => "Unknown".to_string(),
            Some(bytes) => {
                const GB: u64 = 1_073_741_824;
                const MB: u64 = 1_048_576;
                const KB: u64 = 1_024;

                if bytes >= GB {
                    format!("{:.2} GB", bytes as f64 / GB as f64)
                } else if bytes >= MB {
                    format!("{:.2} MB", bytes as f64 / MB as f64)
                } else if bytes >= KB {
                    format!("{:.2} KB", bytes as f64 / KB as f64)
                } else {
                    format!("{} B", bytes)
                }
            }
        }
    }
}

/// Main trait that all LLM providers must implement
///
/// This trait provides a unified interface for interacting with different
/// LLM services, whether they're running locally (like Ollama) or in the
/// cloud (like OpenAI, Anthropic, etc.).
///
/// # Design Principles
///
/// 1. **Async operations**: All I/O operations are async for maximum efficiency
/// 2. **Error handling**: Methods return `Result` for proper error propagation
/// 3. **Flexibility**: Options struct allows provider-specific customization
/// 4. **Observability**: Built-in health checks and model listing
/// 5. **Cost awareness**: Optional cost estimation for budget control
///
/// # Implementation Requirements
///
/// Implementors must:
/// - Be `Send + Sync` for use in async contexts
/// - Provide a unique provider name
/// - Implement health checking (`is_available`)
/// - Support text generation with configurable options
/// - Support model listing for user choice
///
/// # Example Implementation
///
/// ```no_run
/// use cert_x_gen::ai::providers::{LLMProvider, GenerationOptions, ModelInfo, ProviderHealthStatus};
/// use async_trait::async_trait;
/// use anyhow::Result;
///
/// pub struct MyProvider {
///     api_key: String,
/// }
///
/// #[async_trait]
/// impl LLMProvider for MyProvider {
///     fn name(&self) -> &str {
///         "my-provider"
///     }
///     
///     fn is_available(&self) -> bool {
///         !self.api_key.is_empty()
///     }
///     
///     async fn generate(&self, prompt: &str, options: GenerationOptions) -> Result<String> {
///         // Implementation here
///         Ok("generated code".to_string())
///     }
///     
///     async fn list_models(&self) -> Result<Vec<ModelInfo>> {
///         // Implementation here
///         Ok(vec![])
///     }
///     
///     async fn health_check(&self) -> Result<ProviderHealthStatus> {
///         let mut status = ProviderHealthStatus::new("my-provider");
///         status.healthy = true;
///         Ok(status)
///     }
/// }
/// ```
#[async_trait]
pub trait LLMProvider: Send + Sync {
    /// Get the provider's unique name
    ///
    /// This should be a lowercase, kebab-case identifier like:
    /// - "ollama"
    /// - "openai"
    /// - "anthropic"
    /// - "deepseek"
    ///
    /// The name is used for configuration lookup and user-facing displays.
    fn name(&self) -> &str;

    /// Check if the provider is currently available
    ///
    /// This method should perform a quick check to determine if the provider
    /// can be used. For example:
    ///
    /// - **Local providers (Ollama)**: Check if the service is running
    /// - **Cloud providers**: Check if API key is configured
    /// - **Network checks**: Optionally verify connectivity
    ///
    /// # Performance Note
    ///
    /// This method should be fast (< 100ms). For expensive checks,
    /// consider caching the result.
    ///
    /// # Returns
    ///
    /// - `true` if the provider is ready to use
    /// - `false` if the provider is unavailable or misconfigured
    fn is_available(&self) -> bool;

    /// Generate code/text from a prompt
    ///
    /// This is the core method that sends a prompt to the LLM and returns
    /// the generated response.
    ///
    /// # Arguments
    ///
    /// * `prompt` - The input prompt/instruction for the LLM
    /// * `options` - Generation options (temperature, max tokens, timeout)
    ///
    /// # Returns
    ///
    /// The generated text/code as a string.
    ///
    /// # Errors
    ///
    /// This method should return an error for:
    /// - Network failures
    /// - API authentication issues
    /// - Rate limiting
    /// - Invalid parameters
    /// - Timeout
    ///
    /// Error messages should be user-friendly and actionable.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cert_x_gen::ai::providers::{LLMProvider, GenerationOptions};
    /// # async fn example<P: LLMProvider>(provider: &P) -> anyhow::Result<()> {
    /// let options = GenerationOptions::default();
    /// let code = provider.generate(
    ///     "Write a Python function to check Redis auth",
    ///     options,
    /// ).await?;
    /// println!("Generated: {}", code);
    /// # Ok(())
    /// # }
    /// ```
    async fn generate(&self, prompt: &str, options: GenerationOptions) -> Result<String>;

    /// List all available models for this provider
    ///
    /// Returns metadata about models that can be used with this provider.
    /// This is useful for:
    /// - Letting users choose their preferred model
    /// - Displaying available options in CLI
    /// - Checking if a specific model is available
    ///
    /// # Returns
    ///
    /// A vector of `ModelInfo` structs, each describing an available model.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cannot connect to the provider
    /// - API authentication fails
    /// - Provider doesn't support model listing
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cert_x_gen::ai::providers::LLMProvider;
    /// # async fn example<P: LLMProvider>(provider: &P) -> anyhow::Result<()> {
    /// let models = provider.list_models().await?;
    /// for model in models {
    ///     println!("{}: {} ({})",
    ///         model.id,
    ///         model.name,
    ///         model.size_human_readable()
    ///     );
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn list_models(&self) -> Result<Vec<ModelInfo>>;

    /// Estimate the cost of generating with this prompt
    ///
    /// For cloud providers that charge per token, this method estimates
    /// the cost in USD. For local providers (like Ollama), this returns
    /// `None` since there's no per-request cost.
    ///
    /// # Arguments
    ///
    /// * `prompt` - The prompt to estimate cost for
    ///
    /// # Returns
    ///
    /// - `Some(cost)` - Estimated cost in USD
    /// - `None` - Provider doesn't charge per request
    ///
    /// # Note
    ///
    /// This is an *estimate* only. Actual costs may vary based on:
    /// - Actual output length
    /// - Provider pricing changes
    /// - Special promotions or discounts
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cert_x_gen::ai::providers::LLMProvider;
    /// # async fn example<P: LLMProvider>(provider: &P) -> anyhow::Result<()> {
    /// let prompt = "Write a security scanner in Python";
    ///
    /// if let Some(cost) = provider.estimate_cost(prompt) {
    ///     println!("Estimated cost: ${:.4}", cost);
    ///     
    ///     if cost > 1.0 {
    ///         println!("Warning: This request may be expensive!");
    ///     }
    /// } else {
    ///     println!("Free to use (local provider)");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    fn estimate_cost(&self, _prompt: &str) -> Option<f64> {
        None // Default: no cost (for local providers)
    }

    /// Perform a comprehensive health check on the provider
    ///
    /// This method tests the provider's connectivity, authentication, model
    /// availability, and response time. It's more thorough than `is_available()`.
    ///
    /// # Returns
    ///
    /// A `ProviderHealthStatus` struct with detailed diagnostics including:
    /// - Connection status (can we reach the endpoint?)
    /// - Authentication status (is the API key valid?)
    /// - Response time (how fast is the provider?)
    /// - Available models (what models can we use?)
    /// - Error messages and warnings
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cert_x_gen::ai::providers::LLMProvider;
    /// # async fn example<P: LLMProvider>(provider: &P) -> anyhow::Result<()> {
    /// let health = provider.health_check().await?;
    ///
    /// if health.healthy {
    ///     println!("✓ Provider is healthy");
    ///     if let Some(rt) = health.response_time_ms {
    ///         println!("  Response time: {}ms", rt);
    ///     }
    ///     println!("  Models available: {}", health.models_available.unwrap_or(0));
    /// } else {
    ///     println!("✗ Provider is unhealthy");
    ///     for msg in health.messages {
    ///         println!("  - {}", msg);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn health_check(&self) -> Result<ProviderHealthStatus>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generation_options_default() {
        let options = GenerationOptions::default();
        assert_eq!(options.max_tokens, Some(4000));
        assert_eq!(options.temperature, Some(0.7));
        assert!(options.timeout.is_some());
    }

    #[test]
    fn test_model_info_builder() {
        let model = ModelInfo::new(
            "test-model".to_string(),
            "Test Model".to_string(),
            "test-provider".to_string(),
        )
        .with_size(1_073_741_824) // 1 GB
        .with_context_window(8192)
        .with_capability("code-generation")
        .with_capability("chat");

        assert_eq!(model.id, "test-model");
        assert_eq!(model.name, "Test Model");
        assert_eq!(model.provider, "test-provider");
        assert_eq!(model.size, Some(1_073_741_824));
        assert_eq!(model.context_window, Some(8192));
        assert_eq!(model.capabilities.len(), 2);
    }

    #[test]
    fn test_model_info_size_formatting() {
        let model_gb = ModelInfo::new("test".to_string(), "Test".to_string(), "test".to_string())
            .with_size(5_368_709_120); // 5 GB
        assert_eq!(model_gb.size_human_readable(), "5.00 GB");

        let model_mb = ModelInfo::new("test".to_string(), "Test".to_string(), "test".to_string())
            .with_size(157_286_400); // 150 MB
        assert_eq!(model_mb.size_human_readable(), "150.00 MB");

        let model_kb = ModelInfo::new("test".to_string(), "Test".to_string(), "test".to_string())
            .with_size(10_240); // 10 KB
        assert_eq!(model_kb.size_human_readable(), "10.00 KB");

        let model_none = ModelInfo::new("test".to_string(), "Test".to_string(), "test".to_string());
        assert_eq!(model_none.size_human_readable(), "Unknown");
    }

    #[test]
    fn test_generation_options_serialization() {
        let options = GenerationOptions {
            max_tokens: Some(2000),
            temperature: Some(0.5),
            timeout: Some(Duration::from_secs(30)),
        };

        let json = serde_json::to_string(&options).unwrap();
        let deserialized: GenerationOptions = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.max_tokens, Some(2000));
        assert_eq!(deserialized.temperature, Some(0.5));
    }
}
