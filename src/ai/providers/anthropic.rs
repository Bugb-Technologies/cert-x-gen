//! Anthropic LLM Provider Implementation
//!
//! Anthropic provides Claude models known for long context windows and high-quality reasoning.
//! Requires API key from https://console.anthropic.com/
//!
//! # Features
//!
//! - Claude 3.5 Sonnet: Most capable, 200K context window
//! - Claude 3 Opus: Highest intelligence, 200K context
//! - Claude 3 Sonnet: Balanced performance, 200K context
//! - Claude 3 Haiku: Fast and cost-effective, 200K context
//! - Native streaming support
//! - System prompts support
//!
//! # Setup
//!
//! 1. Get API key from https://console.anthropic.com/
//! 2. Set environment variable: export ANTHROPIC_API_KEY="sk-ant-..."
//! 3. Use with cert-x-gen: --provider anthropic
//!
//! # Pricing (as of 2025)
//!
//! Claude 3.5 Sonnet:
//! - Input: $3.00 / 1M tokens
//! - Output: $15.00 / 1M tokens
//!
//! Claude 3 Opus:
//! - Input: $15.00 / 1M tokens
//! - Output: $75.00 / 1M tokens
//!
//! Claude 3 Sonnet:
//! - Input: $3.00 / 1M tokens
//! - Output: $15.00 / 1M tokens
//!
//! Claude 3 Haiku:
//! - Input: $0.25 / 1M tokens
//! - Output: $1.25 / 1M tokens

use super::{AuthStatus, ConnectionStatus, GenerationOptions, LLMProvider, ModelInfo, ProviderHealthStatus};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Anthropic API version to use
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Anthropic provider for Claude models
#[derive(Debug, Clone)]
pub struct AnthropicProvider {
    endpoint: String,
    api_key: String,
    model: String,
    client: Client,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider
    ///
    /// # Arguments
    ///
    /// * `api_key` - Anthropic API key (starts with "sk-ant-")
    /// * `model` - Model identifier (e.g., "claude-3-5-sonnet-20241022")
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cert_x_gen::ai::providers::anthropic::AnthropicProvider;
    ///
    /// let provider = AnthropicProvider::new(
    ///     "sk-ant-...".to_string(),
    ///     "claude-3-5-sonnet-20241022".to_string()
    /// );
    /// ```
    pub fn new(api_key: String, model: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client");
        
        Self {
            endpoint: "https://api.anthropic.com/v1".to_string(),
            api_key,
            model,
            client,
        }
    }
    
    /// Get the current model name
    pub fn model(&self) -> &str {
        &self.model
    }
    
    /// Check if API key appears valid (starts with sk-ant-)
    fn is_api_key_valid(&self) -> bool {
        !self.api_key.is_empty() 
            && !self.api_key.starts_with("${")
            && self.api_key.starts_with("sk-ant-")
    }
}

#[async_trait]
impl LLMProvider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }
    
    fn is_available(&self) -> bool {
        self.is_api_key_valid()
    }
    
    async fn generate(&self, prompt: &str, options: GenerationOptions) -> Result<String> {
        info!("Generating with Anthropic model: {}", self.model);
        debug!("Prompt length: {} chars", prompt.len());
        
        if !self.is_api_key_valid() {
            anyhow::bail!(
                "Invalid Anthropic API key. Get your key from: https://console.anthropic.com/"
            );
        }
        
        #[derive(Serialize)]
        struct MessagesRequest {
            model: String,
            messages: Vec<Message>,
            max_tokens: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            temperature: Option<f32>,
            stream: bool,
        }
        
        #[derive(Serialize)]
        struct Message {
            role: String,
            content: String,
        }
        
        #[derive(Deserialize)]
        struct MessagesResponse {
            content: Vec<ContentBlock>,
            #[serde(default)]
            usage: Option<Usage>,
            stop_reason: Option<String>,
        }
        
        #[derive(Deserialize)]
        struct ContentBlock {
            #[serde(rename = "type")]
            block_type: String,
            text: String,
        }
        
        #[derive(Deserialize)]
        struct Usage {
            input_tokens: u32,
            output_tokens: u32,
        }
        
        let request = MessagesRequest {
            model: self.model.clone(),
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            max_tokens: options.max_tokens.unwrap_or(4000),
            temperature: options.temperature,
            stream: false, // Disable streaming for simplicity
        };
        
        let timeout = options.timeout.unwrap_or(Duration::from_secs(60));
        
        let response = self.client
            .post(format!("{}/messages", self.endpoint))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("Content-Type", "application/json")
            .json(&request)
            .timeout(timeout)
            .send()
            .await
            .context("Failed to connect to Anthropic API. Check your internet connection.")?;
        
        let status = response.status();
        let headers = response.headers().clone();
        
        // Check for rate limiting
        if status.as_u16() == 429 {
            let retry_after = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60);
            
            warn!("Anthropic rate limit hit, retry after {} seconds", retry_after);
            anyhow::bail!(
                "Anthropic rate limit exceeded. Please wait {} seconds and try again.",
                retry_after
            );
        }
        
        // Check for authentication errors
        if status.as_u16() == 401 {
            anyhow::bail!(
                "Anthropic authentication failed. Check your API key at: https://console.anthropic.com/"
            );
        }
        
        // Check for other errors
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Anthropic API error {}: {}",
                status, error_text
            );
        }
        
        let response_data: MessagesResponse = response.json().await
            .context("Failed to parse Anthropic response")?;
        
        if response_data.content.is_empty() {
            anyhow::bail!("Anthropic returned empty response");
        }
        
        // Extract text from content blocks
        let content = response_data.content
            .iter()
            .filter(|block| block.block_type == "text")
            .map(|block| block.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        
        if content.is_empty() {
            anyhow::bail!("Anthropic returned no text content");
        }
        
        // Log token usage if available
        if let Some(usage) = response_data.usage {
            info!(
                "Token usage - Input: {}, Output: {}, Total: {}",
                usage.input_tokens,
                usage.output_tokens,
                usage.input_tokens + usage.output_tokens
            );
            
            // Calculate actual cost
            if let Some(cost) = self.calculate_cost(usage.input_tokens, usage.output_tokens) {
                info!("Estimated cost: ${:.4}", cost);
            }
        }
        
        // Check stop reason
        if let Some(reason) = &response_data.stop_reason {
            if reason == "max_tokens" {
                warn!("Response was truncated due to max_tokens limit");
            }
        }
        
        info!("Generation completed, {} chars", content.len());
        
        Ok(content)
    }
    
    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        Ok(vec![
            // Claude 3.5 Sonnet - Most capable
            ModelInfo::new(
                "claude-3-5-sonnet-20241022".to_string(),
                "Claude 3.5 Sonnet".to_string(),
                "anthropic".to_string(),
            )
            .with_context_window(200000)
            .with_capability("code-generation")
            .with_capability("reasoning")
            .with_capability("analysis"),
            
            // Claude 3 Opus - Highest intelligence
            ModelInfo::new(
                "claude-3-opus-20240229".to_string(),
                "Claude 3 Opus".to_string(),
                "anthropic".to_string(),
            )
            .with_context_window(200000)
            .with_capability("code-generation")
            .with_capability("reasoning")
            .with_capability("analysis"),
            
            // Claude 3 Sonnet - Balanced
            ModelInfo::new(
                "claude-3-sonnet-20240229".to_string(),
                "Claude 3 Sonnet".to_string(),
                "anthropic".to_string(),
            )
            .with_context_window(200000)
            .with_capability("code-generation")
            .with_capability("reasoning"),
            
            // Claude 3 Haiku - Fast and cost-effective
            ModelInfo::new(
                "claude-3-haiku-20240307".to_string(),
                "Claude 3 Haiku".to_string(),
                "anthropic".to_string(),
            )
            .with_context_window(200000)
            .with_capability("code-generation")
            .with_capability("chat"),
        ])
    }
    
    fn estimate_cost(&self, prompt: &str) -> Option<f64> {
        // Rough token estimation: 1 token ≈ 4 characters
        let input_tokens = (prompt.len() / 4) as f64;
        let output_tokens = 1000.0; // Assume average output
        
        self.calculate_cost(input_tokens as u32, output_tokens as u32)
    }
    
    async fn health_check(&self) -> Result<ProviderHealthStatus> {
        use std::time::Instant;
        
        let mut status = ProviderHealthStatus::new(self.name());
        status.add_metadata("endpoint", &self.endpoint);
        status.add_metadata("model", &self.model);
        status.add_metadata("type", "cloud");
        status.add_metadata("api_version", ANTHROPIC_VERSION);
        
        // Check API key configuration
        if !self.is_api_key_valid() {
            status.connection = ConnectionStatus::Failed;
            status.authentication = AuthStatus::NotConfigured;
            status.add_message("API key not configured or invalid format");
            status.add_message("Hint: Set ANTHROPIC_API_KEY environment variable");
            status.add_message("Hint: API keys should start with 'sk-ant-'");
            status.update_health();
            return Ok(status);
        }
        
        status.authentication = AuthStatus::Untested;
        
        // Test connection and authentication with a minimal request
        // Anthropic doesn't have a models endpoint, so we'll make a small generation request
        let start = Instant::now();
        
        #[derive(Serialize)]
        struct TestRequest {
            model: String,
            max_tokens: u32,
            messages: Vec<TestMessage>,
        }
        
        #[derive(Serialize)]
        struct TestMessage {
            role: String,
            content: String,
        }
        
        let test_request = TestRequest {
            model: self.model.clone(),
            max_tokens: 10,
            messages: vec![TestMessage {
                role: "user".to_string(),
                content: "Hi".to_string(),
            }],
        };
        
        match self.client
            .post(format!("{}/messages", self.endpoint))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(15))
            .json(&test_request)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let elapsed = start.elapsed();
                status.connection = ConnectionStatus::Connected;
                status.authentication = AuthStatus::Authenticated;
                status.response_time_ms = Some(elapsed.as_millis() as u64);
                status.add_message("Successfully connected to Anthropic API");
                
                // List available models (hardcoded since Anthropic doesn't have a models endpoint)
                match self.list_models().await {
                    Ok(models) => {
                        status.models_available = Some(models.len());
                        status.models = models.into_iter().take(5).collect();
                    }
                    Err(e) => {
                        status.add_message(format!("Could not list models: {}", e));
                    }
                }
            }
            Ok(response) if response.status() == 401 => {
                status.connection = ConnectionStatus::Connected;
                status.authentication = AuthStatus::Failed;
                status.add_message("Authentication failed: Invalid API key");
                status.add_message("Hint: Check your ANTHROPIC_API_KEY");
            }
            Ok(response) if response.status() == 429 => {
                status.connection = ConnectionStatus::Connected;
                status.authentication = AuthStatus::Authenticated;
                status.add_message("Rate limit exceeded");
                status.add_message("Hint: Wait a moment before trying again");
            }
            Ok(response) => {
                status.connection = ConnectionStatus::Failed;
                status.add_message(format!("Anthropic API error: HTTP {}", response.status()));
            }
            Err(e) if e.is_timeout() => {
                status.connection = ConnectionStatus::Failed;
                status.add_message("Connection timeout");
                status.add_message("Hint: Check your internet connection");
            }
            Err(e) => {
                status.connection = ConnectionStatus::Failed;
                status.add_message(format!("Cannot connect to Anthropic: {}", e));
                status.add_message("Hint: Check your internet connection");
            }
        }
        
        status.update_health();
        Ok(status)
    }
}

impl AnthropicProvider {
    /// Calculate actual cost based on token usage
    ///
    /// Pricing as of 2025:
    /// - Claude 3.5 Sonnet: $3/$15 per 1M tokens
    /// - Claude 3 Opus: $15/$75 per 1M tokens
    /// - Claude 3 Sonnet: $3/$15 per 1M tokens
    /// - Claude 3 Haiku: $0.25/$1.25 per 1M tokens
    fn calculate_cost(&self, input_tokens: u32, output_tokens: u32) -> Option<f64> {
        let (input_price, output_price) = match self.model.as_str() {
            // Claude 3.5 Sonnet
            m if m.starts_with("claude-3-5-sonnet") => (3.0, 15.0),
            
            // Claude 3 Opus
            m if m.starts_with("claude-3-opus") => (15.0, 75.0),
            
            // Claude 3 Sonnet
            m if m.starts_with("claude-3-sonnet") => (3.0, 15.0),
            
            // Claude 3 Haiku
            m if m.starts_with("claude-3-haiku") => (0.25, 1.25),
            
            // Unknown model, use Claude 3.5 Sonnet pricing as default
            _ => (3.0, 15.0),
        };
        
        let input_cost = (input_tokens as f64 / 1_000_000.0) * input_price;
        let output_cost = (output_tokens as f64 / 1_000_000.0) * output_price;
        
        Some(input_cost + output_cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_anthropic_provider_creation() {
        let provider = AnthropicProvider::new(
            "sk-ant-test123".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );
        
        assert_eq!(provider.name(), "anthropic");
        assert_eq!(provider.model(), "claude-3-5-sonnet-20241022");
        assert!(provider.is_available());
    }
    
    #[test]
    fn test_invalid_api_key() {
        let provider = AnthropicProvider::new(
            "invalid-key".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );
        
        assert!(!provider.is_available());
    }
    
    #[test]
    fn test_api_key_validation() {
        // Valid key
        let provider1 = AnthropicProvider::new(
            "sk-ant-abc123".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );
        assert!(provider1.is_api_key_valid());
        
        // Invalid keys
        let provider2 = AnthropicProvider::new("".to_string(), "claude-3-5-sonnet-20241022".to_string());
        assert!(!provider2.is_api_key_valid());
        
        let provider3 = AnthropicProvider::new(
            "${ANTHROPIC_API_KEY}".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );
        assert!(!provider3.is_api_key_valid());
        
        let provider4 = AnthropicProvider::new(
            "sk-wrong-prefix".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );
        assert!(!provider4.is_api_key_valid());
    }
    
    #[tokio::test]
    async fn test_list_models() {
        let provider = AnthropicProvider::new(
            "sk-ant-test".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );
        
        let models = provider.list_models().await.unwrap();
        assert!(!models.is_empty());
        assert!(models.iter().any(|m| m.id.contains("claude-3-5-sonnet")));
        assert!(models.iter().any(|m| m.id.contains("claude-3-opus")));
        assert!(models.iter().any(|m| m.id.contains("claude-3-haiku")));
    }
    
    #[test]
    fn test_cost_estimation() {
        let provider_sonnet = AnthropicProvider::new(
            "sk-ant-test".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );
        
        let cost = provider_sonnet.estimate_cost("Test prompt");
        assert!(cost.is_some());
        assert!(cost.unwrap() > 0.0);
        
        let provider_haiku = AnthropicProvider::new(
            "sk-ant-test".to_string(),
            "claude-3-haiku-20240307".to_string(),
        );
        
        let cost_haiku = provider_haiku.estimate_cost("Test prompt");
        assert!(cost_haiku.is_some());
        
        // Haiku should be cheaper than Sonnet
        assert!(cost_haiku.unwrap() < cost.unwrap());
    }
    
    #[test]
    fn test_cost_calculation() {
        let provider = AnthropicProvider::new(
            "sk-ant-test".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );
        
        // Test with known token counts
        let cost = provider.calculate_cost(1000, 500);
        assert!(cost.is_some());
        
        // Claude 3.5 Sonnet: $3 per 1M input, $15 per 1M output
        // 1000 input tokens = $0.003
        // 500 output tokens = $0.0075
        // Total should be $0.0105
        let expected = 0.0105;
        let actual = cost.unwrap();
        assert!((actual - expected).abs() < 0.0001, "Expected {}, got {}", expected, actual);
    }
    
    #[test]
    fn test_opus_more_expensive_than_sonnet() {
        let provider_sonnet = AnthropicProvider::new(
            "sk-ant-test".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );
        
        let provider_opus = AnthropicProvider::new(
            "sk-ant-test".to_string(),
            "claude-3-opus-20240229".to_string(),
        );
        
        let cost_sonnet = provider_sonnet.calculate_cost(1000, 500).unwrap();
        let cost_opus = provider_opus.calculate_cost(1000, 500).unwrap();
        
        // Opus should be 5x more expensive
        assert!(cost_opus > cost_sonnet);
        assert!((cost_opus / cost_sonnet - 5.0).abs() < 0.1);
    }
}
