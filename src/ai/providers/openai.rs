//! OpenAI LLM Provider Implementation
//!
//! OpenAI provides industry-leading language models including GPT-4 and GPT-3.5-turbo.
//! Requires API key from https://platform.openai.com/api-keys
//!
//! # Features
//!
//! - GPT-4 Turbo: Most capable model with 128K context
//! - GPT-4: High-quality reasoning and code generation
//! - GPT-3.5-turbo: Fast and cost-effective
//! - Function calling support
//! - JSON mode support
//!
//! # Setup
//!
//! 1. Get API key from https://platform.openai.com/api-keys
//! 2. Set environment variable: export OPENAI_API_KEY="sk-..."
//! 3. Use with cert-x-gen: --provider openai
//!
//! # Pricing (as of 2025)
//!
//! GPT-4 Turbo:
//! - Input: $10.00 / 1M tokens
//! - Output: $30.00 / 1M tokens
//!
//! GPT-4:
//! - Input: $30.00 / 1M tokens
//! - Output: $60.00 / 1M tokens
//!
//! GPT-3.5-turbo:
//! - Input: $0.50 / 1M tokens
//! - Output: $1.50 / 1M tokens

use super::{
    AuthStatus, ConnectionStatus, GenerationOptions, LLMProvider, ModelInfo, ProviderHealthStatus,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

/// OpenAI provider for cloud-based LLM execution
#[derive(Debug, Clone)]
pub struct OpenAIProvider {
    endpoint: String,
    api_key: String,
    model: String,
    client: Client,
}

impl OpenAIProvider {
    /// Create a new OpenAI provider
    ///
    /// # Arguments
    ///
    /// * `api_key` - OpenAI API key (starts with "sk-")
    /// * `model` - Model identifier (e.g., "gpt-4", "gpt-3.5-turbo")
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cert_x_gen::ai::providers::openai::OpenAIProvider;
    ///
    /// let provider = OpenAIProvider::new(
    ///     "sk-...".to_string(),
    ///     "gpt-4".to_string()
    /// );
    /// ```
    pub fn new(api_key: String, model: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            endpoint: "https://api.openai.com/v1".to_string(),
            api_key,
            model,
            client,
        }
    }

    /// Get the current model name
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Check if API key appears valid (starts with sk-)
    fn is_api_key_valid(&self) -> bool {
        !self.api_key.is_empty()
            && !self.api_key.starts_with("${")
            && (self.api_key.starts_with("sk-") || self.api_key.starts_with("sk-proj-"))
    }
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    fn name(&self) -> &str {
        "openai"
    }

    fn is_available(&self) -> bool {
        self.is_api_key_valid()
    }

    async fn generate(&self, prompt: &str, options: GenerationOptions) -> Result<String> {
        info!("Generating with OpenAI model: {}", self.model);
        debug!("Prompt length: {} chars", prompt.len());

        if !self.is_api_key_valid() {
            anyhow::bail!(
                "Invalid OpenAI API key. Get your key from: https://platform.openai.com/api-keys"
            );
        }

        #[derive(Serialize)]
        struct ChatRequest {
            model: String,
            messages: Vec<Message>,
            #[serde(skip_serializing_if = "Option::is_none")]
            max_tokens: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            temperature: Option<f32>,
        }

        #[derive(Serialize)]
        struct Message {
            role: String,
            content: String,
        }

        #[derive(Deserialize)]
        struct ChatResponse {
            choices: Vec<Choice>,
            #[serde(default)]
            usage: Option<Usage>,
        }

        #[derive(Deserialize)]
        struct Choice {
            message: ResponseMessage,
            finish_reason: Option<String>,
        }

        #[derive(Deserialize)]
        struct ResponseMessage {
            content: String,
        }

        #[derive(Deserialize)]
        struct Usage {
            prompt_tokens: u32,
            completion_tokens: u32,
            total_tokens: u32,
        }

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            max_tokens: options.max_tokens,
            temperature: options.temperature,
        };
        let timeout = options.timeout.unwrap_or(Duration::from_secs(60));

        let response = self
            .client
            .post(format!("{}/chat/completions", self.endpoint))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .timeout(timeout)
            .send()
            .await
            .context("Failed to connect to OpenAI API. Check your internet connection.")?;

        let status = response.status();
        let headers = response.headers().clone();

        // Check for rate limiting
        if status.as_u16() == 429 {
            let retry_after = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60);

            warn!("OpenAI rate limit hit, retry after {} seconds", retry_after);
            anyhow::bail!(
                "OpenAI rate limit exceeded. Please wait {} seconds and try again.",
                retry_after
            );
        }

        // Check for authentication errors
        if status.as_u16() == 401 {
            anyhow::bail!(
                "OpenAI authentication failed. Check your API key at: https://platform.openai.com/api-keys"
            );
        }

        // Check for other errors
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("OpenAI API error {}: {}", status, error_text);
        }

        let response_data: ChatResponse = response
            .json()
            .await
            .context("Failed to parse OpenAI response")?;

        if response_data.choices.is_empty() {
            anyhow::bail!("OpenAI returned empty response");
        }

        let choice = &response_data.choices[0];
        let content = &choice.message.content;

        // Log token usage if available
        if let Some(usage) = response_data.usage {
            info!(
                "Token usage - Input: {}, Output: {}, Total: {}",
                usage.prompt_tokens, usage.completion_tokens, usage.total_tokens
            );

            // Calculate actual cost
            if let Some(cost) = self.calculate_cost(usage.prompt_tokens, usage.completion_tokens) {
                info!("Estimated cost: ${:.4}", cost);
            }
        }

        // Check finish reason
        if let Some(reason) = &choice.finish_reason {
            if reason == "length" {
                warn!("Response was truncated due to max_tokens limit");
            }
        }

        info!("Generation completed, {} chars", content.len());

        Ok(content.clone())
    }

    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        Ok(vec![
            // GPT-4 Turbo - Most capable, 128K context
            ModelInfo::new(
                "gpt-4-turbo-preview".to_string(),
                "GPT-4 Turbo (Preview)".to_string(),
                "openai".to_string(),
            )
            .with_context_window(128000)
            .with_capability("code-generation")
            .with_capability("reasoning")
            .with_capability("vision"),
            // GPT-4 - High quality
            ModelInfo::new(
                "gpt-4".to_string(),
                "GPT-4".to_string(),
                "openai".to_string(),
            )
            .with_context_window(8192)
            .with_capability("code-generation")
            .with_capability("reasoning"),
            // GPT-4 32K
            ModelInfo::new(
                "gpt-4-32k".to_string(),
                "GPT-4 32K".to_string(),
                "openai".to_string(),
            )
            .with_context_window(32768)
            .with_capability("code-generation")
            .with_capability("reasoning"),
            // GPT-3.5 Turbo - Fast and cost-effective
            ModelInfo::new(
                "gpt-3.5-turbo".to_string(),
                "GPT-3.5 Turbo".to_string(),
                "openai".to_string(),
            )
            .with_context_window(16385)
            .with_capability("code-generation")
            .with_capability("chat"),
            // GPT-3.5 Turbo 16K
            ModelInfo::new(
                "gpt-3.5-turbo-16k".to_string(),
                "GPT-3.5 Turbo 16K".to_string(),
                "openai".to_string(),
            )
            .with_context_window(16385)
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

        // Check API key configuration
        if !self.is_api_key_valid() {
            status.connection = ConnectionStatus::Failed;
            status.authentication = AuthStatus::NotConfigured;
            status.add_message("API key not configured or invalid format");
            status.add_message("Hint: Set OPENAI_API_KEY environment variable");
            status.add_message("Hint: API keys should start with 'sk-'");
            status.update_health();
            return Ok(status);
        }

        status.authentication = AuthStatus::Untested;

        // Test connection and authentication by listing models
        let start = Instant::now();
        match self
            .client
            .get(format!("{}/models", self.endpoint))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let elapsed = start.elapsed();
                status.connection = ConnectionStatus::Connected;
                status.authentication = AuthStatus::Authenticated;
                status.response_time_ms = Some(elapsed.as_millis() as u64);
                status.add_message("Successfully connected to OpenAI API");

                // Try to list models
                match self.list_models().await {
                    Ok(models) => {
                        status.models_available = Some(models.len());
                        // Take up to 5 models as sample
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
                status.add_message("Hint: Check your OPENAI_API_KEY");
            }
            Ok(response) if response.status() == 429 => {
                status.connection = ConnectionStatus::Connected;
                status.authentication = AuthStatus::Authenticated;
                status.add_message("Rate limit exceeded");
                status.add_message("Hint: Wait a moment before trying again");
            }
            Ok(response) => {
                status.connection = ConnectionStatus::Failed;
                status.add_message(format!("OpenAI API error: HTTP {}", response.status()));
            }
            Err(e) if e.is_timeout() => {
                status.connection = ConnectionStatus::Failed;
                status.add_message("Connection timeout");
                status.add_message("Hint: Check your internet connection");
            }
            Err(e) => {
                status.connection = ConnectionStatus::Failed;
                status.add_message(format!("Cannot connect to OpenAI: {}", e));
                status.add_message("Hint: Check your internet connection");
            }
        }

        status.update_health();
        Ok(status)
    }
}

impl OpenAIProvider {
    /// Calculate actual cost based on token usage
    ///
    /// Pricing as of 2025:
    /// - GPT-4 Turbo: $10/$30 per 1M tokens (input/output)
    /// - GPT-4: $30/$60 per 1M tokens
    /// - GPT-3.5-turbo: $0.50/$1.50 per 1M tokens
    fn calculate_cost(&self, input_tokens: u32, output_tokens: u32) -> Option<f64> {
        let (input_price, output_price) = match self.model.as_str() {
            // GPT-4 Turbo
            "gpt-4-turbo" | "gpt-4-turbo-preview" | "gpt-4-1106-preview" | "gpt-4-0125-preview" => {
                (10.0, 30.0)
            }
            // GPT-4
            "gpt-4" | "gpt-4-0613" => (30.0, 60.0),
            // GPT-4 32K
            "gpt-4-32k" | "gpt-4-32k-0613" => (60.0, 120.0),
            // GPT-3.5 Turbo
            "gpt-3.5-turbo" | "gpt-3.5-turbo-16k" | "gpt-3.5-turbo-0125" | "gpt-3.5-turbo-1106" => {
                (0.50, 1.50)
            }
            // Unknown model, use GPT-4 pricing as safe estimate
            _ => (30.0, 60.0),
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
    fn test_openai_provider_creation() {
        let provider = OpenAIProvider::new("sk-test123".to_string(), "gpt-4".to_string());

        assert_eq!(provider.name(), "openai");
        assert_eq!(provider.model(), "gpt-4");
        assert!(provider.is_available());
    }

    #[test]
    fn test_invalid_api_key() {
        let provider = OpenAIProvider::new("invalid-key".to_string(), "gpt-4".to_string());

        assert!(!provider.is_available());
    }

    #[test]
    fn test_api_key_validation() {
        // Valid keys
        let provider1 = OpenAIProvider::new("sk-abc123".to_string(), "gpt-4".to_string());
        assert!(provider1.is_api_key_valid());

        let provider2 = OpenAIProvider::new("sk-proj-xyz789".to_string(), "gpt-4".to_string());
        assert!(provider2.is_api_key_valid());

        // Invalid keys
        let provider3 = OpenAIProvider::new("".to_string(), "gpt-4".to_string());
        assert!(!provider3.is_api_key_valid());

        let provider4 = OpenAIProvider::new("${OPENAI_API_KEY}".to_string(), "gpt-4".to_string());
        assert!(!provider4.is_api_key_valid());

        let provider5 = OpenAIProvider::new("invalid".to_string(), "gpt-4".to_string());
        assert!(!provider5.is_api_key_valid());
    }

    #[tokio::test]
    async fn test_list_models() {
        let provider = OpenAIProvider::new("sk-test".to_string(), "gpt-4".to_string());

        let models = provider.list_models().await.unwrap();
        assert!(!models.is_empty());
        assert!(models.iter().any(|m| m.id == "gpt-4"));
        assert!(models.iter().any(|m| m.id == "gpt-3.5-turbo"));
    }

    #[test]
    fn test_cost_estimation() {
        let provider_gpt4 = OpenAIProvider::new("sk-test".to_string(), "gpt-4".to_string());

        let cost = provider_gpt4.estimate_cost("Test prompt");
        assert!(cost.is_some());
        assert!(cost.unwrap() > 0.0);

        let provider_gpt35 =
            OpenAIProvider::new("sk-test".to_string(), "gpt-3.5-turbo".to_string());

        let cost35 = provider_gpt35.estimate_cost("Test prompt");
        assert!(cost35.is_some());

        // GPT-3.5 should be cheaper than GPT-4
        assert!(cost35.unwrap() < cost.unwrap());
    }

    #[test]
    fn test_cost_calculation() {
        let provider = OpenAIProvider::new("sk-test".to_string(), "gpt-4".to_string());

        // Test with known token counts
        let cost = provider.calculate_cost(1000, 500);
        assert!(cost.is_some());

        // GPT-4: $30 per 1M input, $60 per 1M output
        // 1000 input tokens = $0.030
        // 500 output tokens = $0.030
        // Total should be $0.060
        let expected = 0.060;
        let actual = cost.unwrap();
        assert!(
            (actual - expected).abs() < 0.001,
            "Expected {}, got {}",
            expected,
            actual
        );
    }
}
