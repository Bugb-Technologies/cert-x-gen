//! DeepSeek LLM Provider Implementation
//!
//! DeepSeek provides powerful code-generation models via OpenAI-compatible API.
//! Requires API key from https://platform.deepseek.com/
//!
//! # Features
//!
//! - OpenAI-compatible API
//! - DeepSeek Coder models optimized for code generation
//! - Cost-effective pricing
//! - Fast inference
//!
//! # Setup
//!
//! 1. Get API key from https://platform.deepseek.com/
//! 2. Set environment variable: export DEEPSEEK_API_KEY="your-key"
//! 3. Use with cert-x-gen: --provider deepseek

use super::{AuthStatus, ConnectionStatus, GenerationOptions, LLMProvider, ModelInfo, ProviderHealthStatus};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info};

/// DeepSeek provider for cloud-based LLM execution
#[derive(Debug, Clone)]
pub struct DeepSeekProvider {
    endpoint: String,
    api_key: String,
    model: String,
    client: Client,
}

impl DeepSeekProvider {
    /// Create a new DeepSeek provider
    pub fn new(api_key: String, model: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client");
        
        Self {
            endpoint: "https://api.deepseek.com/v1".to_string(),
            api_key,
            model,
            client,
        }
    }
    
    /// Get the current model name

    pub fn model(&self) -> &str {
        &self.model
    }
}

#[async_trait]
impl LLMProvider for DeepSeekProvider {
    fn name(&self) -> &str {
        "deepseek"
    }
    
    fn is_available(&self) -> bool {
        !self.api_key.is_empty() && !self.api_key.starts_with("${")
    }
    
    async fn generate(&self, prompt: &str, options: GenerationOptions) -> Result<String> {
        info!("Generating with DeepSeek model: {}", self.model);
        debug!("Prompt length: {} chars", prompt.len());
        
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
        }
        
        #[derive(Deserialize)]
        struct Choice {
            message: ResponseMessage,
        }
        
        #[derive(Deserialize)]
        struct ResponseMessage {
            content: String,
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
        
        let response = self.client
            .post(format!("{}/chat/completions", self.endpoint))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .timeout(timeout)
            .send()
            .await
            .context("Failed to connect to DeepSeek API")?;
        
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "DeepSeek API error {}: {}. Check your API key.",
                status, error_text
            );
        }
        
        let response_data: ChatResponse = response.json().await
            .context("Failed to parse DeepSeek response")?;
        
        if response_data.choices.is_empty() {
            anyhow::bail!("DeepSeek returned empty response");
        }
        
        let content = &response_data.choices[0].message.content;
        info!("Generation completed, {} chars", content.len());
        
        Ok(content.clone())
    }
    
    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        Ok(vec![
            ModelInfo::new(
                "deepseek-coder".to_string(),
                "DeepSeek Coder".to_string(),
                "deepseek".to_string(),
            ).with_context_window(16384).with_capability("code-generation"),
            
            ModelInfo::new(
                "deepseek-chat".to_string(),
                "DeepSeek Chat".to_string(),
                "deepseek".to_string(),
            ).with_context_window(16384).with_capability("chat"),
        ])
    }
    
    fn estimate_cost(&self, prompt: &str) -> Option<f64> {
        // DeepSeek: ~$0.14 per 1M input tokens, $0.28 per 1M output
        let input_tokens = (prompt.len() / 4) as f64;
        let output_tokens = 1000.0;
        
        let input_cost = (input_tokens / 1_000_000.0) * 0.14;
        let output_cost = (output_tokens / 1_000_000.0) * 0.28;
        
        Some(input_cost + output_cost)
    }
    
    async fn health_check(&self) -> Result<ProviderHealthStatus> {
        use std::time::Instant;
        
        let mut status = ProviderHealthStatus::new(self.name());
        status.add_metadata("endpoint", &self.endpoint);
        status.add_metadata("model", &self.model);
        status.add_metadata("type", "cloud");
        
        // Check API key configuration
        if self.api_key.is_empty() || self.api_key.starts_with("${") {
            status.connection = ConnectionStatus::Failed;
            status.authentication = AuthStatus::NotConfigured;
            status.add_message("API key not configured");
            status.add_message("Hint: Set DEEPSEEK_API_KEY environment variable");
            status.update_health();
            return Ok(status);
        }
        
        status.authentication = AuthStatus::Untested;
        
        // DeepSeek is OpenAI-compatible, test by listing models
        let start = Instant::now();
        match self.client
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
                status.add_message("Successfully connected to DeepSeek API");
                
                // Try to list models
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
                status.add_message("Hint: Check your DEEPSEEK_API_KEY");
            }
            Ok(response) if response.status() == 429 => {
                status.connection = ConnectionStatus::Connected;
                status.authentication = AuthStatus::Authenticated;
                status.add_message("Rate limit exceeded");
                status.add_message("Hint: Wait a moment before trying again");
            }
            Ok(response) => {
                status.connection = ConnectionStatus::Failed;
                status.add_message(format!("DeepSeek API error: HTTP {}", response.status()));
            }
            Err(e) if e.is_timeout() => {
                status.connection = ConnectionStatus::Failed;
                status.add_message("Connection timeout");
                status.add_message("Hint: Check your internet connection");
            }
            Err(e) => {
                status.connection = ConnectionStatus::Failed;
                status.add_message(format!("Cannot connect to DeepSeek: {}", e));
                status.add_message("Hint: Check your internet connection");
            }
        }
        
        status.update_health();
        Ok(status)
    }
}
