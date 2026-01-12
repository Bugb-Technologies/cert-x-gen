//! Ollama LLM Provider Implementation
//!
//! Ollama is a local LLM provider that runs models on your own hardware.
//! No API key required, completely free, and works offline.
//!
//! # Features
//!
//! - Local execution (no data leaves your machine)
//! - No API costs
//! - Multiple model support (CodeLlama, Mistral, Llama2, etc.)
//! - Streaming support (optional)
//! - Health checking
//!
//! # Setup
//!
//! 1. Install Ollama: https://ollama.ai/
//! 2. Download a model: `ollama pull codellama:13b`
//! 3. Start the server: `ollama serve`
//!
//! # Example
//!
//! ```no_run
//! use cert_x_gen::ai::providers::ollama::OllamaProvider;
//! use cert_x_gen::ai::providers::{LLMProvider, GenerationOptions};
//!
//! async fn example() -> anyhow::Result<()> {
//!     let provider = OllamaProvider::default();
//!     
//!     if !provider.is_available() {
//!         eprintln!("Ollama is not running. Start it with: ollama serve");
//!         return Ok(());
//!     }
//!     
//!     let code = provider.generate(
//!         "Write a Python function to check if a port is open",
//!         GenerationOptions::default(),
//!     ).await?;
//!     
//!     println!("Generated:\n{}", code);
//!     Ok(())
//! }
//! ```

use super::{AuthStatus, ConnectionStatus, GenerationOptions, LLMProvider, ModelInfo, ProviderHealthStatus};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Ollama provider for local LLM execution
///
/// Ollama runs large language models locally on your machine, providing:
/// - Complete privacy (no data sent to cloud)
/// - No API costs
/// - Offline capability
/// - Multiple model support
///
/// Default configuration:
/// - Endpoint: http://localhost:11434
/// - Model: codellama:13b (optimized for code generation)
#[derive(Debug, Clone)]
pub struct OllamaProvider {
    /// Ollama API endpoint
    endpoint: String,
    
    /// Model name to use (e.g., "codellama:13b", "mistral:7b")
    model: String,
    
    /// HTTP client for API requests
    client: Client,
}

impl OllamaProvider {
    /// Create a new Ollama provider with custom endpoint and model
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Ollama API endpoint (e.g., "http://localhost:11434")
    /// * `model` - Model name (e.g., "codellama:13b", "mistral:7b")
    ///
    /// # Example
    ///
    /// ```
    /// use cert_x_gen::ai::providers::ollama::OllamaProvider;
    ///
    /// let provider = OllamaProvider::new(
    ///     "http://localhost:11434".to_string(),
    ///     "codellama:13b".to_string(),
    /// );
    /// ```
    pub fn new(endpoint: String, model: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(300)) // 5 minutes for local generation
            .build()
            .expect("Failed to build HTTP client");
        
        Self {
            endpoint,
            model,
            client,
        }
    }
    
    /// Create a provider with default settings
    ///
    /// Uses:
    /// - Endpoint: http://localhost:11434
    /// - Model: codellama:13b
    ///
    /// # Example
    ///
    /// ```
    /// use cert_x_gen::ai::providers::ollama::OllamaProvider;
    ///
    /// let provider = OllamaProvider::default();
    /// ```
    pub fn default() -> Self {
        Self::new(
            "http://localhost:11434".to_string(),
            "codellama:13b".to_string(),
        )
    }
    
    /// Check if Ollama server is healthy and responding
    ///
    /// Makes a GET request to /api/tags to verify the server is running.
    #[allow(dead_code)]
    async fn check_health(&self) -> Result<bool> {
        let response = self.client
            .get(format!("{}/api/tags", self.endpoint))
            .timeout(Duration::from_secs(5)) // Quick health check
            .send()
            .await
            .context("Failed to connect to Ollama server")?;
        
        Ok(response.status().is_success())
    }
    
    /// Get the current model name
    pub fn model(&self) -> &str {
        &self.model
    }
    
    /// Get the endpoint URL
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[async_trait]
impl LLMProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }
    
    fn is_available(&self) -> bool {
        // For availability check, we need to handle being called from both
        // sync and async contexts. We'll spawn a blocking thread to avoid
        // "cannot start runtime from within runtime" errors.
        
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        
        // Run the check in a separate thread to avoid runtime conflicts
        std::thread::spawn(move || {
            // Create a new runtime just for this check
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(_) => return false,
            };
            
            rt.block_on(async {
                let result = client
                    .get(format!("{}/api/tags", endpoint))
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await;
                
                match result {
                    Ok(response) => response.status().is_success(),
                    Err(_) => false,
                }
            })
        })
        .join()
        .unwrap_or(false)
    }
    
    async fn generate(
        &self,
        prompt: &str,
        options: GenerationOptions,
    ) -> Result<String> {
        info!("Generating with Ollama model: {}", self.model);
        debug!("Prompt length: {} chars", prompt.len());
        
        // Request structure for Ollama /api/generate endpoint
        #[derive(Serialize)]
        struct GenerateRequest {
            model: String,
            prompt: String,
            stream: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            options: Option<GenerateRequestOptions>,
        }
        
        #[derive(Serialize)]
        struct GenerateRequestOptions {
            #[serde(skip_serializing_if = "Option::is_none")]
            num_predict: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            temperature: Option<f32>,
        }
        
        // Response structure for non-streaming
        #[derive(Deserialize)]
        struct GenerateResponse {
            #[serde(default)]
            response: String,
            #[serde(default)]
            done: bool,
        }
        
        let request_options = if options.max_tokens.is_some() || options.temperature.is_some() {
            Some(GenerateRequestOptions {
                num_predict: options.max_tokens,
                temperature: options.temperature,
            })
        } else {
            None
        };
        
        let request = GenerateRequest {
            model: self.model.clone(),
            prompt: prompt.to_string(),
            stream: false,
            options: request_options,
        };
        
        let timeout = options.timeout.unwrap_or(Duration::from_secs(300));
        
        debug!("Sending request to Ollama: {}/api/generate", self.endpoint);
        
        let response = self.client
            .post(format!("{}/api/generate", self.endpoint))
            .json(&request)
            .timeout(timeout)
            .send()
            .await
            .context("Failed to connect to Ollama. Is it running? Try: ollama serve")?;
        
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Ollama returned error {}: {}. Check if model '{}' is installed with: ollama list",
                status,
                error_text,
                self.model
            );
        }
        
        let response_data: GenerateResponse = response
            .json()
            .await
            .context("Failed to parse Ollama response")?;
        
        if !response_data.done {
            warn!("Ollama response not marked as done, may be incomplete");
        }
        
        info!("Generation completed, response length: {} chars", response_data.response.len());
        
        Ok(response_data.response)
    }
    
    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        debug!("Fetching model list from Ollama");
        
        // Response structure for /api/tags endpoint
        #[derive(Deserialize)]
        struct TagsResponse {
            models: Vec<OllamaModel>,
        }
        
        #[derive(Deserialize)]
        struct OllamaModel {
            name: String,
            #[serde(default)]
            size: u64,
            #[serde(default)]
            #[allow(dead_code)]
            details: ModelDetails,
        }
        
        #[derive(Deserialize, Default)]
        struct ModelDetails {
            #[serde(default)]
            #[allow(dead_code)]
            parameter_size: String,
            #[serde(default)]
            #[allow(dead_code)]
            quantization_level: String,
        }
        
        let response: TagsResponse = self.client
            .get(format!("{}/api/tags", self.endpoint))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .context("Failed to connect to Ollama")?
            .json()
            .await
            .context("Failed to parse Ollama model list")?;
        
        let models: Vec<ModelInfo> = response.models
            .into_iter()
            .map(|m| {
                let mut model_info = ModelInfo::new(
                    m.name.clone(),
                    m.name.clone(),
                    "ollama".to_string(),
                );
                
                if m.size > 0 {
                    model_info.size = Some(m.size);
                }
                
                // Add capabilities based on model name
                if m.name.contains("code") {
                    model_info = model_info.with_capability("code-generation");
                }
                if m.name.contains("instruct") || m.name.contains("chat") {
                    model_info = model_info.with_capability("chat");
                }
                
                // Try to extract context window from details
                // Most Ollama models have 2048-4096 token windows
                model_info = model_info.with_context_window(4096);
                
                model_info
            })
            .collect();
        
        info!("Found {} Ollama models", models.len());
        
        Ok(models)
    }
    
    fn estimate_cost(&self, _prompt: &str) -> Option<f64> {
        // Ollama is free (local execution)
        None
    }
    
    async fn health_check(&self) -> Result<ProviderHealthStatus> {
        use std::time::Instant;
        
        let mut status = ProviderHealthStatus::new(self.name());
        status.authentication = AuthStatus::NotRequired;
        status.add_metadata("endpoint", &self.endpoint);
        status.add_metadata("model", &self.model);
        status.add_metadata("type", "local");
        
        // Test connection with timing
        let start = Instant::now();
        match self.client
            .get(format!("{}/api/tags", self.endpoint))
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let elapsed = start.elapsed();
                status.connection = ConnectionStatus::Connected;
                status.response_time_ms = Some(elapsed.as_millis() as u64);
                status.add_message(format!("Connected to Ollama at {}", self.endpoint));
                
                // Try to list models
                match self.list_models().await {
                    Ok(models) => {
                        status.models_available = Some(models.len());
                        // Take up to 5 models as sample
                        status.models = models.into_iter().take(5).collect();
                        
                        if status.models_available == Some(0) {
                            status.add_message("⚠ No models downloaded. Run: ollama pull codellama:13b");
                        }
                    }
                    Err(e) => {
                        status.add_message(format!("Could not list models: {}", e));
                    }
                }
            }
            Ok(response) => {
                status.connection = ConnectionStatus::Failed;
                status.add_message(format!("Ollama responded with error: HTTP {}", response.status()));
            }
            Err(e) => {
                status.connection = ConnectionStatus::Failed;
                status.add_message(format!("Cannot connect to Ollama: {}", e));
                status.add_message("Hint: Make sure Ollama is running (ollama serve)");
                status.add_message(format!("Hint: Check if {} is the correct endpoint", self.endpoint));
            }
        }
        
        status.update_health();
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_provider_creation() {
        let provider = OllamaProvider::default();
        assert_eq!(provider.name(), "ollama");
        assert_eq!(provider.model(), "codellama:13b");
        assert_eq!(provider.endpoint(), "http://localhost:11434");
    }
    
    #[test]
    fn test_custom_provider() {
        let provider = OllamaProvider::new(
            "http://custom:8080".to_string(),
            "mistral:7b".to_string(),
        );
        assert_eq!(provider.model(), "mistral:7b");
        assert_eq!(provider.endpoint(), "http://custom:8080");
    }
    
    #[test]
    fn test_cost_estimation() {
        let provider = OllamaProvider::default();
        assert_eq!(provider.estimate_cost("test prompt"), None);
    }
    
    #[tokio::test]
    async fn test_availability_check() {
        let provider = OllamaProvider::default();
        
        // This will fail if Ollama is not running, which is expected
        // We're just testing that the method doesn't panic
        let _ = provider.is_available();
    }
    
    #[tokio::test]
    #[ignore] // Only run with --ignored flag when Ollama is running
    async fn test_real_generation() {
        let provider = OllamaProvider::default();
        
        if !provider.is_available() {
            eprintln!("Skipping test: Ollama not available");
            return;
        }
        
        let options = GenerationOptions {
            max_tokens: Some(100),
            temperature: Some(0.7),
            timeout: Some(Duration::from_secs(60)),
        };
        
        let result = provider.generate(
            "Write a one-line Python comment saying hello",
            options,
        ).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.is_empty());
        println!("Generated: {}", response);
    }
    
    #[tokio::test]
    #[ignore] // Only run with --ignored flag when Ollama is running
    async fn test_real_model_listing() {
        let provider = OllamaProvider::default();
        
        if !provider.is_available() {
            eprintln!("Skipping test: Ollama not available");
            return;
        }
        
        let result = provider.list_models().await;
        assert!(result.is_ok());
        
        let models = result.unwrap();
        assert!(!models.is_empty());
        
        println!("Available models:");
        for model in models {
            println!("  - {} ({})", model.name, model.size_human_readable());
        }
    }
}
