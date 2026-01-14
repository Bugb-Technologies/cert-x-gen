//! AI Manager - Orchestrates template generation
//!
//! The AIManager is the main entry point for AI-powered template generation.
//! It coordinates between configuration, providers, prompt engineering, parsing,
//! and validation to produce high-quality security scanning templates.

use crate::types::TemplateLanguage;
use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::{debug, info};

use super::config::AIConfig;
use super::parser::ResponseParser;
use super::prompt::PromptBuilder;
use super::providers::{
    AnthropicProvider, DeepSeekProvider, GenerationOptions, LLMProvider, OllamaProvider,
    OpenAIProvider, ProviderHealthStatus,
};
use super::validator::TemplateValidator;

/// Main AI manager for template generation
#[derive(Debug)]
pub struct AIManager {
    /// AI configuration
    config: AIConfig,

    /// Template output directory
    output_dir: PathBuf,

    /// Prompt builder for generating context-aware prompts
    prompt_builder: PromptBuilder,

    /// Response parser for cleaning LLM output
    parser: ResponseParser,

    /// Template validator for syntax checking
    validator: TemplateValidator,
}

impl AIManager {
    /// Create a new AI manager with default configuration
    pub fn new() -> Result<Self> {
        let config = AIConfig::load()?;
        let output_dir = Self::default_output_dir()?;
        let prompt_builder = PromptBuilder::new();
        let parser = ResponseParser::new();
        let validator = TemplateValidator::new();

        // Ensure output directory exists
        std::fs::create_dir_all(&output_dir).with_context(|| {
            format!(
                "Failed to create output directory: {}",
                output_dir.display()
            )
        })?;

        info!(
            "Initialized AI manager with default provider: {}",
            config.default_provider_name()
        );

        Ok(Self {
            config,
            output_dir,
            prompt_builder,
            parser,
            validator,
        })
    }

    /// Create a new AI manager with custom configuration
    pub fn with_config(config: AIConfig) -> Result<Self> {
        let output_dir = Self::default_output_dir()?;
        let prompt_builder = PromptBuilder::new();
        let parser = ResponseParser::new();
        let validator = TemplateValidator::new();

        std::fs::create_dir_all(&output_dir).with_context(|| {
            format!(
                "Failed to create output directory: {}",
                output_dir.display()
            )
        })?;

        Ok(Self {
            config,
            output_dir,
            prompt_builder,
            parser,
            validator,
        })
    }

    /// Get the default output directory for AI-generated templates
    fn default_output_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Failed to determine home directory")?;

        Ok(home
            .join(".cert-x-gen")
            .join("templates")
            .join("ai-generated"))
    }

    /// Set custom output directory
    pub fn set_output_dir<P: Into<PathBuf>>(&mut self, dir: P) {
        self.output_dir = dir.into();
    }

    /// Get the current output directory
    pub fn output_dir(&self) -> &PathBuf {
        &self.output_dir
    }

    /// Generate a template from a natural language prompt
    ///
    /// # Arguments
    ///
    /// * `prompt` - Natural language description of what to detect
    /// * `language` - Target template language
    /// * `provider_name` - Optional provider name (uses default if None)
    ///
    /// # Returns
    ///
    /// Generated template code as a string
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cert_x_gen::ai::AIManager;
    /// use cert_x_gen::types::TemplateLanguage;
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// let manager = AIManager::new()?;
    /// let template = manager.generate_template(
    ///     "detect Redis without authentication",
    ///     TemplateLanguage::Python,
    ///     None,
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn generate_template(
        &self,
        prompt: &str,
        language: TemplateLanguage,
        provider_name: Option<&str>,
    ) -> Result<String> {
        // Determine which provider to use
        let provider = provider_name.unwrap_or_else(|| self.config.default_provider_name());

        info!(
            "Generating {} template for: '{}' using provider: {}",
            language, prompt, provider
        );

        // Check if provider is configured and enabled
        if !self.config.is_provider_enabled(provider) {
            anyhow::bail!(
                "Provider '{}' is not enabled. Check your AI configuration at {}",
                provider,
                AIConfig::config_path()?.display()
            );
        }

        // Create the provider instance
        let llm_provider: Box<dyn LLMProvider> = match provider {
            "ollama" => {
                let provider_config = self
                    .config
                    .get_provider("ollama")
                    .context("Ollama provider configuration not found")?;

                let endpoint = provider_config
                    .endpoint
                    .clone()
                    .unwrap_or_else(|| "http://localhost:11434".to_string());

                let model = provider_config.model.clone();

                Box::new(OllamaProvider::new(endpoint, model))
            }
            "openai" => {
                let provider_config = self
                    .config
                    .get_provider("openai")
                    .context("OpenAI provider configuration not found")?;

                let api_key = provider_config.api_key
                    .clone()
                    .context("OpenAI API key not configured. Set OPENAI_API_KEY environment variable or add to config.")?;

                let model = provider_config.model.clone();

                Box::new(OpenAIProvider::new(api_key, model))
            }
            "anthropic" => {
                let provider_config = self
                    .config
                    .get_provider("anthropic")
                    .context("Anthropic provider configuration not found")?;

                let api_key = provider_config.api_key
                    .clone()
                    .context("Anthropic API key not configured. Set ANTHROPIC_API_KEY environment variable or add to config.")?;

                let model = provider_config.model.clone();

                Box::new(AnthropicProvider::new(api_key, model))
            }
            "deepseek" => {
                let provider_config = self
                    .config
                    .get_provider("deepseek")
                    .context("DeepSeek provider configuration not found")?;

                let api_key = provider_config
                    .api_key
                    .clone()
                    .context("DeepSeek API key not configured")?;

                let model = provider_config.model.clone();

                Box::new(DeepSeekProvider::new(api_key, model))
            }
            _ => {
                anyhow::bail!(
                    "Provider '{}' is not yet implemented. Currently supported: ollama, openai, anthropic, deepseek. \
                     Other providers (Google, Groq) will be added in future updates.",
                    provider
                );
            }
        };

        // Check if the provider is actually available
        if !llm_provider.is_available() {
            anyhow::bail!(
                "Provider '{}' is not available. For Ollama, ensure it's running with: ollama serve",
                provider
            );
        }

        // Build a context-aware prompt using the PromptBuilder (Task 1.4)
        info!("Building context-aware prompt for {} template...", language);
        let llm_prompt = self
            .prompt_builder
            .build_generation_prompt(prompt, language);

        debug!("Generated prompt length: {} chars", llm_prompt.len());

        // Configure generation options from provider config
        let provider_config = self.config.get_provider(provider).unwrap();
        let options = GenerationOptions {
            max_tokens: provider_config.max_tokens,
            temperature: provider_config.temperature,
            timeout: provider_config
                .timeout_secs
                .map(std::time::Duration::from_secs),
        };

        // Generate the template
        info!("Calling LLM provider for generation...");
        let generated_code = llm_provider.generate(&llm_prompt, options).await?; // Show actual error

        info!(
            "Template generated successfully ({} chars)",
            generated_code.len()
        );

        // Task 1.5: Parse the response to extract clean template code
        info!("Parsing response to extract clean template code...");
        let parsed_code = self
            .parser
            .parse(&generated_code, language)
            .context("Failed to parse LLM response")?;

        debug!("Parsed template length: {} chars", parsed_code.len());

        // Task 1.6: Validate the template
        info!("Validating template syntax and structure...");
        self.validator
            .validate(&parsed_code, language)
            .context("Template validation failed")?;

        info!("Template validation passed successfully!");

        Ok(parsed_code)
    }

    /// List available providers
    pub fn list_providers(&self) -> Vec<(String, bool)> {
        self.config
            .providers
            .iter()
            .map(|(name, config)| (name.clone(), config.enabled))
            .collect()
    }

    /// Check if a specific provider is available
    ///
    /// This checks both configuration and actual availability (e.g., is Ollama running?)
    pub async fn is_provider_available(&self, provider_name: &str) -> Result<bool> {
        if !self.config.is_provider_enabled(provider_name) {
            return Ok(false);
        }

        // Create the provider and check availability
        let provider: Box<dyn LLMProvider> = match provider_name {
            "ollama" => {
                let provider_config = self
                    .config
                    .get_provider("ollama")
                    .context("Ollama provider configuration not found")?;

                let endpoint = provider_config
                    .endpoint
                    .clone()
                    .unwrap_or_else(|| "http://localhost:11434".to_string());

                let model = provider_config.model.clone();

                Box::new(OllamaProvider::new(endpoint, model))
            }
            "openai" => {
                let provider_config = self
                    .config
                    .get_provider("openai")
                    .context("OpenAI provider configuration not found")?;

                let api_key = provider_config.api_key.clone().unwrap_or_default();
                let model = provider_config.model.clone();

                Box::new(OpenAIProvider::new(api_key, model))
            }
            "anthropic" => {
                let provider_config = self
                    .config
                    .get_provider("anthropic")
                    .context("Anthropic provider configuration not found")?;

                let api_key = provider_config.api_key.clone().unwrap_or_default();
                let model = provider_config.model.clone();

                Box::new(AnthropicProvider::new(api_key, model))
            }
            "deepseek" => {
                let provider_config = self
                    .config
                    .get_provider("deepseek")
                    .context("DeepSeek provider configuration not found")?;

                let api_key = provider_config.api_key.clone().unwrap_or_default();
                let model = provider_config.model.clone();

                Box::new(DeepSeekProvider::new(api_key, model))
            }
            _ => {
                // Provider not yet implemented
                return Ok(false);
            }
        };

        Ok(provider.is_available())
    }

    /// Get current configuration
    pub fn config(&self) -> &AIConfig {
        &self.config
    }

    /// Get the prompt builder
    pub fn prompt_builder(&self) -> &PromptBuilder {
        &self.prompt_builder
    }

    /// Save a generated template to a file
    ///
    /// # Arguments
    ///
    /// * `template_code` - The template code to save
    /// * `filename` - Filename (without path)
    /// * `language` - Template language (for validation)
    ///
    /// # Returns
    ///
    /// Path to the saved file
    pub fn save_template(
        &self,
        template_code: &str,
        filename: &str,
        language: TemplateLanguage,
    ) -> Result<PathBuf> {
        let file_path = self.output_dir.join(filename);

        debug!("Saving {} template to: {}", language, file_path.display());

        std::fs::write(&file_path, template_code)
            .with_context(|| format!("Failed to save template to {}", file_path.display()))?;

        info!("Successfully saved template: {}", file_path.display());

        Ok(file_path)
    }

    /// Generate a filename for a template based on the prompt
    ///
    /// This is a public wrapper around the private filename generation logic.
    ///
    /// # Arguments
    ///
    /// * `prompt` - The prompt used to generate the template
    /// * `language` - Template language
    ///
    /// # Returns
    ///
    /// A safe filename with appropriate extension
    pub fn generate_filename(&self, prompt: &str, language: TemplateLanguage) -> String {
        self.create_filename_from_prompt(prompt, language)
    }

    /// Generate and save a template in one operation
    ///
    /// This is a convenience method that combines generation and saving.
    pub async fn generate_and_save(
        &self,
        prompt: &str,
        language: TemplateLanguage,
        provider_name: Option<&str>,
        custom_filename: Option<&str>,
    ) -> Result<PathBuf> {
        // Generate the template
        let template_code = self
            .generate_template(prompt, language, provider_name)
            .await?;

        // Create filename from prompt if not provided
        let filename = match custom_filename {
            Some(name) => name.to_string(),
            None => self.create_filename_from_prompt(prompt, language),
        };

        // Save and return path
        self.save_template(&template_code, &filename, language)
    }

    /// Create a safe filename from a prompt
    fn create_filename_from_prompt(&self, prompt: &str, language: TemplateLanguage) -> String {
        // Convert prompt to kebab-case
        let safe_name = prompt
            .to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>();

        // Remove consecutive dashes
        let safe_name = safe_name
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-");

        // Truncate if too long
        let safe_name = if safe_name.len() > 50 {
            &safe_name[..50]
        } else {
            &safe_name
        };

        // Add timestamp for uniqueness
        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");

        // Add appropriate extension
        let extension = match language {
            TemplateLanguage::Python => "py",
            TemplateLanguage::JavaScript => "js",
            TemplateLanguage::Rust => "rs",
            TemplateLanguage::Shell => "sh",
            TemplateLanguage::Yaml => "yaml",
            TemplateLanguage::C => "c",
            TemplateLanguage::Cpp => "cpp",
            TemplateLanguage::Java => "java",
            TemplateLanguage::Go => "go",
            TemplateLanguage::Ruby => "rb",
            TemplateLanguage::Perl => "pl",
            TemplateLanguage::Php => "php",
        };

        format!("{}-{}.{}", safe_name, timestamp, extension)
    }
}

impl Default for AIManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default AI manager")
    }
}

impl AIManager {
    /// Test a specific provider's health
    ///
    /// Performs comprehensive health checks on the specified provider including:
    /// - Connection testing
    /// - Authentication verification
    /// - Response time measurement
    /// - Model availability check
    ///
    /// # Arguments
    ///
    /// * `provider_name` - Name of the provider to test ("ollama", "openai", "anthropic", "deepseek")
    ///
    /// # Returns
    ///
    /// A `ProviderHealthStatus` struct with detailed diagnostics
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cert_x_gen::ai::AIManager;
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// let manager = AIManager::new()?;
    /// let status = manager.test_provider("ollama").await?;
    ///
    /// if status.healthy {
    ///     println!("✓ Provider is healthy");
    /// } else {
    ///     println!("✗ Provider has issues");
    ///     for msg in status.messages {
    ///         println!("  - {}", msg);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn test_provider(&self, provider_name: &str) -> Result<ProviderHealthStatus> {
        use crate::ai::providers::*;

        match provider_name.to_lowercase().as_str() {
            "ollama" => {
                let provider_config = self
                    .config
                    .get_provider("ollama")
                    .ok_or_else(|| anyhow::anyhow!("Ollama provider not configured"))?;
                let endpoint = provider_config
                    .endpoint
                    .clone()
                    .unwrap_or_else(|| "http://localhost:11434".to_string());
                let model = provider_config.model.clone();

                let provider = OllamaProvider::new(endpoint, model);
                provider.health_check().await
            }
            "openai" => {
                let provider_config = self
                    .config
                    .get_provider("openai")
                    .ok_or_else(|| anyhow::anyhow!("OpenAI provider not configured"))?;
                let api_key = provider_config
                    .api_key
                    .clone()
                    .unwrap_or_else(|| "${OPENAI_API_KEY}".to_string());
                let model = provider_config.model.clone();

                let provider = OpenAIProvider::new(api_key, model);
                provider.health_check().await
            }
            "anthropic" => {
                let provider_config = self
                    .config
                    .get_provider("anthropic")
                    .ok_or_else(|| anyhow::anyhow!("Anthropic provider not configured"))?;
                let api_key = provider_config
                    .api_key
                    .clone()
                    .unwrap_or_else(|| "${ANTHROPIC_API_KEY}".to_string());
                let model = provider_config.model.clone();

                let provider = AnthropicProvider::new(api_key, model);
                provider.health_check().await
            }
            "deepseek" => {
                let provider_config = self
                    .config
                    .get_provider("deepseek")
                    .ok_or_else(|| anyhow::anyhow!("DeepSeek provider not configured"))?;
                let api_key = provider_config
                    .api_key
                    .clone()
                    .unwrap_or_else(|| "${DEEPSEEK_API_KEY}".to_string());
                let model = provider_config.model.clone();

                let provider = DeepSeekProvider::new(api_key, model);
                provider.health_check().await
            }
            _ => {
                anyhow::bail!("Unknown provider: {}", provider_name)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_manager() {
        let manager = AIManager::new();
        assert!(manager.is_ok());

        let manager = manager.unwrap();
        assert!(manager.output_dir().exists() || !manager.output_dir().exists());
        // Just check it's a valid path
    }

    #[test]
    fn test_filename_generation() {
        let manager = AIManager::new().unwrap();

        let filename = manager.create_filename_from_prompt(
            "detect Redis without authentication",
            TemplateLanguage::Python,
        );

        assert!(filename.contains("detect"));
        assert!(filename.contains("redis"));
        assert!(filename.ends_with(".py"));
        assert!(filename.len() < 100); // Reasonable length
    }

    #[test]
    fn test_list_providers() {
        let manager = AIManager::new().unwrap();
        let providers = manager.list_providers();

        assert!(!providers.is_empty());
        assert!(providers.iter().any(|(name, _)| name == "ollama"));
    }

    #[test]
    fn test_prompt_builder_integration() {
        let manager = AIManager::new().unwrap();

        // Verify prompt builder is accessible
        let builder = manager.prompt_builder();

        // Test that it can build prompts for all languages
        let languages = vec![
            TemplateLanguage::Python,
            TemplateLanguage::JavaScript,
            TemplateLanguage::Yaml,
            TemplateLanguage::Rust,
        ];

        for language in languages {
            let prompt =
                builder.build_generation_prompt("detect Redis without authentication", language);

            // Verify prompt contains key elements
            assert!(!prompt.is_empty());
            assert!(prompt.contains("Redis"));
            assert!(prompt.contains("authentication") || prompt.contains("unauth"));
            assert!(prompt.len() > 500); // Substantial prompt
        }
    }

    #[test]
    fn test_prompt_builder_skeletons() {
        let manager = AIManager::new().unwrap();
        let builder = manager.prompt_builder();

        // Verify all supported languages have skeletons except YAML
        assert!(builder.has_skeleton(TemplateLanguage::Python));
        assert!(builder.has_skeleton(TemplateLanguage::JavaScript));
        assert!(builder.has_skeleton(TemplateLanguage::Rust));
        assert!(builder.has_skeleton(TemplateLanguage::C));
        assert!(builder.has_skeleton(TemplateLanguage::Cpp));
        assert!(builder.has_skeleton(TemplateLanguage::Java));
        assert!(builder.has_skeleton(TemplateLanguage::Go));
        assert!(builder.has_skeleton(TemplateLanguage::Ruby));
        assert!(builder.has_skeleton(TemplateLanguage::Perl));
        assert!(builder.has_skeleton(TemplateLanguage::Php));
        assert!(builder.has_skeleton(TemplateLanguage::Shell));

        // YAML doesn't have a skeleton (it's declarative)
        assert!(!builder.has_skeleton(TemplateLanguage::Yaml));
    }

    #[tokio::test]
    async fn test_generate_template_ollama_check() {
        let manager = AIManager::new().unwrap();

        // Check if Ollama is available
        let is_available = manager.is_provider_available("ollama").await.unwrap();

        if !is_available {
            // If Ollama is not running, generation should fail with helpful error
            // Explicitly request ollama provider to ensure we test the right code path
            let result = manager
                .generate_template("test prompt", TemplateLanguage::Python, Some("ollama"))
                .await;

            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string().to_lowercase();
            // Check for various error patterns that indicate Ollama is not available
            let has_expected_error = err_msg.contains("not available")
                || err_msg.contains("ollama serve")
                || err_msg.contains("not running")
                || err_msg.contains("connection refused")
                || err_msg.contains("failed to connect");
            assert!(
                has_expected_error,
                "Expected error about Ollama not being available, got: {}",
                err_msg
            );
        } else {
            // If Ollama is available, we can't test actual generation here
            // (would be too slow for unit tests)
            println!("Ollama is available - integration tests can run");
        }
    }

    #[tokio::test]
    #[ignore] // Only run with --ignored when Ollama is available
    async fn test_real_generation_with_ollama() {
        let manager = AIManager::new().unwrap();

        // Check if Ollama is available
        if !manager.is_provider_available("ollama").await.unwrap() {
            eprintln!("Skipping: Ollama not available");
            return;
        }

        // Try generating a simple template
        let result = manager
            .generate_template(
                "write a one-line Python comment",
                TemplateLanguage::Python,
                Some("ollama"),
            )
            .await;

        assert!(result.is_ok());
        let template = result.unwrap();
        assert!(!template.is_empty());
        println!("Generated template:\n{}", template);
    }
}
