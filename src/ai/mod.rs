//! AI-powered template generation for CERT-X-GEN
//!
//! This module provides multi-provider LLM integration for generating security
//! scanning templates from natural language descriptions.
//!
//! # Architecture
//!
//! - `AIManager`: Main orchestrator for template generation
//! - `AIConfig`: Configuration management for AI providers
//! - `providers`: LLM provider implementations (Ollama, OpenAI, Anthropic, etc.)
//! - `prompt`: Prompt engineering system for template generation
//! - `parser`: Response parsing to extract clean template code
//! - `validator`: Template validation before saving
//!
//! # Example
//!
//! ```no_run
//! use cert_x_gen::ai::{AIManager, AIConfig};
//! use cert_x_gen::types::TemplateLanguage;
//!
//! async fn generate_template() -> anyhow::Result<()> {
//!     let manager = AIManager::new()?;
//!     
//!     let template = manager.generate_template(
//!         "detect Redis without authentication",
//!         TemplateLanguage::Python,
//!         None, // Use default provider
//!     ).await?;
//!     
//!     println!("Generated template:\n{}", template);
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod manager;
pub mod parser;
pub mod prompt;
pub mod providers;
pub mod validator;

pub use config::AIConfig;
pub use manager::AIManager;
pub use parser::ResponseParser;
pub use prompt::PromptBuilder;
pub use providers::{
    AuthStatus, ConnectionStatus, DeepSeekProvider, GenerationOptions, LLMProvider, ModelInfo,
    OllamaProvider, ProviderHealthStatus,
};
pub use validator::TemplateValidator;
