// CERT-X-GEN: Advanced Multi-Language Security Scanning Engine
// Copyright (c) 2024 CERT-X-GEN Core Team

//! # CERT-X-GEN Library
//!
//! A next-generation security scanning engine supporting multiple programming languages
//! for template creation with unprecedented flexibility and power in security testing.

#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_qualifications,
    missing_debug_implementations
)]
#![forbid(unsafe_code)]

// Core modules
pub mod ai;
pub mod banner;
pub mod config;
pub mod core;
pub mod csrf;
pub mod engine;
pub mod error;
pub mod executor;
pub mod flows;
pub mod matcher;
pub mod metrics;
pub mod network;
pub mod output;
pub mod plugin;
pub mod progress;
pub mod sandbox;
pub mod scheduler;
pub mod search;
pub mod session;
pub mod template;
pub mod types;
pub mod utils;

// Re-exports for convenience
pub use crate::ai::{
    AIConfig, AIManager, GenerationOptions, LLMProvider, ModelInfo, OllamaProvider, ResponseParser,
    TemplateValidator,
};
pub use crate::config::Config;
pub use crate::core::{CertXGen, ScanJob};
pub use crate::error::{Error, Result};
pub use crate::template::{Template, TemplateEngine};
pub use crate::types::{Finding, Severity, Target, TemplateMetadata};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prelude module for common imports
pub mod prelude {
    pub use crate::config::Config;
    pub use crate::core::{CertXGen, ScanJob};
    pub use crate::error::{Error, Result};
    pub use crate::matcher::{Matcher, MatcherType};
    pub use crate::template::{Template, TemplateEngine};
    pub use crate::types::{
        Context, Evidence, Finding, Protocol, Severity, Target, TemplateLanguage, TemplateMetadata,
    };
    pub use async_trait::async_trait;
}
