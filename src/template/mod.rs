//! Template system for CERT-X-GEN
//!
//! Provides multi-source template discovery, management, and execution.

// Module declarations
mod auto_update;
mod engine;
mod git;
mod manager;
mod paths;
mod repository;
mod repository_config;
mod version;

// Re-export all template engine types (backward compatibility)
pub use engine::*;

// Export new template management types
pub use auto_update::AutoUpdater;
pub use git::GitClient;
pub use manager::{TemplateManager, TemplateLocation, TemplateSource};
pub use paths::PathResolver;
pub use repository::RepositoryManager;
pub use repository_config::{RepositoryConfig, Repository};
pub use version::TemplateVersion;
