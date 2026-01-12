//! Repository configuration management for template synchronization

use crate::error::{Error, Result};
use crate::template::paths::PathResolver;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Main configuration structure for template repositories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryConfig {
    /// Configuration version
    pub version: String,

    /// Default branch to use when not specified
    pub default_branch: String,

    /// List of user-configured repositories
    pub repositories: Vec<Repository>,

    /// System-level repositories (read-only)
    #[serde(default)]
    pub system_repositories: Vec<Repository>,
}

/// Individual repository definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    /// Repository identifier (unique name)
    pub name: String,

    /// Git repository URL
    pub url: String,

    /// Branch to track
    pub branch: String,

    /// Local path where repository is cloned
    pub local_path: PathBuf,

    /// Whether this repository is enabled for syncing
    pub enabled: bool,

    /// Whether this repository is trusted (affects security scanning)
    pub trusted: bool,

    /// Timestamp of last successful update
    pub last_updated: Option<DateTime<Utc>>,

    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl RepositoryConfig {
    /// Load configuration from YAML file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::config(format!(
                "Repository config file not found: {}",
                path.display()
            )));
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("Failed to read config: {}", e)))?;

        serde_yaml::from_str(&content)
            .map_err(|e| Error::config(format!("Failed to parse config: {}", e)))
    }

    /// Save configuration to YAML file
    pub fn save(&self, path: &Path) -> Result<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::config(format!("Failed to create config directory: {}", e)))?;
        }

        let content = serde_yaml::to_string(self)
            .map_err(|e| Error::config(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)
            .map_err(|e| Error::config(format!("Failed to write config: {}", e)))?;

        Ok(())
    }

    /// Create default configuration
    pub fn default_config() -> Self {
        Self {
            version: "1.0".to_string(),
            default_branch: "main".to_string(),
            repositories: vec![Repository {
                name: "official".to_string(),
                url: "https://github.com/BugB-Tech/cert-x-gen-templates.git".to_string(),
                branch: "main".to_string(),
                local_path: PathResolver::user_template_dir().join("official"),
                enabled: true,
                trusted: true,
                last_updated: None,
                description: Some("Official CERT-X-GEN templates".to_string()),
            }],
            system_repositories: Vec::new(),
        }
    }

    /// Get all enabled repositories
    pub fn enabled_repositories(&self) -> Vec<&Repository> {
        self.repositories.iter().filter(|r| r.enabled).collect()
    }

    /// Get repository by name
    pub fn get_repository(&self, name: &str) -> Option<&Repository> {
        self.repositories.iter().find(|r| r.name == name)
    }

    /// Get mutable repository by name
    pub fn get_repository_mut(&mut self, name: &str) -> Option<&mut Repository> {
        self.repositories.iter_mut().find(|r| r.name == name)
    }

    /// Add a new repository
    pub fn add_repository(&mut self, repo: Repository) -> Result<()> {
        // Check for duplicate names
        if self.repositories.iter().any(|r| r.name == repo.name) {
            return Err(Error::config(format!(
                "Repository '{}' already exists",
                repo.name
            )));
        }

        self.repositories.push(repo);
        Ok(())
    }

    /// Remove repository by name
    pub fn remove_repository(&mut self, name: &str) -> Result<()> {
        let initial_len = self.repositories.len();
        self.repositories.retain(|r| r.name != name);

        if self.repositories.len() == initial_len {
            return Err(Error::config(format!("Repository '{}' not found", name)));
        }

        Ok(())
    }
}

impl Default for RepositoryConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

impl Repository {
    /// Create a new repository configuration
    pub fn new(name: String, url: String, branch: String, local_path: PathBuf) -> Self {
        Self {
            name,
            url,
            branch,
            local_path,
            enabled: true,
            trusted: false,
            last_updated: None,
            description: None,
        }
    }

    /// Check if repository needs updating (hasn't been updated recently)
    pub fn needs_update(&self, max_age_hours: i64) -> bool {
        match self.last_updated {
            None => true, // Never updated
            Some(last) => {
                let now = Utc::now();
                let age = now.signed_duration_since(last);
                age.num_hours() >= max_age_hours
            }
        }
    }

    /// Update the last_updated timestamp to now
    pub fn mark_updated(&mut self) {
        self.last_updated = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = RepositoryConfig::default_config();
        assert_eq!(config.version, "1.0");
        assert_eq!(config.default_branch, "main");
        assert_eq!(config.repositories.len(), 1);
        assert_eq!(config.repositories[0].name, "official");
    }

    #[test]
    fn test_add_repository() {
        let mut config = RepositoryConfig::default();

        let repo = Repository::new(
            "test".to_string(),
            "https://github.com/test/repo.git".to_string(),
            "main".to_string(),
            PathBuf::from("/tmp/test"),
        );

        assert!(config.add_repository(repo).is_ok());
        assert_eq!(config.repositories.len(), 2);
    }

    #[test]
    fn test_duplicate_repository() {
        let mut config = RepositoryConfig::default();

        let repo = Repository::new(
            "official".to_string(),
            "https://github.com/test/repo.git".to_string(),
            "main".to_string(),
            PathBuf::from("/tmp/test"),
        );

        // Should fail because "official" already exists
        assert!(config.add_repository(repo).is_err());
    }

    #[test]
    fn test_remove_repository() {
        let mut config = RepositoryConfig::default();
        assert!(config.remove_repository("official").is_ok());
        assert_eq!(config.repositories.len(), 0);
    }

    #[test]
    fn test_get_repository() {
        let config = RepositoryConfig::default();
        let repo = config.get_repository("official");
        assert!(repo.is_some());
        assert_eq!(repo.unwrap().name, "official");
    }

    #[test]
    fn test_enabled_repositories() {
        let mut config = RepositoryConfig::default();
        config.repositories[0].enabled = false;

        let enabled = config.enabled_repositories();
        assert_eq!(enabled.len(), 0);
    }

    #[test]
    fn test_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("repositories.yaml");

        let config = RepositoryConfig::default();
        config.save(&config_path).unwrap();

        let loaded = RepositoryConfig::load(&config_path).unwrap();
        assert_eq!(loaded.version, config.version);
        assert_eq!(loaded.repositories.len(), config.repositories.len());
    }

    #[test]
    fn test_repository_needs_update() {
        let mut repo = Repository::new(
            "test".to_string(),
            "https://example.com".to_string(),
            "main".to_string(),
            PathBuf::from("/tmp/test"),
        );

        // Never updated, should need update
        assert!(repo.needs_update(24));

        // Mark as updated
        repo.mark_updated();

        // Just updated, should not need update
        assert!(!repo.needs_update(24));
    }
}
