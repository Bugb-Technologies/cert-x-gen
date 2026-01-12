//! Template repository management system

use crate::error::{Error, Result};
use crate::template::git::GitClient;
use crate::template::paths::PathResolver;
use crate::template::repository_config::{Repository, RepositoryConfig};
use chrono::Utc;
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug)]
/// Manager for template repository operations
pub struct RepositoryManager {
    config_path: PathBuf,
    config: RepositoryConfig,
}

impl RepositoryManager {
    /// Create a new repository manager
    pub fn new() -> Result<Self> {
        let config_path = PathResolver::user_config_dir().join("repositories.yaml");
        
        let config = if config_path.exists() {
            RepositoryConfig::load(&config_path)?
        } else {
            // Create default config
            let config = RepositoryConfig::default_config();
            
            // Create config directory if needed
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            
            config.save(&config_path)?;
            info!("Created default repository configuration");
            config
        };
        
        Ok(Self { config_path, config })
    }
    
    /// Initialize repositories (clone if needed)
    pub fn initialize(&mut self) -> Result<()> {
        info!("Initializing template repositories");
        
        for repo in &mut self.config.repositories {
            if !repo.enabled {
                continue;
            }
            
            if repo.local_path.exists() {
                info!("Repository '{}' already exists at {}", 
                    repo.name, repo.local_path.display());
            } else {
                info!("Cloning repository '{}'...", repo.name);
                GitClient::clone(&repo.url, &repo.local_path, &repo.branch)?;
                repo.last_updated = Some(Utc::now());
            }
        }
        
        self.save()?;
        Ok(())
    }
    
    /// Update a specific repository
    pub fn update_repository(&mut self, name: &str) -> Result<()> {
        let repo = self.config.repositories.iter_mut()
            .find(|r| r.name == name)
            .ok_or_else(|| Error::config(format!("Repository '{}' not found", name)))?;
        
        if !repo.enabled {
            return Err(Error::config(format!("Repository '{}' is disabled", name)));
        }
        
        if !repo.local_path.exists() {
            // Clone if doesn't exist
            info!("Cloning repository '{}'...", name);
            GitClient::clone(&repo.url, &repo.local_path, &repo.branch)?;
        } else {
            // Check if clean
            if !GitClient::is_clean(&repo.local_path)? {
                warn!("Repository '{}' has uncommitted changes. Skipping update.", name);
                return Ok(());
            }
            
            // Pull updates
            info!("Updating repository '{}'...", name);
            GitClient::pull(&repo.local_path, &repo.branch)?;
        }
        
        repo.last_updated = Some(Utc::now());
        self.save()?;
        
        info!("Successfully updated repository '{}'", name);
        Ok(())
    }
    
    /// Update all enabled repositories
    pub fn update_all(&mut self) -> Result<Vec<String>> {
        let mut updated = Vec::new();
        let mut errors = Vec::new();
        
        // Collect repository names first to avoid borrow checker issues
        let repo_names: Vec<String> = self.config.repositories
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.name.clone())
            .collect();
        
        // Now update each repository
        for name in repo_names {
            match self.update_repository(&name) {
                Ok(_) => updated.push(name.clone()),
                Err(e) => {
                    warn!("Failed to update '{}': {}", name, e);
                    errors.push(format!("{}: {}", name, e));
                }
            }
        }
        
        if !errors.is_empty() {
            warn!("Some repositories failed to update: {:?}", errors);
        }
        
        Ok(updated)
    }
    
    /// Add a new repository
    pub fn add_repository(
        &mut self,
        name: String,
        url: String,
        branch: Option<String>,
    ) -> Result<()> {
        // Check for duplicates
        if self.config.repositories.iter().any(|r| r.name == name) {
            return Err(Error::config(format!("Repository '{}' already exists", name)));
        }
        
        let branch = branch.unwrap_or_else(|| self.config.default_branch.clone());
        let local_path = PathResolver::user_template_dir().join(&name);
        
        let repo = Repository {
            name: name.clone(),
            url,
            branch,
            local_path,
            enabled: true,
            trusted: false,  // Require manual trust
            last_updated: None,
            description: None,
        };
        
        self.config.repositories.push(repo);
        self.save()?;
        
        info!("Added repository '{}'", name);
        Ok(())
    }
    
    /// Remove a repository
    pub fn remove_repository(&mut self, name: &str) -> Result<()> {
        let index = self.config.repositories.iter()
            .position(|r| r.name == name)
            .ok_or_else(|| Error::config(format!("Repository '{}' not found", name)))?;
        
        let repo = self.config.repositories.remove(index);
        
        // Optionally delete local files
        if repo.local_path.exists() {
            info!("Repository files still exist at: {}", repo.local_path.display());
            info!("Run 'rm -rf {}' to remove them", repo.local_path.display());
        }
        
        self.save()?;
        info!("Removed repository '{}'", name);
        Ok(())
    }
    
    /// List all repositories
    pub fn list_repositories(&self) -> &[Repository] {
        &self.config.repositories
    }
    
    /// Get a specific repository
    pub fn get_repository(&self, name: &str) -> Option<&Repository> {
        self.config.repositories.iter().find(|r| r.name == name)
    }
    
    /// Save configuration
    fn save(&self) -> Result<()> {
        self.config.save(&self.config_path)
    }
    
    /// Check if templates need updating (24 hour check)
    pub fn should_auto_update(&self) -> bool {
        // Check if any repository needs updating (hasn't been updated in 24h)
        for repo in &self.config.repositories {
            if !repo.enabled {
                continue;
            }
            
            if let Some(last_updated) = repo.last_updated {
                let hours_since_update = Utc::now()
                    .signed_duration_since(last_updated)
                    .num_hours();
                
                if hours_since_update >= 24 {
                    return true;
                }
            } else {
                // Never updated
                return true;
            }
        }
        
        false
    }
    
    /// Check if any templates are installed
    pub fn has_templates(&self) -> bool {
        for repo in &self.config.repositories {
            if !repo.enabled {
                continue;
            }
            
            if repo.local_path.exists() && repo.local_path.is_dir() {
                // Check if directory has any files
                if let Ok(entries) = std::fs::read_dir(&repo.local_path) {
                    if entries.count() > 0 {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Perform auto-update if needed (silent, non-blocking)
    pub fn auto_update_if_needed(&mut self) -> Result<()> {
        if !self.should_auto_update() {
            return Ok(());
        }
        
        // Silent update - just pull if needed
        for repo in self.config.repositories.clone() {
            if !repo.enabled {
                continue;
            }
            
            if let Err(e) = self.update_repository(&repo.name) {
                // Log but don't fail
                warn!("Auto-update failed for repository '{}': {}", repo.name, e);
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_new_repository_manager() {
        let temp_dir = TempDir::new().unwrap();
        
        // Override config path for testing
        std::env::set_var("HOME", temp_dir.path());
        
        let result = RepositoryManager::new();
        assert!(result.is_ok());
        
        let manager = result.unwrap();
        assert!(!manager.config.repositories.is_empty());
    }
    
    #[test]
    fn test_add_repository() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        
        let mut manager = RepositoryManager::new().unwrap();
        
        let result = manager.add_repository(
            "test".to_string(),
            "https://github.com/test/repo.git".to_string(),
            Some("main".to_string()),
        );
        
        assert!(result.is_ok());
        assert!(manager.get_repository("test").is_some());
    }
    
    #[test]
    fn test_add_duplicate_repository() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        
        let mut manager = RepositoryManager::new().unwrap();
        
        manager.add_repository(
            "test".to_string(),
            "https://github.com/test/repo.git".to_string(),
            None,
        ).unwrap();
        
        // Try to add again
        let result = manager.add_repository(
            "test".to_string(),
            "https://github.com/test/repo2.git".to_string(),
            None,
        );
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }
    
    #[test]
    fn test_remove_repository() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        
        let mut manager = RepositoryManager::new().unwrap();
        
        manager.add_repository(
            "test".to_string(),
            "https://github.com/test/repo.git".to_string(),
            None,
        ).unwrap();
        
        let result = manager.remove_repository("test");
        assert!(result.is_ok());
        assert!(manager.get_repository("test").is_none());
    }
    
    #[test]
    fn test_remove_nonexistent_repository() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        
        let mut manager = RepositoryManager::new().unwrap();
        
        let result = manager.remove_repository("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }
    
    #[test]
    fn test_list_repositories() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        
        let manager = RepositoryManager::new().unwrap();
        let repos = manager.list_repositories();
        
        // Should have default "official" repository
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].name, "official");
    }
    
    #[test]
    fn test_get_repository() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        
        let mut manager = RepositoryManager::new().unwrap();
        
        manager.add_repository(
            "test".to_string(),
            "https://github.com/test/repo.git".to_string(),
            None,
        ).unwrap();
        
        let repo = manager.get_repository("test");
        assert!(repo.is_some());
        assert_eq!(repo.unwrap().name, "test");
        
        let missing = manager.get_repository("missing");
        assert!(missing.is_none());
    }
}
