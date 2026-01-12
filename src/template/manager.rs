//! Template management system with multi-source discovery

use crate::error::{Error, Result};
use crate::template::paths::PathResolver;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Source priority for template resolution
pub enum TemplateSource {
    /// System-wide templates (lowest priority)

    System = 1,   // Lowest priority
    /// User-specific templates (medium priority)

    User = 2,
    /// Local project templates (highest priority)

    Local = 3,    // Highest priority
}

impl TemplateSource {
    /// Get the priority value for this source

    pub fn priority(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone)]
/// Location information for a template
pub struct TemplateLocation {
    /// Template identifier

    pub template_id: String,
    /// File system path

    pub path: PathBuf,
    /// Source location type

    pub source: TemplateSource,
}

#[derive(Debug)]
/// Manager for template discovery and resolution
pub struct TemplateManager {
    system_dir: PathBuf,
    user_dir: PathBuf,
    local_dir: PathBuf,
    cache: Arc<RwLock<HashMap<String, TemplateLocation>>>,
}

impl TemplateManager {
    /// Create a new template manager
    pub fn new() -> Self {
        Self {
            system_dir: PathResolver::system_template_dir(),
            user_dir: PathResolver::user_template_dir(),
            local_dir: PathResolver::local_template_dir(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Initialize template manager (create directories if needed)
    pub async fn initialize(&self) -> Result<()> {
        // Create user directory if it doesn't exist
        if !self.user_dir.exists() {
            std::fs::create_dir_all(&self.user_dir)
                .map_err(|e| Error::config(format!(
                    "Failed to create user template directory: {}", e
                )))?;
            tracing::info!("Created user template directory: {}", self.user_dir.display());
        }
        
        // Discover all templates
        self.discover_all().await?;
        
        Ok(())
    }
    
    /// Discover all templates from all sources
    pub async fn discover_all(&self) -> Result<()> {
        let mut cache = self.cache.write().await;
        cache.clear();
        
        // Discover in reverse priority order so higher priority overrides
        self.discover_from_dir(&self.system_dir, TemplateSource::System, &mut cache)?;
        self.discover_from_dir(&self.user_dir, TemplateSource::User, &mut cache)?;
        self.discover_from_dir(&self.local_dir, TemplateSource::Local, &mut cache)?;
        
        tracing::info!("Discovered {} templates", cache.len());
        Ok(())
    }
    
    /// Discover templates from a specific directory
    fn discover_from_dir(
        &self,
        dir: &Path,
        source: TemplateSource,
        cache: &mut HashMap<String, TemplateLocation>,
    ) -> Result<()> {
        if !dir.exists() {
            tracing::debug!("Template directory does not exist: {}", dir.display());
            return Ok(());
        }
        
        let mut count = 0;
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            
            let path = entry.path();
            if let Some(template_id) = self.extract_template_id(path) {
                // Higher priority sources override lower priority
                cache.entry(template_id.clone())
                    .and_modify(|loc| {
                        if source.priority() > loc.source.priority() {
                            loc.path = path.to_path_buf();
                            loc.source = source;
                        }
                    })
                    .or_insert_with(|| TemplateLocation {
                        template_id: template_id.clone(),
                        path: path.to_path_buf(),
                        source,
                    });
                count += 1;
            }
        }
        
        tracing::debug!("Found {} templates in {} ({:?})",
            count, dir.display(), source);
        
        Ok(())
    }
    
    /// Extract template ID from file path
    fn extract_template_id(&self, path: &Path) -> Option<String> {
        // Get filename without extension
        path.file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
    }
    
    /// Get all template directories in priority order (highest first)
    pub fn get_template_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.local_dir.clone(),
            self.user_dir.clone(),
            self.system_dir.clone(),
        ]
    }
    
    /// Get template location by ID
    pub async fn get_template_location(&self, id: &str) -> Option<TemplateLocation> {
        let cache = self.cache.read().await;
        cache.get(id).cloned()
    }
    
    /// Get all discovered template IDs
    pub async fn get_all_template_ids(&self) -> Vec<String> {
        let cache = self.cache.read().await;
        cache.keys().cloned().collect()
    }
    
    /// Check if any templates exist
    pub async fn has_any_templates(&self) -> bool {
        let cache = self.cache.read().await;
        !cache.is_empty()
    }
    
    /// Refresh template cache
    pub async fn refresh(&self) -> Result<()> {
        self.discover_all().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_template_manager_creation() {
        let manager = TemplateManager::new();
        assert!(manager.system_dir.is_absolute());
    }
    
    #[tokio::test]
    async fn test_template_discovery() {
        let temp = TempDir::new().unwrap();
        let mut manager = TemplateManager::new();
        manager.local_dir = temp.path().to_path_buf();
        
        // Create test template
        let template_path = temp.path().join("test-template.yaml");
        std::fs::write(&template_path, "id: test-template").unwrap();
        
        manager.discover_all().await.unwrap();
        
        let loc = manager.get_template_location("test-template").await;
        assert!(loc.is_some());
    }
}
