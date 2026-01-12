// Template Version Tracking
// Similar to Nuclei's .templates-config.json

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Template version configuration stored in ~/.cert-x-gen/.templates-config.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVersion {
    /// Current template version (git commit hash or tag)
    pub current_version: String,
    
    /// Last time templates were checked for updates (Unix timestamp)
    pub last_checked: i64,
    
    /// Last time templates were updated (Unix timestamp)
    pub last_updated: i64,
    
    /// Directory where templates are stored
    pub templates_directory: String,
    
    /// Whether auto-update check is enabled
    pub auto_check_enabled: bool,
}

impl Default for TemplateVersion {
    fn default() -> Self {
        Self {
            current_version: String::from("unknown"),
            last_checked: 0,
            last_updated: 0,
            templates_directory: String::new(),
            auto_check_enabled: true,
        }
    }
}

impl TemplateVersion {
    /// Load version config from file
    pub fn load(config_path: &Path) -> Result<Self> {
        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(config_path)?;

        let config: TemplateVersion = serde_json::from_str(&content)?;

        Ok(config)
    }

    /// Save version config to file
    pub fn save(&self, config_path: &Path) -> Result<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(self)?;

        fs::write(config_path, content)?;

        Ok(())
    }

    /// Get the default config path (~/.cert-x-gen/.templates-config.json)
    pub fn default_config_path() -> Result<PathBuf> {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| Error::config("Failed to get home directory"))?;

        Ok(home_dir.join(".cert-x-gen").join(".templates-config.json"))
    }

    /// Get current Unix timestamp
    pub fn current_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64
    }

    /// Check if templates should be checked for updates (every 1 hour like Nuclei)
    pub fn should_check_for_updates(&self) -> bool {
        if !self.auto_check_enabled {
            return false;
        }

        let now = Self::current_timestamp();
        let one_hour = 3600; // seconds
        
        now - self.last_checked > one_hour
    }

    /// Update last checked timestamp
    pub fn mark_checked(&mut self) {
        self.last_checked = Self::current_timestamp();
    }

    /// Update version and last updated timestamp
    pub fn update_version(&mut self, version: String) {
        self.current_version = version;
        self.last_updated = Self::current_timestamp();
        self.last_checked = Self::current_timestamp();
    }

    /// Disable auto-update checks
    pub fn disable_auto_check(&mut self) {
        self.auto_check_enabled = false;
    }

    /// Enable auto-update checks
    pub fn enable_auto_check(&mut self) {
        self.auto_check_enabled = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_version() {
        let version = TemplateVersion::default();
        assert_eq!(version.current_version, "unknown");
        assert_eq!(version.last_checked, 0);
        assert_eq!(version.last_updated, 0);
        assert!(version.auto_check_enabled);
    }

    #[test]
    fn test_should_check_for_updates() {
        let mut version = TemplateVersion::default();
        
        // Should check when never checked before
        assert!(version.should_check_for_updates());
        
        // Should not check immediately after checking
        version.mark_checked();
        assert!(!version.should_check_for_updates());
        
        // Should check after 1 hour (simulate by setting old timestamp)
        version.last_checked = TemplateVersion::current_timestamp() - 3601;
        assert!(version.should_check_for_updates());
    }

    #[test]
    fn test_disable_auto_check() {
        let mut version = TemplateVersion::default();
        assert!(version.auto_check_enabled);
        
        version.disable_auto_check();
        assert!(!version.auto_check_enabled);
        assert!(!version.should_check_for_updates());
    }

    #[test]
    fn test_save_and_load() -> Result<()> {
        let temp_dir = env::temp_dir();
        let config_path = temp_dir.join("test-template-version.json");

        // Clean up if exists
        let _ = fs::remove_file(&config_path);

        // Create and save
        let mut version = TemplateVersion::default();
        version.current_version = "v1.0.0".to_string();
        version.templates_directory = "/test/path".to_string();
        version.save(&config_path)?;

        // Load and verify
        let loaded = TemplateVersion::load(&config_path)?;
        assert_eq!(loaded.current_version, "v1.0.0");
        assert_eq!(loaded.templates_directory, "/test/path");

        // Clean up
        let _ = fs::remove_file(&config_path);

        Ok(())
    }

    #[test]
    fn test_update_version() {
        let mut version = TemplateVersion::default();
        let old_timestamp = version.last_updated;
        
        std::thread::sleep(std::time::Duration::from_millis(10));
        version.update_version("v2.0.0".to_string());
        
        assert_eq!(version.current_version, "v2.0.0");
        assert!(version.last_updated > old_timestamp);
        assert!(version.last_checked > old_timestamp);
    }
}
