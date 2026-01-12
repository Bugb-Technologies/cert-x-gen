//! Sandbox configuration management

use crate::error::{Error, Result};
use crate::sandbox::docker::DockerConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Main sandbox configuration file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfigFile {
    /// Default sandbox to use
    pub default_sandbox: Option<String>,
    
    /// All configured sandboxes
    pub sandboxes: HashMap<String, DockerConfig>,
}

impl Default for SandboxConfigFile {
    fn default() -> Self {
        Self {
            default_sandbox: None,
            sandboxes: HashMap::new(),
        }
    }
}

impl SandboxConfigFile {
    /// Get config file path
    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| Error::config("Could not determine config directory"))?;
        
        let cert_x_gen_dir = config_dir.join("cert-x-gen");
        
        // Create directory if it doesn't exist
        if !cert_x_gen_dir.exists() {
            std::fs::create_dir_all(&cert_x_gen_dir)
                .map_err(|e| Error::config(format!("Failed to create config directory: {}", e)))?;
        }
        
        Ok(cert_x_gen_dir.join("sandbox-config.yaml"))
    }
    
    /// Load configuration from file
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        
        if !path.exists() {
            // Return default if file doesn't exist
            return Ok(Self::default());
        }
        
        let content = std::fs::read_to_string(&path)
            .map_err(|e| Error::config(format!("Failed to read sandbox config: {}", e)))?;
        
        serde_yaml::from_str(&content)
            .map_err(|e| Error::config(format!("Failed to parse sandbox config: {}", e)))
    }
    
    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        
        let content = serde_yaml::to_string(self)
            .map_err(|e| Error::config(format!("Failed to serialize sandbox config: {}", e)))?;
        
        std::fs::write(&path, content)
            .map_err(|e| Error::config(format!("Failed to write sandbox config: {}", e)))?;
        
        Ok(())
    }
    
    /// Add or update a sandbox configuration
    pub fn set_sandbox(&mut self, name: String, config: DockerConfig) {
        self.sandboxes.insert(name, config);
    }
    
    /// Remove a sandbox configuration
    pub fn remove_sandbox(&mut self, name: &str) -> Option<DockerConfig> {
        // Clear default if removing default sandbox
        if self.default_sandbox.as_deref() == Some(name) {
            self.default_sandbox = None;
        }
        
        self.sandboxes.remove(name)
    }
    
    /// Get a sandbox configuration
    pub fn get_sandbox(&self, name: &str) -> Option<&DockerConfig> {
        self.sandboxes.get(name)
    }
    
    /// Set default sandbox
    pub fn set_default(&mut self, name: Option<String>) {
        self.default_sandbox = name;
    }
    
    /// Get default sandbox config
    pub fn get_default_sandbox(&self) -> Option<(&String, &DockerConfig)> {
        self.default_sandbox.as_ref()
            .and_then(|name| self.sandboxes.get(name).map(|config| (name, config)))
    }
}
