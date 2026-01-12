//! Sandboxed environment for multi-language template execution
//!
//! This module provides a unified sandboxed environment that isolates
//! all language runtimes and their dependencies from the host system.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub mod config;
pub mod docker;
pub mod go;
pub mod import_export;
pub mod java;
pub mod javascript;
pub mod packages;
pub mod perl;
pub mod php;
pub mod python;
pub mod ruby;
pub mod runtime_installer;
pub mod rust;

/// Get the active Docker sandbox for transparent execution
pub fn get_active_docker_sandbox() -> Option<docker::DockerSandbox> {
    use config::SandboxConfigFile;

    // Check if we're already inside a sandbox
    if docker::inside_sandbox() {
        return None;
    }

    // Load config and get default sandbox
    let cfg = SandboxConfigFile::load().ok()?;
    let (name, _config) = cfg.get_default_sandbox()?;

    // Load the sandbox
    docker::DockerSandbox::load(name).ok()
}

/// Sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Root directory for sandbox
    pub root_dir: PathBuf,
    /// Enable Python support
    pub enable_python: bool,
    /// Enable JavaScript support
    pub enable_javascript: bool,
    /// Enable Ruby support
    pub enable_ruby: bool,
    /// Enable Perl support
    pub enable_perl: bool,
    /// Enable PHP support
    pub enable_php: bool,
    /// Enable Rust support
    pub enable_rust: bool,
    /// Enable Go support
    pub enable_go: bool,
    /// Enable Java support
    pub enable_java: bool,
    /// Auto-initialize on startup
    pub auto_init: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            root_dir: Self::default_sandbox_dir(),
            enable_python: true,
            enable_javascript: true,
            enable_ruby: true,
            enable_perl: true,
            enable_php: true,
            enable_rust: true,
            enable_go: true,
            enable_java: true,
            auto_init: true,
        }
    }
}

impl SandboxConfig {
    /// Get default sandbox directory
    pub fn default_sandbox_dir() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("cert-x-gen")
            .join("sandbox")
    }

    /// Load configuration from file
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| Error::config(format!("Failed to read sandbox config: {}", e)))?;

        serde_yaml::from_str(&content)
            .map_err(|e| Error::config(format!("Failed to parse sandbox config: {}", e)))
    }

    /// Save configuration to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_yaml::to_string(self)
            .map_err(|e| Error::config(format!("Failed to serialize sandbox config: {}", e)))?;

        fs::write(path, content)
            .map_err(|e| Error::config(format!("Failed to write sandbox config: {}", e)))
    }
}

/// Sandboxed environment manager
#[derive(Debug)]
pub struct Sandbox {
    config: SandboxConfig,
    initialized: bool,
}

impl Sandbox {
    /// Create a new sandbox with default configuration
    pub fn new() -> Self {
        Self {
            config: SandboxConfig::default(),
            initialized: false,
        }
    }

    /// Create a sandbox with custom configuration
    pub fn with_config(config: SandboxConfig) -> Self {
        Self {
            config,
            initialized: false,
        }
    }

    /// Get sandbox root directory
    pub fn root_dir(&self) -> &Path {
        &self.config.root_dir
    }

    /// Get configuration
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Check if sandbox is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized && self.root_dir().exists()
    }

    /// Initialize the sandbox environment
    pub async fn init(&mut self) -> Result<()> {
        tracing::info!("Initializing sandbox at: {}", self.root_dir().display());

        // Create root directory
        fs::create_dir_all(self.root_dir())
            .map_err(|e| Error::config(format!("Failed to create sandbox directory: {}", e)))?;

        // Create subdirectories
        self.create_directory_structure()?;

        // Initialize language environments
        if self.config.enable_python {
            python::init_environment(self).await?;
        }
        if self.config.enable_javascript {
            javascript::init_environment(self).await?;
        }
        if self.config.enable_ruby {
            ruby::init_environment(self).await?;
        }
        if self.config.enable_perl {
            perl::init_environment(self).await?;
        }
        if self.config.enable_php {
            php::init_environment(self).await?;
        }
        if self.config.enable_rust {
            rust::init_environment(self).await?;
        }
        if self.config.enable_go {
            go::init_environment(self).await?;
        }
        if self.config.enable_java {
            java::init_environment(self).await?;
        }

        // Save configuration
        let config_path = self.root_dir().join("config.yaml");
        self.config.save(&config_path)?;

        self.initialized = true;
        tracing::info!("Sandbox initialized successfully");

        Ok(())
    }

    /// Create sandbox directory structure
    fn create_directory_structure(&self) -> Result<()> {
        let dirs = vec![
            "python/venv",
            "python/packages",
            "javascript/node_modules",
            "javascript/packages",
            "ruby/gems",
            "ruby/packages",
            "perl/local",
            "perl/packages",
            "php/vendor",
            "php/packages",
            "rust/target",
            "rust/packages",
            "go/pkg",
            "go/packages",
            "java/lib",
            "java/packages",
            "bin",
            "tmp",
            "logs",
        ];

        for dir in dirs {
            let path = self.root_dir().join(dir);
            fs::create_dir_all(&path).map_err(|e| {
                Error::config(format!(
                    "Failed to create directory {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        Ok(())
    }

    /// Clean the sandbox environment
    pub fn clean(&self) -> Result<()> {
        tracing::info!("Cleaning sandbox at: {}", self.root_dir().display());

        if self.root_dir().exists() {
            fs::remove_dir_all(self.root_dir())
                .map_err(|e| Error::config(format!("Failed to clean sandbox: {}", e)))?;
        }

        tracing::info!("Sandbox cleaned successfully");
        Ok(())
    }

    /// Get environment variables for sandboxed execution
    pub fn get_env_vars(&self) -> Vec<(String, String)> {
        let mut env_vars = Vec::new();

        // Python
        if self.config.enable_python {
            let python_path = self.root_dir().join("python/venv");
            env_vars.push((
                "VIRTUAL_ENV".to_string(),
                python_path.to_string_lossy().to_string(),
            ));
            env_vars.push((
                "PYTHONUSERBASE".to_string(),
                self.root_dir()
                    .join("python/packages")
                    .to_string_lossy()
                    .to_string(),
            ));
        }

        // JavaScript/Node
        if self.config.enable_javascript {
            env_vars.push((
                "NODE_PATH".to_string(),
                self.root_dir()
                    .join("javascript/node_modules")
                    .to_string_lossy()
                    .to_string(),
            ));
        }

        // Ruby
        if self.config.enable_ruby {
            env_vars.push((
                "GEM_HOME".to_string(),
                self.root_dir()
                    .join("ruby/gems")
                    .to_string_lossy()
                    .to_string(),
            ));
        }

        // Perl
        if self.config.enable_perl {
            env_vars.push((
                "PERL_LOCAL_LIB_ROOT".to_string(),
                self.root_dir()
                    .join("perl/local")
                    .to_string_lossy()
                    .to_string(),
            ));
        }

        // PHP
        if self.config.enable_php {
            env_vars.push((
                "PHP_USER_INI".to_string(),
                self.root_dir().join("php").to_string_lossy().to_string(),
            ));
        }

        // Rust
        if self.config.enable_rust {
            env_vars.push((
                "CARGO_TARGET_DIR".to_string(),
                self.root_dir()
                    .join("rust/target")
                    .to_string_lossy()
                    .to_string(),
            ));
        }

        // Go
        if self.config.enable_go {
            env_vars.push((
                "GOPATH".to_string(),
                self.root_dir().join("go").to_string_lossy().to_string(),
            ));
        }

        // Java
        if self.config.enable_java {
            env_vars.push((
                "JAVA_HOME".to_string(),
                self.root_dir().join("java").to_string_lossy().to_string(),
            ));
        }

        env_vars
    }

    /// Execute a command in the sandbox environment
    pub fn execute_command(&self, program: &str, args: &[&str]) -> Result<std::process::Output> {
        let mut cmd = Command::new(program);
        cmd.args(args);

        // Set environment variables
        for (key, value) in self.get_env_vars() {
            cmd.env(key, value);
        }

        // Set working directory to sandbox
        cmd.current_dir(self.root_dir());

        cmd.output()
            .map_err(|e| Error::command(format!("Failed to execute command: {}", e)))
    }

    /// Get sandbox status
    pub fn status(&self) -> SandboxStatus {
        SandboxStatus {
            initialized: self.is_initialized(),
            root_dir: self.root_dir().to_path_buf(),
            python_ready: self.config.enable_python && self.root_dir().join("python/venv").exists(),
            javascript_ready: self.config.enable_javascript
                && self.root_dir().join("javascript/node_modules").exists(),
            ruby_ready: self.config.enable_ruby && self.root_dir().join("ruby/gems").exists(),
            perl_ready: self.config.enable_perl && self.root_dir().join("perl/local").exists(),
            php_ready: self.config.enable_php && self.root_dir().join("php/vendor").exists(),
            rust_ready: self.config.enable_rust && self.root_dir().join("rust/target").exists(),
            go_ready: self.config.enable_go && self.root_dir().join("go/pkg").exists(),
            java_ready: self.config.enable_java && self.root_dir().join("java/lib").exists(),
        }
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Sandbox status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxStatus {
    /// Whether the sandbox has been initialized
    pub initialized: bool,
    /// Root directory of the sandbox
    pub root_dir: PathBuf,
    /// Whether Python runtime is ready
    pub python_ready: bool,
    /// Whether JavaScript/Node.js runtime is ready
    pub javascript_ready: bool,
    /// Whether Ruby runtime is ready
    pub ruby_ready: bool,
    /// Whether Perl runtime is ready
    pub perl_ready: bool,
    /// Whether PHP runtime is ready
    pub php_ready: bool,
    /// Whether Rust runtime is ready
    pub rust_ready: bool,
    /// Whether Go runtime is ready
    pub go_ready: bool,
    /// Whether Java runtime is ready
    pub java_ready: bool,
}

impl SandboxStatus {
    /// Check if all enabled languages are ready
    pub fn all_ready(&self) -> bool {
        self.initialized && (self.python_ready || !self.python_ready) // All or none
    }

    /// Get ready languages
    pub fn ready_languages(&self) -> Vec<&str> {
        let mut langs = Vec::new();
        if self.python_ready {
            langs.push("python");
        }
        if self.javascript_ready {
            langs.push("javascript");
        }
        if self.ruby_ready {
            langs.push("ruby");
        }
        if self.perl_ready {
            langs.push("perl");
        }
        if self.php_ready {
            langs.push("php");
        }
        if self.rust_ready {
            langs.push("rust");
        }
        if self.go_ready {
            langs.push("go");
        }
        if self.java_ready {
            langs.push("java");
        }
        langs
    }

    /// Get pending languages
    pub fn pending_languages(&self) -> Vec<&str> {
        let mut langs = Vec::new();
        if !self.python_ready {
            langs.push("python");
        }
        if !self.javascript_ready {
            langs.push("javascript");
        }
        if !self.ruby_ready {
            langs.push("ruby");
        }
        if !self.perl_ready {
            langs.push("perl");
        }
        if !self.php_ready {
            langs.push("php");
        }
        if !self.rust_ready {
            langs.push("rust");
        }
        if !self.go_ready {
            langs.push("go");
        }
        if !self.java_ready {
            langs.push("java");
        }
        langs
    }
}
