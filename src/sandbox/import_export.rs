//! Sandbox import/export functionality for "bring your own sandbox"

use crate::error::{Error, Result};
use crate::sandbox::{Sandbox, SandboxConfig};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Exportable sandbox configuration with packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExport {
    /// Sandbox configuration
    pub config: SandboxConfig,

    /// Installed Python packages
    pub python_packages: Vec<String>,

    /// Installed JavaScript packages
    pub javascript_packages: Vec<String>,

    /// Installed Ruby gems
    pub ruby_gems: Vec<String>,

    /// Installed Perl modules
    pub perl_modules: Vec<String>,

    /// Installed PHP packages
    pub php_packages: Vec<String>,

    /// Go modules
    pub go_modules: Vec<String>,

    /// Rust crates
    pub rust_crates: Vec<String>,

    /// Java dependencies
    pub java_dependencies: Vec<String>,

    /// Custom environment variables
    pub custom_env_vars: Vec<(String, String)>,

    /// Export metadata
    pub metadata: ExportMetadata,
}

/// Export metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    /// Export timestamp
    pub exported_at: String,

    /// Export version
    pub version: String,

    /// Description
    pub description: Option<String>,

    /// Author
    pub author: Option<String>,

    /// Tags
    pub tags: Vec<String>,
}

impl SandboxExport {
    /// Create a new sandbox export
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            config,
            python_packages: Vec::new(),
            javascript_packages: Vec::new(),
            ruby_gems: Vec::new(),
            perl_modules: Vec::new(),
            php_packages: Vec::new(),
            go_modules: Vec::new(),
            rust_crates: Vec::new(),
            java_dependencies: Vec::new(),
            custom_env_vars: Vec::new(),
            metadata: ExportMetadata {
                exported_at: chrono::Utc::now().to_rfc3339(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: None,
                author: None,
                tags: Vec::new(),
            },
        }
    }

    /// Export from existing sandbox
    pub fn from_sandbox(sandbox: &Sandbox) -> Result<Self> {
        let mut export = Self::new(sandbox.config().clone());

        // Read installed packages from each language
        if sandbox.config().enable_python {
            export.python_packages = Self::read_python_packages(sandbox)?;
        }
        if sandbox.config().enable_javascript {
            export.javascript_packages = Self::read_javascript_packages(sandbox)?;
        }
        if sandbox.config().enable_ruby {
            export.ruby_gems = Self::read_ruby_gems(sandbox)?;
        }
        // Add more as needed...

        Ok(export)
    }

    /// Read installed Python packages
    fn read_python_packages(sandbox: &Sandbox) -> Result<Vec<String>> {
        let pip_list = sandbox.root_dir().join("python/venv/bin/pip");
        if !pip_list.exists() {
            return Ok(Vec::new());
        }

        let output = std::process::Command::new(pip_list)
            .args(&["list", "--format=freeze"])
            .output()
            .map_err(|e| Error::command(format!("Failed to list Python packages: {}", e)))?;

        let packages = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| line.to_string())
            .collect();

        Ok(packages)
    }

    /// Read installed JavaScript packages
    fn read_javascript_packages(sandbox: &Sandbox) -> Result<Vec<String>> {
        let package_json = sandbox.root_dir().join("javascript/package.json");
        if !package_json.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&package_json)
            .map_err(|e| Error::config(format!("Failed to read package.json: {}", e)))?;

        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| Error::config(format!("Failed to parse package.json: {}", e)))?;

        let mut packages = Vec::new();
        if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
            for (name, version) in deps {
                packages.push(format!("{}@{}", name, version.as_str().unwrap_or("latest")));
            }
        }

        Ok(packages)
    }

    /// Read installed Ruby gems
    fn read_ruby_gems(sandbox: &Sandbox) -> Result<Vec<String>> {
        let gem_home = sandbox.root_dir().join("ruby/gems");
        if !gem_home.exists() {
            return Ok(Vec::new());
        }

        let output = std::process::Command::new("gem")
            .args(&["list", "--local"])
            .env("GEM_HOME", &gem_home)
            .output()
            .map_err(|e| Error::command(format!("Failed to list Ruby gems: {}", e)))?;

        let gems = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with("***"))
            .map(|line| line.to_string())
            .collect();

        Ok(gems)
    }

    /// Save to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_yaml::to_string(self)
            .map_err(|e| Error::config(format!("Failed to serialize sandbox export: {}", e)))?;

        fs::write(path, content)
            .map_err(|e| Error::config(format!("Failed to write sandbox export: {}", e)))?;

        tracing::info!("Sandbox exported to: {}", path.display());
        Ok(())
    }

    /// Load from file
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| Error::config(format!("Failed to read sandbox export: {}", e)))?;

        let export: Self = serde_yaml::from_str(&content)
            .map_err(|e| Error::config(format!("Failed to parse sandbox export: {}", e)))?;

        tracing::info!("Sandbox imported from: {}", path.display());
        Ok(export)
    }

    /// Apply to sandbox
    pub async fn apply_to_sandbox(&self, sandbox: &mut Sandbox) -> Result<()> {
        tracing::info!("Applying imported sandbox configuration...");

        // Apply configuration
        *sandbox = Sandbox::with_config(self.config.clone());

        // Initialize
        sandbox.init().await?;

        // Install packages
        if !self.python_packages.is_empty() {
            tracing::info!(
                "Installing {} Python packages...",
                self.python_packages.len()
            );
            let packages: Vec<&str> = self.python_packages.iter().map(|s| s.as_str()).collect();
            crate::sandbox::python::install_packages(sandbox, &packages).await?;
        }

        if !self.javascript_packages.is_empty() {
            tracing::info!(
                "Installing {} JavaScript packages...",
                self.javascript_packages.len()
            );
            let packages: Vec<&str> = self
                .javascript_packages
                .iter()
                .map(|s| s.as_str())
                .collect();
            crate::sandbox::javascript::install_packages(sandbox, &packages).await?;
        }

        if !self.ruby_gems.is_empty() {
            tracing::info!("Installing {} Ruby gems...", self.ruby_gems.len());
            let packages: Vec<&str> = self.ruby_gems.iter().map(|s| s.as_str()).collect();
            crate::sandbox::ruby::install_gems(sandbox, &packages).await?;
        }

        // Add more languages as needed...

        tracing::info!("Sandbox configuration applied successfully!");
        Ok(())
    }
}

/// Sandbox template - pre-configured sandbox for specific use cases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxTemplate {
    /// Template name
    pub name: String,

    /// Template description
    pub description: String,

    /// Template export
    pub export: SandboxExport,
}

impl SandboxTemplate {
    /// Create web security template
    pub fn web_security() -> Self {
        let mut export = SandboxExport::new(SandboxConfig::default());
        export.metadata.description = Some("Web security testing sandbox".to_string());
        export.metadata.tags = vec!["web".to_string(), "security".to_string()];

        // Python packages for web security
        export.python_packages = vec![
            "requests".to_string(),
            "beautifulsoup4".to_string(),
            "selenium".to_string(),
            "scrapy".to_string(),
            "sqlmap".to_string(),
        ];

        // JavaScript packages for web security
        export.javascript_packages = vec![
            "puppeteer".to_string(),
            "playwright".to_string(),
            "axios".to_string(),
            "cheerio".to_string(),
        ];

        Self {
            name: "web-security".to_string(),
            description: "Pre-configured sandbox for web application security testing".to_string(),
            export,
        }
    }

    /// Create network security template
    pub fn network_security() -> Self {
        let mut export = SandboxExport::new(SandboxConfig::default());
        export.metadata.description = Some("Network security testing sandbox".to_string());
        export.metadata.tags = vec!["network".to_string(), "security".to_string()];

        export.python_packages = vec![
            "scapy".to_string(),
            "python-nmap".to_string(),
            "impacket".to_string(),
            "paramiko".to_string(),
        ];

        Self {
            name: "network-security".to_string(),
            description: "Pre-configured sandbox for network security testing".to_string(),
            export,
        }
    }

    /// Create API testing template
    pub fn api_testing() -> Self {
        let mut export = SandboxExport::new(SandboxConfig::default());
        export.metadata.description = Some("API testing sandbox".to_string());
        export.metadata.tags = vec!["api".to_string(), "testing".to_string()];

        export.python_packages = vec![
            "requests".to_string(),
            "httpx".to_string(),
            "pytest".to_string(),
        ];

        export.javascript_packages = vec![
            "axios".to_string(),
            "node-fetch".to_string(),
            "jest".to_string(),
        ];

        Self {
            name: "api-testing".to_string(),
            description: "Pre-configured sandbox for API testing".to_string(),
            export,
        }
    }
}
