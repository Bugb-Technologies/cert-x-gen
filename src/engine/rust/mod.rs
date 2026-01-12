//! Rust template engine implementation

use crate::engine::common::{build_env_vars, create_metadata, execute_command, generate_cache_key, get_cache_dir, parse_findings};
use crate::error::{Error, Result};
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Finding, Protocol, Target, TemplateLanguage};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

/// Rust template engine - compiles and executes Rust templates
#[derive(Debug)]
pub struct RustEngine {
    name: String,
    rustc_path: String,
    cache_dir: PathBuf,
}

impl RustEngine {
    /// Create a new Rust engine
    pub fn new() -> Self {
        Self {
            name: "rust".to_string(),
            rustc_path: "rustc".to_string(),
            cache_dir: get_cache_dir("rust"),
        }
    }
    
    /// Compile and execute Rust template
    async fn execute_rust_template(
        &self,
        template_path: &Path,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>> {
        // Ensure cache directory exists
        tokio::fs::create_dir_all(&self.cache_dir).await?;
        
        // Generate cache key and binary path
        let cache_key = generate_cache_key(template_path)?;
        let binary_name = template_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("template");
        let binary_path = self.cache_dir.join(format!("{}-{}", binary_name, cache_key));
        
        // Check if binary exists and is newer than source
        if !binary_path.exists() || self.is_source_newer(template_path, &binary_path).await? {
            // Compile Rust template
            self.compile_template(template_path, &binary_path).await?;
        }
        
        // Build environment variables
        let env_vars = build_env_vars(target, context)?;
        
        // Execute compiled binary (no arguments, uses environment variables)
        let stdout = execute_command(
            &binary_path.to_string_lossy(),
            &[],
            &env_vars,
        ).await?;
        
        // Parse findings from JSON output
        let template_id = template_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        parse_findings(&stdout, target, &template_id)
    }
    
    /// Compile Rust template to binary
    async fn compile_template(&self, source_path: &Path, binary_path: &Path) -> Result<()> {
        // Check if Cargo.toml exists in the same directory
        let source_dir = source_path.parent().ok_or_else(|| Error::Execution("Invalid source path".to_string()))?;
        let cargo_toml = source_dir.join("Cargo.toml");
        
        let output = if cargo_toml.exists() {
            // Use cargo build for projects with Cargo.toml
            let build_output = Command::new("cargo")
                .arg("build")
                .arg("--release")
                .arg("--manifest-path")
                .arg(&cargo_toml)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| Error::Execution(format!("Failed to run cargo build: {}", e)))?;
            
            if !build_output.status.success() {
                let stderr = String::from_utf8_lossy(&build_output.stderr);
                return Err(Error::Execution(format!("Cargo build failed: {}", stderr)));
            }
            
            // Copy the built binary to cache
            let binary_name = source_path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("template");
            let cargo_binary = source_dir.join("target/release").join(binary_name);
            tokio::fs::copy(&cargo_binary, binary_path).await
                .map_err(|e| Error::Execution(format!("Failed to copy binary: {}", e)))?;
            
            return Ok(());
        } else {
            // Use rustc for standalone files
            Command::new(&self.rustc_path)
                .arg(source_path)
                .arg("-o")
                .arg(binary_path)
                .arg("-O") // Optimize
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| Error::Execution(format!("Failed to compile Rust template: {}", e)))?
        };
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Execution(format!("Rust compilation failed: {}", stderr)));
        }
        
        Ok(())
    }
    
    /// Check if source file is newer than binary
    async fn is_source_newer(&self, source: &Path, binary: &Path) -> Result<bool> {
        let source_meta = tokio::fs::metadata(source).await?;
        let binary_meta = tokio::fs::metadata(binary).await?;
        
        Ok(source_meta.modified()? > binary_meta.modified()?)
    }
}

impl Clone for RustEngine {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            rustc_path: self.rustc_path.clone(),
            cache_dir: self.cache_dir.clone(),
        }
    }
}

impl Default for RustEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Rust template wrapper
struct RustTemplate {
    path: PathBuf,
    engine: RustEngine,
    metadata: crate::types::TemplateMetadata,
}

#[async_trait]
impl Template for RustTemplate {
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine.execute_rust_template(&self.path, target, context).await
    }
    
    fn validate(&self) -> Result<()> {
        if !self.path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Template not found: {:?}", self.path)
            )));
        }
        Ok(())
    }
    
    fn metadata(&self) -> &crate::types::TemplateMetadata {
        &self.metadata
    }
}

#[async_trait]
impl TemplateEngine for RustEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let metadata = create_metadata(path, TemplateLanguage::Rust);
        
        Ok(Box::new(RustTemplate {
            path: path.to_path_buf(),
            engine: self.clone(),
            metadata,
        }))
    }

    async fn validate_template(&self, template: &dyn Template) -> Result<()> {
        template.validate()
    }

    async fn execute_template(
        &self,
        template: &dyn Template,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>> {
        template.execute(target, context).await
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Http, Protocol::Https, Protocol::Tcp, Protocol::Udp, Protocol::Dns]
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn supports_file(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|s| s.to_str())
            .map(|ext| ext == "rs")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_engine_supports_file() {
        let engine = RustEngine::new();
        assert!(engine.supports_file(Path::new("test.rs")));
        assert!(!engine.supports_file(Path::new("test.py")));
    }

    #[test]
    fn test_rust_engine_name() {
        let engine = RustEngine::new();
        assert_eq!(engine.name(), "rust");
    }
}
