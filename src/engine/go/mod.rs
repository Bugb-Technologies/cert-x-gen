//! Go template engine implementation

use crate::engine::common::{build_env_vars, create_metadata, execute_command, generate_cache_key, get_cache_dir, parse_findings, check_tool_available};
use crate::error::{Error, Result};
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Finding, Protocol, Target, TemplateLanguage};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

/// Go template engine - compiles and executes Go templates
#[derive(Debug)]
pub struct GoEngine {
    name: String,
    go_path: String,
    cache_dir: PathBuf,
}

impl GoEngine {
    /// Create a new Go engine
    pub fn new() -> Self {
        Self {
            name: "go".to_string(),
            go_path: "go".to_string(),
            cache_dir: get_cache_dir("go"),
        }
    }
    
    /// Compile and execute Go template
    async fn execute_go_template(
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
            // Compile Go template
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
    
    /// Compile Go template to binary
    async fn compile_template(&self, source_path: &Path, binary_path: &Path) -> Result<()> {
        if !check_tool_available("go").await {
            return Err(Error::Execution("Go compiler not found".to_string()));
        }
        
        let output = Command::new(&self.go_path)
            .arg("build")
            .arg("-o")
            .arg(binary_path)
            .arg(source_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::Execution(format!("Failed to compile Go template: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Execution(format!("Go compilation failed: {}", stderr)));
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

impl Clone for GoEngine {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            go_path: self.go_path.clone(),
            cache_dir: self.cache_dir.clone(),
        }
    }
}

impl Default for GoEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Go template wrapper
struct GoTemplate {
    path: PathBuf,
    engine: GoEngine,
    metadata: crate::types::TemplateMetadata,
}

#[async_trait]
impl Template for GoTemplate {
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine.execute_go_template(&self.path, target, context).await
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
impl TemplateEngine for GoEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let metadata = create_metadata(path, TemplateLanguage::Go);
        
        Ok(Box::new(GoTemplate {
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
        vec![Protocol::Http, Protocol::Https, Protocol::Tcp, Protocol::Udp]
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn supports_file(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|s| s.to_str())
            .map(|ext| ext == "go")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_engine_supports_file() {
        let engine = GoEngine::new();
        assert!(engine.supports_file(Path::new("test.go")));
        assert!(!engine.supports_file(Path::new("test.rs")));
    }

    #[test]
    fn test_go_engine_name() {
        let engine = GoEngine::new();
        assert_eq!(engine.name(), "go");
    }
}
