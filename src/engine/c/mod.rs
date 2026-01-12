//! C template engine implementation

use crate::engine::common::{build_env_vars, create_metadata, execute_command, generate_cache_key, get_cache_dir, parse_findings, check_tool_available};
use crate::error::{Error, Result};
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Finding, Protocol, Target, TemplateLanguage};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

/// C template engine - compiles and executes C templates
#[derive(Debug)]
pub struct CEngine {
    name: String,
    compiler_path: String,
    cache_dir: PathBuf,
}

impl CEngine {
    /// Create a new C engine
    pub fn new() -> Self {
        Self {
            name: "c".to_string(),
            compiler_path: "gcc".to_string(),
            cache_dir: get_cache_dir("c"),
        }
    }
    
    /// Compile and execute C template
    async fn execute_c_template(
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
            // Compile C template
            self.compile_template(template_path, &binary_path).await?;
        }
        
        // Build environment variables
        let env_vars = build_env_vars(target, context)?;
        
        // Execute compiled binary
        let stdout = execute_command(
            &binary_path.to_string_lossy(),
            &["--json".to_string(), "--target".to_string(), target.address.clone()],
            &env_vars,
        ).await?;
        
        // Parse findings from JSON output
        let template_id = template_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        parse_findings(&stdout, target, &template_id)
    }
    
    /// Compile C template to binary
    async fn compile_template(&self, source_path: &Path, binary_path: &Path) -> Result<()> {
        // Try gcc first, then clang
        let compiler = if check_tool_available("gcc").await {
            "gcc"
        } else if check_tool_available("clang").await {
            "clang"
        } else {
            return Err(Error::Execution("Neither gcc nor clang found".to_string()));
        };
        
        let output = Command::new(compiler)
            .arg(source_path)
            .arg("-o")
            .arg(binary_path)
            .arg("-O2")
            .arg("-std=c11")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::Execution(format!("Failed to compile C template: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Execution(format!("C compilation failed: {}", stderr)));
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

impl Clone for CEngine {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            compiler_path: self.compiler_path.clone(),
            cache_dir: self.cache_dir.clone(),
        }
    }
}

impl Default for CEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// C template wrapper
struct CTemplate {
    path: PathBuf,
    engine: CEngine,
    metadata: crate::types::TemplateMetadata,
}

#[async_trait]
impl Template for CTemplate {
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine.execute_c_template(&self.path, target, context).await
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
impl TemplateEngine for CEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let metadata = create_metadata(path, TemplateLanguage::C);
        
        Ok(Box::new(CTemplate {
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
            .map(|ext| ext == "c")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_engine_supports_file() {
        let engine = CEngine::new();
        assert!(engine.supports_file(Path::new("test.c")));
        assert!(!engine.supports_file(Path::new("test.cpp")));
    }

    #[test]
    fn test_c_engine_name() {
        let engine = CEngine::new();
        assert_eq!(engine.name(), "c");
    }
}
