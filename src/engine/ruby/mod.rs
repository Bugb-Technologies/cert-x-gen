//! Ruby template engine implementation

use crate::engine::common::{build_env_vars, create_metadata, execute_command, parse_findings};
use crate::error::{Error, Result};
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Finding, Protocol, Target, TemplateLanguage};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;

/// Ruby template engine - executes Ruby scripts as templates
#[derive(Debug)]
pub struct RubyEngine {
    name: String,
    ruby_path: String,
}

impl RubyEngine {
    /// Create a new Ruby engine
    pub fn new() -> Self {
        Self {
            name: "ruby".to_string(),
            ruby_path: "ruby".to_string(),
        }
    }
    
    /// Execute Ruby template
    async fn execute_ruby_template(
        &self,
        template_path: &Path,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>> {
        tracing::debug!("Ruby engine executing template: {:?}", template_path);
        
        // Build environment variables
        let env_vars = build_env_vars(target, context)?;
        
        // Execute Ruby script
        let stdout = execute_command(
            &self.ruby_path,
            &[template_path.to_string_lossy().to_string()],
            &env_vars,
        ).await?;
        
        // Parse findings from JSON output
        let template_id = template_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        parse_findings(&stdout, target, &template_id)
    }
}

impl Clone for RubyEngine {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            ruby_path: self.ruby_path.clone(),
        }
    }
}

impl Default for RubyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Ruby template wrapper
struct RubyTemplate {
    path: PathBuf,
    engine: RubyEngine,
    metadata: crate::types::TemplateMetadata,
}

#[async_trait]
impl Template for RubyTemplate {
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine.execute_ruby_template(&self.path, target, context).await
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
impl TemplateEngine for RubyEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let metadata = create_metadata(path, TemplateLanguage::Ruby);
        
        Ok(Box::new(RubyTemplate {
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
            .map(|ext| ext == "rb")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ruby_engine_supports_file() {
        let engine = RubyEngine::new();
        assert!(engine.supports_file(Path::new("test.rb")));
        assert!(!engine.supports_file(Path::new("test.py")));
    }

    #[test]
    fn test_ruby_engine_name() {
        let engine = RubyEngine::new();
        assert_eq!(engine.name(), "ruby");
    }
}
