//! Perl template engine implementation

use crate::engine::common::{build_env_vars, create_metadata, execute_command, parse_findings};
use crate::error::{Error, Result};
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Finding, Protocol, Target, TemplateLanguage};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;

/// Perl template engine - executes Perl scripts as templates
#[derive(Debug)]
pub struct PerlEngine {
    name: String,
    perl_path: String,
}

impl PerlEngine {
    /// Create a new Perl engine
    pub fn new() -> Self {
        Self {
            name: "perl".to_string(),
            perl_path: "perl".to_string(),
        }
    }
    
    /// Execute Perl template
    async fn execute_perl_template(
        &self,
        template_path: &Path,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>> {
        tracing::debug!("Perl engine executing template: {:?}", template_path);
        
        // Build environment variables
        let env_vars = build_env_vars(target, context)?;
        
        // Execute Perl script
        let stdout = execute_command(
            &self.perl_path,
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

impl Clone for PerlEngine {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            perl_path: self.perl_path.clone(),
        }
    }
}

impl Default for PerlEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Perl template wrapper
struct PerlTemplate {
    path: PathBuf,
    engine: PerlEngine,
    metadata: crate::types::TemplateMetadata,
}

#[async_trait]
impl Template for PerlTemplate {
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine.execute_perl_template(&self.path, target, context).await
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
impl TemplateEngine for PerlEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let metadata = create_metadata(path, TemplateLanguage::Perl);
        
        Ok(Box::new(PerlTemplate {
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
            .map(|ext| ext == "pl")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perl_engine_supports_file() {
        let engine = PerlEngine::new();
        assert!(engine.supports_file(Path::new("test.pl")));
        assert!(!engine.supports_file(Path::new("test.rb")));
    }

    #[test]
    fn test_perl_engine_name() {
        let engine = PerlEngine::new();
        assert_eq!(engine.name(), "perl");
    }
}
