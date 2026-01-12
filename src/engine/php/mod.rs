//! PHP template engine implementation

use crate::engine::common::{build_env_vars, create_metadata, execute_command, parse_findings};
use crate::error::{Error, Result};
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Finding, Protocol, Target, TemplateLanguage};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;

/// PHP template engine - executes PHP scripts as templates
#[derive(Debug)]
pub struct PhpEngine {
    name: String,
    php_path: String,
}

impl PhpEngine {
    /// Create a new PHP engine
    pub fn new() -> Self {
        Self {
            name: "php".to_string(),
            php_path: "php".to_string(),
        }
    }

    /// Execute PHP template
    async fn execute_php_template(
        &self,
        template_path: &Path,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>> {
        tracing::debug!("PHP engine executing template: {:?}", template_path);

        // Build environment variables
        let env_vars = build_env_vars(target, context)?;

        // Execute PHP script
        let stdout = execute_command(
            &self.php_path,
            &[template_path.to_string_lossy().to_string()],
            &env_vars,
        )
        .await?;

        // Parse findings from JSON output
        let template_id = template_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        parse_findings(&stdout, target, &template_id)
    }
}

impl Clone for PhpEngine {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            php_path: self.php_path.clone(),
        }
    }
}

impl Default for PhpEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// PHP template wrapper
struct PhpTemplate {
    path: PathBuf,
    engine: PhpEngine,
    metadata: crate::types::TemplateMetadata,
}

#[async_trait]
impl Template for PhpTemplate {
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine
            .execute_php_template(&self.path, target, context)
            .await
    }

    fn validate(&self) -> Result<()> {
        if !self.path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Template not found: {:?}", self.path),
            )));
        }
        Ok(())
    }

    fn metadata(&self) -> &crate::types::TemplateMetadata {
        &self.metadata
    }
}

#[async_trait]
impl TemplateEngine for PhpEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let metadata = create_metadata(path, TemplateLanguage::Php);

        Ok(Box::new(PhpTemplate {
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
        vec![
            Protocol::Http,
            Protocol::Https,
            Protocol::Tcp,
            Protocol::Udp,
        ]
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn supports_file(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|s| s.to_str())
            .map(|ext| ext == "php")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_php_engine_supports_file() {
        let engine = PhpEngine::new();
        assert!(engine.supports_file(Path::new("test.php")));
        assert!(!engine.supports_file(Path::new("test.pl")));
    }

    #[test]
    fn test_php_engine_name() {
        let engine = PhpEngine::new();
        assert_eq!(engine.name(), "php");
    }
}
