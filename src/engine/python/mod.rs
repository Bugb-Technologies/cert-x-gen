//! Python template engine implementation

use crate::engine::common::{build_env_vars, create_metadata, execute_command, parse_findings};
use crate::error::{Error, Result};
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Finding, Protocol, Target, TemplateLanguage};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;

/// Python template engine - executes Python scripts as templates
#[derive(Debug)]
pub struct PythonEngine {
    name: String,
    python_path: String,
}

impl PythonEngine {
    /// Create a new Python engine
    pub fn new() -> Self {
        Self {
            name: "python".to_string(),
            python_path: "python3".to_string(), // Use python3 by default
        }
    }
    
    /// Execute Python template and parse results
    async fn execute_python_template(
        &self,
        template_path: &Path,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>> {
        tracing::debug!("Python engine executing template: {:?}", template_path);
        
        // Build environment variables
        let env_vars = build_env_vars(target, context)?;
        
        // Execute Python script
        let stdout = execute_command(
            &self.python_path,
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

impl Clone for PythonEngine {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            python_path: self.python_path.clone(),
        }
    }
}

impl Default for PythonEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Python template wrapper
struct PythonTemplate {
    path: PathBuf,
    engine: PythonEngine,
    metadata: crate::types::TemplateMetadata,
}

#[async_trait]
impl Template for PythonTemplate {
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine.execute_python_template(&self.path, target, context).await
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
impl TemplateEngine for PythonEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let metadata = create_metadata(path, TemplateLanguage::Python);
        
        Ok(Box::new(PythonTemplate {
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
            .map(|ext| ext == "py")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_engine_supports_file() {
        let engine = PythonEngine::new();
        assert!(engine.supports_file(Path::new("test.py")));
        assert!(!engine.supports_file(Path::new("test.yaml")));
    }

    #[test]
    fn test_python_engine_name() {
        let engine = PythonEngine::new();
        assert_eq!(engine.name(), "python");
    }
}
