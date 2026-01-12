//! JavaScript template engine implementation

use crate::engine::common::{build_env_vars, create_metadata, execute_command, parse_findings};
use crate::error::{Error, Result};
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Finding, Protocol, Target, TemplateLanguage};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;

/// JavaScript template engine - executes JavaScript/Node.js templates
#[derive(Debug)]
pub struct JavaScriptEngine {
    name: String,
    node_path: String,
}

impl JavaScriptEngine {
    /// Create a new JavaScript engine
    pub fn new() -> Self {
        Self {
            name: "javascript".to_string(),
            node_path: "node".to_string(),
        }
    }
    
    /// Execute JavaScript template
    async fn execute_js_template(
        &self,
        template_path: &Path,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>> {
        tracing::debug!("JavaScript engine executing template: {:?}", template_path);
        
        // Build environment variables
        let env_vars = build_env_vars(target, context)?;
        
        // Execute Node.js script
        let stdout = execute_command(
            &self.node_path,
            &[template_path.to_string_lossy().to_string()],
            &env_vars,
        ).await?;
        
        // Try to find JSON in output (Node.js may have console.log output)
        let json_str = if let Some(json_start) = stdout.rfind("__CERT_X_GEN_FINDINGS__:") {
            tracing::debug!("Found JSON marker at position {}", json_start);
            let marker_len = "__CERT_X_GEN_FINDINGS__:".len();
            &stdout[json_start + marker_len..]
        } else {
            tracing::debug!("No JSON marker found, parsing entire stdout");
            stdout.as_ref()
        };
        
        // Parse findings from JSON output
        let template_id = template_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        parse_findings(json_str, target, &template_id)
    }
}

impl Clone for JavaScriptEngine {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            node_path: self.node_path.clone(),
        }
    }
}

impl Default for JavaScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// JavaScript template wrapper
struct JavaScriptTemplate {
    path: PathBuf,
    engine: JavaScriptEngine,
    metadata: crate::types::TemplateMetadata,
}

#[async_trait]
impl Template for JavaScriptTemplate {
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine.execute_js_template(&self.path, target, context).await
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
impl TemplateEngine for JavaScriptEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let metadata = create_metadata(path, TemplateLanguage::JavaScript);
        
        Ok(Box::new(JavaScriptTemplate {
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
            .map(|ext| ext == "js" || ext == "mjs")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_javascript_engine_supports_file() {
        let engine = JavaScriptEngine::new();
        assert!(engine.supports_file(Path::new("test.js")));
        assert!(engine.supports_file(Path::new("test.mjs")));
        assert!(!engine.supports_file(Path::new("test.py")));
    }

    #[test]
    fn test_javascript_engine_name() {
        let engine = JavaScriptEngine::new();
        assert_eq!(engine.name(), "javascript");
    }
}
