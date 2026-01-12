//! Shell template engine implementation

use crate::engine::common::{build_env_vars, create_metadata, execute_command, parse_findings};
use crate::error::{Error, Result};
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Finding, Protocol, Target, TemplateLanguage};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;

/// Shell template engine - executes shell scripts as templates
#[derive(Debug)]
pub struct ShellEngine {
    name: String,
    shell_path: String,
}

impl ShellEngine {
    /// Create a new Shell engine
    pub fn new() -> Self {
        Self {
            name: "shell".to_string(),
            shell_path: "/bin/bash".to_string(),
        }
    }

    /// Execute shell template
    async fn execute_shell_template(
        &self,
        template_path: &Path,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>> {
        tracing::debug!("Shell engine executing template: {:?}", template_path);

        // Build environment variables
        let env_vars = build_env_vars(target, context)?;

        // Execute shell script with arguments
        let port = target.port.unwrap_or(80);
        let args = vec![
            template_path.to_string_lossy().to_string(),
            target.address.clone(),
            port.to_string(),
            "--json".to_string(),
        ];

        let stdout = execute_command(&self.shell_path, &args, &env_vars).await?;

        // Try to extract JSON from output (shell scripts may have mixed output)
        let json_str = if let Some(json_start) = stdout.find("[CERT-X-GEN-JSON]") {
            let json_data = &stdout[json_start + 17..];
            if let Some(json_end) = json_data.find("[/CERT-X-GEN-JSON]") {
                &json_data[..json_end]
            } else {
                stdout.as_ref()
            }
        } else {
            stdout.as_ref()
        };

        // Parse findings from JSON output
        let template_id = template_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        parse_findings(json_str, target, &template_id)
    }
}

impl Clone for ShellEngine {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            shell_path: self.shell_path.clone(),
        }
    }
}

impl Default for ShellEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Shell template wrapper
struct ShellTemplate {
    path: PathBuf,
    engine: ShellEngine,
    metadata: crate::types::TemplateMetadata,
}

#[async_trait]
impl Template for ShellTemplate {
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine
            .execute_shell_template(&self.path, target, context)
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
impl TemplateEngine for ShellEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let metadata = create_metadata(path, TemplateLanguage::Shell);

        Ok(Box::new(ShellTemplate {
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
        vec![Protocol::Tcp, Protocol::Udp]
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn supports_file(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|s| s.to_str())
            .map(|ext| ext == "sh")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_engine_supports_file() {
        let engine = ShellEngine::new();
        assert!(engine.supports_file(Path::new("test.sh")));
        assert!(!engine.supports_file(Path::new("test.py")));
    }

    #[test]
    fn test_shell_engine_name() {
        let engine = ShellEngine::new();
        assert_eq!(engine.name(), "shell");
    }
}
