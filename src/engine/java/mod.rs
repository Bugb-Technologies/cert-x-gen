//! Java template engine implementation

use crate::engine::common::{
    build_env_vars, check_tool_available, create_metadata, execute_command, generate_cache_key,
    get_cache_dir, parse_findings,
};
use crate::error::{Error, Result};
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Finding, Protocol, Target, TemplateLanguage};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

/// Java template engine - compiles and executes Java templates
#[derive(Debug)]
pub struct JavaEngine {
    name: String,
    javac_path: String,
    java_path: String,
    cache_dir: PathBuf,
}

impl JavaEngine {
    /// Create a new Java engine
    pub fn new() -> Self {
        Self {
            name: "java".to_string(),
            javac_path: "javac".to_string(),
            java_path: "java".to_string(),
            cache_dir: get_cache_dir("java"),
        }
    }

    /// Compile and execute Java template
    async fn execute_java_template(
        &self,
        template_path: &Path,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>> {
        // Ensure cache directory exists
        tokio::fs::create_dir_all(&self.cache_dir).await?;

        // Generate cache key and class path
        let cache_key = generate_cache_key(template_path)?;
        let class_name = template_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Template");
        let class_file = self
            .cache_dir
            .join(format!("{}-{}.class", class_name, cache_key));

        // Check if class file exists and is newer than source
        if !class_file.exists() || self.is_source_newer(template_path, &class_file).await? {
            // Compile Java template
            self.compile_template(template_path, &class_file).await?;
        }

        // Build environment variables
        let env_vars = build_env_vars(target, context)?;

        // Execute Java class (no arguments, uses environment variables)
        let stdout = execute_command(
            &self.java_path,
            &[
                "-cp".to_string(),
                self.cache_dir.to_string_lossy().to_string(),
                class_name.to_string(),
            ],
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

    /// Compile Java template to class file
    async fn compile_template(&self, source_path: &Path, _class_file: &Path) -> Result<()> {
        if !check_tool_available("javac").await {
            return Err(Error::Execution(
                "Java compiler (javac) not found".to_string(),
            ));
        }

        let output = Command::new(&self.javac_path)
            .arg("-d")
            .arg(&self.cache_dir)
            .arg(source_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::Execution(format!("Failed to compile Java template: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Execution(format!(
                "Java compilation failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Check if source file is newer than class file
    async fn is_source_newer(&self, source: &Path, class_file: &Path) -> Result<bool> {
        let source_meta = tokio::fs::metadata(source).await?;
        let class_meta = tokio::fs::metadata(class_file).await?;

        Ok(source_meta.modified()? > class_meta.modified()?)
    }
}

impl Clone for JavaEngine {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            javac_path: self.javac_path.clone(),
            java_path: self.java_path.clone(),
            cache_dir: self.cache_dir.clone(),
        }
    }
}

impl Default for JavaEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Java template wrapper
struct JavaTemplate {
    path: PathBuf,
    engine: JavaEngine,
    metadata: crate::types::TemplateMetadata,
}

#[async_trait]
impl Template for JavaTemplate {
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine
            .execute_java_template(&self.path, target, context)
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
impl TemplateEngine for JavaEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let metadata = create_metadata(path, TemplateLanguage::Java);

        Ok(Box::new(JavaTemplate {
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
            .map(|ext| ext == "java")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_java_engine_supports_file() {
        let engine = JavaEngine::new();
        assert!(engine.supports_file(Path::new("test.java")));
        assert!(!engine.supports_file(Path::new("test.go")));
    }

    #[test]
    fn test_java_engine_name() {
        let engine = JavaEngine::new();
        assert_eq!(engine.name(), "java");
    }
}
