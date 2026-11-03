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
        )
        .await?;

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
        let template_id = template_path
            .file_stem()
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
    probe_contract: bool,
}

#[async_trait]
impl Template for JavaScriptTemplate {
    fn is_js_probe(&self) -> bool {
        self.probe_contract
    }

    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        if self.probe_contract {
            return Err(Error::config(
                "JS probe contracts require the pentest engine; Node execution is refused",
            ));
        }
        self.engine
            .execute_js_template(&self.path, target, context)
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
impl TemplateEngine for JavaScriptEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let source = std::fs::read_to_string(path)?;
        let probe_contract = has_probe_contract(&source);
        let mut metadata = create_metadata(path, TemplateLanguage::JavaScript);
        if probe_contract && !metadata.tags.iter().any(|tag| tag == "probe") {
            metadata.tags.push("probe".into());
        }

        Ok(Box::new(JavaScriptTemplate {
            path: path.to_path_buf(),
            engine: self.clone(),
            metadata,
            probe_contract,
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
            .map(|ext| ext == "js" || ext == "mjs")
            .unwrap_or(false)
    }
}

// Ignore quoted examples and prose when identifying a function declaration.
// Probe headers are recognised only in actual, whole-line JS comments.
fn has_probe_contract(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut code = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i = (i + 2).min(bytes.len());
                    } else if bytes[i] == quote {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                let line_start = source[..start].rfind('\n').map_or(0, |n| n + 1);
                if source[line_start..start].trim().is_empty() {
                    let body = source[start + 2..i].trim_start();
                    if [
                        "@attach_scheme",
                        "@requires_auth_count",
                        "@requires_capability",
                    ]
                    .iter()
                    .any(|key| {
                        body.strip_prefix(key)
                            .is_some_and(|tail| tail.trim_start().starts_with(':'))
                    }) {
                        return true;
                    }
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            _ => {
                i += 1;
                continue;
            }
        }
        for byte in &mut code[start..i] {
            if *byte != b'\n' && *byte != b'\r' {
                *byte = b' ';
            }
        }
    }
    regex::Regex::new(r"\bfunction\s+cxgProbe\s*\(")
        .expect("fixed JS probe function pattern")
        .is_match(&String::from_utf8_lossy(&code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_contracts_are_detected_and_never_execute_as_node_scripts() {
        for source in [
            "async function cxgProbe(cxg) { return []; }",
            "// @attach_scheme: path\nconsole.log('[]');",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("probe.js");
            std::fs::write(&path, source).unwrap();
            let template = JavaScriptEngine::new().load_template(&path).await.unwrap();
            assert!(template.is_js_probe());
            let error = template
                .execute(
                    &Target::new("localhost", Protocol::Http),
                    &Context::default(),
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains("Node execution is refused"));
        }
    }

    #[tokio::test]
    async fn ordinary_javascript_scanners_keep_their_existing_contract() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scanner.js");
        std::fs::write(
            &path,
            r#"// @id: scanner
// Documentation: async function cxgProbe(cxg) is a different contract.
/* function cxgProbe(cxg) {} */
const example = "async function cxgProbe(cxg) {}";
const header = `// @attach_scheme: path`;
console.log('[]');"#,
        )
        .unwrap();
        assert!(!JavaScriptEngine::new()
            .load_template(&path)
            .await
            .unwrap()
            .is_js_probe());
    }

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
