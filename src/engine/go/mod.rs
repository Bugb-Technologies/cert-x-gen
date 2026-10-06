//! Go template engine implementation

pub mod modules;

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
        let binary_path = self.ensure_binary(template_path).await?;

        // Build environment variables
        let env_vars = build_env_vars(target, context)?;

        // Execute compiled binary (no arguments, uses environment variables)
        let stdout = execute_command(&binary_path.to_string_lossy(), &[], &env_vars).await?;

        // Parse findings from JSON output
        let template_id = template_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        parse_findings(&stdout, target, &template_id)
    }

    /// Return a compiled binary for the template, building it if needed.
    ///
    /// A template that imports only the standard library, or that already sits
    /// inside a Go module, is built in place as before. A template that imports
    /// third-party packages from outside any module is built in a private module
    /// under the cxg home (see [`modules`]), so its imports resolve without the
    /// operator writing a `go.mod` by hand.
    // @comment -- "chooses the Go build strategy: in place for stdlib-only or in-module templates, a private generated module for third-party imports outside any module"
    async fn ensure_binary(&self, template_path: &Path) -> Result<PathBuf> {
        let source = tokio::fs::read(template_path).await?;
        let imports = modules::third_party_imports(&String::from_utf8_lossy(&source));
        let template_dir = template_dir(template_path);

        if imports.is_empty() || modules::find_enclosing_module(&template_dir).is_some() {
            return self.ensure_in_place_binary(template_path).await;
        }

        let cache_root = modules::private_module_cache_root();
        self.ensure_private_module_binary(template_path, &source, &imports, &cache_root)
            .await
    }

    /// Existing behaviour: `go build -o <cache>/<stem>-<key> <file>`, rebuilt
    /// when the source is newer than the cached binary.
    async fn ensure_in_place_binary(&self, template_path: &Path) -> Result<PathBuf> {
        // Ensure cache directory exists
        tokio::fs::create_dir_all(&self.cache_dir).await?;

        // Generate cache key and binary path
        let cache_key = generate_cache_key(template_path)?;
        let binary_name = template_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("template");
        let binary_path = self
            .cache_dir
            .join(format!("{}-{}", binary_name, cache_key));

        // Check if binary exists and is newer than source
        if !binary_path.exists() || self.is_source_newer(template_path, &binary_path).await? {
            // Compile Go template
            self.compile_template(template_path, &binary_path).await?;
        }
        Ok(binary_path)
    }

    /// Build a template with third-party imports in its own module.
    ///
    /// Layout: `<cache_root>/<stem>-<content hash>/{<stem>.go, go.mod, go.sum,
    /// <stem>}`. The directory is assembled under a unique staging name and
    /// renamed into place only once the binary exists, so a failed or
    /// interrupted build never leaves a half-made entry that a later scan would
    /// trust, and two concurrent scans of the same template cannot corrupt
    /// each other.
    // @comment -- "builds a third-party-importing Go template in a private module keyed by content hash; go mod tidy downloads through the operator's own GOPROXY/GOMODCACHE/GOFLAGS"
    async fn ensure_private_module_binary(
        &self,
        template_path: &Path,
        source: &[u8],
        imports: &[String],
        cache_root: &Path,
    ) -> Result<PathBuf> {
        let stem = template_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("template");
        let key = modules::content_cache_key(source);
        let build_dir = cache_root.join(format!("{}-{}", stem, key));
        let binary_path = build_dir.join(stem);
        if binary_path.is_file() {
            return Ok(binary_path);
        }

        if !check_tool_available(&self.go_path).await {
            return Err(Error::Execution("Go compiler not found".to_string()));
        }

        tokio::fs::create_dir_all(cache_root).await?;
        let staging = cache_root.join(format!(
            ".{}-{}.{}.{}.staging",
            stem,
            key,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        tokio::fs::create_dir_all(&staging).await?;

        let built = self
            .build_private_module(&staging, stem, source, imports)
            .await;
        if let Err(e) = built {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(e);
        }

        if tokio::fs::rename(&staging, &build_dir).await.is_err() {
            // Another scan finished the same build first; use its result.
            let _ = tokio::fs::remove_dir_all(&staging).await;
            if !binary_path.is_file() {
                return Err(Error::Execution(format!(
                    "Go template build finished but could not be moved into {}",
                    build_dir.display()
                )));
            }
        }
        Ok(binary_path)
    }

    /// Write the module files into `dir`, then `go mod tidy` and `go build`.
    async fn build_private_module(
        &self,
        dir: &Path,
        stem: &str,
        source: &[u8],
        imports: &[String],
    ) -> Result<()> {
        tokio::fs::write(dir.join(format!("{}.go", stem)), source).await?;
        tokio::fs::write(dir.join("go.mod"), modules::generate_go_mod()).await?;

        let tidy = self
            .go_command(dir)
            .args(["mod", "tidy"])
            .output()
            .await
            .map_err(|e| Error::Execution(format!("Failed to run go mod tidy: {}", e)))?;
        if !tidy.status.success() {
            let stderr = String::from_utf8_lossy(&tidy.stderr);
            let mut message = format!(
                "Go template imports packages outside the standard library ({}) and is not \
                 inside a Go module, so cxg resolves them in a private module at {} with \
                 `go mod tidy`, which failed:\n{}",
                imports.join(", "),
                dir.display(),
                stderr.trim_end()
            );
            if let Some(hint) = modules::tidy_failure_hint(&stderr) {
                message.push_str("\nHint: ");
                message.push_str(hint);
            }
            return Err(Error::Execution(message));
        }

        let build = self
            .go_command(dir)
            .arg("build")
            .arg("-o")
            .arg(dir.join(stem))
            .arg(".")
            .output()
            .await
            .map_err(|e| Error::Execution(format!("Failed to compile Go template: {}", e)))?;
        if !build.status.success() {
            return Err(Error::Execution(format!(
                "Go compilation failed: {}",
                String::from_utf8_lossy(&build.stderr)
            )));
        }
        Ok(())
    }

    /// A `go` invocation for the private module in `dir`.
    ///
    /// The operator's environment is inherited untouched -- GOPATH, GOMODCACHE,
    /// GOCACHE, GOFLAGS, GOPROXY, GONOSUMDB, GOTOOLCHAIN all apply -- except the
    /// two variables that would stop a generated module from being one:
    /// `GO111MODULE=on` (the directory is a module by construction) and
    /// `GOWORK=off` (a private module must not join the operator's workspace).
    /// The child is killed if the scan's template timeout drops this future, so
    /// a stalled download cannot outlive the scan.
    // @comment -- "go subprocess for the private module: inherits operator Go env, forces module mode, opts out of go.work, killed on template timeout"
    fn go_command(&self, dir: &Path) -> Command {
        let mut cmd = Command::new(&self.go_path);
        cmd.current_dir(dir)
            .env("GO111MODULE", "on")
            .env("GOWORK", "off")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    }

    /// Compile Go template to binary
    ///
    /// Runs in the template's own directory, so a template inside a Go module
    /// is built against that module rather than whatever module cxg was
    /// launched from.
    async fn compile_template(&self, source_path: &Path, binary_path: &Path) -> Result<()> {
        if !check_tool_available(&self.go_path).await {
            return Err(Error::Execution("Go compiler not found".to_string()));
        }

        // Absolute, because the build no longer runs in cxg's own directory.
        let source_abs =
            std::fs::canonicalize(source_path).unwrap_or_else(|_| source_path.to_path_buf());
        let output = Command::new(&self.go_path)
            .current_dir(template_dir(source_path))
            .arg("build")
            .arg("-o")
            .arg(binary_path)
            .arg(&source_abs)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| Error::Execution(format!("Failed to compile Go template: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Execution(format!(
                "Go compilation failed: {}",
                stderr
            )));
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

/// The directory a template lives in, as an absolute path where possible.
fn template_dir(template_path: &Path) -> PathBuf {
    let absolute = std::fs::canonicalize(template_path).unwrap_or_else(|_| template_path.into());
    match absolute.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
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
    /// Compile (and, for a private module, resolve imports) before the probe
    /// timeout starts; `execute` then finds the binary already built.
    // @comment -- "Go build runs in the executor's prepare phase, outside the probe timeout"
    async fn prepare(&self) -> Result<()> {
        self.engine.ensure_binary(&self.path).await.map(|_| ())
    }

    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        self.engine
            .execute_go_template(&self.path, target, context)
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
