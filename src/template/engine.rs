//! Template system for CERT-X-GEN
//!
//! Provides abstractions for multi-language template support.

use crate::error::{Error, Result};
use crate::types::{Context, Finding, Protocol, Target, TemplateMetadata};
use async_trait::async_trait;
use std::path::Path;

/// Template trait that all templates must implement
#[async_trait]
pub trait Template: Send + Sync {
    /// Get template metadata
    fn metadata(&self) -> &TemplateMetadata;

    /// Execute the template against a target
    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>>;

    /// Validate the template
    fn validate(&self) -> Result<()> {
        Ok(())
    }

    /// Get supported protocols
    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Http, Protocol::Https]
    }

    /// Get template name
    fn name(&self) -> &str {
        &self.metadata().name
    }

    /// Get template ID
    fn id(&self) -> &str {
        &self.metadata().id
    }
}

/// Template engine trait
#[async_trait]
pub trait TemplateEngine: Send + Sync {
    /// Load a template from file
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>>;

    /// Validate a template
    async fn validate_template(&self, template: &dyn Template) -> Result<()>;

    /// Execute a template
    async fn execute_template(
        &self,
        template: &dyn Template,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>>;

    /// Get supported protocols
    fn supported_protocols(&self) -> Vec<Protocol>;

    /// Get engine name
    fn name(&self) -> &str;

    /// Check if engine supports a file
    fn supports_file(&self, path: &Path) -> bool;
}

/// Template loader for managing multiple template engines
#[allow(missing_debug_implementations)]
pub struct TemplateLoader {
    engines: Vec<Box<dyn TemplateEngine>>,
}

impl TemplateLoader {
    /// Create a new template loader
    pub fn new() -> Self {
        Self {
            engines: Vec::new(),
        }
    }

    /// Register a template engine
    pub fn register_engine(&mut self, engine: Box<dyn TemplateEngine>) {
        self.engines.push(engine);
    }

    /// Load a template from file
    pub async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        for engine in &self.engines {
            if engine.supports_file(path) {
                return engine.load_template(path).await;
            }
        }

        Err(Error::TemplateNotFound(
            path.display().to_string(),
        ))
    }

    /// Check if a file has a valid template extension
    fn is_valid_template_file(path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            matches!(
                ext,
                "yaml" | "yml" |  // YAML templates
                "py" |            // Python
                "js" |            // JavaScript
                "rs" |            // Rust
                "c" |             // C
                "cpp" | "cc" | "cxx" | // C++
                "java" |          // Java
                "go" |            // Go
                "rb" |            // Ruby
                "pl" |            // Perl
                "php" |           // PHP
                "sh" | "bash"     // Shell
            )
        } else {
            false
        }
    }

    /// Load all templates from a directory
    pub fn load_templates_from_dir<'a>(
        &'a self,
        dir: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Box<dyn Template>>>> + 'a>> {
        Box::pin(async move {
            let mut templates = Vec::new();

            if !dir.exists() {
                return Err(Error::FileNotFound(dir.to_path_buf()));
            }

            let entries = std::fs::read_dir(dir).map_err(|e| {
                Error::config(format!("Failed to read template directory: {}", e))
            })?;

            for entry in entries {
                let entry = entry.map_err(|e| {
                    Error::config(format!("Failed to read directory entry: {}", e))
                })?;
                let path = entry.path();

                if path.is_file() {
                    // Only attempt to load files with valid template extensions
                    if !Self::is_valid_template_file(&path) {
                        tracing::trace!("Skipping non-template file: {}", path.display());
                        continue;
                    }

                    match self.load_template(&path).await {
                        Ok(template) => templates.push(template),
                        Err(e) => {
                            tracing::warn!("Failed to load template {}: {}", path.display(), e);
                        }
                    }
                } else if path.is_dir() {
                    // Skip build artifact directories, disabled templates, and skeleton templates
                    if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                        if matches!(dir_name, "target" | "node_modules" | ".git" | "__pycache__" | "_disabled" | "skeleton") {
                            tracing::trace!("Skipping excluded directory: {}", path.display());
                            continue;
                        }
                    }

                    // Recursively load templates from subdirectories
                    match self.load_templates_from_dir(&path).await {
                        Ok(mut sub_templates) => templates.append(&mut sub_templates),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to load templates from {}: {}",
                                path.display(),
                                e
                            );
                        }
                    }
                }
            }

            Ok(templates)
        })
    }

    /// Get all registered engines
    pub fn engines(&self) -> &[Box<dyn TemplateEngine>] {
        &self.engines
    }
}

impl Default for TemplateLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Template filter for selecting templates
#[derive(Debug, Clone, Default)]
pub struct TemplateFilter {
    /// Filter by template IDs
    pub ids: Vec<String>,
    /// Filter by tags
    pub tags: Vec<String>,
    /// Filter by severity
    pub severities: Vec<crate::types::Severity>,
    /// Filter by language
    pub languages: Vec<crate::types::TemplateLanguage>,
    /// Exclude template IDs
    pub exclude_ids: Vec<String>,
}

impl TemplateFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a template matches the filter
    pub fn matches(&self, template: &dyn Template) -> bool {
        let metadata = template.metadata();

        // Check ID filter (supports both template ID and file path)
        if !self.ids.is_empty() {
            let matches_id = self.ids.iter().any(|filter_id| {
                // Exact ID match (case-insensitive)
                if metadata.id.eq_ignore_ascii_case(filter_id) {
                    return true;
                }
                
                // Check if the file path ends with the filter (for path-based matching)
                let file_path_str = metadata.file_path.to_string_lossy();
                if file_path_str.ends_with(filter_id) {
                    return true;
                }
                
                // Check if filter is a full or partial path that matches
                // Normalize both paths for comparison
                let normalized_filter = filter_id.replace('\\', "/");
                let normalized_path = file_path_str.replace('\\', "/");
                
                if normalized_path.ends_with(&normalized_filter) {
                    return true;
                }
                
                // Check if the file name (without extension) matches the filter
                if let Some(file_name) = metadata.file_path.file_stem() {
                    if file_name.to_string_lossy().eq_ignore_ascii_case(filter_id) {
                        return true;
                    }
                }
                
                false
            });
            
            if !matches_id {
                return false;
            }
        }

        // Check exclusion (supports wildcards)
        for exclude_pattern in &self.exclude_ids {
            if metadata.id.contains(exclude_pattern) || exclude_pattern.contains(&metadata.id) {
                return false;
            }
            
            // Check file path for exclusion
            let file_path_str = metadata.file_path.to_string_lossy();
            if file_path_str.contains(exclude_pattern) {
                return false;
            }
        }

        // Check tags
        if !self.tags.is_empty() {
            let has_matching_tag = self
                .tags
                .iter()
                .any(|tag| metadata.tags.contains(tag));
            if !has_matching_tag {
                return false;
            }
        }

        // Check severity
        if !self.severities.is_empty() && !self.severities.contains(&metadata.severity) {
            return false;
        }

        // Check language
        if !self.languages.is_empty() && !self.languages.contains(&metadata.language) {
            return false;
        }

        true
    }

    /// Filter a list of templates
    pub fn filter<'a>(
        &self,
        templates: &'a [Box<dyn Template>],
    ) -> Vec<&'a Box<dyn Template>> {
        templates
            .iter()
            .filter(|t| self.matches(t.as_ref()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthorInfo, Severity, TemplateLanguage};
    use chrono::Utc;
    use std::path::PathBuf;

    struct MockTemplate {
        metadata: TemplateMetadata,
    }

    #[async_trait]
    impl Template for MockTemplate {
        fn metadata(&self) -> &TemplateMetadata {
            &self.metadata
        }

        async fn execute(&self, _target: &Target, _context: &Context) -> Result<Vec<Finding>> {
            Ok(Vec::new())
        }
    }

    fn create_test_template(id: &str, tags: Vec<String>, severity: Severity) -> Box<dyn Template> {
        Box::new(MockTemplate {
            metadata: TemplateMetadata {
                id: id.to_string(),
                name: format!("Test Template {}", id),
                author: AuthorInfo {
                    name: "Test Author".to_string(),
                    email: None,
                    github: None,
                },
                severity,
                description: "Test template".to_string(),
                cve_ids: Vec::new(),
                cwe_ids: Vec::new(),
                cvss_score: None,
                tags,
                language: TemplateLanguage::Yaml,
                file_path: PathBuf::from("test.yaml"),
                created: Utc::now(),
                updated: Utc::now(),
                version: "1.0".to_string(),
                confidence: None,
            },
        })
    }

    #[test]
    fn test_template_filter() {
        let templates = vec![
            create_test_template("CVE-2024-1", vec!["rce".to_string()], Severity::Critical),
            create_test_template("CVE-2024-2", vec!["sqli".to_string()], Severity::High),
            create_test_template("CVE-2024-3", vec!["xss".to_string()], Severity::Medium),
        ];

        let mut filter = TemplateFilter::new();
        filter.tags.push("rce".to_string());

        let filtered = filter.filter(&templates);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id(), "CVE-2024-1");
    }

    #[test]
    fn test_template_filter_severity() {
        let templates = vec![
            create_test_template("CVE-2024-1", Vec::new(), Severity::Critical),
            create_test_template("CVE-2024-2", Vec::new(), Severity::High),
            create_test_template("CVE-2024-3", Vec::new(), Severity::Medium),
        ];

        let mut filter = TemplateFilter::new();
        filter.severities.push(Severity::Critical);
        filter.severities.push(Severity::High);

        let filtered = filter.filter(&templates);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_template_filter_exclusion() {
        let templates = vec![
            create_test_template("CVE-2024-1", Vec::new(), Severity::Critical),
            create_test_template("CVE-2024-2", Vec::new(), Severity::High),
        ];

        let mut filter = TemplateFilter::new();
        filter.exclude_ids.push("CVE-2024-1".to_string());

        let filtered = filter.filter(&templates);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id(), "CVE-2024-2");
    }
}
