//! Template statistics and counting utilities

use crate::template::paths::PathResolver;
use std::collections::HashMap;
use std::path::Path;
use walkdir::WalkDir;

/// Template statistics
#[derive(Debug, Default)]
pub struct TemplateStats {
    /// Total number of templates
    pub total: usize,
    /// Count of templates by language
    pub by_language: HashMap<String, usize>,
}

impl TemplateStats {
    /// Count templates in a directory
    pub fn from_directory(path: &Path) -> Self {
        let mut stats = Self::default();

        if !path.exists() {
            return stats;
        }

        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();

            // Skip skeleton templates and hidden files
            if path.to_string_lossy().contains("skeleton")
                || path
                    .file_name()
                    .map(|n| n.to_string_lossy().starts_with('.'))
                    .unwrap_or(false)
            {
                continue;
            }

            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let lang = match ext {
                    "py" => "python",
                    "js" => "javascript",
                    "rs" => "rust",
                    "c" => "c",
                    "cpp" | "cc" | "cxx" => "cpp",
                    "go" => "go",
                    "java" => "java",
                    "rb" => "ruby",
                    "pl" => "perl",
                    "php" => "php",
                    "sh" | "bash" => "shell",
                    "yaml" | "yml" => "yaml",
                    _ => continue,
                };

                stats.total += 1;
                *stats.by_language.entry(lang.to_string()).or_insert(0) += 1;
            }
        }

        stats
    }

    /// Count templates from installed template directories only
    /// (user and system directories, not local dev directories)
    pub fn from_all_directories() -> Self {
        let mut combined = Self::default();

        // Only count from user and system directories (not ./templates which is for dev)
        let user_dir = PathResolver::user_template_dir();
        let system_dir = PathResolver::system_template_dir();

        for dir in [user_dir, system_dir] {
            let stats = Self::from_directory(&dir);
            combined.total += stats.total;

            for (lang, count) in stats.by_language {
                *combined.by_language.entry(lang).or_insert(0) += count;
            }
        }

        combined
    }

    /// Format stats as a summary string
    pub fn summary(&self) -> String {
        if self.total == 0 {
            return "No templates installed".to_string();
        }

        let mut parts: Vec<String> = Vec::new();

        // Sort languages by count (descending)
        let mut langs: Vec<_> = self.by_language.iter().collect();
        langs.sort_by(|a, b| b.1.cmp(a.1));

        for (lang, count) in langs.iter().take(5) {
            parts.push(format!("{}: {}", lang, count));
        }

        if langs.len() > 5 {
            let others: usize = langs.iter().skip(5).map(|(_, c)| *c).sum();
            if others > 0 {
                parts.push(format!("others: {}", others));
            }
        }

        format!("{} templates ({})", self.total, parts.join(", "))
    }

    /// Format stats as a detailed breakdown
    pub fn detailed(&self) -> String {
        if self.total == 0 {
            return "No templates installed".to_string();
        }

        let mut lines = vec![format!("Total: {} templates", self.total)];

        // Sort languages alphabetically
        let mut langs: Vec<_> = self.by_language.iter().collect();
        langs.sort_by(|a, b| a.0.cmp(b.0));

        for (lang, count) in langs {
            lines.push(format!("  {}: {}", lang, count));
        }

        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let stats = TemplateStats::from_directory(temp_dir.path());
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn test_count_templates() {
        let temp_dir = TempDir::new().unwrap();

        // Create some test files
        fs::write(temp_dir.path().join("test1.py"), "# python").unwrap();
        fs::write(temp_dir.path().join("test2.py"), "# python").unwrap();
        fs::write(temp_dir.path().join("test.yaml"), "id: test").unwrap();
        fs::write(temp_dir.path().join("test.rs"), "// rust").unwrap();

        let stats = TemplateStats::from_directory(temp_dir.path());

        assert_eq!(stats.total, 4);
        assert_eq!(stats.by_language.get("python"), Some(&2));
        assert_eq!(stats.by_language.get("yaml"), Some(&1));
        assert_eq!(stats.by_language.get("rust"), Some(&1));
    }

    #[test]
    fn test_summary_format() {
        let mut stats = TemplateStats::default();
        stats.total = 63;
        stats.by_language.insert("yaml".to_string(), 25);
        stats.by_language.insert("python".to_string(), 10);
        stats.by_language.insert("rust".to_string(), 8);

        let summary = stats.summary();
        assert!(summary.contains("63 templates"));
        assert!(summary.contains("yaml: 25"));
    }
}
