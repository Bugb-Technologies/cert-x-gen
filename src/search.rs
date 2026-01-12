//! Template search functionality for CERT-X-GEN

// Note: CLI types are defined in main.rs, not in the library
// We'll define the search types here instead
use crate::types::{Severity, TemplateLanguage};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::time::SystemTime;

/// Search arguments structure
#[derive(Debug, Clone)]
pub struct SearchArgs {
    /// Search query string

    pub query: Option<String>,
    /// Filter by template language

    pub language: Option<TemplateLanguage>,
    /// Filter by severity level

    pub severity: Option<Severity>,
    /// Filter by tags (comma-separated)

    pub tags: Option<String>,
    /// Filter by author name

    pub author: Option<String>,
    /// Filter by CWE identifier

    /// CWE identifier if applicable

    pub cwe: Option<String>,
    /// Search in template content

    pub content: bool,
    /// Case-sensitive search

    pub case_sensitive: bool,
    /// Use regex for search

    pub regex: bool,
    /// Maximum number of results

    pub limit: usize,
    /// Output format

    pub format: SearchFormat,
    /// Show detailed results

    pub detailed: bool,
    /// Sort order

    pub sort: SearchSort,
    /// Reverse sort order

    pub reverse: bool,
    /// Output only template IDs

    pub ids_only: bool,
    /// Show search statistics

    pub stats: bool,
}

/// Search output format
#[derive(Debug, Clone, Copy)]
pub enum SearchFormat {
    /// Table format

    Table,
    /// JSON format

    Json,
    /// YAML format

    Yaml,
    /// CSV format

    Csv,
    /// Simple list format

    List,
    /// Detailed format with all metadata

    Detailed,
}

/// Search sort options
#[derive(Debug, Clone, Copy)]
pub enum SearchSort {
    /// Sort by relevance score

    Relevance,
    /// Sort by template name

    Name,
    /// Sort by programming language

    Language,
    /// Sort by severity level

    Severity,
    /// Sort by author name

    Author,
    /// Sort by last modified date

    Date,
    /// Sort by popularity/usage

    Popularity,
}

/// Search result for a template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Template ID

    pub id: String,
    /// Template name

    pub name: String,
    /// Template description

    pub description: String,
    /// Template language

    pub language: TemplateLanguage,
    /// Severity level

    pub severity: Severity,
    /// Author name

    pub author: String,
    /// Template tags

    pub tags: Vec<String>,
    /// Filter by CWE identifier

    /// CWE identifier if applicable

    pub cwe: Option<String>,
    /// File system path to template

    pub file_path: String,
    /// Search relevance score (0.0-1.0)

    pub relevance_score: f64,
    /// Fields that matched the search

    pub match_fields: Vec<String>,
    /// Preview of matching content

    pub content_preview: Option<String>,
}

/// Search statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchStats {
    /// Total number of templates in index

    pub total_templates: usize,
    /// Number of templates matching search

    pub matching_templates: usize,
    /// Template count by language

    pub languages: HashMap<TemplateLanguage, usize>,
    /// Template count by severity

    pub severities: HashMap<Severity, usize>,
    /// Search execution time in milliseconds

    pub search_time_ms: u64,
}

/// Template search engine
#[derive(Debug)]
pub struct TemplateSearchEngine {
    templates: Vec<SearchResult>,
    #[allow(dead_code)]
    index: HashMap<String, Vec<usize>>, // word -> template indices
    #[allow(dead_code)]
    content_index: HashMap<String, Vec<usize>>, // word -> template indices (content)
}

impl TemplateSearchEngine {
    /// Create a new search engine from loaded templates
    pub fn new(templates: Vec<Box<dyn crate::template::Template>>) -> Self {
        let mut search_results = Vec::new();
        let mut index = HashMap::new();
        let mut content_index = HashMap::new();

        for (i, template) in templates.iter().enumerate() {
            let metadata = template.metadata();
            
            // Create search result
            let search_result = SearchResult {
                id: metadata.id.clone(),
                name: metadata.name.clone(),
                description: metadata.description.clone(),
                language: metadata.language,
                severity: metadata.severity,
                author: metadata.author.name.clone(),
                tags: metadata.tags.clone(),
                cwe: metadata.cwe_ids.first().cloned(),
                file_path: metadata.file_path.to_string_lossy().to_string(),
                relevance_score: 0.0,
                match_fields: Vec::new(),
                content_preview: None,
            };

            // Build search index
            Self::index_template(&search_result, i, &mut index);
            
            // Build content index if available
            if let Ok(content) = fs::read_to_string(&metadata.file_path) {
                Self::index_content(&content, i, &mut content_index);
            }

            search_results.push(search_result);
        }

        Self {
            templates: search_results,
            index,
            content_index,
        }
    }

    /// Index a template for search
    fn index_template(
        template: &SearchResult,
        index: usize,
        search_index: &mut HashMap<String, Vec<usize>>,
    ) {
        let text = format!(
            "{} {} {} {} {}",
            template.id,
            template.name,
            template.description,
            template.author,
            template.tags.join(" ")
        );

        for word in Self::extract_words(&text) {
            search_index.entry(word).or_insert_with(Vec::new).push(index);
        }
    }

    /// Index template content for search
    fn index_content(
        content: &str,
        index: usize,
        content_index: &mut HashMap<String, Vec<usize>>,
    ) {
        for word in Self::extract_words(content) {
            content_index.entry(word).or_insert_with(Vec::new).push(index);
        }
    }

    /// Extract words from text for indexing
    fn extract_words(text: &str) -> Vec<String> {
        text.split_whitespace()
            .map(|word| word.to_lowercase())
            .filter(|word| word.len() > 2) // Filter out short words
            .collect()
    }

    /// Search templates with the given criteria
    pub fn search(&self, args: &SearchArgs) -> (Vec<SearchResult>, SearchStats) {
        let start_time = SystemTime::now();
        
        let mut results = self.templates.clone();
        let total_templates = results.len();

        // Apply filters
        results = self.apply_filters(results, args);

        // Apply search query
        if let Some(query) = &args.query {
            results = self.apply_search_query(results, query, args);
        }

        // Sort results
        results = self.sort_results(results, args);

        // Apply limit
        if results.len() > args.limit {
            results.truncate(args.limit);
        }

        // Calculate statistics
        let search_time = start_time.elapsed().unwrap_or_default().as_millis() as u64;
        let stats = self.calculate_stats(&results, total_templates, search_time);

        (results, stats)
    }

    /// Apply filters to search results
    fn apply_filters(&self, mut results: Vec<SearchResult>, args: &SearchArgs) -> Vec<SearchResult> {
        // Filter by language
        if let Some(language) = &args.language {
            let target_language: TemplateLanguage = (*language).into();
            results.retain(|template| template.language == target_language);
        }

        // Filter by severity
        if let Some(severity) = &args.severity {
            let target_severity: Severity = (*severity).into();
            results.retain(|template| template.severity == target_severity);
        }

        // Filter by tags
        if let Some(tags) = &args.tags {
            let target_tags: Vec<String> = tags.split(',').map(|s| s.trim().to_string()).collect();
            results.retain(|template| {
                target_tags.iter().any(|tag| template.tags.contains(tag))
            });
        }

        // Filter by author
        if let Some(author) = &args.author {
            results.retain(|template| {
                template.author.to_lowercase().contains(&author.to_lowercase())
            });
        }

        // Filter by CWE
        if let Some(cwe) = &args.cwe {
            results.retain(|template| {
                template.cwe.as_ref().map_or(false, |t| t.contains(cwe))
            });
        }

        results
    }

    /// Apply search query to results
    fn apply_search_query(
        &self,
        mut results: Vec<SearchResult>,
        query: &str,
        args: &SearchArgs,
    ) -> Vec<SearchResult> {
        let query_lower = if args.case_sensitive {
            query.to_string()
        } else {
            query.to_lowercase()
        };

        // Create regex if requested
        let regex = if args.regex {
            Regex::new(&query_lower).ok()
        } else {
            None
        };

        // Score and filter results
        for result in &mut results {
            let mut score = 0.0;
            let mut match_fields = Vec::new();

            // Search in basic fields
            let fields = [
                ("id", &result.id),
                ("name", &result.name),
                ("description", &result.description),
                ("author", &result.author),
                ("tags", &result.tags.join(" ")),
            ];

            for (field_name, field_value) in &fields {
                let field_lower: String = if args.case_sensitive {
                    field_value.to_string()
                } else {
                    field_value.to_lowercase()
                };

                if let Some(regex) = &regex {
                    if regex.is_match(&field_lower) {
                        score += 10.0;
                        match_fields.push(field_name.to_string());
                    }
                } else if field_lower.contains(&query_lower) {
                    // Exact match gets higher score
                    if field_lower == query_lower {
                        score += 20.0;
                    } else {
                        score += 5.0;
                    }
                    match_fields.push(field_name.to_string());
                }
            }

            // Search in content if requested
            if args.content {
                if let Ok(content) = fs::read_to_string(&result.file_path) {
                    let content_lower = if args.case_sensitive {
                        content.clone()
                    } else {
                        content.to_lowercase()
                    };

                    if let Some(regex) = &regex {
                        if regex.is_match(&content_lower) {
                            score += 2.0;
                            match_fields.push("content".to_string());
                            
                            // Add content preview
                            if result.content_preview.is_none() {
                                result.content_preview = Some(self.extract_preview(&content, &query_lower));
                            }
                        }
                    } else if content_lower.contains(&query_lower) {
                        score += 1.0;
                        match_fields.push("content".to_string());
                        
                        // Add content preview
                        if result.content_preview.is_none() {
                            result.content_preview = Some(self.extract_preview(&content, &query_lower));
                        }
                    }
                }
            }

            result.relevance_score = score;
            result.match_fields = match_fields;
        }

        // Filter out results with zero score
        results.retain(|result| result.relevance_score > 0.0);

        results
    }

    /// Extract a preview of content around the search term
    fn extract_preview(&self, content: &str, query: &str) -> String {
        const PREVIEW_LENGTH: usize = 200;
        
        if let Some(pos) = content.to_lowercase().find(&query.to_lowercase()) {
            let start = pos.saturating_sub(PREVIEW_LENGTH / 2);
            let end = (pos + query.len() + PREVIEW_LENGTH / 2).min(content.len());
            let preview = &content[start..end];
            
            if start > 0 {
                format!("...{}...", preview)
            } else {
                format!("{}...", preview)
            }
        } else {
            content.chars().take(PREVIEW_LENGTH).collect::<String>() + "..."
        }
    }

    /// Sort results based on the specified criteria
    fn sort_results(&self, mut results: Vec<SearchResult>, args: &SearchArgs) -> Vec<SearchResult> {
        match args.sort {
            SearchSort::Relevance => {
                results.sort_by(|a, b| b.relevance_score.partial_cmp(&a.relevance_score).unwrap());
            }
            SearchSort::Name => {
                results.sort_by(|a, b| a.name.cmp(&b.name));
            }
            SearchSort::Language => {
                results.sort_by(|a, b| format!("{:?}", a.language).cmp(&format!("{:?}", b.language)));
            }
            SearchSort::Severity => {
                results.sort_by(|a, b| {
                    let severity_order = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];
                    let a_order = severity_order.iter().position(|&s| s == a.severity).unwrap_or(5);
                    let b_order = severity_order.iter().position(|&s| s == b.severity).unwrap_or(5);
                    a_order.cmp(&b_order)
                });
            }
            SearchSort::Author => {
                results.sort_by(|a, b| a.author.cmp(&b.author));
            }
            SearchSort::Date => {
                // For now, sort by file modification time
                results.sort_by(|a, b| {
                    let a_time = fs::metadata(&a.file_path).and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
                    let b_time = fs::metadata(&b.file_path).and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
                    b_time.cmp(&a_time) // Newest first
                });
            }
            SearchSort::Popularity => {
                // For now, sort by relevance score as a proxy for popularity
                results.sort_by(|a, b| b.relevance_score.partial_cmp(&a.relevance_score).unwrap());
            }
        }

        if args.reverse {
            results.reverse();
        }

        results
    }

    /// Calculate search statistics
    fn calculate_stats(
        &self,
        results: &[SearchResult],
        total_templates: usize,
        search_time_ms: u64,
    ) -> SearchStats {
        let mut languages = HashMap::new();
        let mut severities = HashMap::new();

        for result in results {
            *languages.entry(result.language).or_insert(0) += 1;
            *severities.entry(result.severity).or_insert(0) += 1;
        }

        SearchStats {
            total_templates,
            matching_templates: results.len(),
            languages,
            severities,
            search_time_ms,
        }
    }
}

/// Format search results for output
#[derive(Debug)]
pub struct SearchResultFormatter;

impl SearchResultFormatter {
    /// Format search results based on the specified format
    pub fn format_results(
        results: &[SearchResult],
        stats: &SearchStats,
        format: SearchFormat,
        detailed: bool,
        ids_only: bool,
    ) -> String {
        match format {
            SearchFormat::Table => Self::format_table(results, stats, detailed),
            SearchFormat::Json => Self::format_json(results, stats),
            SearchFormat::Yaml => Self::format_yaml(results, stats),
            SearchFormat::Csv => Self::format_csv(results),
            SearchFormat::List => Self::format_list(results, ids_only),
            SearchFormat::Detailed => Self::format_detailed(results, stats),
        }
    }

    /// Format results as a table
    fn format_table(results: &[SearchResult], stats: &SearchStats, detailed: bool) -> String {
        let mut output = String::new();

        // Add statistics
        output.push_str(&format!(
            "Found {} templates ({} total)\n",
            stats.matching_templates, stats.total_templates
        ));
        output.push_str(&format!("Search time: {}ms\n\n", stats.search_time_ms));

        if results.is_empty() {
            output.push_str("No templates found matching your criteria.\n");
            return output;
        }

        if detailed {
            // Detailed table format
            output.push_str("┌─────────────────────────────────────────────────────────────────────────────────────────────────┐\n");
            output.push_str("│ Template Search Results                                                                        │\n");
            output.push_str("├─────────────────────────────────────────────────────────────────────────────────────────────────┤\n");

            for result in results {
                output.push_str(&format!(
                    "│ ID: {:<20} │ Name: {:<30} │ Language: {:<10} │ Severity: {:<8} │\n",
                    result.id,
                    result.name,
                    format!("{:?}", result.language),
                    format!("{:?}", result.severity)
                ));
                output.push_str(&format!(
                    "│ Author: {:<18} │ Tags: {:<40} │ Score: {:<8.2} │\n",
                    result.author,
                    result.tags.join(", "),
                    result.relevance_score
                ));
                if !result.match_fields.is_empty() {
                    output.push_str(&format!(
                        "│ Matched in: {:<66} │\n",
                        result.match_fields.join(", ")
                    ));
                }
                if let Some(preview) = &result.content_preview {
                    output.push_str(&format!(
                        "│ Preview: {:<68} │\n",
                        preview.chars().take(70).collect::<String>()
                    ));
                }
                output.push_str("├─────────────────────────────────────────────────────────────────────────────────────────────────┤\n");
            }
            output.push_str("└─────────────────────────────────────────────────────────────────────────────────────────────────┘\n");
        } else {
            // Simple table format
            output.push_str("┌─────────────────────────────────────────────────────────────────────────────────────────────────┐\n");
            output.push_str("│ ID                    │ Name                          │ Language   │ Severity │ Score │\n");
            output.push_str("├─────────────────────────────────────────────────────────────────────────────────────────────────┤\n");

            for result in results {
                output.push_str(&format!(
                    "│ {:<20} │ {:<28} │ {:<10} │ {:<8} │ {:<5.2} │\n",
                    result.id,
                    result.name.chars().take(28).collect::<String>(),
                    format!("{:?}", result.language),
                    format!("{:?}", result.severity),
                    result.relevance_score
                ));
            }
            output.push_str("└─────────────────────────────────────────────────────────────────────────────────────────────────┘\n");
        }

        output
    }

    /// Format results as JSON
    fn format_json(results: &[SearchResult], stats: &SearchStats) -> String {
        let data = serde_json::json!({
            "statistics": stats,
            "results": results
        });
        serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format results as YAML
    fn format_yaml(results: &[SearchResult], stats: &SearchStats) -> String {
        let data = serde_yaml::to_string(&serde_json::json!({
            "statistics": stats,
            "results": results
        })).unwrap_or_else(|_| "".to_string());
        data
    }

    /// Format results as CSV
    fn format_csv(results: &[SearchResult]) -> String {
        let mut output = String::new();
        output.push_str("ID,Name,Description,Language,Severity,Author,Tags,CWE,Score,Match Fields\n");

        for result in results {
            output.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                result.id,
                result.name,
                result.description.replace(',', ";"),
                format!("{:?}", result.language),
                format!("{:?}", result.severity),
                result.author,
                result.tags.join(";"),
                result.cwe.as_deref().unwrap_or(""),
                result.relevance_score,
                result.match_fields.join(";")
            ));
        }

        output
    }

    /// Format results as a simple list
    fn format_list(results: &[SearchResult], ids_only: bool) -> String {
        let mut output = String::new();

        if ids_only {
            for result in results {
                output.push_str(&format!("{}\n", result.id));
            }
        } else {
            for result in results {
                output.push_str(&format!(
                    "{} - {} ({:?}, {:?})\n",
                    result.id,
                    result.name,
                    result.language,
                    result.severity
                ));
            }
        }

        output
    }

    /// Format results with detailed information
    fn format_detailed(results: &[SearchResult], stats: &SearchStats) -> String {
        let mut output = String::new();

        // Add statistics
        output.push_str(&format!(
            "Search Statistics:\n\
            - Total templates: {}\n\
            - Matching templates: {}\n\
            - Search time: {}ms\n\n",
            stats.total_templates,
            stats.matching_templates,
            stats.search_time_ms
        ));

        // Add language breakdown
        if !stats.languages.is_empty() {
            output.push_str("Languages:\n");
            for (language, count) in &stats.languages {
                output.push_str(&format!("  - {:?}: {}\n", language, count));
            }
            output.push_str("\n");
        }

        // Add severity breakdown
        if !stats.severities.is_empty() {
            output.push_str("Severities:\n");
            for (severity, count) in &stats.severities {
                output.push_str(&format!("  - {:?}: {}\n", severity, count));
            }
            output.push_str("\n");
        }

        // Add detailed results
        for (i, result) in results.iter().enumerate() {
            output.push_str(&format!(
                "Result {}: {}\n\
                ===================\n\
                ID: {}\n\
                Name: {}\n\
                Description: {}\n\
                Language: {:?}\n\
                Severity: {:?}\n\
                Author: {}\n\
                Tags: {}\n\
                CWE: {}\n\
                File: {}\n\
                Relevance Score: {:.2}\n\
                Match Fields: {}\n",
                i + 1,
                result.name,
                result.id,
                result.name,
                result.description,
                result.language,
                result.severity,
                result.author,
                result.tags.join(", "),
                result.cwe.as_deref().unwrap_or("N/A"),
                result.file_path,
                result.relevance_score,
                result.match_fields.join(", ")
            ));

            if let Some(preview) = &result.content_preview {
                output.push_str(&format!("Content Preview: {}\n", preview));
            }

            output.push_str("\n");
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Severity, TemplateLanguage};
    use std::path::PathBuf;

    #[test]
    fn test_search_engine_creation() {
        // This would need actual template data to test
        // For now, just test that the struct can be created
        let engine = TemplateSearchEngine {
            templates: Vec::new(),
            index: HashMap::new(),
            content_index: HashMap::new(),
        };
        assert_eq!(engine.templates.len(), 0);
    }

    #[test]
    fn test_word_extraction() {
        let text = "SQL injection detection template";
        let words = TemplateSearchEngine::extract_words(text);
        assert!(words.contains(&"sql".to_string()));
        assert!(words.contains(&"injection".to_string()));
        assert!(words.contains(&"detection".to_string()));
        assert!(words.contains(&"template".to_string()));
    }

    #[test]
    fn test_content_preview_extraction() {
        let engine = TemplateSearchEngine {
            templates: Vec::new(),
            index: HashMap::new(),
            content_index: HashMap::new(),
        };

        let content = "This is a long content with the word injection in the middle of the text and more content after it";
        let query = "injection";
        let preview = engine.extract_preview(content, query);
        
        assert!(preview.contains("injection"));
        assert!(preview.len() <= 200 + 6); // 200 chars + "..."
    }
}
