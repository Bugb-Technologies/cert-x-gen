//! Scheduler for template execution prioritization and resource management

use crate::config::Config;
use crate::core::ScanJob;
use crate::error::{Error, Result};
use crate::template::Template;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;

/// Scheduler for managing template execution order
#[derive(Debug)]
pub struct Scheduler {
    #[allow(dead_code)]
    config: Arc<Config>,
    priority_queue: BinaryHeap<PrioritizedTemplate>,
}

impl Scheduler {
    /// Create a new scheduler
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            priority_queue: BinaryHeap::new(),
        }
    }

    /// Schedule a scan job
    pub fn schedule_job(&mut self, job: &ScanJob) -> Result<()> {
        tracing::debug!("Scheduling job {} with {} templates", job.id, job.templates.len());

        for template in &job.templates {
            let prioritized = PrioritizedTemplate::new(template.as_ref());
            self.priority_queue.push(prioritized);
        }

        Ok(())
    }

    /// Get next template to execute
    pub fn next_template(&mut self) -> Option<PrioritizedTemplate> {
        self.priority_queue.pop()
    }

    /// Get number of pending templates
    pub fn pending_count(&self) -> usize {
        self.priority_queue.len()
    }

    /// Clear the schedule
    pub fn clear(&mut self) {
        self.priority_queue.clear();
    }
}

/// Template with priority information
#[derive(Debug, Clone)]
pub struct PrioritizedTemplate {
    /// Template ID
    pub template_id: String,
    /// Priority score (higher = more important)
    pub priority: u32,
    /// Template severity score
    pub severity_score: u8,
    /// Estimated execution time (milliseconds)
    pub estimated_time_ms: u64,
}

impl PrioritizedTemplate {
    /// Create a prioritized template
    pub fn new(template: &dyn Template) -> Self {
        let metadata = template.metadata();
        let severity_score = metadata.severity.score();

        // Calculate priority based on severity and other factors
        let priority = Self::calculate_priority(severity_score);

        Self {
            template_id: metadata.id.clone(),
            priority,
            severity_score,
            estimated_time_ms: 1000, // Default 1 second estimate
        }
    }

    /// Calculate priority score
    fn calculate_priority(severity_score: u8) -> u32 {
        // Higher severity = higher priority
        // Critical: 1000, High: 750, Medium: 500, Low: 250, Info: 100
        match severity_score {
            4 => 1000, // Critical
            3 => 750,  // High
            2 => 500,  // Medium
            1 => 250,  // Low
            _ => 100,  // Info
        }
    }
}

impl PartialEq for PrioritizedTemplate {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for PrioritizedTemplate {}

impl PartialOrd for PrioritizedTemplate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedTemplate {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first
        self.priority.cmp(&other.priority)
    }
}

/// Resource manager for tracking and limiting resource usage
#[derive(Debug)]
pub struct ResourceManager {
    /// Maximum memory limit (bytes)
    max_memory_bytes: usize,
    /// Current memory usage (bytes)
    current_memory_bytes: usize,
    /// Maximum CPU percentage
    #[allow(dead_code)]
    max_cpu_percent: usize,
    /// Maximum concurrent operations
    max_concurrent: usize,
    /// Current concurrent operations
    current_concurrent: usize,
}

impl ResourceManager {
    /// Create a new resource manager
    pub fn new(config: &Config) -> Self {
        Self {
            max_memory_bytes: config.sandbox.memory_limit_mb * 1024 * 1024,
            current_memory_bytes: 0,
            max_cpu_percent: config.sandbox.cpu_limit_percent,
            max_concurrent: config.execution.parallel_templates,
            current_concurrent: 0,
        }
    }

    /// Check if resources are available
    pub fn can_allocate(&self, memory_bytes: usize) -> bool {
        self.current_memory_bytes + memory_bytes <= self.max_memory_bytes
            && self.current_concurrent < self.max_concurrent
    }

    /// Allocate resources
    pub fn allocate(&mut self, memory_bytes: usize) -> Result<()> {
        if !self.can_allocate(memory_bytes) {
            return Err(Error::resource_limit(
                "memory or concurrency",
                format!("{} MB", self.max_memory_bytes / 1024 / 1024),
                format!("{} MB", self.current_memory_bytes / 1024 / 1024),
            ));
        }

        self.current_memory_bytes += memory_bytes;
        self.current_concurrent += 1;
        Ok(())
    }

    /// Release resources
    pub fn release(&mut self, memory_bytes: usize) {
        self.current_memory_bytes = self.current_memory_bytes.saturating_sub(memory_bytes);
        self.current_concurrent = self.current_concurrent.saturating_sub(1);
    }

    /// Get current memory usage
    pub fn current_memory_mb(&self) -> usize {
        self.current_memory_bytes / 1024 / 1024
    }

    /// Get maximum memory limit
    pub fn max_memory_mb(&self) -> usize {
        self.max_memory_bytes / 1024 / 1024
    }

    /// Get current concurrent operations
    pub fn current_concurrent(&self) -> usize {
        self.current_concurrent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthorInfo, Severity, TemplateLanguage, TemplateMetadata};
    use async_trait::async_trait;
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

        async fn execute(
            &self,
            _target: &crate::types::Target,
            _context: &crate::types::Context,
        ) -> Result<Vec<crate::types::Finding>> {
            Ok(Vec::new())
        }
    }

    fn create_mock_template(id: &str, severity: Severity) -> MockTemplate {
        MockTemplate {
            metadata: TemplateMetadata {
                id: id.to_string(),
                name: format!("Mock {}", id),
                author: AuthorInfo {
                    name: "Test".to_string(),
                    email: None,
                    github: None,
                },
                severity,
                description: "Test template".to_string(),
                cve_ids: Vec::new(),
                cwe_ids: Vec::new(),
                cvss_score: None,
                tags: Vec::new(),
                language: TemplateLanguage::Yaml,
                file_path: PathBuf::from("test.yaml"),
                created: Utc::now(),
                updated: Utc::now(),
                version: "1.0".to_string(),
                confidence: None,
            },
        }
    }

    #[test]
    fn test_prioritized_template_ordering() {
        let critical = PrioritizedTemplate::new(&create_mock_template("t1", Severity::Critical));
        let high = PrioritizedTemplate::new(&create_mock_template("t2", Severity::High));
        let medium = PrioritizedTemplate::new(&create_mock_template("t3", Severity::Medium));

        assert!(critical > high);
        assert!(high > medium);
    }

    #[test]
    fn test_resource_manager() {
        let config = Config::default();
        let mut manager = ResourceManager::new(&config);

        assert!(manager.can_allocate(100 * 1024 * 1024)); // 100 MB
        assert!(manager.allocate(100 * 1024 * 1024).is_ok());
        assert_eq!(manager.current_memory_mb(), 100);

        manager.release(100 * 1024 * 1024);
        assert_eq!(manager.current_memory_mb(), 0);
    }
}
