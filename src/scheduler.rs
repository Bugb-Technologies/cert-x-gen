//! Scheduler for template execution prioritization

use crate::config::Config;
use crate::core::ScanJob;
use crate::error::Result;
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
        tracing::debug!(
            "Scheduling job {} with {} templates",
            job.id,
            job.templates.len()
        );

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
                context_vars: Vec::new(),
                vuln_class: None,
                hypothesis_tags: Vec::new(),
                batch_group: None,
                auto_probe: false,
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
}
