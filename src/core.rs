//! Core engine for CERT-X-GEN

use crate::config::Config;
use crate::error::Result;
use crate::executor::Executor;
use crate::scheduler::Scheduler;
use crate::template::{Template, TemplateFilter, TemplateLoader, TemplateManager};
use crate::types::{Context, ScanResults, Target};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Main CERT-X-GEN engine
#[allow(missing_debug_implementations)]
pub struct CertXGen {
    config: Arc<Config>,
    template_loader: Arc<TemplateLoader>,
    template_manager: Arc<TemplateManager>,
    executor: Arc<Executor>,
    scheduler: Arc<RwLock<Scheduler>>,
}

impl CertXGen {
    /// Create a new CERT-X-GEN engine
    pub async fn new(config: Config) -> Result<Self> {
        config.validate()?;

        let config = Arc::new(config);
        let executor = Arc::new(Executor::new(config.clone()).await?);

        // Initialize template manager
        let template_manager = Arc::new(TemplateManager::new());
        template_manager.initialize().await?;

        // Create template loader with registered engines
        let mut template_loader = TemplateLoader::new();

        // Register YAML engine with network client
        let yaml_engine = crate::engine::YamlTemplateEngine::new()
            .with_network_client(executor.network_client().clone());
        template_loader.register_engine(Box::new(yaml_engine));

        // Register other engines
        template_loader.register_engine(Box::new(crate::engine::PythonEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::RustEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::ShellEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::JavaScriptEngine::new()));

        // Register compiled language engines
        template_loader.register_engine(Box::new(crate::engine::CEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::CppEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::JavaEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::GoEngine::new()));

        // Register interpreted language engines
        template_loader.register_engine(Box::new(crate::engine::RubyEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::PerlEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::PhpEngine::new()));

        let template_loader = Arc::new(template_loader);
        let scheduler = Arc::new(RwLock::new(Scheduler::new(config.clone())));

        Ok(Self {
            config,
            template_loader,
            template_manager,
            executor,
            scheduler,
        })
    }

    /// Load templates from configured directories
    pub async fn load_templates(&self) -> Result<Vec<Box<dyn Template>>> {
        let mut all_templates = Vec::new();

        // Get directories from template manager
        let directories = if self.config.templates.directories.is_empty() {
            // Use discovery system
            self.template_manager.get_template_dirs()
        } else {
            // Use explicitly configured directories (backward compatibility)
            self.config.templates.directories.clone()
        };

        for dir in &directories {
            if !dir.exists() {
                tracing::debug!("Template directory does not exist: {}", dir.display());
                continue;
            }

            tracing::info!("Loading templates from: {}", dir.display());

            match self.template_loader.load_templates_from_dir(dir).await {
                Ok(mut templates) => {
                    tracing::info!(
                        "Loaded {} templates from {}",
                        templates.len(),
                        dir.display()
                    );
                    all_templates.append(&mut templates);
                }
                Err(e) => {
                    tracing::warn!("Failed to load templates from {}: {}", dir.display(), e);
                }
            }
        }

        // If no templates found, show helpful message
        if all_templates.is_empty() {
            tracing::warn!(
                "No templates found. Run 'cert-x-gen template update' to download templates."
            );
        }

        // Deduplicate templates by ID, keeping first occurrence (priority: Local > User > System)
        let mut seen_ids = std::collections::HashSet::new();
        let original_count = all_templates.len();
        let deduplicated_templates: Vec<Box<dyn Template>> = all_templates
            .into_iter()
            .filter(|template| {
                let id = template.id().to_string();
                if seen_ids.contains(&id) {
                    tracing::debug!("Skipping duplicate template: {} (already loaded from higher priority directory)", id);
                    false
                } else {
                    seen_ids.insert(id);
                    true
                }
            })
            .collect();

        if original_count != deduplicated_templates.len() {
            tracing::info!(
                "Deduplicated templates: {} -> {} (removed {} duplicates)",
                original_count,
                deduplicated_templates.len(),
                original_count - deduplicated_templates.len()
            );
        }

        tracing::info!("Total templates loaded: {}", deduplicated_templates.len());
        Ok(deduplicated_templates)
    }

    /// Create a new scan job
    pub fn create_scan_job(
        &self,
        targets: Vec<Target>,
        templates: Vec<Box<dyn Template>>,
    ) -> ScanJob {
        ScanJob::new(targets, templates, self.config.clone())
    }

    /// Execute a scan job
    pub async fn execute_scan(&self, job: ScanJob) -> Result<ScanResults> {
        tracing::info!(
            "Starting scan {} with {} targets and {} templates",
            job.id,
            job.targets.len(),
            job.templates.len()
        );

        let mut results = ScanResults::new(job.id);

        // Schedule templates for execution
        let mut scheduler = self.scheduler.write().await;
        scheduler.schedule_job(&job)?;
        drop(scheduler); // Release lock

        // Execute scan using executor
        let findings = self.executor.execute(&job).await?;

        // Aggregate results
        for finding in findings {
            results.add_finding(finding);
        }

        // Update statistics
        results.statistics.targets_scanned = job.targets.len();
        results.statistics.templates_executed = job.templates.len();

        // Calculate success rate
        let total_checks = job.targets.len() * job.templates.len();
        if total_checks > 0 {
            results.statistics.success_rate = results.findings.len() as f64 / total_checks as f64;
        }

        results.complete();

        tracing::info!(
            "Scan {} completed. Found {} findings",
            job.id,
            results.findings.len()
        );

        Ok(results)
    }

    /// Get configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get template loader
    pub fn template_loader(&self) -> &TemplateLoader {
        &self.template_loader
    }

    /// Get template manager
    pub fn template_manager(&self) -> &TemplateManager {
        &self.template_manager
    }

    /// Get executor
    pub fn executor(&self) -> &Executor {
        &self.executor
    }
}

/// A scan job containing targets and templates to execute
#[allow(missing_debug_implementations)]
pub struct ScanJob {
    /// Unique job ID
    pub id: Uuid,
    /// Targets to scan
    pub targets: Vec<Target>,
    /// Templates to execute
    pub templates: Vec<Box<dyn Template>>,
    /// Execution context
    pub context: Context,
    /// Configuration
    pub config: Arc<Config>,
}

impl ScanJob {
    /// Create a new scan job
    pub fn new(
        targets: Vec<Target>,
        templates: Vec<Box<dyn Template>>,
        config: Arc<Config>,
    ) -> Self {
        let mut context = Context::default();
        context.aggressive_mode = config.execution.aggressive_mode;
        context.stealth_mode = config.execution.stealth_mode;
        context.passive_mode = config.execution.passive_mode;
        context.safe_mode = config.execution.safe_mode;
        context.max_retries = config.execution.max_retries;

        Self {
            id: Uuid::new_v4(),
            targets,
            templates,
            context,
            config,
        }
    }

    /// Filter templates
    pub fn filter_templates(&mut self, filter: &TemplateFilter) {
        self.templates.retain(|t| filter.matches(t.as_ref()));
    }

    /// Get total work units (targets × templates)
    pub fn total_work_units(&self) -> usize {
        self.targets.len() * self.templates.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Protocol;

    #[tokio::test]
    async fn test_certxgen_creation() {
        let config = Config::default();
        let engine = CertXGen::new(config).await;
        assert!(engine.is_ok());
    }

    #[test]
    fn test_scan_job_creation() {
        let config = Arc::new(Config::default());
        let targets = vec![Target::new("example.com", Protocol::Https)];
        let templates = Vec::new();

        let job = ScanJob::new(targets, templates, config);
        assert_eq!(job.targets.len(), 1);
    }
}
