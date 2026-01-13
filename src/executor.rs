//! Execution orchestrator for running templates against targets

use crate::config::Config;
use crate::core::ScanJob;
use crate::error::{Error, Result};
use crate::flows::FlowExecutor;
use crate::network::NetworkClient;
use crate::progress::get_progress;
use crate::session::SessionManager;
use crate::types::Finding;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Executor for running scan jobs
#[derive(Debug)]
pub struct Executor {
    config: Arc<Config>,
    network_client: Arc<NetworkClient>,
    session_manager: Arc<SessionManager>,
    flow_executor: Arc<FlowExecutor>,
    semaphore: Arc<Semaphore>,
}

impl Executor {
    /// Create a new executor
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let session_manager = Arc::new(SessionManager::new());
        let network_client =
            Arc::new(NetworkClient::with_session(config.clone(), session_manager.clone()).await?);
        let flow_executor = Arc::new(FlowExecutor::new(network_client.clone()));
        let semaphore = Arc::new(Semaphore::new(config.execution.parallel_targets));

        Ok(Self {
            config,
            network_client,
            session_manager,
            flow_executor,
            semaphore,
        })
    }

    /// Get session manager
    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    /// Get flow executor
    pub fn flow_executor(&self) -> &Arc<FlowExecutor> {
        &self.flow_executor
    }

    /// Execute a scan job
    pub async fn execute(&self, job: &ScanJob) -> Result<Vec<Finding>> {
        tracing::info!(
            "Executing scan job {} with {} targets and {} templates",
            job.id,
            job.targets.len(),
            job.templates.len()
        );

        let findings = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        // Process targets in parallel with semaphore control
        stream::iter(&job.targets)
            .map(|target| {
                let findings = Arc::clone(&findings);
                let executor = self;

                async move {
                    // Acquire semaphore permit for concurrency control
                    let _permit = executor.semaphore.acquire().await.unwrap();

                    // Update progress with current target
                    if let Some(progress) = get_progress() {
                        progress.set_target(&target.address);
                    }

                    tracing::debug!("Processing target: {}", target.address);

                    // Execute all templates for this target
                    match executor.execute_templates_for_target(target, job).await {
                        Ok(target_findings) => {
                            if !target_findings.is_empty() {
                                tracing::info!(
                                    "Found {} findings for target {}",
                                    target_findings.len(),
                                    target.address
                                );
                                findings.lock().await.extend(target_findings);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error processing target {}: {}", target.address, e);
                        }
                    }
                }
            })
            .buffer_unordered(self.config.execution.parallel_targets)
            .collect::<Vec<_>>()
            .await;

        let findings = match Arc::try_unwrap(findings) {
            Ok(mutex) => mutex.into_inner(),
            Err(arc) => arc.blocking_lock().clone(),
        };

        Ok(findings)
    }

    /// Execute all templates for a single target
    async fn execute_templates_for_target(
        &self,
        target: &crate::types::Target,
        job: &ScanJob,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Execute templates in parallel with limited concurrency
        let template_findings: Vec<Result<Vec<Finding>>> = stream::iter(&job.templates)
            .map(|template| async {
                // Update progress with current template
                if let Some(progress) = get_progress() {
                    progress.set_template(template.id(), &target.address);
                }

                match self
                    .execute_single_template(template.as_ref(), target, &job.context)
                    .await
                {
                    Ok(template_findings) => {
                        let findings_count = template_findings.len();

                        // Update progress
                        if let Some(progress) = get_progress() {
                            progress.template_done(&target.address, template.id(), findings_count);
                        }

                        if !template_findings.is_empty() {
                            tracing::info!(
                                "Template {} found {} findings for {}",
                                template.id(),
                                template_findings.len(),
                                target.address
                            );
                        }
                        Ok(template_findings)
                    }
                    Err(e) => {
                        // Update progress even on failure
                        if let Some(progress) = get_progress() {
                            progress.template_done(&target.address, template.id(), 0);
                        }

                        tracing::warn!(
                            "Template {} failed for target {}: {}",
                            template.id(),
                            target.address,
                            e
                        );
                        Err(e)
                    }
                }
            })
            .buffer_unordered(self.config.execution.parallel_templates)
            .collect()
            .await;

        // Collect successful results
        for result in template_findings {
            if let Ok(mut template_findings) = result {
                findings.append(&mut template_findings);
            }
        }

        Ok(findings)
    }

    /// Execute a single template against a target
    async fn execute_single_template(
        &self,
        template: &dyn crate::template::Template,
        target: &crate::types::Target,
        context: &crate::types::Context,
    ) -> Result<Vec<Finding>> {
        tracing::debug!(
            "Executing template {} against target {}",
            template.id(),
            target.address
        );

        // Set timeout for template execution
        let timeout = std::time::Duration::from_secs(self.config.templates.timeout_secs);

        match tokio::time::timeout(timeout, template.execute(target, context)).await {
            Ok(Ok(findings)) => Ok(findings),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::Timeout {
                duration: format!("{}s", self.config.templates.timeout_secs),
            }),
        }
    }

    /// Get network client
    pub fn network_client(&self) -> &Arc<NetworkClient> {
        &self.network_client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_executor_creation() {
        let config = Arc::new(Config::default());
        let executor = Executor::new(config).await;
        assert!(executor.is_ok());
    }
}
