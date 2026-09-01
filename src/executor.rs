//! Execution orchestrator for running templates against targets

use crate::config::Config;
use crate::core::ScanJob;
use crate::error::{Error, Result};
use crate::flows::FlowExecutor;
use crate::network::NetworkClient;
use crate::progress::get_progress;
use crate::session::SessionManager;
use crate::types::{ExecutionRecord, ExecutionStatus, Finding};
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

    /// Execute a scan job (findings only).
    ///
    /// Preserved signature: library callers that only want findings are
    /// unaffected. [`Executor::execute_with_records`] is the same run with the
    /// execution ledger attached.
    pub async fn execute(&self, job: &ScanJob) -> Result<Vec<Finding>> {
        self.execute_with_records(job).await.map(|(f, _)| f)
    }

    /// Execute a scan job and return the per-(template, target) execution
    /// ledger alongside the findings.
    pub async fn execute_with_records(
        &self,
        job: &ScanJob,
    ) -> Result<(Vec<Finding>, Vec<ExecutionRecord>)> {
        tracing::info!(
            "Executing scan job {} with {} targets and {} templates",
            job.id,
            job.targets.len(),
            job.templates.len()
        );

        let findings = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        // Process targets in parallel with semaphore control. Findings keep
        // their existing shared-accumulator path; the ledger is returned from
        // each target task and collected by the stream, so it needs no lock.
        let per_target_records: Vec<Vec<ExecutionRecord>> = stream::iter(&job.targets)
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
                        Ok((target_findings, target_records)) => {
                            if !target_findings.is_empty() {
                                tracing::info!(
                                    "Found {} findings for target {}",
                                    target_findings.len(),
                                    target.address
                                );
                                findings.lock().await.extend(target_findings);
                            }
                            target_records
                        }
                        Err(e) => {
                            tracing::error!("Error processing target {}: {}", target.address, e);
                            Vec::new()
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

        // Targets are processed unordered; sort so the ledger is deterministic.
        let mut records: Vec<ExecutionRecord> = per_target_records.into_iter().flatten().collect();
        records.sort_by(|a, b| {
            a.target
                .cmp(&b.target)
                .then_with(|| a.template_id.cmp(&b.template_id))
        });

        Ok((findings, records))
    }

    /// Execute all templates for a single target
    async fn execute_templates_for_target(
        &self,
        target: &crate::types::Target,
        job: &ScanJob,
    ) -> Result<(Vec<Finding>, Vec<ExecutionRecord>)> {
        let mut findings = Vec::new();
        let mut records = Vec::new();

        // Execute templates in parallel with limited concurrency
        let per_template: Vec<(Vec<Finding>, ExecutionRecord)> = stream::iter(&job.templates)
            .map(|template| async {
                // Update progress with current template
                if let Some(progress) = get_progress() {
                    progress.set_template(template.id(), &target.address);
                }

                let started = std::time::Instant::now();
                match self
                    .execute_single_template(template.as_ref(), target, &job.context)
                    .await
                {
                    Ok((template_findings, report)) => {
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

                        let record = Self::record_from_report(
                            target,
                            template.id(),
                            findings_count,
                            report,
                            started.elapsed(),
                        );
                        tracing::info!(
                            "Execution {} against {} -> {} ({} findings, {})",
                            template.id(),
                            target.address,
                            record.status,
                            findings_count,
                            if record.declared_by_template {
                                "template-declared"
                            } else {
                                "cxg-inferred"
                            }
                        );
                        (template_findings, record)
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

                        let status = if matches!(e, Error::Timeout { .. }) {
                            ExecutionStatus::TimedOut
                        } else {
                            ExecutionStatus::Errored
                        };
                        (
                            Vec::new(),
                            ExecutionRecord {
                                target: target.address.clone(),
                                target_kind: target.protocol.to_string(),
                                template_id: template.id().to_string(),
                                status,
                                declared_by_template: false,
                                findings: 0,
                                exit_code: None,
                                detail: Some(e.to_string()),
                                duration_ms: started.elapsed().as_millis() as u64,
                            },
                        )
                    }
                }
            })
            .buffer_unordered(self.config.execution.parallel_templates)
            .collect()
            .await;

        for (mut template_findings, record) in per_template {
            findings.append(&mut template_findings);
            records.push(record);
        }

        Ok((findings, records))
    }

    /// Build a ledger row from a completed execution.
    ///
    /// cxg *infers* a status from what it observed -- findings > 0 means
    /// confirmed, 0 means refuted -- and a template may *override* it with its
    /// own declared verdict. `declared_by_template` records which happened, so
    /// an operator can always tell a template's considered verdict from cxg's
    /// default guess.
    fn record_from_report(
        target: &crate::types::Target,
        template_id: &str,
        findings_count: usize,
        report: crate::engine::common::TemplateReport,
        elapsed: std::time::Duration,
    ) -> ExecutionRecord {
        let inferred = if findings_count > 0 {
            ExecutionStatus::Confirmed
        } else {
            ExecutionStatus::Refuted
        };
        let declared_by_template = report.status.is_some();
        let status = report.status.unwrap_or(inferred);

        // A status cxg could not parse must not vanish: surface it in the
        // ledger rather than silently substituting the inferred one.
        let detail = match (report.unrecognised_status, report.detail) {
            (Some(raw), Some(d)) => Some(format!("unrecognised-status({}): {}", raw, d)),
            (Some(raw), None) => Some(format!("unrecognised-status({})", raw)),
            (None, d) => d,
        };

        ExecutionRecord {
            target: target.address.clone(),
            target_kind: target.protocol.to_string(),
            template_id: template_id.to_string(),
            status,
            declared_by_template,
            findings: findings_count,
            exit_code: report.exit_code,
            detail,
            duration_ms: elapsed.as_millis() as u64,
        }
    }

    /// Execute a single template against a target
    async fn execute_single_template(
        &self,
        template: &dyn crate::template::Template,
        target: &crate::types::Target,
        context: &crate::types::Context,
    ) -> Result<(Vec<Finding>, crate::engine::common::TemplateReport)> {
        tracing::debug!(
            "Executing template {} against target {}",
            template.id(),
            target.address
        );

        // Set timeout for template execution
        let timeout = std::time::Duration::from_secs(self.config.templates.timeout_secs);

        match tokio::time::timeout(timeout, template.execute_with_status(target, context)).await {
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

    use crate::engine::common::TemplateReport;
    use crate::types::{Protocol, Target};
    use std::time::Duration;

    #[tokio::test]
    async fn test_executor_creation() {
        let config = Arc::new(Config::default());
        let executor = Executor::new(config).await;
        assert!(executor.is_ok());
    }

    fn cli_target() -> Target {
        Target::new("/opt/build/toy", Protocol::Cli)
    }

    #[test]
    fn infers_confirmed_from_findings_when_the_template_declares_nothing() {
        let record = Executor::record_from_report(
            &cli_target(),
            "probe",
            2,
            TemplateReport::default(),
            Duration::from_millis(7),
        );
        assert_eq!(record.status, ExecutionStatus::Confirmed);
        assert!(!record.declared_by_template);
        assert_eq!(record.findings, 2);
        assert_eq!(record.target_kind, "cli");
    }

    /// Zero findings is only a refutation by cxg's default guess. The record
    /// says so, so an operator can tell it from a considered verdict.
    #[test]
    fn infers_refuted_from_no_findings_when_the_template_declares_nothing() {
        let record = Executor::record_from_report(
            &cli_target(),
            "probe",
            0,
            TemplateReport::default(),
            Duration::from_millis(1),
        );
        assert_eq!(record.status, ExecutionStatus::Refuted);
        assert!(!record.declared_by_template);
    }

    #[test]
    fn a_template_declared_status_overrides_the_inference() {
        let report = TemplateReport {
            status: Some(ExecutionStatus::Skipped),
            detail: Some("no-instrumentation".to_string()),
            exit_code: Some(0),
            ..TemplateReport::default()
        };
        let record = Executor::record_from_report(
            &cli_target(),
            "probe",
            0,
            report,
            Duration::from_millis(1),
        );
        assert_eq!(record.status, ExecutionStatus::Skipped);
        assert!(record.declared_by_template);
        assert_eq!(record.detail.as_deref(), Some("no-instrumentation"));
        assert_eq!(record.exit_code, Some(0));
    }

    #[test]
    fn an_unrecognised_declared_status_is_surfaced_in_the_ledger() {
        let report = TemplateReport {
            unrecognised_status: Some("refuuted".to_string()),
            detail: Some("clean run".to_string()),
            ..TemplateReport::default()
        };
        let record = Executor::record_from_report(
            &cli_target(),
            "probe",
            0,
            report,
            Duration::from_millis(1),
        );
        // cxg falls back to its own inference...
        assert_eq!(record.status, ExecutionStatus::Refuted);
        assert!(!record.declared_by_template);
        // ...but the typo is visible rather than swallowed.
        assert_eq!(
            record.detail.as_deref(),
            Some("unrecognised-status(refuuted): clean run")
        );
    }
}
