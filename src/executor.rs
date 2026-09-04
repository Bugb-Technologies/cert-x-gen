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

/// The preflight reason that a *template* can still be let through: the build
/// carries no instrumentation, which only matters to a template whose oracles
/// need some. Distinct from `target-not-found`, where nothing can run.
const NO_INSTRUMENTATION: &str = "no-instrumentation-detected";

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

        // Instrumentation preflight. For a local CLI target, "no findings" is
        // only evidence of absence if the build could have shown the defect.
        // With --require-instrumentation, refuse honestly instead of running a
        // probe whose refutation cxg could not have earned.
        //
        // A target-level reason does not always mean *nothing* can run against
        // this target. `target-not-found` does -- there is no build to probe.
        // `no-instrumentation-detected` does not: a template whose oracles all
        // work on any build (exit, signal, timeout, exception) can still earn
        // its verdict here, and blanket-skipping it made cxg refuse to test
        // interpreted CLIs at all, since those always detect `none`
        // (s14 report §4.1(a)). Carry the reason into the per-template loop
        // and let those through.
        let preflight_reason = Self::preflight_skip_reason(target, &job.context);
        if let Some(reason) = &preflight_reason {
            tracing::warn!(
                "Target {} did not pass the instrumentation preflight: {}",
                target.address,
                reason
            );
            if reason != NO_INSTRUMENTATION {
                for template in &job.templates {
                    records.push(ExecutionRecord {
                        target: target.address.clone(),
                        target_kind: target.protocol.to_string(),
                        template_id: template.id().to_string(),
                        status: ExecutionStatus::Skipped,
                        declared_by_template: false,
                        findings: 0,
                        exit_code: None,
                        detail: Some(reason.clone()),
                        duration_ms: 0,
                    });
                }
                return Ok((findings, records));
            }
        }

        // What this build can reveal, read once per target and reused by every
        // template's oracle check below.
        let instrumentation: Vec<String> = if matches!(target.protocol, crate::types::Protocol::Cli)
        {
            crate::engine::common::detect_instrumentation(std::path::Path::new(&target.address))
        } else {
            Vec::new()
        };

        // Execute templates in parallel with limited concurrency
        let per_template: Vec<(Vec<Finding>, ExecutionRecord)> = stream::iter(&job.templates)
            .map(|template| async {
                // Update progress with current template
                if let Some(progress) = get_progress() {
                    progress.set_template(template.id(), &target.address);
                }

                let started = std::time::Instant::now();

                // The target carries no instrumentation and the operator asked
                // for the preflight: only a template whose oracles all work on
                // any build gets to run.
                if let Some(reason) = &preflight_reason {
                    if !crate::engine::common::oracles_are_build_independent(
                        &template.metadata().oracles,
                    ) {
                        if let Some(progress) = get_progress() {
                            progress.template_done(&target.address, template.id(), 0);
                        }
                        tracing::info!(
                            "Skipping template {} for target {}: {}",
                            template.id(),
                            target.address,
                            reason
                        );
                        return (
                            Vec::new(),
                            ExecutionRecord {
                                target: target.address.clone(),
                                target_kind: target.protocol.to_string(),
                                template_id: template.id().to_string(),
                                status: ExecutionStatus::Skipped,
                                declared_by_template: false,
                                findings: 0,
                                exit_code: None,
                                detail: Some(reason.clone()),
                                duration_ms: 0,
                            },
                        );
                    }
                }

                // A template that has declared it cannot handle this target, or
                // cannot reach a verdict on this build, is recorded as skipped
                // with the reason rather than run and reported as no-findings.
                if let Some(reason) = Self::declaration_skip_reason(
                    target,
                    template.metadata(),
                    &job.context,
                    &instrumentation,
                ) {
                    if let Some(progress) = get_progress() {
                        progress.template_done(&target.address, template.id(), 0);
                    }
                    tracing::info!(
                        "Skipping template {} for target {}: {}",
                        template.id(),
                        target.address,
                        reason
                    );
                    return (
                        Vec::new(),
                        ExecutionRecord {
                            target: target.address.clone(),
                            target_kind: target.protocol.to_string(),
                            template_id: template.id().to_string(),
                            status: ExecutionStatus::Skipped,
                            declared_by_template: false,
                            findings: 0,
                            exit_code: None,
                            detail: Some(reason),
                            duration_ms: started.elapsed().as_millis() as u64,
                        },
                    );
                }

                match self
                    .execute_single_template(template.as_ref(), target, &job.context)
                    .await
                {
                    Ok((mut template_findings, mut report)) => {
                        // cxg's own oracle: an unhandled exception in the
                        // target's output is a defect the template's exit and
                        // signal oracles cannot see.
                        if let Some((finding, detail)) = Self::exception_oracle_finding(
                            target,
                            template.metadata(),
                            &template_findings,
                            &report,
                        ) {
                            tracing::info!(
                                "Exception oracle fired for template {} against {}: {}",
                                template.id(),
                                target.address,
                                detail
                            );
                            template_findings.push(finding);
                            report.detail = Some(match report.detail.take() {
                                Some(existing) => format!("{}; {}", existing, detail),
                                None => detail,
                            });
                        }

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

    /// Decide whether a target must be skipped before anything runs against it.
    ///
    /// Returns the machine-readable skip reason, or `None` to proceed. Only
    /// `cli://` targets are gated, and only when the operator asked for the
    /// preflight -- the check is about what a *build* can reveal, which is
    /// meaningless for a network host.
    fn preflight_skip_reason(
        target: &crate::types::Target,
        context: &crate::types::Context,
    ) -> Option<String> {
        if !context.require_instrumentation
            || !matches!(target.protocol, crate::types::Protocol::Cli)
        {
            return None;
        }

        let path = std::path::Path::new(&target.address);
        if !path.is_file() {
            // Distinct from "no instrumentation": there is no build here at all,
            // and calling that a missing sanitizer would misdescribe it.
            return Some("target-not-found".to_string());
        }

        let detected = crate::engine::common::detect_instrumentation(path);
        if detected.is_empty() {
            Some(NO_INSTRUMENTATION.to_string())
        } else {
            tracing::debug!(
                "Target {} carries instrumentation: {}",
                target.address,
                detected.join(",")
            );
            None
        }
    }

    /// Decide whether a template's own declarations rule this target out.
    ///
    /// Two independent checks, both driven by annotations that did not exist
    /// before this contract, so no template written against the old contract
    /// changes behaviour:
    ///
    /// * `@target_kinds` -- a template that declares which kinds it handles
    ///   cannot work against any other kind, whatever the operator asked for.
    ///   An *absent* declaration accepts every kind, which is what keeps the
    ///   existing registry running.
    /// * `@oracles` -- a template whose only ways of deciding depend on
    ///   instrumentation the build does not carry cannot reach a verdict worth
    ///   having. This is gated on `--require-instrumentation`, the same flag
    ///   that says "only run where the build can earn the verdict".
    fn declaration_skip_reason(
        target: &crate::types::Target,
        metadata: &crate::types::TemplateMetadata,
        context: &crate::types::Context,
        instrumentation: &[String],
    ) -> Option<String> {
        let kind = target.protocol.to_string();
        if !crate::engine::common::target_kind_accepted(&metadata.target_kinds, &kind) {
            return Some(format!(
                "target-kind-mismatch(kind={}, accepts={})",
                kind,
                metadata.target_kinds.join("|")
            ));
        }

        if context.require_instrumentation && matches!(target.protocol, crate::types::Protocol::Cli)
        {
            if let Some(missing) =
                crate::engine::common::unsupported_oracles(&metadata.oracles, instrumentation)
            {
                return Some(format!("oracle-unavailable({})", missing.join("|")));
            }
        }

        None
    }

    /// cxg's own `exception` oracle: did an unhandled language-level exception
    /// escape the target?
    ///
    /// Returns the finding to record and the detail to append, or `None` when
    /// the oracle does not apply. It applies only when all of:
    ///
    /// * the template declared `@oracles: exception` -- cxg never volunteers a
    ///   verdict a template did not ask for;
    /// * the template reported no findings of its own and declared no status
    ///   of its own -- a template that reached its own verdict keeps it, which
    ///   is the existing contract;
    /// * the template handed back the target's output in
    ///   `metadata.target_output` -- cxg runs the template, the template runs
    ///   the target, so the output has to come back through the report.
    ///
    /// The match is on the output, never on the exit status: the two real
    /// defects s14 found exited **1** with no signal, which is what a
    /// deliberate, correct non-zero exit looks like too (s14 report §5).
    fn exception_oracle_finding(
        target: &crate::types::Target,
        metadata: &crate::types::TemplateMetadata,
        findings: &[Finding],
        report: &crate::engine::common::TemplateReport,
    ) -> Option<(Finding, String)> {
        const EVIDENCE_MAX_CHARS: usize = 2000;
        const DETAIL_MAX_CHARS: usize = 160;

        if !metadata
            .oracles
            .iter()
            .any(|o| o.trim().eq_ignore_ascii_case("exception"))
        {
            return None;
        }
        if !findings.is_empty() || report.status.is_some() {
            return None;
        }

        let output = report.target_output.as_deref()?;
        let kind = crate::engine::common::detect_unhandled_exception(output)?;

        let first_line = output
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or_default();
        let exit = match report.target_exit_code {
            Some(rc) => format!(" target-exit={}", rc),
            None => String::new(),
        };
        let detail = format!(
            "oracle=exception({}){} {}",
            kind.label(),
            exit,
            crate::engine::common::truncate_chars(first_line, DETAIL_MAX_CHARS)
        );

        let mut evidence = crate::types::Evidence::new();
        evidence.matched_patterns.push(kind.label().to_string());
        evidence.response = Some(crate::engine::common::truncate_chars(
            output,
            EVIDENCE_MAX_CHARS,
        ));

        let finding = Finding::new(
            target.address.as_str(),
            metadata.id.as_str(),
            metadata.severity,
            "Unhandled exception escaped the target",
            detail.as_str(),
        )
        .with_evidence(evidence);

        Some((finding, detail))
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
    fn the_preflight_is_off_unless_the_operator_asks_for_it() {
        let context = crate::types::Context::default();
        assert_eq!(
            Executor::preflight_skip_reason(&cli_target(), &context),
            None,
            "an un-requested preflight must never change a scan"
        );
    }

    /// The preflight is about what a *build* can reveal, which is meaningless
    /// for a network host -- those are never gated.
    #[test]
    fn the_preflight_never_gates_a_network_target() {
        let context = crate::types::Context {
            require_instrumentation: true,
            ..crate::types::Context::default()
        };
        let net = Target::with_port("example.com", 443, Protocol::Https);
        assert_eq!(Executor::preflight_skip_reason(&net, &context), None);
    }

    /// Real compiled objects on both sides, because the preflight's whole job
    /// is to tell one build from another: a file that merely *spells*
    /// `__asan_init` is not an ASan build, and reading it as one is the false
    /// all-clear this flag exists to refuse.
    #[cfg(unix)]
    #[test]
    fn the_preflight_skips_an_uninstrumented_build_and_passes_an_instrumented_one() {
        use crate::engine::common::object_fixtures::{compile_c, no_markers, references};

        let dir = tempfile::tempdir().unwrap();
        let context = crate::types::Context {
            require_instrumentation: true,
            ..crate::types::Context::default()
        };

        let stripped = compile_c(dir.path(), "toy_stripped", &no_markers(16), &["-c"]);
        assert_eq!(
            Executor::preflight_skip_reason(
                &Target::new(stripped.to_string_lossy().to_string(), Protocol::Cli),
                &context
            ),
            Some("no-instrumentation-detected".to_string())
        );

        let instrumented = compile_c(dir.path(), "toy_asan", &references("__asan_init"), &["-c"]);
        assert_eq!(
            Executor::preflight_skip_reason(
                &Target::new(instrumented.to_string_lossy().to_string(), Protocol::Cli),
                &context
            ),
            None
        );
    }

    /// A shebang script is not a build, whatever symbols it names -- the s14
    /// shape, and the one half of the pair that needs no toolchain.
    #[test]
    fn the_preflight_skips_a_script_that_merely_names_a_sanitizer() {
        let dir = tempfile::tempdir().unwrap();
        let context = crate::types::Context {
            require_instrumentation: true,
            ..crate::types::Context::default()
        };

        let script = dir.path().join("interp-cli");
        std::fs::write(&script, b"#!/usr/bin/env node\n// calls __asan_init\n").unwrap();
        assert_eq!(
            Executor::preflight_skip_reason(
                &Target::new(script.to_string_lossy().to_string(), Protocol::Cli),
                &context
            ),
            Some("no-instrumentation-detected".to_string())
        );
    }

    /// A target that is not there at all is a different failure from a build
    /// with no sanitizer, and gets its own reason rather than being
    /// misdescribed as one.
    #[test]
    fn the_preflight_distinguishes_a_missing_target_from_a_bare_build() {
        let context = crate::types::Context {
            require_instrumentation: true,
            ..crate::types::Context::default()
        };
        assert_eq!(
            Executor::preflight_skip_reason(
                &Target::new("/definitely/not/here", Protocol::Cli),
                &context
            ),
            Some("target-not-found".to_string())
        );
    }

    fn metadata_with(oracles: &[&str], kinds: &[&str]) -> crate::types::TemplateMetadata {
        use crate::types::{AuthorInfo, Severity, TemplateLanguage, TemplateMetadata};
        TemplateMetadata {
            id: "probe".to_string(),
            name: "Probe".to_string(),
            author: AuthorInfo {
                name: "test".to_string(),
                email: None,
                github: None,
            },
            severity: Severity::High,
            description: "probe".to_string(),
            cve_ids: Vec::new(),
            cwe_ids: Vec::new(),
            cvss_score: None,
            tags: Vec::new(),
            language: TemplateLanguage::Shell,
            file_path: std::path::PathBuf::from("probe.sh"),
            created: chrono::Utc::now(),
            updated: chrono::Utc::now(),
            version: "1.0".to_string(),
            confidence: None,
            context_vars: Vec::new(),
            vuln_class: None,
            hypothesis_tags: Vec::new(),
            batch_group: None,
            auto_probe: false,
            allow_nonzero_exit: false,
            oracles: oracles.iter().map(|s| s.to_string()).collect(),
            target_kinds: kinds.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// The behaviour that protects the existing registry: a template with no
    /// declarations is never gated, on any target.
    #[test]
    fn a_template_that_declares_nothing_is_never_gated() {
        let context = crate::types::Context {
            require_instrumentation: true,
            ..crate::types::Context::default()
        };
        assert_eq!(
            Executor::declaration_skip_reason(
                &cli_target(),
                &metadata_with(&[], &[]),
                &context,
                &[]
            ),
            None
        );
    }

    #[test]
    fn a_declared_target_kind_mismatch_is_skipped_with_the_reason() {
        let context = crate::types::Context::default();
        let net = Target::with_port("example.com", 443, Protocol::Https);

        let reason =
            Executor::declaration_skip_reason(&net, &metadata_with(&[], &["cli"]), &context, &[])
                .unwrap();
        assert!(reason.starts_with("target-kind-mismatch"), "{reason}");
        assert!(reason.contains("kind=https"), "{reason}");
        assert!(reason.contains("accepts=cli"), "{reason}");

        // ...and the matching kind is not gated.
        assert_eq!(
            Executor::declaration_skip_reason(
                &cli_target(),
                &metadata_with(&[], &["cli"]),
                &context,
                &[]
            ),
            None
        );
    }

    /// The join between the oracle declaration and the instrumentation
    /// preflight: a template that can only decide via ASan, on a build with no
    /// ASan, is skipped with the reason rather than run to a verdict it cannot
    /// earn. Gated on --require-instrumentation.
    #[test]
    fn an_asan_only_template_is_skipped_on_a_build_without_asan() {
        let context = crate::types::Context {
            require_instrumentation: true,
            ..crate::types::Context::default()
        };
        let metadata = metadata_with(&["asan"], &["cli"]);

        assert_eq!(
            Executor::declaration_skip_reason(&cli_target(), &metadata, &context, &[]),
            Some("oracle-unavailable(asan)".to_string())
        );
        assert_eq!(
            Executor::declaration_skip_reason(
                &cli_target(),
                &metadata,
                &context,
                &["asan".to_string()]
            ),
            None
        );
    }

    #[test]
    fn oracle_gating_only_applies_when_the_preflight_was_requested() {
        let context = crate::types::Context::default();
        assert_eq!(
            Executor::declaration_skip_reason(
                &cli_target(),
                &metadata_with(&["asan"], &["cli"]),
                &context,
                &[]
            ),
            None
        );
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

    fn report_with_target_output(output: &str, rc: i32) -> TemplateReport {
        TemplateReport {
            target_output: Some(output.to_string()),
            target_exit_code: Some(rc),
            ..TemplateReport::default()
        }
    }

    const PY_TRACEBACK: &str = "Traceback (most recent call last):\n  File \"/tmp/app.py\", line 12, in <module>\n    main()\nValueError: synthetic\n";

    /// s14 item 4. A traceback and a deliberate `exit 1` are the same thing to
    /// the `exit` oracle; they are not the same thing.
    #[test]
    fn the_exception_oracle_confirms_a_traceback_and_not_a_clean_nonzero_exit() {
        let metadata = metadata_with(&["exception"], &["cli"]);

        let (finding, detail) = Executor::exception_oracle_finding(
            &cli_target(),
            &metadata,
            &[],
            &report_with_target_output(PY_TRACEBACK, 1),
        )
        .expect("a traceback is an escaped exception");
        assert!(
            detail.starts_with("oracle=exception(python-traceback) target-exit=1"),
            "detail was {detail:?}"
        );
        assert_eq!(finding.template_id, metadata.id);
        assert!(finding
            .evidence
            .matched_patterns
            .contains(&"python-traceback".to_string()));
        assert!(finding
            .evidence
            .response
            .as_deref()
            .unwrap_or_default()
            .contains("ValueError: synthetic"));

        assert!(
            Executor::exception_oracle_finding(
                &cli_target(),
                &metadata,
                &[],
                &report_with_target_output("error: no such file: /tmp/nope\n", 1),
            )
            .is_none(),
            "a correct non-zero exit is not a defect"
        );
    }

    #[test]
    fn the_exception_oracle_reads_a_node_unhandled_rejection() {
        let node = "node:internal/process/promises:288\n            triggerUncaughtException(err, true /* fromPromise */);\n[UnhandledPromiseRejection: synthetic]\n";
        let (_, detail) = Executor::exception_oracle_finding(
            &cli_target(),
            &metadata_with(&["exception", "exit"], &["cli"]),
            &[],
            &report_with_target_output(node, 1),
        )
        .expect("an unhandled rejection is an escaped exception");
        assert!(
            detail.contains("exception(node-unhandled-rejection)"),
            "detail was {detail:?}"
        );
    }

    /// cxg never volunteers a verdict a template did not ask for, and never
    /// overrides one it reached itself.
    #[test]
    fn the_exception_oracle_applies_only_where_the_template_asked_for_it() {
        let declared = metadata_with(&["exception"], &["cli"]);
        let report = report_with_target_output(PY_TRACEBACK, 1);

        assert!(
            Executor::exception_oracle_finding(
                &cli_target(),
                &metadata_with(&["exit", "signal"], &["cli"]),
                &[],
                &report,
            )
            .is_none(),
            "the template did not declare the oracle"
        );

        let own_finding = Finding::new(
            "/opt/build/toy",
            "probe",
            crate::types::Severity::High,
            "the template's own finding",
            "found by the template itself",
        );
        assert!(
            Executor::exception_oracle_finding(
                &cli_target(),
                &declared,
                std::slice::from_ref(&own_finding),
                &report,
            )
            .is_none(),
            "the template already reported the defect"
        );

        let declared_status = TemplateReport {
            status: Some(ExecutionStatus::Refuted),
            ..report_with_target_output(PY_TRACEBACK, 1)
        };
        assert!(
            Executor::exception_oracle_finding(&cli_target(), &declared, &[], &declared_status)
                .is_none(),
            "a template that declared its own status keeps it"
        );

        assert!(
            Executor::exception_oracle_finding(
                &cli_target(),
                &declared,
                &[],
                &TemplateReport::default(),
            )
            .is_none(),
            "no target output means nothing to match"
        );
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
