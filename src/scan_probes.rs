//! Supplied-only probe dispatch for ordinary scans, including mixed template packs.
use crate::cli::{self, Cli, Commands, PentestAction, PentestCommand};
use cert_x_gen::{
    error::{Error, Result},
    template::{PathResolver, Template},
    types::{ExecutionRecord, ExecutionStatus, Finding, ScanResults, Severity},
};
use serde_json::{json, Value};
use std::{collections::HashSet, fs};

pub async fn execute(
    args: &cli::ScanArgs,
    templates: Vec<Box<dyn Template>>,
    results: &mut ScanResults,
) -> Result<i32> {
    let mut reports = Vec::new();
    let mut refused = Vec::new();
    let mut exit = 0;
    let mut executed_targets = HashSet::new();
    let root = args.probe_inputs.session_dir.clone().unwrap_or_else(|| {
        PathResolver::user_config_dir()
            .join("sessions")
            .join(format!("scan-{}", results.scan_id))
    });
    let root = if root.is_absolute() {
        root
    } else {
        std::env::current_dir()?.join(root)
    };
    let inputs = root.join("probe-inputs").join(results.scan_id.to_string());
    let mut sources = Vec::new();
    let mut seen = HashSet::new();
    for template in templates {
        let path = template.metadata().file_path.clone();
        if seen.insert(path.clone()) {
            sources.push((template.id().to_string(), path));
        }
    }
    if let Err(error) = fs::create_dir_all(&inputs) {
        for (id, path) in &sources {
            refused.push(json!({"template": id, "path": path, "reason": error.to_string()}));
        }
        exit = 4;
    } else {
        let mut mappings = Vec::new();
        for (index, (id, path)) in sources.iter().enumerate() {
            let directory = inputs.join(index.to_string());
            if let Err(error) = fs::create_dir_all(&directory) {
                refused.push(json!({"template": id, "path": path, "reason": error.to_string()}));
                exit = 4;
                continue;
            }
            let staged = directory.join(path.file_name().unwrap_or_default());
            match fs::copy(path, &staged) {
                Ok(_) => mappings.push(json!({"template": id, "source": path, "staged": staged})),
                Err(error) => {
                    refused
                        .push(json!({"template": id, "path": path, "reason": error.to_string()}));
                    exit = 4;
                }
            }
        }
        let mut targets = Vec::new();
        let mut stack = HashSet::new();
        for scope in &args.scope {
            let direct = url::Url::parse(scope).ok().is_some_and(|u| {
                matches!(u.scheme(), "http" | "https")
                    && u.host_str().is_some_and(|h| !h.contains(','))
            });
            if direct {
                targets.push(scope.clone());
            } else {
                crate::expand_scope_entry(scope, &mut targets, &mut stack)?;
            }
        }
        let mut unique = HashSet::new();
        for (index, raw) in targets
            .into_iter()
            .filter(|s| unique.insert(s.clone()))
            .enumerate()
        {
            let url = if raw.starts_with("http://") || raw.starts_with("https://") {
                Some(raw.clone())
            } else if raw.starts_with("cli:") || raw.contains('/') {
                None
            } else {
                Some(crate::parse_target_string(&raw).url())
            };
            let Some(target) = url else {
                for (id, path) in &sources {
                    refused.push(json!({"template": id, "path": path, "target": raw, "reason": "JS probes require an HTTP(S) target; CLI and CIDR scopes cannot be honoured by the probe engine"}));
                }
                exit = 4;
                continue;
            };
            if mappings.is_empty() {
                continue;
            }
            let session = root.join(format!("engine-{}-{index}", results.scan_id));
            if let Err(error) = fs::create_dir_all(&session) {
                for (id, path) in &sources {
                    refused.push(json!({"template": id, "path": path, "target": target, "reason": error.to_string()}));
                }
                exit = 4;
                continue;
            }
            let report_path = session.join("report.json");
            let parsed = Cli::try_parse_from([
                "cxg",
                "pentest",
                "run",
                "--codebase",
                ".",
                "--target",
                &target,
            ])
            .map_err(|e| Error::config(e.to_string()))?;
            let Some(Commands::Pentest(PentestCommand {
                action: PentestAction::Run(mut run),
            })) = parsed.command
            else {
                unreachable!()
            };
            run.probe_inputs = args.probe_inputs.clone();
            run.probe_inputs.session_dir = Some(session.clone());
            run.template_dir = Some(inputs.clone());
            run.probe_inputs.no_author = true;
            run.mutation_retries = 0;
            run.output = Some(report_path.clone());
            // Scanner proxy semantics are identical; other engine controls retain
            // their native defaults and are bounded by --scope-file.
            run.proxy = args.proxy.clone();
            let outcome = crate::run_pentest_process(
                PentestCommand {
                    action: PentestAction::Run(run),
                },
                true,
            )
            .await;
            let (code, error) = match outcome {
                Ok(result) => (result.code, result.error),
                Err(error) => (4, error.to_string()),
            };
            if code != 0 {
                exit = if code == 2 && exit == 0 {
                    2
                } else if code != 2 {
                    code
                } else {
                    exit
                };
            }
            let report: Option<Value> = fs::read_to_string(&report_path)
                .ok()
                .and_then(|text| serde_json::from_str(&text).ok());
            if let Some(report) = &report {
                let executed = report
                    .get("templates_executed")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                results.statistics.templates_executed += executed;
                if executed > 0 {
                    executed_targets.insert(target.clone());
                }
                for key in [
                    "probe_refusals",
                    "auth_skipped",
                    "chain_skipped",
                    "rejected_templates",
                    "template_errors",
                    "not_run",
                ] {
                    if let Some(entries) = report.get(key).and_then(Value::as_array) {
                        for entry in entries {
                            let id = entry
                                .get("template")
                                .or_else(|| entry.get("template_id"))
                                .or_else(|| entry.get("id"))
                                .cloned()
                                .unwrap_or(Value::Null);
                            let source = entry
                                .get("path")
                                .and_then(|path| {
                                    mappings.iter().find(|m| Some(path) == m.get("staged"))
                                })
                                .or_else(|| {
                                    let mut candidates =
                                        mappings.iter().filter(|m| m.get("template") == Some(&id));
                                    let first = candidates.next();
                                    if candidates.next().is_none() {
                                        first
                                    } else {
                                        None
                                    }
                                })
                                .and_then(|m| m.get("source"))
                                .cloned()
                                .unwrap_or(Value::Null);
                            let reason = entry.get("reason").cloned().unwrap_or_else(|| {
                                json!(entry.get("errors").unwrap_or(entry).to_string())
                            });
                            refused.push(json!({"target": target, "template": id, "path": source,
                                "status": "refused", "reason": reason, "details": entry}));
                        }
                    }
                }
                if let Some(findings) = report.get("confirmed_findings").and_then(Value::as_array) {
                    for finding in findings {
                        let severity = match finding
                            .get("severity")
                            .and_then(Value::as_str)
                            .unwrap_or("info")
                        {
                            "critical" => Severity::Critical,
                            "high" => Severity::High,
                            "medium" => Severity::Medium,
                            "low" => Severity::Low,
                            _ => Severity::Info,
                        };
                        let mut converted = Finding::new(
                            target.clone(),
                            finding
                                .get("template_id")
                                .or_else(|| finding.get("hypothesis_id"))
                                .or_else(|| finding.get("id"))
                                .and_then(Value::as_str)
                                .unwrap_or("probe")
                                .to_string(),
                            severity,
                            format!(
                                "[engine-adjudicated] {}",
                                finding
                                    .get("vuln_class")
                                    .and_then(Value::as_str)
                                    .unwrap_or("probe finding")
                            ),
                            finding
                                .get("description")
                                .and_then(Value::as_str)
                                .unwrap_or("Engine-confirmed probe finding")
                                .to_string(),
                        );
                        converted.verdict_source = Some("engine-adjudicated".into());
                        converted
                            .evidence
                            .add_data("engine_finding", finding.clone());
                        results.add_finding(converted);
                    }
                }
            } else {
                for (id, path) in &sources {
                    refused.push(json!({"template": id, "path": path, "target": target, "reason": if error.trim().is_empty() { format!("probe engine did not produce a report (exit {code})") } else { error.chars().take(4000).collect::<String>() }}));
                }
                if exit == 0 {
                    exit = 4;
                }
            }
            let audited_requests = audited_http_requests(&session.join("audit.jsonl"));
            results.statistics.network_requests_measured += audited_requests;
            // The durable audit counts observed HTTP attempts, not arbitrary
            // networking a probe can cause. Do not present that subset as a total.
            if audited_requests > 0
                || report
                    .as_ref()
                    .and_then(|r| r.get("templates_executed"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    > 0
            {
                results.statistics.network_requests = None;
            }
            append_executions(results, &target, &mappings, report.as_ref(), code, &refused);
            reports.push(json!({"target": target, "session_dir": session, "audit_log": session.join("audit.jsonl"),
                "report_path": report_path, "exit_code": code, "templates": mappings,
                "request_counts": {"audited_http_attempts": audited_requests, "probe_budget_requests": report.as_ref().and_then(|r| r.pointer("/scope_stats/total_requests")).and_then(Value::as_u64).unwrap_or(0)},
                "report": report}));
        }
    }
    if !refused.is_empty() && exit != 3 {
        exit = 4;
    }
    // Refusals before engine dispatch still need a gateable execution row.
    for entry in &refused {
        let target = entry.get("target").and_then(Value::as_str).unwrap_or("");
        let id = entry
            .get("template")
            .and_then(Value::as_str)
            .unwrap_or("probe");
        if !results
            .executions
            .iter()
            .any(|e| e.target == target && e.template_id == id)
        {
            results.executions.push(probe_execution(
                target,
                id,
                ExecutionStatus::Skipped,
                0,
                4,
                &format!(
                    "probe refused: {}",
                    entry.get("reason").unwrap_or(&Value::Null)
                ),
            ));
        }
    }
    let mut seen_refusals = HashSet::new();
    refused.retain(|entry| {
        seen_refusals.insert(
            json!([
                entry.get("target"),
                entry.get("template"),
                entry.get("path"),
                entry.get("reason")
            ])
            .to_string(),
        )
    });
    results.statistics.targets_scanned = results
        .statistics
        .targets_scanned
        .max(executed_targets.len());
    for refusal in &refused {
        eprintln!("[REFUSED] {}", refusal);
        results.errors.push(format!("Probe refused: {refusal}"));
    }
    results.probe_results = Some(
        json!({"verdict_source": "engine-adjudicated", "authoring": {"mode": "no_author", "model_calls": 0, "ranking": false, "generation": false, "mutation_retries": 0},
        "sessions": reports, "refused_probes": refused}),
    );
    Ok(exit)
}

fn audited_http_requests(path: &std::path::Path) -> usize {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| {
            row.get("_event").and_then(Value::as_str) == Some("request")
                && row
                    .get("url")
                    .and_then(Value::as_str)
                    .is_some_and(|url| url.starts_with("http://") || url.starts_with("https://"))
        })
        .count()
}

fn probe_execution(
    target: &str,
    id: &str,
    status: ExecutionStatus,
    findings: usize,
    _engine_code: i32,
    reason: &str,
) -> ExecutionRecord {
    ExecutionRecord {
        target: target.into(),
        target_kind: "http".into(),
        template_id: id.into(),
        status,
        declared_by_template: false,
        findings,
        // Probes execute inside a shared engine, without individual processes.
        exit_code: None,
        detail: Some(format!("engine-adjudicated: {reason}")),
        duration_ms: 0,
    }
}

fn append_executions(
    results: &mut ScanResults,
    target: &str,
    mappings: &[Value],
    report: Option<&Value>,
    code: i32,
    refusals: &[Value],
) {
    for mapping in mappings {
        let id = mapping["template"].as_str().unwrap_or("probe");
        let count = |key: &str| {
            report
                .and_then(|r| r.get(key))
                .and_then(Value::as_array)
                .map_or(0, |rows| {
                    rows.iter()
                        .filter(|r| {
                            r.get("template_id")
                                .or_else(|| r.get("hypothesis_id"))
                                .or_else(|| r.get("template"))
                                .and_then(Value::as_str)
                                == Some(id)
                        })
                        .count()
                })
        };
        let findings = count("confirmed_findings");
        let refusal = refusals.iter().find(|r| {
            r.get("target").and_then(Value::as_str) == Some(target)
                && if r.get("path").is_some_and(|p| !p.is_null()) {
                    r.get("path") == mapping.get("source")
                } else {
                    r.get("template").and_then(Value::as_str) == Some(id)
                }
        });
        let native = report
            .and_then(|r| r.get("probe_executions"))
            .and_then(Value::as_array)
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row.get("path") == mapping.get("staged"))
            });
        if let Some(row) = native {
            let mut execution = probe_execution(
                target,
                id,
                row.get("status")
                    .and_then(Value::as_str)
                    .and_then(ExecutionStatus::parse)
                    .unwrap_or(ExecutionStatus::Errored),
                row.get("findings").and_then(Value::as_u64).unwrap_or(0) as usize,
                code,
                row.get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("native probe execution"),
            );
            execution.duration_ms = row.get("duration_ms").and_then(Value::as_u64).unwrap_or(0);
            results.executions.push(execution);
            continue;
        }
        let (status, detail) = if let Some(refusal) = refusal {
            (
                ExecutionStatus::Skipped,
                format!(
                    "probe refused: {}",
                    refusal.get("reason").unwrap_or(&Value::Null)
                ),
            )
        } else if findings > 0 {
            (
                ExecutionStatus::Confirmed,
                format!("{findings} engine-confirmed finding(s)"),
            )
        } else if count("template_errors") > 0 {
            (
                ExecutionStatus::Errored,
                "probe runtime error; see native report".into(),
            )
        } else if count("mitigation_verifications") > 0 {
            (
                ExecutionStatus::Refuted,
                "engine verified mitigation/control".into(),
            )
        } else {
            (
                ExecutionStatus::Errored,
                "no conclusive engine verdict; see native report (silence is not refutation)"
                    .into(),
            )
        };
        results
            .executions
            .push(probe_execution(target, id, status, findings, code, &detail));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_verdicts_are_gateable_and_silence_is_never_refutation() {
        for (report, expected) in [
            (
                json!({"confirmed_findings":[{"template_id":"p"}]}),
                ExecutionStatus::Confirmed,
            ),
            (
                json!({"mitigation_verifications":[{"template_id":"p"}]}),
                ExecutionStatus::Refuted,
            ),
            (
                json!({"ambiguous":[{"template_id":"p"}]}),
                ExecutionStatus::Errored,
            ),
            (json!({}), ExecutionStatus::Errored),
        ] {
            let mut results = ScanResults::new(uuid::Uuid::new_v4());
            append_executions(
                &mut results,
                "http://target",
                &[json!({"template":"p","source":"probe.js"})],
                Some(&report),
                0,
                &[],
            );
            assert_eq!(results.executions.len(), 1);
            assert_eq!(results.executions[0].status, expected);
            assert!(!results.executions[0].declared_by_template);
            assert!(results.executions[0]
                .detail
                .as_ref()
                .unwrap()
                .starts_with("engine-adjudicated:"));
        }
    }
    #[test]
    fn audit_counts_engine_and_probe_http_attempts_without_budget_or_event_rows() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("audit.jsonl");
        let rows = [
            json!({"_event":"request","actor":"engine","url":"http://target/","method":"GET"}),
            json!({"_event":"request","actor":"engine","url":"http://target/api/me","method":"GET"}),
            json!({"_event":"request","template_id":"probe","url":"http://target/check","method":"POST"}),
            json!({"_event":"blocked","url":"http://target/blocked"}),
            json!({"_event":"request","method":"TEMPLATE_START","url":""}),
        ];
        fs::write(
            &file,
            rows.iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        assert_eq!(audited_http_requests(&file), 3);
    }
}
