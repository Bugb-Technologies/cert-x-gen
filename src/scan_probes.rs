//! Supplied-only probe dispatch for ordinary scans, including mixed template packs.
use crate::cli::{self, Cli, Commands, PentestAction, PentestCommand};
use cert_x_gen::{
    error::{Error, Result},
    template::{PathResolver, Template},
    types::{Finding, ScanResults, Severity},
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
            run.no_author = true;
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
                results.statistics.network_requests += report
                    .pointer("/scope_stats/total_requests")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
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
            reports.push(json!({"target": target, "session_dir": session, "audit_log": session.join("audit.jsonl"),
                "report_path": report_path, "exit_code": code, "templates": mappings, "report": report}));
        }
    }
    if !refused.is_empty() {
        exit = 4;
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
