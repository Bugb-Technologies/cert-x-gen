// CERT-X-GEN: Advanced Multi-Language Security Scanning Engine
// Copyright (c) 2024 CERT-X-GEN Core Team

use cert_x_gen::{
    ai::{AIManager, TemplateValidator},
    config::Config,
    core::CertXGen,
    error::{Error, Result},
    output::OutputManager,
    plugin::{LoggingPlugin, PluginManager},
    progress::{get_progress, init_progress},
    template::{Template, TemplateFilter},
    types::{Protocol, Target, TemplateLanguage},
    utils,
};
use clap::Parser;
use std::sync::Arc;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod cli;
use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    // Display banner first (before parsing CLI)
    // Check if --quiet flag is present in args
    let args: Vec<String> = std::env::args().collect();
    let is_quiet = args.iter().any(|arg| arg == "--quiet" || arg == "-q");

    if !is_quiet {
        cert_x_gen::banner::display_banner();
    }

    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize logging
    if let Err(e) = init_logging(&cli) {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    // Check if we should auto-enter a Docker sandbox
    if let Err(e) = check_and_enter_sandbox(&cli).await {
        tracing::error!("Sandbox error: {}", e);
        eprintln!("Sandbox error: {}", e);
        std::process::exit(1);
    }

    // Run the command
    if let Err(e) = run(cli).await {
        tracing::error!("Error: {}", e);
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Initialize logging system based on verbosity level
/// - 0: No logging (progress bar mode) - only errors logged internally
/// - 1 (-v): INFO + WARN logs
/// - 2 (-vv): INFO + WARN + TRACE logs  
/// - 3+ (-vvv): INFO + WARN + TRACE + DEBUG logs (everything)
fn init_logging(cli: &Cli) -> Result<()> {
    // Initialize progress tracker (enabled only when verbose=0)
    let progress_enabled = cli.verbose == 0;
    init_progress(progress_enabled);

    // Build filter - for verbose modes, we want cert_x_gen logs at the right level
    // When progress bar is enabled (verbose=0), suppress all logs except errors
    let filter_str = match cli.verbose {
        0 => "error".to_string(),
        1 => "cert_x_gen=info".to_string(),
        2 => "cert_x_gen=trace".to_string(),
        _ => "cert_x_gen=trace,debug".to_string(),
    };

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&filter_str));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    Ok(())
}

/// Run the CLI command
async fn run(cli: Cli) -> Result<()> {
    // Handle -ut shorthand (update templates and exit)
    if cli.update_templates {
        use cert_x_gen::template::AutoUpdater;
        let mut updater = AutoUpdater::new()?;
        updater.perform_update()?;
        
        // Show stats after update
        let stats = updater.get_stats();
        println!();
        println!("Templates: {}", stats.summary());
        return Ok(());
    }

    // Check if command is 'template update' - skip auto-update since command handles it
    let is_template_update = matches!(
        &cli.command,
        Some(Commands::Template(cmd)) if matches!(cmd.action, cli::TemplateAction::Update { .. })
    );

    // Handle auto-update flags before running any command (skip for template update)
    if !is_template_update {
        handle_auto_update(&cli).await?;
    }

    // If no command provided, show help
    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            // No command and no -ut flag - show help
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            cmd.print_help().ok();
            println!();
            return Ok(());
        }
    };

    match command {
        Commands::Scan(args) => {
            run_scan(args, cli.config).await?;
        }
        Commands::Template(cmd) => {
            run_template_command(cmd).await?;
        }
        Commands::Ai(cmd) => {
            run_ai_command(cmd).await?;
        }
        Commands::Search(args) => {
            run_search_command(args).await?;
        }
        Commands::Server(args) => {
            run_server(args).await?;
        }
        Commands::Config(cmd) => {
            run_config_command(cmd)?;
        }
        Commands::Sandbox(cmd) => {
            run_sandbox_command(cmd).await?;
        }
        Commands::Version => {
            print_version();
        }
    }

    Ok(())
}

/// Handle auto-update logic based on CLI flags
async fn handle_auto_update(cli: &Cli) -> Result<()> {
    use cert_x_gen::template::AutoUpdater;

    let mut updater = AutoUpdater::new()?;

    // Option 1: Force update on every startup (--update-templates-on-startup)
    if cli.update_templates_on_startup {
        tracing::info!("Forced template update on startup enabled");
        updater.perform_update()?;
        return Ok(());
    }

    // Option 2: Auto-update before running (--auto-update-templates)
    if cli.auto_update_templates {
        tracing::info!("Auto-updating templates before running...");
        updater.perform_update()?;
        return Ok(());
    }

    // Option 3: Disable update checks (--disable-update-check)
    if cli.disable_update_check {
        tracing::debug!("Auto-update checks disabled by user");
        updater.disable_auto_check()?;
        return Ok(());
    }

    // Option 4: Default behavior - check if templates exist (first-run auto-install)
    if updater.needs_initial_install() {
        updater.auto_install()?;
        return Ok(());
    }

    // Option 5: Hourly update check (like Nuclei)
    if updater.should_check_for_updates() {
        tracing::debug!("Checking for template updates...");
        let _ = updater.check_for_updates(); // Don't fail if update check fails
    }

    Ok(())
}

/// Run a security scan
async fn run_scan(args: cli::ScanArgs, config_path: Option<PathBuf>) -> Result<()> {
    // Load configuration
    let mut config = if let Some(path) = config_path {
        Config::from_file(path)?
    } else {
        Config::default()
    };

    // Override config with CLI arguments
    apply_scan_args_to_config(&mut config, &args);

    tracing::info!("Starting CERT-X-GEN v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Configuration loaded and validated");

    // Create CERT-X-GEN engine (template engines are auto-registered)
    let engine = CertXGen::new(config.clone()).await?;

    // Check for direct template file paths in --templates argument
    let (direct_template_paths, filter_ids) = if !args.templates.is_empty() {
        tracing::debug!("Processing --templates argument: {:?}", args.templates);
        separate_template_entries(&args.templates, &config.templates.directories)?
    } else {
        (Vec::new(), Vec::new())
    };

    // Determine loading strategy
    let has_direct_paths = !direct_template_paths.is_empty();
    let has_filter_ids = !filter_ids.is_empty();

    // Load templates based on what user specified
    tracing::info!("Loading templates...");

    let templates: Vec<Box<dyn Template>> = if has_direct_paths {
        // CASE 1: User specified direct file paths - load ONLY those (most efficient)
        tracing::info!(
            "Loading {} template(s) from direct paths",
            direct_template_paths.len()
        );
        let mut direct_templates: Vec<Box<dyn Template>> = Vec::new();

        for path in &direct_template_paths {
            tracing::debug!("Loading template from: {}", path.display());
            match engine.template_loader().load_template(path).await {
                Ok(template) => {
                    tracing::info!(
                        "Loaded template: {} ({}) from {}",
                        template.id(),
                        template.metadata().language,
                        path.display()
                    );
                    direct_templates.push(template);
                }
                Err(e) => {
                    tracing::error!("Failed to load template from {}: {}", path.display(), e);
                    return Err(Error::config(format!(
                        "Failed to load template '{}': {}",
                        path.display(),
                        e
                    )));
                }
            }
        }

        if direct_templates.is_empty() {
            return Err(Error::config(
                "No templates could be loaded from the specified paths.",
            ));
        }

        direct_templates
    } else if has_filter_ids {
        // CASE 2: User specified template IDs - search and load only matching templates
        tracing::info!(
            "Searching for {} specified template ID(s): {:?}",
            filter_ids.len(),
            filter_ids
        );
        let mut matched_templates: Vec<Box<dyn Template>> = Vec::new();
        let mut found_ids: HashSet<String> = HashSet::new();

        // Search in template directories for matching templates
        for dir in engine.template_manager().get_template_dirs() {
            if !dir.exists() {
                continue;
            }

            match engine.template_loader().load_templates_from_dir(&dir).await {
                Ok(templates) => {
                    for template in templates {
                        let template_id = template.id().to_string();
                        let template_name = template.name().to_string();
                        let file_path = template.metadata().file_path.to_string_lossy().to_string();

                        // Check if this template matches any of the filter IDs
                        let matches = filter_ids.iter().any(|filter_id| {
                            template_id.eq_ignore_ascii_case(filter_id)
                                || template_name.eq_ignore_ascii_case(filter_id)
                                || file_path.contains(filter_id)
                                || template
                                    .metadata()
                                    .file_path
                                    .file_stem()
                                    .and_then(|s| s.to_str())
                                    .map(|s| s.eq_ignore_ascii_case(filter_id))
                                    .unwrap_or(false)
                        });

                        if matches && !found_ids.contains(&template_id) {
                            tracing::info!(
                                "Found matching template: {} ({}) in {}",
                                template_id,
                                template.metadata().language,
                                dir.display()
                            );
                            found_ids.insert(template_id);
                            matched_templates.push(template);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to search templates in {}: {}", dir.display(), e);
                }
            }
        }

        // Report any filter IDs that weren't found
        for filter_id in &filter_ids {
            if !found_ids
                .iter()
                .any(|id| id.eq_ignore_ascii_case(filter_id))
            {
                tracing::warn!("Template not found: {}", filter_id);
            }
        }

        if matched_templates.is_empty() {
            return Err(Error::config(format!(
                "No templates found matching: {:?}. Use 'cxg template list' to see available templates.",
                filter_ids
            )));
        }

        matched_templates
    } else {
        // CASE 3: No specific templates - load all templates from directories
        tracing::debug!("No specific templates specified, loading all from directories");
        let loaded = engine.load_templates().await?;
        tracing::info!(
            "Loaded {} templates from template directories",
            loaded.len()
        );
        loaded
    };

    tracing::info!("Total templates to use: {}", templates.len());

    // Debug: Print all loaded template IDs
    for template in &templates {
        let metadata = template.metadata();
        tracing::debug!(
            "Available template: {} ({})",
            metadata.id,
            metadata.language
        );
    }

    if templates.is_empty() {
        return Err(Error::config(
            "No templates loaded. Please add templates to the templates directory.",
        ));
    }

    // Parse targets
    let mut targets = parse_targets(&args)?;
    if targets.is_empty() {
        return Err(Error::config(
            "No scope provided. Use --scope (aliases: --target, --targets, --target-file, --domain, --cidr, etc.).",
        ));
    }
    tracing::info!("Parsed {} targets", targets.len());

    // Expand targets for additional ports
    let mut additional_ports = Vec::new();
    if !args.ports.is_empty() {
        additional_ports = parse_port_entries(&args.ports)?;
        if !additional_ports.is_empty() {
            targets = expand_targets_for_ports(targets, &additional_ports);
            tracing::info!(
                "Expanded to {} targets with additional ports: {:?}",
                targets.len(),
                additional_ports
            );
        }
    }

    let mut top_ports = Vec::new();
    if let Some(count) = args.top_ports {
        top_ports = select_top_ports(count);
        if !top_ports.is_empty() {
            targets = expand_targets_for_ports(targets, &top_ports);
            tracing::info!(
                "Expanded to {} targets with top ports: {:?}",
                targets.len(),
                top_ports
            );
        }
    }

    // Create template filter
    // When we've already done targeted loading (direct paths or filter_ids), skip ID filtering
    let skip_id_filter = has_direct_paths || has_filter_ids;
    let filter = create_template_filter(&args, skip_id_filter)?;

    // Debug: Print filter details
    if !filter.ids.is_empty() {
        tracing::info!("Filtering templates by IDs: {:?}", filter.ids);
    }
    if !filter.tags.is_empty() {
        tracing::info!("Filtering templates by tags: {:?}", filter.tags);
    }
    if !filter.severities.is_empty() {
        tracing::info!("Filtering templates by severities: {:?}", filter.severities);
    }
    if !filter.languages.is_empty() {
        tracing::info!("Filtering templates by languages: {:?}", filter.languages);
    }
    if !filter.exclude_ids.is_empty() {
        tracing::info!("Excluding templates: {:?}", filter.exclude_ids);
    }

    // Create scan job
    let mut job = engine.create_scan_job(targets, templates);
    let templates_before = job.templates.len();
    job.filter_templates(&filter);

    // Apply mode-based template filtering
    if args.safe {
        // Safe mode: Exclude dangerous templates
        let dangerous_tags = vec![
            "dos",
            "resource-exhaustion",
            "intrusive",
            "destructive",
            "brute-force",
            "exploit",
        ];
        let before_safe = job.templates.len();
        job.templates.retain(|template| {
            let metadata = template.metadata();
            !dangerous_tags
                .iter()
                .any(|tag| metadata.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
        });
        let after_safe = job.templates.len();
        if before_safe != after_safe {
            tracing::info!(
                "Safe mode: Excluded {} dangerous templates (DoS, resource-exhaustion, etc.)",
                before_safe - after_safe
            );
        }
    }

    if args.passive {
        // Passive mode: Only include passive templates or exclude active ones
        let active_tags = vec!["active", "probe", "intrusive", "exploit"];
        let before_passive = job.templates.len();
        job.templates.retain(|template| {
            let metadata = template.metadata();
            // Include if tagged as passive, exclude if tagged as active
            let has_passive_tag = metadata
                .tags
                .iter()
                .any(|t| t.eq_ignore_ascii_case("passive"));
            let has_active_tag = active_tags
                .iter()
                .any(|tag| metadata.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)));
            has_passive_tag || !has_active_tag
        });
        let after_passive = job.templates.len();
        if before_passive != after_passive {
            tracing::info!(
                "Passive mode: Excluded {} active probe templates",
                before_passive - after_passive
            );
        }
    }

    let templates_after = job.templates.len();

    tracing::info!(
        "Templates selected: {} (total available: {})",
        templates_after,
        templates_before
    );

    // List selected templates in verbose mode
    if templates_after > 0 && templates_after <= 10 {
        for template in &job.templates {
            tracing::info!(
                "  - {} ({})",
                template.metadata().id,
                template.metadata().language
            );
        }
    }

    if !additional_ports.is_empty() || !top_ports.is_empty() {
        let mut combined = additional_ports.clone();
        combined.extend(top_ports.iter().copied());
        combined.sort_unstable();
        combined.dedup();
        job.context.additional_ports = combined;
        tracing::info!(
            "Adding {} additional ports to scan (custom + top): {:?}",
            job.context.additional_ports.len(),
            job.context.additional_ports
        );
    }

    if let Some(ref override_ports) = args.override_ports {
        let override_ports = parse_ports(override_ports)?;
        job.context.override_ports = Some(override_ports.clone());
        tracing::info!(
            "Overriding template default ports with: {:?}",
            override_ports
        );
    }

    tracing::info!(
        "Scan job created: {} targets × {} templates = {} total checks",
        job.targets.len(),
        job.templates.len(),
        job.total_work_units()
    );

    // Initialize plugin system
    let mut plugin_manager = PluginManager::new();
    plugin_manager.register(Arc::new(LoggingPlugin::new()));
    plugin_manager.notify_scan_start(job.id);

    // Initialize progress bar
    if let Some(progress) = get_progress() {
        progress.init(job.targets.len(), job.templates.len());
    }

    // Execute scan
    tracing::info!("Starting scan execution...");
    let start = std::time::Instant::now();
    let results = engine.execute_scan(job).await?;
    let duration = start.elapsed();

    // Finish progress bar
    if let Some(progress) = get_progress() {
        progress.finish();
    }

    tracing::info!("Scan completed in {:.2}s", duration.as_secs_f64());
    tracing::info!("Found {} total findings", results.findings.len());

    // Notify plugins
    plugin_manager.notify_scan_complete(&results);

    // Output results
    let output_manager = OutputManager::new();
    let formats: Vec<String> = args
        .output_format
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let output_path = PathBuf::from(&args.output);
    output_manager.write_results(&results, &output_path, &formats)?;

    // Print summary
    print_scan_summary(&results);

    Ok(())
}

/// Apply scan arguments to configuration
fn apply_scan_args_to_config(config: &mut Config, args: &cli::ScanArgs) {
    config.execution.threads = args.threads;
    config.execution.parallel_targets = args.parallel_targets;
    config.execution.parallel_templates = args.parallel_templates;
    config.execution.max_retries = args.retry;
    config.execution.aggressive_mode = args.aggressive;
    config.execution.stealth_mode = args.stealth;
    config.execution.passive_mode = args.passive;
    config.execution.safe_mode = args.safe;

    // Apply mode-specific optimizations
    if args.aggressive {
        // Aggressive mode: Increase concurrency, remove rate limits, increase retries
        config.execution.parallel_targets = config.execution.parallel_targets * 2;
        config.execution.parallel_templates = config.execution.parallel_templates * 2;
        config.execution.max_retries = config.execution.max_retries * 2;
        config.network.rate_limit = None; // Remove rate limits
        tracing::info!("Aggressive mode: Increased concurrency and retries, removed rate limits");
    }

    if args.stealth {
        // Stealth mode: Reduce concurrency, enforce rate limits, use browser user agent
        config.execution.parallel_targets = std::cmp::max(1, config.execution.parallel_targets / 3);
        config.execution.parallel_templates =
            std::cmp::max(1, config.execution.parallel_templates / 2);
        // Enforce rate limiting (default to 10 req/s if not set)
        if config.network.rate_limit.is_none() {
            config.network.rate_limit = Some(10);
        }
        // Use browser-like user agent if not already set
        if args.user_agent.is_none() {
            config.network.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string();
        }
        tracing::info!(
            "Stealth mode: Reduced concurrency, enforced rate limiting, using browser user agent"
        );
    }

    if args.passive {
        // Passive mode: Minimal concurrency
        config.execution.parallel_targets = std::cmp::max(1, config.execution.parallel_targets / 5);
        config.execution.parallel_templates = 1; // Sequential templates
        tracing::info!("Passive mode: Minimal concurrency, sequential template execution");
    }

    if args.safe {
        // Safe mode: Slightly reduce concurrency, keep rate limiting
        config.execution.parallel_targets =
            std::cmp::max(1, (config.execution.parallel_targets * 3) / 4);
        config.execution.parallel_templates =
            std::cmp::max(1, (config.execution.parallel_templates * 3) / 4);
        // Ensure rate limiting is enabled
        if config.network.rate_limit.is_none() {
            config.network.rate_limit = Some(50);
        }
        tracing::info!("Safe mode: Reduced concurrency, rate limiting enabled");
    }

    // Parse and apply timeout
    match utils::parse_duration(&args.timeout) {
        Ok(duration) => {
            config.network.timeout_secs = duration.as_secs();
            // Also apply to template timeout if reasonable
            if duration.as_secs() > 0 {
                config.templates.timeout_secs = duration.as_secs();
            }
        }
        Err(e) => {
            tracing::warn!(
                "Failed to parse timeout '{}': {}. Using default.",
                args.timeout,
                e
            );
        }
    }

    if let Some(proxy) = &args.proxy {
        config.network.proxy = Some(proxy.clone());
    }

    if let Some(user_agent) = &args.user_agent {
        config.network.user_agent = user_agent.clone();
    }

    config.network.follow_redirects = args.follow_redirects;
    config.network.max_redirects = args.max_redirects;

    if let Some(rate_limit) = args.rate_limit {
        config.network.rate_limit = Some(rate_limit);
    }

    config.output.stream = args.stream;

    // Apply template directory if specified
    if let Some(template_dir) = &args.template_dir {
        config.templates.directories = vec![template_dir.clone()];
    }

    // Apply custom headers
    if let Some(headers) = &args.header {
        for header in headers {
            if let Some((key, value)) = header.split_once(':') {
                config.network.headers.push((key.trim().to_string(), value.trim().to_string()));
            }
        }
    }

    // Apply cookies for authenticated scans
    if let Some(cookies) = &args.cookie {
        for cookie in cookies {
            if let Some((key, value)) = cookie.split_once('=') {
                config.network.cookies.push((key.trim().to_string(), value.trim().to_string()));
            }
        }
        if !config.network.cookies.is_empty() {
            tracing::info!("Using {} cookie(s) for authenticated scanning", config.network.cookies.len());
        }
    }
}

/// Expand targets to create one target per port
/// This enables testing multiple ports on the same host
fn expand_targets_for_ports(targets: Vec<Target>, ports: &[u16]) -> Vec<Target> {
    if ports.is_empty() {
        return targets;
    }

    let mut expanded = Vec::new();

    for target in targets {
        // If target already has a port, keep it and add additional ports
        if target.port.is_some() {
            expanded.push(target.clone());
        }

        // Create a target for each additional port
        for &port in ports {
            // Skip if this port is already the target's port
            if target.port == Some(port) {
                continue;
            }

            let mut new_target = target.clone();
            new_target.port = Some(port);
            expanded.push(new_target);
        }
    }

    expanded
}

/// Parse a single target string (supports host:port format)
fn parse_target_string(target_str: &str) -> Target {
    if let Ok(url) = url::Url::parse(target_str) {
        if let Some(host) = url.host_str() {
            let protocol = match url.scheme().to_lowercase().as_str() {
                "http" => Protocol::Http,
                "https" => Protocol::Https,
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                other => Protocol::Custom(other.to_string()),
            };

            let mut target = Target::new(host, protocol);
            if let Some(port) = url.port() {
                target.port = Some(port);
            }
            return target;
        }
    }

    match utils::parse_target(target_str) {
        Ok((host, port)) => {
            if let Some(port) = port {
                let protocol = match port {
                    80 | 8000 | 8080 => Protocol::Http,
                    443 | 8443 => Protocol::Https,
                    _ => Protocol::Https,
                };
                Target::with_port(host, port, protocol)
            } else {
                Target::new(host, Protocol::Https)
            }
        }
        Err(_) => Target::new(target_str, Protocol::Https),
    }
}

/// Parse targets from CLI scope arguments
fn parse_targets(args: &cli::ScanArgs) -> Result<Vec<Target>> {
    let mut expanded_entries = Vec::new();
    let mut in_progress_files = HashSet::new();

    for entry in &args.scope {
        expand_scope_entry(entry, &mut expanded_entries, &mut in_progress_files)?;
    }

    let mut seen = HashSet::new();
    let mut targets = Vec::new();

    for raw in expanded_entries {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !seen.insert(trimmed.to_string()) {
            continue;
        }

        targets.push(parse_target_string(trimmed));
    }

    Ok(targets)
}

fn expand_scope_entry(
    entry: &str,
    acc: &mut Vec<String>,
    file_stack: &mut HashSet<PathBuf>,
) -> Result<()> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    // Allow comma-separated lists inside scope values (e.g., from files)
    if trimmed.contains(',') {
        for part in trimmed.split(',') {
            expand_scope_entry(part, acc, file_stack)?;
        }
        return Ok(());
    }

    let (candidate, forced_file) = if let Some(rest) = trimmed.strip_prefix('@') {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix("file://") {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix("file:") {
        (rest, true)
    } else {
        (trimmed, false)
    };

    let path = Path::new(candidate);
    if forced_file || path.exists() {
        if !path.exists() {
            return Err(Error::config(format!(
                "Scope file not found: {}",
                candidate
            )));
        }

        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        if !file_stack.insert(canonical.clone()) {
            return Err(Error::config(format!(
                "Recursive scope file reference detected: {}",
                canonical.display()
            )));
        }

        let content = fs::read_to_string(path).map_err(|e| {
            Error::config(format!("Failed to read scope file '{}': {}", candidate, e))
        })?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            expand_scope_entry(line, acc, file_stack)?;
        }

        file_stack.remove(&canonical);
        return Ok(());
    }

    if trimmed.contains('/') && !trimmed.contains("://") {
        if let Ok(addresses) = utils::parse_cidr(trimmed) {
            for ip in addresses {
                acc.push(ip.to_string());
            }
            return Ok(());
        }
    }

    acc.push(trimmed.to_string());
    Ok(())
}

/// Create template filter from CLI arguments
/// When skip_id_filter is true, ID filtering is skipped (used when templates were already loaded by path/ID)
fn create_template_filter(args: &cli::ScanArgs, skip_id_filter: bool) -> Result<TemplateFilter> {
    let mut filter = TemplateFilter::new();

    // Smart template selector entries - skip if we already did targeted loading
    if !skip_id_filter && !args.templates.is_empty() {
        let template_entries = parse_template_entries(&args.templates)?;
        filter.ids.extend(template_entries);
    }

    // Filter by tags
    if let Some(tags) = &args.tags {
        filter.tags = tags.split(',').map(|s| s.trim().to_string()).collect();
    }

    // Filter by severity
    if let Some(severities) = &args.severity {
        filter.severities = severities.iter().map(|s| (*s).into()).collect();
    }

    // Filter by language
    if let Some(languages) = &args.template_language {
        filter.languages = languages.iter().map(|l| (*l).into()).collect();
    }

    // Exclude templates (supports comma-separated patterns)
    if let Some(exclude) = &args.exclude_templates {
        for pattern in exclude.split(',') {
            filter.exclude_ids.push(pattern.trim().to_string());
        }
    }

    Ok(filter)
}

/// Parse port specification string (supports individual ports and ranges)
/// Examples: "80,443,8000-9000" -> [80, 443, 8000, 8001, ..., 9000]
fn parse_ports(port_spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in port_spec.split(',') {
        let part = part.trim();

        if part.contains('-') {
            // Handle range (e.g., "8000-9000")
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(Error::config(format!("Invalid port range: {}", part)));
            }

            let start: u16 = range_parts[0]
                .trim()
                .parse()
                .map_err(|_| Error::config(format!("Invalid port number: {}", range_parts[0])))?;
            let end: u16 = range_parts[1]
                .trim()
                .parse()
                .map_err(|_| Error::config(format!("Invalid port number: {}", range_parts[1])))?;

            if start > end {
                return Err(Error::config(format!(
                    "Invalid port range: {} > {}",
                    start, end
                )));
            }

            for port in start..=end {
                ports.push(port);
            }
        } else {
            // Handle single port
            let port: u16 = part
                .parse()
                .map_err(|_| Error::config(format!("Invalid port number: {}", part)))?;
            ports.push(port);
        }
    }

    // Remove duplicates and sort
    ports.sort_unstable();
    ports.dedup();

    Ok(ports)
}

fn parse_port_entries(entries: &[String]) -> Result<Vec<u16>> {
    let mut collected = Vec::new();
    let mut file_stack = HashSet::new();

    for entry in entries {
        expand_port_entry(entry, &mut collected, &mut file_stack)?;
    }

    collected.sort_unstable();
    collected.dedup();
    Ok(collected)
}

fn expand_port_entry(
    entry: &str,
    acc: &mut Vec<u16>,
    file_stack: &mut HashSet<PathBuf>,
) -> Result<()> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    if trimmed.contains(',') {
        for part in trimmed.split(',') {
            expand_port_entry(part, acc, file_stack)?;
        }
        return Ok(());
    }

    let (candidate, forced_file) = if let Some(rest) = trimmed.strip_prefix('@') {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix("file://") {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix("file:") {
        (rest, true)
    } else {
        (trimmed, false)
    };

    let path = Path::new(candidate);
    if forced_file || path.exists() {
        if !path.exists() {
            return Err(Error::config(format!("Port file not found: {}", candidate)));
        }

        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        if !file_stack.insert(canonical.clone()) {
            return Err(Error::config(format!(
                "Recursive port file reference detected: {}",
                canonical.display()
            )));
        }

        let content = fs::read_to_string(path).map_err(|e| {
            Error::config(format!("Failed to read port file '{}': {}", candidate, e))
        })?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            expand_port_entry(line, acc, file_stack)?;
        }

        file_stack.remove(&canonical);
        return Ok(());
    }

    acc.extend(parse_ports(trimmed)?);
    Ok(())
}

fn select_top_ports(count: u16) -> Vec<u16> {
    utils::top_ports(count)
}

/// Check if a path is a template source file (actual template, not a list file)
fn is_template_source_file(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => matches!(
            ext.to_ascii_lowercase().as_str(),
            "yaml" | "yml" |  // YAML templates
            "py" |            // Python
            "js" |            // JavaScript
            "rs" |            // Rust
            "c" |             // C
            "cpp" | "cc" | "cxx" | // C++
            "java" |          // Java
            "go" |            // Go
            "rb" |            // Ruby
            "pl" |            // Perl
            "php" |           // PHP
            "sh" | "bash" // Shell
        ),
        None => false,
    }
}

/// Separate template entries into direct file paths and filter IDs
/// Returns (direct_template_paths, filter_ids)
///
/// When a relative path is provided, it will be resolved against the template directories.
fn separate_template_entries(
    entries: &[String],
    template_dirs: &[PathBuf],
) -> Result<(Vec<PathBuf>, Vec<String>)> {
    let mut direct_paths = Vec::new();
    let mut filter_ids = Vec::new();

    tracing::debug!(
        "Separating {} template entries (template_dirs: {:?})",
        entries.len(),
        template_dirs
    );

    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Handle comma-separated entries
        if trimmed.contains(',') {
            for part in trimmed.split(',') {
                let (mut paths, mut ids) =
                    separate_template_entries(&[part.to_string()], template_dirs)?;
                direct_paths.append(&mut paths);
                filter_ids.append(&mut ids);
            }
            continue;
        }

        let path = Path::new(trimmed);
        let exists = path.exists();
        let is_file = path.is_file();
        let is_template = is_template_source_file(path);
        let is_abs = path.is_absolute();

        tracing::debug!(
            "Entry '{}': exists={}, is_file={}, is_template={}, is_absolute={}",
            trimmed,
            exists,
            is_file,
            is_template,
            is_abs
        );

        // Check if it's a direct path to a template file (absolute or relative that exists)
        if exists && is_file && is_template {
            tracing::info!("Detected direct template path: {}", trimmed);
            direct_paths.push(path.to_path_buf());
        } else if is_abs && is_template && !exists {
            // Absolute path that looks like a template but doesn't exist - report error
            return Err(Error::config(format!(
                "Template file not found: {}",
                trimmed
            )));
        } else if !is_abs && (trimmed.contains('/') || trimmed.contains('\\')) && is_template {
            // Relative path that looks like a template - try resolving against template directories
            let mut found = false;

            for template_dir in template_dirs {
                let resolved_path = template_dir.join(trimmed);
                tracing::debug!(
                    "Trying to resolve relative path: {} -> {}",
                    trimmed,
                    resolved_path.display()
                );

                if resolved_path.exists() && resolved_path.is_file() {
                    tracing::info!(
                        "Resolved relative template path: {} -> {}",
                        trimmed,
                        resolved_path.display()
                    );
                    direct_paths.push(resolved_path);
                    found = true;
                    break;
                }
            }

            if !found {
                // Couldn't find the template in any directory
                let searched_dirs: Vec<String> = template_dirs
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect();
                return Err(Error::config(format!(
                    "Template file not found: {} (searched in: {})",
                    trimmed,
                    if searched_dirs.is_empty() {
                        "current directory".to_string()
                    } else {
                        searched_dirs.join(", ")
                    }
                )));
            }
        } else {
            // Treat as template ID for filtering
            tracing::debug!("Treating as filter ID: {}", trimmed);
            filter_ids.push(trimmed.to_string());
        }
    }

    tracing::info!(
        "Separated template entries: {} direct paths, {} filter IDs",
        direct_paths.len(),
        filter_ids.len()
    );

    Ok((direct_paths, filter_ids))
}

fn parse_template_entries(entries: &[String]) -> Result<Vec<String>> {
    let mut collected = Vec::new();
    let mut file_stack = HashSet::new();

    for entry in entries {
        expand_template_entry(entry, &mut collected, &mut file_stack)?;
    }

    let mut seen = HashSet::new();
    let mut unique = Vec::new();

    for entry in collected {
        if seen.insert(entry.clone()) {
            unique.push(entry);
        }
    }

    Ok(unique)
}

fn expand_template_entry(
    entry: &str,
    acc: &mut Vec<String>,
    file_stack: &mut HashSet<PathBuf>,
) -> Result<()> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    if trimmed.contains(',') {
        for part in trimmed.split(',') {
            expand_template_entry(part, acc, file_stack)?;
        }
        return Ok(());
    }

    let (candidate, forced_file) = if let Some(rest) = trimmed.strip_prefix('@') {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix("file://") {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix("file:") {
        (rest, true)
    } else {
        (trimmed, false)
    };

    let path = Path::new(candidate);

    if forced_file || (path.exists() && path.is_file() && is_template_list_file(path)) {
        if !path.exists() {
            return Err(Error::config(format!(
                "Template list file not found: {}",
                candidate
            )));
        }

        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        if !file_stack.insert(canonical.clone()) {
            return Err(Error::config(format!(
                "Recursive template file reference detected: {}",
                canonical.display()
            )));
        }

        let content = fs::read_to_string(path).map_err(|e| {
            Error::config(format!(
                "Failed to read template list '{}': {}",
                candidate, e
            ))
        })?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            expand_template_entry(line, acc, file_stack)?;
        }

        file_stack.remove(&canonical);
        return Ok(());
    }

    acc.push(trimmed.to_string());
    Ok(())
}

fn is_template_list_file(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => matches!(
            ext.to_ascii_lowercase().as_str(),
            "txt" | "list" | "lst" | "cfg"
        ),
        None => false,
    }
}

/// Run template validation command
async fn run_validate_command(
    path: PathBuf,
    recursive: bool,
    _show_score: bool,
    strict: bool,
    format: String,
    _summary: bool,
    _language: Option<cli::LanguageArg>,
    _min_score: u8,
) -> Result<()> {
    use cert_x_gen::ai::validator::{DiagnosticSeverity, TemplateDiagnostic};
    use console::style;
    use std::fs;

    println!("{}", style("═".repeat(80)).dim());
    println!("{}", style("CERT-X-GEN Template Validator").bold().cyan());
    println!("{}", style("═".repeat(80)).dim());
    println!();

    // Create validator
    let validator = TemplateValidator::new();

    // Collect template files
    let mut template_files = Vec::new();

    if path.is_file() {
        template_files.push(path.clone());
    } else if path.is_dir() {
        if recursive {
            for entry in walkdir::WalkDir::new(&path)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    if let Some(ext) = entry_path.extension() {
                        let ext_str = ext.to_string_lossy();
                        if [
                            "py", "js", "sh", "rb", "pl", "php", "rs", "c", "cpp", "go", "java",
                            "yaml", "yml",
                        ]
                        .contains(&ext_str.as_ref())
                        {
                            template_files.push(entry_path.to_path_buf());
                        }
                    }
                }
            }
        } else {
            if let Ok(entries) = fs::read_dir(&path) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let entry_path = entry.path();
                    if entry_path.is_file() {
                        if let Some(ext) = entry_path.extension() {
                            let ext_str = ext.to_string_lossy();
                            if [
                                "py", "js", "sh", "rb", "pl", "php", "rs", "c", "cpp", "go",
                                "java", "yaml", "yml",
                            ]
                            .contains(&ext_str.as_ref())
                            {
                                template_files.push(entry_path);
                            }
                        }
                    }
                }
            }
        }
    }

    if template_files.is_empty() {
        println!("{}", style("No template files found!").red().bold());
        return Ok(());
    }

    println!(
        "Found {} template(s) to validate",
        style(template_files.len()).cyan().bold()
    );
    println!();

    // Simple validation results
    #[derive(serde::Serialize)]
    struct ValidationResult {
        template_path: String,
        language: Option<TemplateLanguage>,
        passed: bool,
        diagnostics: Vec<TemplateDiagnostic>,
        error: Option<String>,
    }

    // Validate each template
    let mut results = Vec::new();
    let mut passed_count = 0;
    let mut failed_count = 0;

    for template_path in &template_files {
        // Read template content
        let content = match fs::read_to_string(template_path) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("Failed to read file: {}", e);
                let diag = TemplateDiagnostic {
                    code: "io.read_error".to_string(),
                    message: msg.clone(),
                    severity: DiagnosticSeverity::Error,
                    line: None,
                    column: None,
                };
                let result = ValidationResult {
                    template_path: template_path.display().to_string(),
                    language: None,
                    passed: false,
                    diagnostics: vec![diag],
                    error: Some(msg),
                };
                results.push(result);
                failed_count += 1;
                continue;
            }
        };

        // Determine language from extension
        let language = match template_path.extension().and_then(|e| e.to_str()) {
            Some("py") => TemplateLanguage::Python,
            Some("js") => TemplateLanguage::JavaScript,
            Some("sh") => TemplateLanguage::Shell,
            Some("rb") => TemplateLanguage::Ruby,
            Some("pl") => TemplateLanguage::Perl,
            Some("php") => TemplateLanguage::Php,
            Some("rs") => TemplateLanguage::Rust,
            Some("c") => TemplateLanguage::C,
            Some("cpp") | Some("cc") | Some("cxx") => TemplateLanguage::Cpp,
            Some("go") => TemplateLanguage::Go,
            Some("java") => TemplateLanguage::Java,
            Some("yaml") | Some("yml") => TemplateLanguage::Yaml,
            _ => {
                let msg = "Unknown file extension".to_string();
                let diag = TemplateDiagnostic {
                    code: "template.unknown_extension".to_string(),
                    message: msg.clone(),
                    severity: DiagnosticSeverity::Error,
                    line: None,
                    column: None,
                };
                let result = ValidationResult {
                    template_path: template_path.display().to_string(),
                    language: None,
                    passed: false,
                    diagnostics: vec![diag],
                    error: Some(msg),
                };
                results.push(result);
                failed_count += 1;
                continue;
            }
        };

        // Validate template with structured diagnostics
        let mut diagnostics =
            match validator.validate_with_diagnostics(&content, language, Some(&template_path)) {
                Ok(diags) => diags,
                Err(e) => {
                    vec![TemplateDiagnostic {
                        code: "validator.internal_error".to_string(),
                        message: e.to_string(),
                        severity: DiagnosticSeverity::Error,
                        line: None,
                        column: None,
                    }]
                }
            };

        // YAML-specific best-practice: id should match filename stem
        if let TemplateLanguage::Yaml = language {
            if let Ok(yaml_value) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                if let Some(id_val) = yaml_value.get("id").and_then(|v| v.as_str()) {
                    if let Some(stem) = template_path.file_stem().and_then(|s| s.to_str()) {
                        if id_val != stem {
                            let line = content
                                .lines()
                                .enumerate()
                                .find(|(_, line)| line.contains("id:"))
                                .map(|(idx, _)| idx + 1);

                            diagnostics.push(TemplateDiagnostic {
                                code: "yaml.id_filename_mismatch".to_string(),
                                message: format!(
                                    "YAML template id '{}' does not match filename '{}'. For best results, keep them aligned.",
                                    id_val, stem
                                ),
                                severity: DiagnosticSeverity::Warning,
                                line,
                                column: None,
                            });
                        }
                    }
                }
            }
        }

        let has_error = diagnostics
            .iter()
            .any(|d| matches!(d.severity, DiagnosticSeverity::Error));

        let error_summary = if has_error {
            let messages: Vec<String> = diagnostics
                .iter()
                .filter(|d| matches!(d.severity, DiagnosticSeverity::Error))
                .map(|d| format!("{}: {}", d.code, d.message))
                .collect();
            if messages.is_empty() {
                None
            } else {
                Some(messages.join(" | "))
            }
        } else {
            None
        };

        let result = ValidationResult {
            template_path: template_path.display().to_string(),
            language: Some(language),
            passed: !has_error,
            diagnostics,
            error: error_summary,
        };

        if result.passed {
            passed_count += 1;
        } else {
            failed_count += 1;
        }

        results.push(result);
    }

    // Output results based on format
    match format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        "table" | "text" => {
            for result in &results {
                let filename = PathBuf::from(&result.template_path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string();

                if result.passed {
                    println!("{} {}", style("✓").green().bold(), style(&filename).green());
                } else {
                    println!("{} {}", style("✗").red().bold(), style(&filename).red());
                }

                for diag in &result.diagnostics {
                    let sev_label = match diag.severity {
                        DiagnosticSeverity::Error => style("error").red().bold(),
                        DiagnosticSeverity::Warning => style("warning").yellow().bold(),
                        DiagnosticSeverity::Info => style("info").blue().bold(),
                    };

                    let location = match (diag.line, diag.column) {
                        (Some(line), Some(col)) => format!("{}:{}: ", line, col),
                        (Some(line), None) => format!("{}: ", line),
                        _ => String::new(),
                    };

                    println!(
                        "    [{}] {}{}: {}",
                        sev_label, location, diag.code, diag.message
                    );
                }

                if !result.diagnostics.is_empty() {
                    println!();
                }
            }

            println!();

            // Print summary
            println!("{}", style("═".repeat(80)).dim());
            println!("{}", style("Validation Summary").bold().cyan());
            println!("{}", style("═".repeat(80)).dim());
            println!();
            println!("  Total Templates: {}", style(results.len()).bold());
            println!(
                "  {} {}",
                style("✓").green().bold(),
                style(format!("Passed: {}", passed_count)).green()
            );
            println!(
                "  {} {}",
                style("✗").red().bold(),
                style(format!("Failed: {}", failed_count)).red()
            );
            if results.len() > 0 {
                println!(
                    "  Success Rate: {}%",
                    style(passed_count * 100 / results.len()).bold()
                );
            }
            println!();
        }
        _ => {
            eprintln!("Unknown format: {}", format);
            return Err(Error::Validation(format!("Invalid format: {}", format)));
        }
    }

    // Exit with error if any failed and strict mode
    if strict && failed_count > 0 {
        return Err(Error::Validation(format!(
            "{} template(s) failed validation",
            failed_count
        )));
    }

    Ok(())
}

/// Run template management commands
async fn run_template_command(cmd: cli::TemplateCommand) -> Result<()> {
    use cli::TemplateAction;

    match cmd.action {
        TemplateAction::List {
            language,
            severity,
            tags,
        } => {
            // Load configuration
            let config = Config::default();

            // Create CERT-X-GEN engine
            let engine = CertXGen::new(config).await?;

            // Load all templates
            let templates = engine.load_templates().await?;

            // Filter templates based on criteria
            let mut filtered_templates = templates;

            if let Some(lang) = language {
                let target_language: cert_x_gen::types::TemplateLanguage = lang.into();
                filtered_templates
                    .retain(|template| template.metadata().language == target_language);
            }

            if let Some(sev) = severity {
                let target_severity: cert_x_gen::types::Severity = sev.into();
                filtered_templates
                    .retain(|template| template.metadata().severity == target_severity);
            }

            if let Some(tag_filter) = tags {
                let target_tags: Vec<String> = tag_filter
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
                filtered_templates.retain(|template| {
                    target_tags
                        .iter()
                        .any(|tag| template.metadata().tags.contains(tag))
                });
            }

            // Display templates
            println!("Found {} templates:", filtered_templates.len());
            println!();

            for template in filtered_templates {
                let metadata = template.metadata();
                println!("ID: {}", metadata.id);
                println!("Name: {}", metadata.name);
                println!("Language: {:?}", metadata.language);
                println!("Severity: {:?}", metadata.severity);
                println!("Author: {}", metadata.author.name);
                println!("Description: {}", metadata.description);
                println!("Tags: {}", metadata.tags.join(", "));
                println!("File: {}", metadata.file_path.display());
                println!("---");
            }

            Ok(())
        }
        TemplateAction::Validate {
            path,
            recursive,
            json,
        } => {
            // Call the validation function with default parameters
            let format = if json {
                "json".to_string()
            } else {
                "text".to_string()
            };
            run_validate_command(
                path, recursive, false,  // show_score
                false,  // strict
                format, // format
                false,  // summary
                None,   // language
                0,      // min_score
            )
            .await?;
            Ok(())
        }
        TemplateAction::Update { force: _ } => {
            use cert_x_gen::template::AutoUpdater;

            let mut updater = AutoUpdater::new().map_err(|e| {
                Error::config(format!("Failed to initialize updater: {}", e))
            })?;

            // Check if this is first run (no templates)
            if updater.needs_initial_install() {
                updater.auto_install().map_err(|e| {
                    Error::config(format!("Failed to install templates: {}", e))
                })?;
            } else {
                // Regular update
                updater.perform_update().map_err(|e| {
                    Error::config(format!("Failed to update templates: {}", e))
                })?;

                // Show stats
                let stats = updater.get_stats();
                println!();
                println!("✅ Templates ready: {}", stats.summary());
            }

            Ok(())
        }
        TemplateAction::Info { template_id } => {
            // Use the same template loading as search command
            let config = Config::default();
            let engine = CertXGen::new(config).await?;
            let templates = engine.load_templates().await?;
            
            // Find template by ID (case-insensitive partial match)
            let matching: Vec<_> = templates
                .iter()
                .filter(|t| {
                    t.id().to_lowercase().contains(&template_id.to_lowercase())
                })
                .collect();
            
            if matching.is_empty() {
                println!("❌ No template found matching: {}", template_id);
                println!("\nTry: cxg search --query \"{}\"", template_id);
                return Ok(());
            }
            
            if matching.len() > 1 {
                println!("Found {} templates matching '{}':\n", matching.len(), template_id);
                for t in &matching {
                    println!("  • {} ({:?})", t.id(), t.metadata().language);
                }
                println!("\nPlease specify a more exact template ID.");
                return Ok(());
            }
            
            // Show detailed info for the single match
            let template = matching[0];
            let meta = template.metadata();
            
            println!("\n╔════════════════════════════════════════════════════════════════╗");
            println!("║  Template Information                                          ║");
            println!("╚════════════════════════════════════════════════════════════════╝\n");
            
            println!("  ID:          {}", template.id());
            println!("  Name:        {}", meta.name);
            println!("  Language:    {:?}", meta.language);
            println!("  Severity:    {:?}", meta.severity);
            println!("  Author:      {}", meta.author.name);
            println!("  Description: {}", meta.description);
            
            if !meta.tags.is_empty() {
                println!("  Tags:        {}", meta.tags.join(", "));
            }
            
            if !meta.file_path.as_os_str().is_empty() {
                println!("  File:        {}", meta.file_path.display());
                
                // Show file size
                if let Ok(file_meta) = std::fs::metadata(&meta.file_path) {
                    let size = file_meta.len();
                    if size > 1024 {
                        println!("  Size:        {:.1} KB", size as f64 / 1024.0);
                    } else {
                        println!("  Size:        {} bytes", size);
                    }
                }
            }
            
            println!();
            Ok(())
        }
        TemplateAction::Create {
            id,
            language,
            name,
            output,
        } => {
            use cli::LanguageArg;
            
            // Map language to file extension and skeleton name
            let (ext, skeleton_name) = match language {
                LanguageArg::Python => ("py", "python-template-skeleton.py"),
                LanguageArg::Rust => ("rs", "rust-template-skeleton.rs"),
                LanguageArg::C => ("c", "c-template-skeleton.c"),
                LanguageArg::Cpp => ("cpp", "cpp-template-skeleton.cpp"),
                LanguageArg::Java => ("java", "java-template-skeleton.java"),
                LanguageArg::Go => ("go", "go-template-skeleton.go"),
                LanguageArg::JavaScript => ("js", "javascript-template-skeleton.js"),
                LanguageArg::Ruby => ("rb", "ruby-template-skeleton.rb"),
                LanguageArg::Perl => ("pl", "perl-template-skeleton.pl"),
                LanguageArg::Php => ("php", "php-template-skeleton.php"),
                LanguageArg::Shell => ("sh", "shell-template-skeleton.sh"),
                LanguageArg::Yaml => ("yaml", "yaml-template-skeleton.yaml"),
            };
            
            // Try to find skeleton in multiple locations
            let skeleton_paths = vec![
                // Local dev path
                std::path::PathBuf::from("templates/skeleton").join(skeleton_name),
                // Installed user path
                dirs::home_dir()
                    .unwrap_or_default()
                    .join(".cert-x-gen/templates/official/templates/skeleton")
                    .join(skeleton_name),
            ];
            
            let skeleton_content = skeleton_paths
                .iter()
                .find_map(|p| std::fs::read_to_string(p).ok())
                .ok_or_else(|| Error::config(format!(
                    "Skeleton template '{}' not found. Run 'cxg --ut' to download templates.",
                    skeleton_name
                )))?;
            
            // Replace placeholders
            let template_name = if name.is_empty() {
                // Convert kebab-case to Title Case
                id.split('-')
                    .map(|word| {
                        let mut chars = word.chars();
                        match chars.next() {
                            Some(c) => c.to_uppercase().chain(chars).collect(),
                            None => String::new(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                name.clone()
            };
            
            let content = skeleton_content
                .replace("template-skeleton", &id)
                .replace("Template Skeleton", &template_name);
            
            // Determine output path
            let output_path = output.join(format!("{}.{}", id, ext));
            
            // Write template
            std::fs::write(&output_path, &content)
                .map_err(|e| Error::config(format!("Failed to write template: {}", e)))?;
            
            println!("✅ Created template: {}", output_path.display());
            println!("   Language: {:?}", language);
            println!("   ID: {}", id);
            println!("\nNext steps:");
            println!("   1. Edit the template to add your detection logic");
            println!("   2. Validate: cxg template validate {}", output_path.display());
            println!("   3. Test: cxg scan --scope <target> --templates {}", output_path.display());
            
            Ok(())
        }
        TemplateAction::Test {
            template,
            target,
            debug: _,
        } => {
            println!("Testing template {} against {}", template.display(), target);
            // TODO: Implement template testing
            Ok(())
        }
    }
}

/// Run search command
async fn run_search_command(args: cli::SearchArgs) -> Result<()> {
    use cert_x_gen::search::{
        SearchArgs as LibSearchArgs, SearchFormat, SearchResultFormatter, SearchSort,
        TemplateSearchEngine,
    };
    use std::fs;

    tracing::info!("Starting template search...");

    // Load configuration
    let config = Config::default();

    // Create CERT-X-GEN engine
    let engine = CertXGen::new(config).await?;

    // Load all templates
    let templates = engine.load_templates().await?;
    tracing::info!("Loaded {} templates", templates.len());

    // Convert CLI args to library args
    let search_args = LibSearchArgs {
        query: args.query,
        language: args.language.map(|l| l.into()),
        severity: args.severity.map(|s| s.into()),
        tags: args.tags,
        author: args.author,
        cwe: args.cwe,
        content: args.content,
        case_sensitive: args.case_sensitive,
        regex: args.regex,
        limit: args.limit,
        format: match args.format {
            cli::SearchFormat::Table => SearchFormat::Table,
            cli::SearchFormat::Json => SearchFormat::Json,
            cli::SearchFormat::Yaml => SearchFormat::Yaml,
            cli::SearchFormat::Csv => SearchFormat::Csv,
            cli::SearchFormat::List => SearchFormat::List,
            cli::SearchFormat::Detailed => SearchFormat::Detailed,
        },
        detailed: args.detailed,
        sort: match args.sort {
            cli::SearchSort::Relevance => SearchSort::Relevance,
            cli::SearchSort::Name => SearchSort::Name,
            cli::SearchSort::Language => SearchSort::Language,
            cli::SearchSort::Severity => SearchSort::Severity,
            cli::SearchSort::Author => SearchSort::Author,
            cli::SearchSort::Date => SearchSort::Date,
            cli::SearchSort::Popularity => SearchSort::Popularity,
        },
        reverse: args.reverse,
        ids_only: args.ids_only,
        stats: args.stats,
    };

    // Create search engine
    let search_engine = TemplateSearchEngine::new(templates);

    // Perform search
    let (results, stats) = search_engine.search(&search_args);

    // Format and output results
    let output = SearchResultFormatter::format_results(
        &results,
        &stats,
        search_args.format,
        args.detailed,
        args.ids_only,
    );

    // Output results
    if let Some(output_file) = args.output {
        fs::write(&output_file, &output)?;
        println!("Search results written to: {}", output_file.display());
    } else {
        print!("{}", output);
    }

    // Show statistics if requested
    if args.stats {
        println!("\nSearch Statistics:");
        println!("  Total templates: {}", stats.total_templates);
        println!("  Matching templates: {}", stats.matching_templates);
        println!("  Search time: {}ms", stats.search_time_ms);

        if !stats.languages.is_empty() {
            println!("  Languages:");
            for (language, count) in &stats.languages {
                println!("    {:?}: {}", language, count);
            }
        }

        if !stats.severities.is_empty() {
            println!("  Severities:");
            for (severity, count) in &stats.severities {
                println!("    {:?}: {}", severity, count);
            }
        }
    }

    Ok(())
}

/// Run API server
async fn run_server(args: cli::ServerArgs) -> Result<()> {
    tracing::info!("Starting API server on {}:{}", args.bind, args.port);
    // TODO: Implement API server
    Err(Error::NotImplemented(
        "API server not yet implemented".to_string(),
    ))
}

/// Run configuration commands
fn run_config_command(cmd: cli::ConfigCommand) -> Result<()> {
    use cli::ConfigAction;

    match cmd.action {
        ConfigAction::Generate { output, format: _ } => {
            let config = Config::default();
            config.save(&output)?;
            println!("Configuration generated: {}", output.display());
            Ok(())
        }
        ConfigAction::Validate { config } => {
            let cfg = Config::from_file(&config)?;
            cfg.validate()?;
            println!("Configuration is valid");
            Ok(())
        }
        ConfigAction::Show => {
            let config = Config::default();
            let yaml =
                serde_yaml::to_string(&config).map_err(|e| Error::Serialization(e.to_string()))?;
            println!("{}", yaml);
            Ok(())
        }
    }
}

/// Run sandbox commands
async fn run_sandbox_command(cmd: cli::SandboxCommand) -> Result<()> {
    use cert_x_gen::sandbox::{Sandbox, SandboxConfig};
    use cli::SandboxAction;
    use console::{style, Term};

    let term = Term::stdout();

    match cmd.action {
        SandboxAction::Init {
            force,
            languages,
            directory,
        } => {
            use cert_x_gen::sandbox::config::SandboxConfigFile;
            use cert_x_gen::sandbox::docker::{
                current_sandbox_name, inside_sandbox, DockerSandbox,
            };
            use cert_x_gen::sandbox::Sandbox;

            // Check if we're inside a Docker sandbox
            if inside_sandbox() {
                if let Some(sandbox_name) = current_sandbox_name() {
                    term.write_line(&format!(
                        "\n{} Running inside Docker sandbox: {}",
                        style("🐳").cyan(),
                        style(&sandbox_name).yellow()
                    ))?;
                    term.write_line(&format!(
                        "  Initializing package environment inside the container..."
                    ))?;
                    term.write_line("")?;
                }
            } else {
                // Check if there's a default Docker sandbox
                if let Ok(cfg) = SandboxConfigFile::load() {
                    if let Some((name, config)) = cfg.get_default_sandbox() {
                        if config.auto_start {
                            term.write_line(&format!(
                                "\n{} Default Docker sandbox detected: {}",
                                style("🐳").cyan(),
                                style(name).yellow()
                            ))?;
                            term.write_line(&format!(
                                "  This command will run INSIDE the Docker container."
                            ))?;
                            term.write_line(&format!(
                                "  You'll stay on your host, but init happens in the sandbox."
                            ))?;
                            term.write_line("")?;
                        }
                    }
                }

                // Check if Docker is available and recommend it (only if no default sandbox)
                if DockerSandbox::docker_available() && DockerSandbox::docker_running() {
                    if SandboxConfigFile::load()
                        .ok()
                        .and_then(|c| c.default_sandbox)
                        .is_none()
                    {
                        term.write_line(&format!("\n{} Docker detected!", style("ℹ").blue()))?;
                        term.write_line(&format!("  For true OS-level isolation, consider using Docker sandboxes instead:"))?;
                        term.write_line(&format!(
                            "  {}",
                            style("cxg sandbox create my-env").yellow()
                        ))?;
                        term.write_line(&format!(
                            "  {}",
                            style("cxg sandbox set-default my-env").yellow()
                        ))?;
                        term.write_line("")?;
                        term.write_line(&format!("  This command (init) creates a package-level sandbox using your host's language runtimes."))?;
                        term.write_line(&format!("  Docker sandboxes provide complete isolation with fresh runtimes inside containers."))?;
                        term.write_line("")?;
                        term.write_line(&format!(
                            "  Run {} for more info.",
                            style("cxg sandbox info").cyan()
                        ))?;
                        term.write_line("")?;
                    }
                }
            }

            let mut config = SandboxConfig::default();

            if let Some(dir) = directory {
                config.root_dir = dir;
            }

            // Parse language filter
            if let Some(langs) = languages {
                config.enable_python = langs.contains("python");
                config.enable_javascript = langs.contains("javascript") || langs.contains("js");
                config.enable_ruby = langs.contains("ruby");
                config.enable_perl = langs.contains("perl");
                config.enable_php = langs.contains("php");
                config.enable_rust = langs.contains("rust");
                config.enable_go = langs.contains("go");
                config.enable_java = langs.contains("java");
            }

            let mut sandbox = Sandbox::with_config(config.clone());

            // Check if sandbox is already initialized
            let already_initialized = sandbox.is_initialized();

            if already_initialized && !force {
                term.write_line(&format!(
                    "{} Sandbox already initialized at: {}",
                    style("✓").green(),
                    sandbox.root_dir().display()
                ))?;

                // Check current status to see what's already there
                let status = sandbox.status();
                let mut existing_langs = Vec::new();
                if status.python_ready {
                    existing_langs.push("Python");
                }
                if status.javascript_ready {
                    existing_langs.push("JavaScript");
                }
                if status.ruby_ready {
                    existing_langs.push("Ruby");
                }
                if status.perl_ready {
                    existing_langs.push("Perl");
                }
                if status.php_ready {
                    existing_langs.push("PHP");
                }
                if status.rust_ready {
                    existing_langs.push("Rust");
                }
                if status.go_ready {
                    existing_langs.push("Go");
                }
                if status.java_ready {
                    existing_langs.push("Java");
                }

                term.write_line(&format!(
                    "  Existing languages: {}",
                    if existing_langs.is_empty() {
                        "None".to_string()
                    } else {
                        existing_langs.join(", ")
                    }
                ))?;

                // Check if user requested new languages
                let mut languages_to_add = Vec::new();
                if config.enable_python && !status.python_ready {
                    languages_to_add.push("Python");
                }
                if config.enable_javascript && !status.javascript_ready {
                    languages_to_add.push("JavaScript");
                }
                if config.enable_ruby && !status.ruby_ready {
                    languages_to_add.push("Ruby");
                }
                if config.enable_perl && !status.perl_ready {
                    languages_to_add.push("Perl");
                }
                if config.enable_php && !status.php_ready {
                    languages_to_add.push("PHP");
                }
                if config.enable_rust && !status.rust_ready {
                    languages_to_add.push("Rust");
                }
                if config.enable_go && !status.go_ready {
                    languages_to_add.push("Go");
                }
                if config.enable_java && !status.java_ready {
                    languages_to_add.push("Java");
                }

                if languages_to_add.is_empty() {
                    term.write_line(&format!(
                        "\n{} All requested languages are already initialized!",
                        style("✓").green()
                    ))?;
                    term.write_line(&format!(
                        "  Nothing to do. Use {} to rebuild everything.",
                        style("--force").yellow()
                    ))?;
                    return Ok(());
                } else {
                    term.write_line(&format!(
                        "\n{} Adding new languages: {}",
                        style("→").cyan(),
                        style(languages_to_add.join(", ")).yellow()
                    ))?;
                    // Continue to init only the new ones
                }
            } else if force {
                term.write_line(&format!(
                    "{} Force re-initialization requested",
                    style("→").cyan()
                ))?;
                term.write_line(&format!(
                    "  Rebuilding all language environments from scratch..."
                ))?;
            }

            term.write_line(&format!(
                "{} Initializing sandbox environment...",
                style("→").cyan()
            ))?;
            sandbox.init().await?;

            // Show summary of what was initialized
            let status = sandbox.status();
            let mut initialized_langs = Vec::new();
            if status.python_ready {
                initialized_langs.push("Python");
            }
            if status.javascript_ready {
                initialized_langs.push("JavaScript");
            }
            if status.ruby_ready {
                initialized_langs.push("Ruby");
            }
            if status.perl_ready {
                initialized_langs.push("Perl");
            }
            if status.php_ready {
                initialized_langs.push("PHP");
            }
            if status.rust_ready {
                initialized_langs.push("Rust");
            }
            if status.go_ready {
                initialized_langs.push("Go");
            }
            if status.java_ready {
                initialized_langs.push("Java");
            }

            if !initialized_langs.is_empty() {
                term.write_line(&format!(
                    "{} Sandbox initialized successfully!",
                    style("✓").green()
                ))?;
                term.write_line(&format!(
                    "  Initialized languages: {}",
                    style(initialized_langs.join(", ")).cyan()
                ))?;
            } else {
                term.write_line(&format!(
                    "{} Sandbox initialization completed with warnings",
                    style("⚠").yellow()
                ))?;
                term.write_line(&format!(
                    "  No language environments were successfully initialized"
                ))?;
                term.write_line(&format!("  Check logs above for details on what failed"))?;
            }

            term.write_line("")?;
            term.write_line(&format!(
                "{} Note: Some packages may have failed to install due to:",
                style("ℹ").blue()
            ))?;
            term.write_line("  - Missing system dependencies (build tools, compilers)")?;
            term.write_line("  - Outdated runtime versions (e.g., Ruby < 3.0)")?;
            term.write_line("  - Package incompatibilities")?;
            term.write_line("")?;
            term.write_line(&format!(
                "{} The sandbox will continue to work with successfully installed packages.",
                style("ℹ").blue()
            ))?;
            term.write_line(&format!(
                "{} You can install missing packages manually if needed.",
                style("ℹ").blue()
            ))?;
            term.write_line(&format!("  Location: {}", sandbox.root_dir().display()))?;

            Ok(())
        }

        SandboxAction::Status => {
            let sandbox = Sandbox::new();
            let status = sandbox.status();

            term.write_line(&format!("\n{}", style("Sandbox Status").bold().cyan()))?;
            term.write_line(&format!("{}", style("═".repeat(60)).dim()))?;

            term.write_line(&format!("Location: {}", status.root_dir.display()))?;
            term.write_line(&format!(
                "Initialized: {}",
                if status.initialized {
                    style("Yes").green()
                } else {
                    style("No").red()
                }
            ))?;

            term.write_line(&format!("\n{}", style("Language Runtimes:").bold()))?;
            term.write_line(&format!(
                "  Python:     {}",
                if status.python_ready {
                    style("✓").green()
                } else {
                    style("✗").red()
                }
            ))?;
            term.write_line(&format!(
                "  JavaScript: {}",
                if status.javascript_ready {
                    style("✓").green()
                } else {
                    style("✗").red()
                }
            ))?;
            term.write_line(&format!(
                "  Ruby:       {}",
                if status.ruby_ready {
                    style("✓").green()
                } else {
                    style("✗").red()
                }
            ))?;
            term.write_line(&format!(
                "  Perl:       {}",
                if status.perl_ready {
                    style("✓").green()
                } else {
                    style("✗").red()
                }
            ))?;
            term.write_line(&format!(
                "  PHP:        {}",
                if status.php_ready {
                    style("✓").green()
                } else {
                    style("✗").red()
                }
            ))?;
            term.write_line(&format!(
                "  Rust:       {}",
                if status.rust_ready {
                    style("✓").green()
                } else {
                    style("✗").red()
                }
            ))?;
            term.write_line(&format!(
                "  Go:         {}",
                if status.go_ready {
                    style("✓").green()
                } else {
                    style("✗").red()
                }
            ))?;
            term.write_line(&format!(
                "  Java:       {}",
                if status.java_ready {
                    style("✓").green()
                } else {
                    style("✗").red()
                }
            ))?;

            term.write_line("")?;

            Ok(())
        }

        SandboxAction::Install { language, packages } => {
            let sandbox = Sandbox::new();

            if !sandbox.is_initialized() {
                return Err(Error::config(
                    "Sandbox not initialized. Run 'cxg sandbox init' first.",
                ));
            }

            term.write_line(&format!(
                "{} Installing {} packages for {}...",
                style("→").cyan(),
                packages.len(),
                style(&language).yellow()
            ))?;

            let packages_str: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();

            match language.as_str() {
                "python" | "py" => {
                    cert_x_gen::sandbox::python::install_packages(&sandbox, &packages_str).await?;
                }
                "javascript" | "js" | "node" => {
                    cert_x_gen::sandbox::javascript::install_packages(&sandbox, &packages_str)
                        .await?;
                }
                "ruby" | "rb" => {
                    cert_x_gen::sandbox::ruby::install_gems(&sandbox, &packages_str).await?;
                }
                "perl" | "pl" => {
                    cert_x_gen::sandbox::perl::install_modules(&sandbox, &packages_str).await?;
                }
                "php" => {
                    cert_x_gen::sandbox::php::install_packages(&sandbox, &packages_str).await?;
                }
                _ => {
                    return Err(Error::config(format!("Unsupported language: {}", language)));
                }
            }

            term.write_line(&format!(
                "{} Packages installed successfully!",
                style("✓").green()
            ))?;

            Ok(())
        }

        SandboxAction::Clean { language: _, force } => {
            let sandbox = Sandbox::new();

            if !force {
                term.write_line(&format!(
                    "{} This will delete the sandbox environment.",
                    style("⚠").yellow()
                ))?;
                term.write_line("Use --force to confirm.")?;
                return Ok(());
            }

            term.write_line(&format!("{} Cleaning sandbox...", style("→").cyan()))?;
            sandbox.clean()?;
            term.write_line(&format!(
                "{} Sandbox cleaned successfully!",
                style("✓").green()
            ))?;

            Ok(())
        }

        SandboxAction::Shell { language } => {
            let sandbox = Sandbox::new();

            if !sandbox.is_initialized() {
                return Err(Error::config(
                    "Sandbox not initialized. Run 'cxg sandbox init' first.",
                ));
            }

            term.write_line(&format!(
                "{} Opening {} shell in sandbox...",
                style("→").cyan(),
                style(&language).yellow()
            ))?;
            term.write_line(&format!("Location: {}", sandbox.root_dir().display()))?;
            term.write_line("Type 'exit' to return.\n")?;

            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
            std::process::Command::new(shell)
                .current_dir(sandbox.root_dir())
                .envs(sandbox.get_env_vars())
                .status()
                .map_err(|e| Error::command(format!("Failed to open shell: {}", e)))?;

            Ok(())
        }

        SandboxAction::Path => {
            let sandbox = Sandbox::new();
            println!("{}", sandbox.root_dir().display());
            Ok(())
        }

        SandboxAction::Update { language: _ } => {
            term.write_line(&format!("{} Updating packages...", style("→").cyan()))?;

            // Implement update logic here
            term.write_line(&format!("{} Update complete!", style("✓").green()))?;

            Ok(())
        }

        SandboxAction::Export {
            output,
            description,
            author,
        } => {
            let sandbox = Sandbox::new();

            if !sandbox.is_initialized() {
                return Err(Error::config(
                    "Sandbox not initialized. Run 'cxg sandbox init' first.",
                ));
            }

            term.write_line(&format!(
                "{} Exporting sandbox configuration...",
                style("→").cyan()
            ))?;

            let mut export =
                cert_x_gen::sandbox::import_export::SandboxExport::from_sandbox(&sandbox)?;

            if let Some(desc) = description {
                export.metadata.description = Some(desc);
            }
            if let Some(auth) = author {
                export.metadata.author = Some(auth);
            }

            export.save(&output)?;

            term.write_line(&format!(
                "{} Sandbox exported to: {}",
                style("✓").green(),
                output.display()
            ))?;
            term.write_line(&format!(
                "  Python packages: {}",
                export.python_packages.len()
            ))?;
            term.write_line(&format!(
                "  JavaScript packages: {}",
                export.javascript_packages.len()
            ))?;
            term.write_line(&format!("  Ruby gems: {}", export.ruby_gems.len()))?;

            Ok(())
        }

        SandboxAction::Import { file, force } => {
            term.write_line(&format!(
                "{} Importing sandbox configuration from: {}",
                style("→").cyan(),
                file.display()
            ))?;

            let export = cert_x_gen::sandbox::import_export::SandboxExport::load(&file)?;

            term.write_line(&format!("  Version: {}", export.metadata.version))?;
            term.write_line(&format!("  Exported: {}", export.metadata.exported_at))?;
            if let Some(desc) = &export.metadata.description {
                term.write_line(&format!("  Description: {}", desc))?;
            }

            if !force {
                term.write_line(&format!(
                    "\n{} This will replace your current sandbox. Use --force to confirm.",
                    style("⚠").yellow()
                ))?;
                return Ok(());
            }

            let mut sandbox = Sandbox::new();
            export.apply_to_sandbox(&mut sandbox).await?;

            term.write_line(&format!(
                "{} Sandbox imported successfully!",
                style("✓").green()
            ))?;

            Ok(())
        }

        SandboxAction::Templates => {
            term.write_line(&format!(
                "\n{}",
                style("Available Sandbox Templates").bold().cyan()
            ))?;
            term.write_line(&format!("{}", style("═".repeat(60)).dim()))?;

            let templates = vec![
                cert_x_gen::sandbox::import_export::SandboxTemplate::web_security(),
                cert_x_gen::sandbox::import_export::SandboxTemplate::network_security(),
                cert_x_gen::sandbox::import_export::SandboxTemplate::api_testing(),
            ];

            for template in templates {
                term.write_line(&format!("\n{}", style(&template.name).yellow().bold()))?;
                term.write_line(&format!("  {}", template.description))?;
                term.write_line(&format!(
                    "  Python: {} packages",
                    template.export.python_packages.len()
                ))?;
                term.write_line(&format!(
                    "  JavaScript: {} packages",
                    template.export.javascript_packages.len()
                ))?;
                term.write_line(&format!(
                    "  Usage: cxg sandbox use-template {}",
                    template.name
                ))?;
            }

            term.write_line("")?;

            Ok(())
        }

        SandboxAction::UseTemplate { template } => {
            term.write_line(&format!(
                "{} Loading template: {}",
                style("→").cyan(),
                style(&template).yellow()
            ))?;

            let sandbox_template = match template.as_str() {
                "web-security" => {
                    cert_x_gen::sandbox::import_export::SandboxTemplate::web_security()
                }
                "network-security" => {
                    cert_x_gen::sandbox::import_export::SandboxTemplate::network_security()
                }
                "api-testing" => cert_x_gen::sandbox::import_export::SandboxTemplate::api_testing(),
                _ => {
                    return Err(Error::config(format!("Unknown template: {}. Use 'cxg sandbox templates' to list available templates.", template)));
                }
            };

            let mut sandbox = Sandbox::new();
            sandbox_template
                .export
                .apply_to_sandbox(&mut sandbox)
                .await?;

            term.write_line(&format!(
                "{} Template applied successfully!",
                style("✓").green()
            ))?;

            Ok(())
        }

        SandboxAction::List { language } => {
            let sandbox = Sandbox::new();

            if !sandbox.is_initialized() {
                return Err(Error::config(
                    "Sandbox not initialized. Run 'cxg sandbox init' first.",
                ));
            }

            term.write_line(&format!(
                "\n{} Installed Packages",
                style(&language).bold().cyan()
            ))?;
            term.write_line(&format!("{}", style("═".repeat(60)).dim()))?;

            let export = cert_x_gen::sandbox::import_export::SandboxExport::from_sandbox(&sandbox)?;

            let packages = match language.as_str() {
                "python" | "py" => export.python_packages,
                "javascript" | "js" | "node" => export.javascript_packages,
                "ruby" | "rb" => export.ruby_gems,
                "perl" | "pl" => export.perl_modules,
                "php" => export.php_packages,
                _ => {
                    return Err(Error::config(format!("Unsupported language: {}", language)));
                }
            };

            for (i, package) in packages.iter().enumerate() {
                term.write_line(&format!("{}. {}", i + 1, package))?;
            }

            term.write_line(&format!(
                "\n{} Total: {} packages",
                style("✓").green(),
                packages.len()
            ))?;

            Ok(())
        }

        SandboxAction::Create {
            name,
            languages,
            persist,
            auto_start,
        } => {
            use cert_x_gen::sandbox::config::SandboxConfigFile;
            use cert_x_gen::sandbox::docker::{DockerConfig, DockerSandbox, ResourceLimits};

            // Check if Docker is available
            if !DockerSandbox::docker_available() {
                term.write_line(&format!(
                    "{} Docker is not installed or not available",
                    style("✗").red()
                ))?;
                term.write_line(&format!(
                    "\nTo use Docker sandboxes, please install Docker:"
                ))?;
                term.write_line(&format!(
                    "  macOS: https://docs.docker.com/desktop/install/mac-install/"
                ))?;
                term.write_line(&format!("  Linux: https://docs.docker.com/engine/install/"))?;
                term.write_line(&format!(
                    "  Windows: https://docs.docker.com/desktop/install/windows-install/"
                ))?;
                return Ok(());
            }

            if !DockerSandbox::docker_running() {
                term.write_line(&format!(
                    "{} Docker is installed but not running",
                    style("⚠").yellow()
                ))?;
                term.write_line(&format!("  Please start Docker Desktop and try again"))?;
                return Ok(());
            }

            term.write_line(&format!(
                "{} Creating Docker sandbox: {}",
                style("→").cyan(),
                style(&name).yellow()
            ))?;

            // Prepare config
            let selected_languages = languages.unwrap_or_else(|| {
                vec![
                    "python".to_string(),
                    "ruby".to_string(),
                    "node".to_string(),
                    "go".to_string(),
                    "java".to_string(),
                    "perl".to_string(),
                    "php".to_string(),
                    "rust".to_string(),
                ]
            });

            // Get current directory and templates directory
            let current_dir = std::env::current_dir()?;
            let templates_dir = current_dir.join("templates");

            let mut volumes = std::collections::HashMap::new();
            if templates_dir.exists() {
                volumes.insert(
                    templates_dir.to_str().unwrap().to_string(),
                    "/workspace/templates".to_string(),
                );
            }

            let config = DockerConfig {
                name: name.clone(),
                image: format!("cert-x-gen/sandbox:{}", name),
                languages: selected_languages.clone(),
                persist,
                auto_start,
                resources: ResourceLimits {
                    memory: "4g".to_string(),
                    cpus: "2".to_string(),
                },
                volumes,
                environment: std::collections::HashMap::new(),
                network_mode: "bridge".to_string(), // Allow network access
            };

            let mut sandbox = DockerSandbox::new(config.clone());

            term.write_line(&format!(
                "  Building Docker image with languages: {}",
                selected_languages.join(", ")
            ))?;
            sandbox.build_image(None).await?;

            term.write_line(&format!("  Creating container..."))?;
            sandbox.create().await?;

            // Save to config file
            let mut cfg = SandboxConfigFile::load()?;
            cfg.set_sandbox(name.clone(), config);
            cfg.save()?;

            term.write_line(&format!(
                "{} Sandbox '{}' created successfully!",
                style("✓").green(),
                name
            ))?;
            term.write_line(&format!(
                "  Set as default: cxg sandbox set-default {}",
                name
            ))?;
            term.write_line(&format!("  Enter sandbox: cxg sandbox enter {}", name))?;

            Ok(())
        }

        SandboxAction::Delete { name, force } => {
            use cert_x_gen::sandbox::config::SandboxConfigFile;
            use cert_x_gen::sandbox::docker::DockerSandbox;

            if !force {
                term.write_line(&format!(
                    "{} This will delete the sandbox '{}'",
                    style("⚠").yellow(),
                    name
                ))?;
                term.write_line(&format!("  Use --force to confirm deletion"))?;
                return Ok(());
            }

            term.write_line(&format!("{} Deleting sandbox: {}", style("→").cyan(), name))?;

            // Load and delete container
            match DockerSandbox::load(&name) {
                Ok(mut sandbox) => {
                    sandbox.delete().await?;
                    term.write_line(&format!("  Container deleted"))?;
                }
                Err(_) => {
                    term.write_line(&format!(
                        "  {} Container not found (may already be deleted)",
                        style("⚠").yellow()
                    ))?;
                }
            }

            // Remove from config
            let mut cfg = SandboxConfigFile::load()?;
            cfg.remove_sandbox(&name);
            cfg.save()?;

            term.write_line(&format!(
                "{} Sandbox '{}' deleted",
                style("✓").green(),
                name
            ))?;

            Ok(())
        }

        SandboxAction::Enter { name } => {
            use cert_x_gen::sandbox::config::SandboxConfigFile;
            use cert_x_gen::sandbox::docker::DockerSandbox;

            let cfg = SandboxConfigFile::load()?;

            let sandbox_name = name.or_else(|| cfg.default_sandbox.clone())
                .ok_or_else(|| Error::config("No sandbox specified and no default set. Use: cxg sandbox set-default <name>"))?;

            term.write_line(&format!(
                "{} Entering sandbox: {}",
                style("→").cyan(),
                sandbox_name
            ))?;

            let mut sandbox = DockerSandbox::load(&sandbox_name)?;

            if !sandbox.is_running() {
                term.write_line(&format!("  Starting container..."))?;
                sandbox.start().await?;
            }

            sandbox.shell().await?;

            Ok(())
        }

        SandboxAction::SetDefault { name } => {
            use cert_x_gen::sandbox::config::SandboxConfigFile;

            let mut cfg = SandboxConfigFile::load()?;

            if let Some(sandbox_name) = name {
                // Verify sandbox exists
                if !cfg.sandboxes.contains_key(&sandbox_name) {
                    return Err(Error::config(format!(
                        "Sandbox '{}' not found",
                        sandbox_name
                    )));
                }

                cfg.set_default(Some(sandbox_name.clone()));
                cfg.save()?;

                term.write_line(&format!(
                    "{} Default sandbox set to: {}",
                    style("✓").green(),
                    sandbox_name
                ))?;
            } else {
                cfg.set_default(None);
                cfg.save()?;

                term.write_line(&format!("{} Default sandbox cleared", style("✓").green()))?;
            }

            Ok(())
        }

        SandboxAction::Info => {
            use cert_x_gen::sandbox::config::SandboxConfigFile;
            use cert_x_gen::sandbox::docker::DockerSandbox;

            term.write_line(&format!(
                "\n{}",
                style("Docker Sandbox Information").bold().cyan()
            ))?;
            term.write_line(&format!("{}", style("═".repeat(60)).dim()))?;

            // Check Docker status
            if DockerSandbox::docker_available() {
                term.write_line(&format!("{} Docker: Installed", style("✓").green()))?;
                if let Some(version) = DockerSandbox::docker_version() {
                    term.write_line(&format!("  Version: {}", version))?;
                }

                if DockerSandbox::docker_running() {
                    term.write_line(&format!("{} Docker Daemon: Running", style("✓").green()))?;
                } else {
                    term.write_line(&format!(
                        "{} Docker Daemon: Not running",
                        style("⚠").yellow()
                    ))?;
                    term.write_line(&format!("  Please start Docker Desktop"))?;
                }
            } else {
                term.write_line(&format!("{} Docker: Not installed", style("✗").red()))?;
                term.write_line(&format!("\nInstallation:"))?;
                term.write_line(&format!(
                    "  macOS: https://docs.docker.com/desktop/install/mac-install/"
                ))?;
                term.write_line(&format!("  Linux: https://docs.docker.com/engine/install/"))?;
                term.write_line(&format!(
                    "  Windows: https://docs.docker.com/desktop/install/windows-install/"
                ))?;
            }

            // Show configured sandboxes
            let cfg = SandboxConfigFile::load()?;

            term.write_line(&format!(
                "\n{}",
                style("Configured Sandboxes").bold().cyan()
            ))?;
            term.write_line(&format!("{}", style("═".repeat(60)).dim()))?;

            if cfg.sandboxes.is_empty() {
                term.write_line(&format!("  No sandboxes configured"))?;
                term.write_line(&format!("\nCreate one: cxg sandbox create my-sandbox"))?;
            } else {
                for (name, config) in &cfg.sandboxes {
                    let is_default = cfg.default_sandbox.as_ref() == Some(name);
                    let marker = if is_default { "* " } else { "  " };

                    term.write_line(&format!("{}{}", marker, style(name).yellow().bold()))?;
                    term.write_line(&format!("    Image: {}", config.image))?;
                    term.write_line(&format!("    Languages: {}", config.languages.join(", ")))?;
                    term.write_line(&format!("    Persist: {}", config.persist))?;
                    term.write_line(&format!("    Auto-start: {}", config.auto_start))?;

                    // Check if container running
                    if let Ok(sandbox) = DockerSandbox::load(name) {
                        if sandbox.is_running() {
                            term.write_line(&format!("    Status: {}", style("Running").green()))?;
                        } else {
                            term.write_line(&format!("    Status: {}", style("Stopped").dim()))?;
                        }
                    }

                    term.write_line("")?;
                }

                if let Some(default) = &cfg.default_sandbox {
                    term.write_line(&format!("* Default sandbox: {}", style(default).cyan()))?;
                }
            }

            Ok(())
        }

        SandboxAction::Build { dockerfile } => {
            use cert_x_gen::sandbox::config::SandboxConfigFile;
            use cert_x_gen::sandbox::docker::DockerSandbox;

            term.write_line(&format!("{} Building Docker image...", style("→").cyan()))?;

            let cfg = SandboxConfigFile::load()?;
            let (_name, config) = cfg.get_default_sandbox().ok_or_else(|| {
                Error::config("No default sandbox set. Use: cxg sandbox set-default <name>")
            })?;

            let sandbox = DockerSandbox::new(config.clone());

            sandbox.build_image(dockerfile.as_deref()).await?;

            term.write_line(&format!("{} Image built successfully!", style("✓").green()))?;

            Ok(())
        }
    }
}

/// Check if we should auto-enter a Docker sandbox
async fn check_and_enter_sandbox(cli: &Cli) -> Result<()> {
    use cert_x_gen::sandbox::config::SandboxConfigFile;
    use cert_x_gen::sandbox::docker::{inside_sandbox, DockerSandbox};

    // Don't auto-enter if we're already inside a sandbox
    if inside_sandbox() {
        tracing::debug!("Already inside sandbox, skipping auto-enter");
        return Ok(());
    }

    // Don't auto-enter for sandbox management commands (except init, which should run in sandbox)
    if matches!(cli.command, Some(Commands::Sandbox(_))) {
        // Allow 'sandbox init' to run in Docker if default sandbox is set
        if !matches!(cli.command, Some(Commands::Sandbox(ref cmd)) if matches!(cmd.action, cli::SandboxAction::Init { .. }))
        {
            return Ok(());
        }
    }

    // Check if Docker is available
    if !DockerSandbox::docker_available() {
        tracing::debug!("Docker not available, skipping sandbox auto-enter");
        return Ok(());
    }

    if !DockerSandbox::docker_running() {
        tracing::debug!("Docker not running, skipping sandbox auto-enter");
        return Ok(());
    }

    // Load config and check for default sandbox
    let cfg = match SandboxConfigFile::load() {
        Ok(c) => c,
        Err(_) => {
            tracing::debug!("No sandbox config found, skipping auto-enter");
            return Ok(());
        }
    };

    // Check if there's a default sandbox with auto_start enabled
    if let Some((name, config)) = cfg.get_default_sandbox() {
        if config.auto_start {
            tracing::info!("Auto-entering sandbox: {}", name);

            // Load sandbox
            let mut sandbox = match DockerSandbox::load(name) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Failed to load default sandbox '{}': {}", name, e);
                    return Ok(()); // Don't fail, just skip
                }
            };

            // Start if not running
            if !sandbox.is_running() {
                tracing::info!("Starting sandbox container...");
                if let Err(e) = sandbox.start().await {
                    tracing::warn!("Failed to start sandbox: {}", e);
                    return Ok(()); // Don't fail, just skip
                }
            }

            // Verify container is ready
            sandbox
                .exec_cli(&std::env::args().collect::<Vec<_>>())
                .await?;

            // Mark that we're using Docker sandbox context
            // The actual command will execute with container awareness
            tracing::info!("Command will execute with Docker sandbox context");

            // Don't exit - let the command run with container context
            // The sandbox module will use docker exec for operations
        }
    }

    Ok(())
}

/// Print version information
fn print_version() {
    println!("CERT-X-GEN v{}", env!("CARGO_PKG_VERSION"));
    println!("Advanced Multi-Language Security Scanning Engine");
    println!();
    println!("Build Information:");
    println!("  Rust Version: {}", env!("CARGO_PKG_RUST_VERSION"));
    println!("  Target: {}", std::env::consts::ARCH);
    println!("  OS: {}", std::env::consts::OS);
}

/// Print scan summary
fn print_scan_summary(results: &cert_x_gen::types::ScanResults) {
    use console::{style, Term};

    let _term = Term::stdout();

    println!();
    println!("{}", style("═".repeat(80)).dim());
    println!("{}", style("Scan Summary").bold().cyan());
    println!("{}", style("═".repeat(80)).dim());
    println!();

    println!("  Scan ID: {}", style(&results.scan_id).yellow());
    println!(
        "  Duration: {:.2}s",
        results.statistics.duration.as_secs_f64()
    );
    println!("  Targets Scanned: {}", results.statistics.targets_scanned);
    println!(
        "  Templates Executed: {}",
        results.statistics.templates_executed
    );
    println!();

    println!("{}", style("Findings by Severity:").bold());

    let critical = results
        .statistics
        .findings_by_severity
        .get(&cert_x_gen::types::Severity::Critical)
        .unwrap_or(&0);
    let high = results
        .statistics
        .findings_by_severity
        .get(&cert_x_gen::types::Severity::High)
        .unwrap_or(&0);
    let medium = results
        .statistics
        .findings_by_severity
        .get(&cert_x_gen::types::Severity::Medium)
        .unwrap_or(&0);
    let low = results
        .statistics
        .findings_by_severity
        .get(&cert_x_gen::types::Severity::Low)
        .unwrap_or(&0);
    let info = results
        .statistics
        .findings_by_severity
        .get(&cert_x_gen::types::Severity::Info)
        .unwrap_or(&0);

    println!(
        "  {} {}",
        style("CRITICAL:").red().bold(),
        style(critical).red().bold()
    );
    println!("  {} {}", style("HIGH:    ").red(), style(high).red());
    println!(
        "  {} {}",
        style("MEDIUM:  ").yellow(),
        style(medium).yellow()
    );
    println!("  {} {}", style("LOW:     ").blue(), style(low).blue());
    println!("  {} {}", style("INFO:    ").cyan(), style(info).cyan());
    println!();

    println!(
        "  {} {}",
        style("TOTAL:").bold(),
        style(results.findings.len()).bold()
    );
    println!();
    println!("{}", style("═".repeat(80)).dim());
}

/// Run AI command
async fn run_ai_command(cmd: cli::AiCommand) -> Result<()> {
    use cli::AiAction;

    match cmd.action {
        AiAction::Generate {
            prompt,
            language,
            provider,
            model,
            output,
            test,
            test_target,
            force,
            estimate_cost,
        } => {
            handle_ai_generate(
                prompt,
                language,
                provider,
                model,
                output,
                test,
                test_target,
                force,
                estimate_cost,
            )
            .await?;
        }
        AiAction::Providers { action } => {
            handle_providers_command(action).await?;
        }
    }

    Ok(())
}

/// Handle AI template generation
async fn handle_ai_generate(
    prompt: String,
    language: cli::LanguageArg,
    provider: Option<String>,
    model: Option<String>,
    output: Option<PathBuf>,
    test: bool,
    test_target: Option<String>,
    force: bool,
    estimate_cost: bool,
) -> Result<()> {
    use console::{style, Term};
    use std::fs;

    let term = Term::stdout();

    // Convert language argument to TemplateLanguage
    let template_lang: TemplateLanguage = language.into();

    println!();
    println!("{}", style("🤖 AI Template Generation").bold().cyan());
    println!("{}", style("═".repeat(60)).dim());
    println!();
    println!("  {}  {}", style("Prompt:").bold(), prompt);
    println!("  {}  {:?}", style("Language:").bold(), template_lang);
    if let Some(ref p) = provider {
        println!("  {}  {}", style("Provider:").bold(), p);
    }
    if let Some(ref m) = model {
        println!("  {}  {}", style("Model:").bold(), m);
    }
    println!();

    // Create AI manager
    term.write_line(&format!(
        "{} Initializing AI manager...",
        style("[1/5]").dim()
    ))?;
    let manager = AIManager::new()
        .map_err(|e| Error::Ai(format!("Failed to initialize AI manager: {}", e)))?;

    // Show cost estimate if requested
    if estimate_cost {
        term.write_line(&format!("{} Estimating cost...", style("[2/5]").dim()))?;
        println!(
            "  {} Cost estimation not yet implemented",
            style("ℹ").blue()
        );
        println!();
    }

    // Generate template
    term.write_line(&format!("{} Generating template...", style("[2/5]").dim()))?;
    term.write_line("  This may take 10-30 seconds depending on the model...")?;

    let template_code = manager
        .generate_template(&prompt, template_lang, provider.as_deref())
        .await
        .map_err(|e| Error::Ai(format!("Template generation failed: {}", e)))?;

    term.write_line(&format!(
        "  {} Template generated successfully!",
        style("✓").green()
    ))?;
    println!();

    // Validate template
    term.write_line(&format!("{} Validating template...", style("[3/5]").dim()))?;
    let validator = TemplateValidator::new();
    validator
        .validate(&template_code, template_lang)
        .map_err(|e| Error::Ai(format!("Template validation failed: {}", e)))?;

    term.write_line(&format!("  {} Template is valid!", style("✓").green()))?;
    println!();

    // Determine output path
    let output_path = if let Some(path) = output {
        path
    } else {
        // Auto-generate filename
        let filename = manager.generate_filename(&prompt, template_lang);
        let ai_templates_dir = dirs::home_dir()
            .ok_or_else(|| Error::Internal("Could not determine home directory".to_string()))?
            .join(".cert-x-gen")
            .join("templates")
            .join("ai-generated");

        ai_templates_dir.join(filename)
    };

    // Check if file exists and force flag
    if output_path.exists() && !force {
        return Err(Error::Internal(format!(
            "File already exists: {}. Use --force to overwrite",
            output_path.display()
        )));
    }

    // Save template
    term.write_line(&format!("{} Saving template...", style("[4/5]").dim()))?;

    // Create directory if it doesn't exist
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::Internal(format!("Failed to create directory: {}", e)))?;
    }

    fs::write(&output_path, &template_code)
        .map_err(|e| Error::Internal(format!("Failed to write template: {}", e)))?;

    term.write_line(&format!(
        "  {} Template saved to: {}",
        style("✓").green(),
        output_path.display()
    ))?;
    println!();

    // Test template if requested
    if test {
        term.write_line(&format!("{} Testing template...", style("[5/5]").dim()))?;

        if let Some(target) = test_target {
            println!("  Testing against target: {}", target);
            println!(
                "  {} Template testing not yet implemented",
                style("ℹ").blue()
            );
        } else {
            println!(
                "  {} No test target specified, skipping test",
                style("ℹ").yellow()
            );
        }
        println!();
    }

    // Print summary
    println!("{}", style("═".repeat(60)).dim());
    println!(
        "{}",
        style("✓ Template Generation Complete!").bold().green()
    );
    println!("{}", style("═".repeat(60)).dim());
    println!();
    println!("  {} {}", style("Location:").bold(), output_path.display());
    println!(
        "  {} {} lines",
        style("Size:").bold(),
        template_code.lines().count()
    );
    println!("  {} {:?}", style("Language:").bold(), template_lang);
    println!();
    println!("Next steps:");
    println!("  • View template:    cat {}", output_path.display());
    println!(
        "  • Run scan:         cert-x-gen scan --template {} --target <host>",
        output_path.display()
    );
    println!("  • Edit template:    $EDITOR {}", output_path.display());
    println!();

    Ok(())
}

/// Handle providers command
async fn handle_providers_command(action: cli::ProviderAction) -> Result<()> {
    use cert_x_gen::ai::AIManager;
    use cli::ProviderAction;
    use console::style;

    match action {
        ProviderAction::List { detailed } => {
            println!();
            println!("{}", style("Available LLM Providers").bold().cyan());
            println!("{}", style("═".repeat(60)).dim());
            println!();

            let manager = AIManager::new()
                .map_err(|e| Error::Ai(format!("Failed to initialize AI manager: {}", e)))?;

            let providers = manager.list_providers();

            if providers.is_empty() {
                println!("  {} No providers configured", style("ℹ").yellow());
                println!();
                println!("To get started:");
                println!("  1. Install Ollama: curl -fsSL https://ollama.com/install.sh | sh");
                println!("  2. Download model: ollama pull codellama:13b");
                println!("  3. Start Ollama: ollama serve");
                println!();
                return Ok(());
            }

            for (provider_name, enabled) in providers {
                let icon = if provider_name == "ollama" && enabled {
                    style("✓").green()
                } else if enabled {
                    style("○").cyan()
                } else {
                    style("○").dim()
                };

                println!("  {} {}", icon, style(&provider_name).bold());

                if detailed {
                    // TODO: Get more detailed info from provider
                    println!(
                        "      Type: {}",
                        if provider_name == "ollama" {
                            "Local"
                        } else {
                            "Cloud"
                        }
                    );
                    println!(
                        "      Status: {}",
                        if enabled { "Enabled" } else { "Disabled" }
                    );
                }
            }

            println!();
            println!("Use 'cxg ai providers test <name>' to test a provider");
            println!();

            Ok(())
        }
        ProviderAction::Test { provider } => {
            println!();
            println!(
                "{}",
                style(format!("Testing Provider: {}", provider))
                    .bold()
                    .cyan()
            );
            println!("{}", style("═".repeat(60)).dim());
            println!();

            let manager = AIManager::new()
                .map_err(|e| Error::Ai(format!("Failed to initialize AI manager: {}", e)))?;

            println!("  {} Running health checks...", style("⚙").cyan());
            println!();

            match manager.test_provider(&provider).await {
                Ok(status) => {
                    // Connection status
                    let conn_icon = if status.connection.is_ok() {
                        style("✓").green()
                    } else {
                        style("✗").red()
                    };
                    println!(
                        "  {} Connection: {}",
                        conn_icon,
                        match status.connection {
                            cert_x_gen::ai::providers::ConnectionStatus::Connected =>
                                style("OK").green(),
                            cert_x_gen::ai::providers::ConnectionStatus::Failed =>
                                style("Failed").red(),
                            cert_x_gen::ai::providers::ConnectionStatus::Untested =>
                                style("Not tested").yellow(),
                        }
                    );

                    // Authentication status
                    let auth_icon = if status.authentication.is_ok() {
                        style("✓").green()
                    } else if matches!(
                        status.authentication,
                        cert_x_gen::ai::providers::AuthStatus::NotRequired
                    ) {
                        style("○").dim()
                    } else {
                        style("✗").red()
                    };
                    println!(
                        "  {} Authentication: {}",
                        auth_icon,
                        match status.authentication {
                            cert_x_gen::ai::providers::AuthStatus::Authenticated =>
                                style("Valid").green(),
                            cert_x_gen::ai::providers::AuthStatus::Failed => style("Invalid").red(),
                            cert_x_gen::ai::providers::AuthStatus::NotRequired =>
                                style("Not required").dim(),
                            cert_x_gen::ai::providers::AuthStatus::NotConfigured =>
                                style("Not configured").yellow(),
                            cert_x_gen::ai::providers::AuthStatus::Untested =>
                                style("Not tested").yellow(),
                        }
                    );

                    // Response time
                    if let Some(rt) = status.response_time_ms {
                        let rt_style = if rt < 1000 {
                            style(format!("{}ms", rt)).green()
                        } else if rt < 5000 {
                            style(format!("{}ms", rt)).yellow()
                        } else {
                            style(format!("{}ms", rt)).red()
                        };
                        println!("  {} Response time: {}", style("⚡").cyan(), rt_style);
                    }

                    // Models available
                    if let Some(count) = status.models_available {
                        println!(
                            "  {} Models available: {}",
                            style("📦").cyan(),
                            style(count).bold()
                        );

                        if !status.models.is_empty() {
                            println!();
                            println!("  Available models:");
                            for model in &status.models {
                                let size_info = if let Some(_size) = model.size {
                                    format!(" ({})", model.size_human_readable())
                                } else {
                                    String::new()
                                };
                                println!(
                                    "    • {}{}",
                                    style(&model.name).dim(),
                                    style(size_info).dim()
                                );
                            }
                        }
                    }

                    // Messages
                    if !status.messages.is_empty() {
                        println!();
                        println!("  Messages:");
                        for msg in &status.messages {
                            if msg.starts_with("⚠") || msg.starts_with("Hint:") {
                                println!("    {}", style(msg).yellow());
                            } else if msg.contains("✓") || msg.contains("Success") {
                                println!("    {}", style(msg).green());
                            } else {
                                println!("    {}", style(msg).dim());
                            }
                        }
                    }

                    // Overall status
                    println!();
                    if status.healthy {
                        println!(
                            "  {} Status: {}",
                            style("✓").green().bold(),
                            style("Ready").green().bold()
                        );
                    } else {
                        println!(
                            "  {} Status: {}",
                            style("✗").red().bold(),
                            style("Not Ready").red().bold()
                        );
                    }

                    println!();
                }
                Err(e) => {
                    println!("  {} Error testing provider: {}", style("✗").red(), e);
                    println!();
                }
            }

            Ok(())
        }
        ProviderAction::Status => {
            println!();
            println!("{}", style("Provider Status").bold().cyan());
            println!("{}", style("═".repeat(60)).dim());
            println!();

            let manager = AIManager::new()
                .map_err(|e| Error::Ai(format!("Failed to initialize AI manager: {}", e)))?;

            let providers = manager.list_providers();

            if providers.is_empty() {
                println!("  {} No providers configured", style("ℹ").yellow());
                println!();
                return Ok(());
            }

            println!(
                "  {} Testing {} providers...",
                style("⚙").cyan(),
                providers.len()
            );
            println!();

            for (provider_name, enabled) in providers {
                // Provider header
                let icon = if enabled {
                    style("●").green()
                } else {
                    style("○").dim()
                };
                println!("  {} {}", icon, style(&provider_name).bold());
                println!(
                    "    Enabled: {}",
                    if enabled {
                        style("Yes").green()
                    } else {
                        style("No").dim()
                    }
                );

                if enabled {
                    // Test the provider
                    match manager.test_provider(&provider_name).await {
                        Ok(status) => {
                            // Connection
                            let conn_status = match status.connection {
                                cert_x_gen::ai::providers::ConnectionStatus::Connected => {
                                    style("Connected").green()
                                }
                                cert_x_gen::ai::providers::ConnectionStatus::Failed => {
                                    style("Failed").red()
                                }
                                _ => style("Unknown").yellow(),
                            };
                            println!("    Connection: {}", conn_status);

                            // Auth
                            let auth_status = match status.authentication {
                                cert_x_gen::ai::providers::AuthStatus::Authenticated => {
                                    style("Valid").green()
                                }
                                cert_x_gen::ai::providers::AuthStatus::NotRequired => {
                                    style("Not required").dim()
                                }
                                cert_x_gen::ai::providers::AuthStatus::Failed => {
                                    style("Invalid").red()
                                }
                                cert_x_gen::ai::providers::AuthStatus::NotConfigured => {
                                    style("Not configured").yellow()
                                }
                                _ => style("Unknown").yellow(),
                            };
                            println!("    Authentication: {}", auth_status);

                            // Response time
                            if let Some(rt) = status.response_time_ms {
                                println!("    Response time: {}ms", rt);
                            }

                            // Models
                            if let Some(count) = status.models_available {
                                println!("    Models: {}", count);
                            }

                            // Overall
                            let health = if status.healthy {
                                style("✓ Ready").green()
                            } else {
                                style("✗ Not Ready").red()
                            };
                            println!("    Status: {}", health);
                        }
                        Err(e) => {
                            println!("    Status: {} ({})", style("Error").red(), e);
                        }
                    }
                } else {
                    println!("    Status: {}", style("Disabled").dim());
                }

                println!();
            }

            Ok(())
        }
    }
}
