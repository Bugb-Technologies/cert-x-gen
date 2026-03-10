//! MCP client installer — auto-configure AI coding agents
//!
//! Detects installed MCP-compatible clients and writes config entries
//! so agents can use CXG tools without manual JSON editing.

use crate::error::{Error, Result};
use serde_json::Value;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

// ─── Client definitions ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct McpClient {
    /// Short ID for --client flag
    pub id: &'static str,
    /// Display name
    pub label: &'static str,
    /// Config file path (resolved at runtime per OS)
    pub config_path: fn() -> Option<PathBuf>,
    /// JSON key that holds MCP server entries
    pub servers_key: &'static str,
    /// Whether restart is needed after config change
    pub needs_restart: bool,
}

/// Get the CXG binary path for config entries.
fn cxg_command() -> String {
    if let Ok(exe) = std::env::current_exe() {
        exe.to_string_lossy().to_string()
    } else {
        "cxg".to_string()
    }
}

// ─── Config path resolvers (cross-platform) ──────────────────────────

fn claude_desktop_config() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .map(|h| h.join("Library/Application Support/Claude/claude_desktop_config.json"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|a| PathBuf::from(a).join("Claude/claude_desktop_config.json"))
    }
    #[cfg(target_os = "linux")]
    {
        dirs::config_dir().map(|c| c.join("Claude/claude_desktop_config.json"))
    }
}

fn claude_code_config() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude/settings.json"))
}

fn cursor_config() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".cursor/mcp.json"))
}

fn windsurf_config() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".codeium/windsurf/mcp_config.json"))
}

fn vscode_config() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".vscode/mcp.json"))
}

fn zed_config() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join(".config/zed/settings.json"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::config_dir().map(|c| c.join("zed/settings.json"))
    }
}

/// All supported MCP clients
fn all_clients() -> Vec<McpClient> {
    vec![
        McpClient {
            id: "claude-desktop",
            label: "Claude Desktop",
            config_path: claude_desktop_config,
            servers_key: "mcpServers",
            needs_restart: true,
        },
        McpClient {
            id: "claude-code",
            label: "Claude Code",
            config_path: claude_code_config,
            servers_key: "mcpServers",
            needs_restart: false,
        },
        McpClient {
            id: "cursor",
            label: "Cursor",
            config_path: cursor_config,
            servers_key: "mcpServers",
            needs_restart: true,
        },
        McpClient {
            id: "windsurf",
            label: "Windsurf",
            config_path: windsurf_config,
            servers_key: "mcpServers",
            needs_restart: true,
        },
        McpClient {
            id: "vscode",
            label: "VS Code (Copilot)",
            config_path: vscode_config,
            servers_key: "servers",
            needs_restart: false,
        },
        McpClient {
            id: "zed",
            label: "Zed",
            config_path: zed_config,
            servers_key: "context_servers",
            needs_restart: false,
        },
    ]
}

// ─── Detection ───────────────────────────────────────────────────────

#[derive(Debug)]
struct ClientStatus {
    client: McpClient,
    config_exists: bool,
    already_configured: bool,
    config_path: Option<PathBuf>,
}

fn detect_clients() -> Vec<ClientStatus> {
    all_clients()
        .into_iter()
        .map(|client| {
            let path = (client.config_path)();
            let config_exists = path.as_ref().is_some_and(|p| p.exists());
            let already_configured = if config_exists {
                path.as_ref()
                    .is_some_and(|p| check_already_configured(p, client.servers_key))
            } else {
                false
            };
            ClientStatus {
                client,
                config_exists,
                already_configured,
                config_path: path,
            }
        })
        .collect()
}

fn check_already_configured(path: &PathBuf, servers_key: &str) -> bool {
    let content = match std::fs::read_to_string(path) {
        Ok(c) if !c.trim().is_empty() => c,
        _ => return false,
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };
    json.get(servers_key)
        .and_then(|s| s.get("cert-x-gen"))
        .is_some()
}

// ─── Interactive picker ──────────────────────────────────────────────

fn prompt_client_selection(statuses: &[ClientStatus]) -> Result<Vec<usize>> {
    use console::style;

    println!();
    println!("{}", style("CERT-X-GEN MCP Installer").bold().cyan());
    println!("{}", style("═".repeat(50)).dim());
    println!();
    println!("Detected MCP-compatible clients:");
    println!();

    let mut selectable: Vec<usize> = Vec::new();

    for (i, status) in statuses.iter().enumerate() {
        let num = i + 1;
        if status.already_configured {
            println!(
                "  {} {} {} {}",
                style(format!("{}.", num)).dim(),
                style(&status.client.label).green(),
                style("✓ already configured").green().dim(),
                style(format!(
                    "({})",
                    status
                        .config_path
                        .as_ref()
                        .map_or("".into(), |p| p.display().to_string())
                ))
                .dim(),
            );
        } else if status.config_exists {
            println!(
                "  {} {} {}",
                style(format!("{}.", num)).bold(),
                style(&status.client.label).white().bold(),
                style("(installed)").green(),
            );
            selectable.push(i);
        } else {
            println!(
                "  {} {} {}",
                style(format!("{}.", num)).dim(),
                style(&status.client.label).dim(),
                style("(not detected)").dim(),
            );
            selectable.push(i);
        }
    }

    if selectable.is_empty() {
        println!();
        println!(
            "{}",
            style("All detected clients already configured!").green()
        );
        return Ok(vec![]);
    }

    // Build default selection (installed but not yet configured)
    let defaults: Vec<usize> = statuses
        .iter()
        .enumerate()
        .filter(|(_, s)| s.config_exists && !s.already_configured)
        .map(|(i, _)| i + 1)
        .collect();

    let default_str = if defaults.is_empty() {
        "1".to_string()
    } else {
        defaults
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };

    println!();
    print!(
        "Configure which clients? (comma-separated, e.g. 1,2) [{}]: ",
        default_str
    );
    io::stdout()
        .flush()
        .map_err(|e| Error::config(e.to_string()))?;

    let mut input = String::new();
    io::stdin()
        .lock()
        .read_line(&mut input)
        .map_err(|e| Error::config(e.to_string()))?;

    let input = input.trim();
    let selected_nums: Vec<usize> = if input.is_empty() {
        defaults
    } else {
        input
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 1 && n <= statuses.len())
            .collect()
    };

    Ok(selected_nums.into_iter().map(|n| n - 1).collect())
}

// ─── Config manipulation ─────────────────────────────────────────────

fn write_config_entry(path: &PathBuf, servers_key: &str) -> Result<()> {
    // Read existing config or create empty object
    let mut json: Value = if path.exists() {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("Failed to read {}: {}", path.display(), e)))?;
        if content.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&content)
                .map_err(|e| Error::config(format!("Invalid JSON in {}: {}", path.display(), e)))?
        }
    } else {
        // Create parent dirs if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::config(format!("Failed to create {}: {}", parent.display(), e))
            })?;
        }
        serde_json::json!({})
    };

    // Build the CXG server entry
    let command = cxg_command();
    let entry = serde_json::json!({
        "command": command,
        "args": ["mcp"]
    });

    // Ensure servers_key object exists, then insert
    if json.get(servers_key).is_none() {
        json[servers_key] = serde_json::json!({});
    }
    json[servers_key]["cert-x-gen"] = entry;

    // Write back with pretty formatting
    let formatted = serde_json::to_string_pretty(&json)
        .map_err(|e| Error::config(format!("JSON serialize error: {}", e)))?;
    std::fs::write(path, formatted)
        .map_err(|e| Error::config(format!("Failed to write {}: {}", path.display(), e)))?;

    Ok(())
}

fn remove_config_entry(path: &PathBuf, servers_key: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::config(format!("Failed to read {}: {}", path.display(), e)))?;
    if content.trim().is_empty() {
        return Ok(false);
    }
    let mut json: Value = serde_json::from_str(&content)
        .map_err(|e| Error::config(format!("Invalid JSON in {}: {}", path.display(), e)))?;

    let removed = json
        .get_mut(servers_key)
        .and_then(|s| s.as_object_mut())
        .map(|obj| obj.remove("cert-x-gen").is_some())
        .unwrap_or(false);

    if removed {
        let formatted = serde_json::to_string_pretty(&json)
            .map_err(|e| Error::config(format!("JSON serialize error: {}", e)))?;
        std::fs::write(path, formatted)
            .map_err(|e| Error::config(format!("Failed to write {}: {}", path.display(), e)))?;
    }

    Ok(removed)
}

// ─── Public commands ─────────────────────────────────────────────────

/// `cxg mcp install [--client claude-desktop,cursor,...]`
pub async fn run_install(client_filter: Option<String>) -> Result<()> {
    use console::style;

    let statuses = detect_clients();

    // Determine which clients to configure
    let indices = if let Some(filter) = client_filter {
        // --client flag: resolve IDs to indices
        let ids: Vec<&str> = filter.split(',').map(|s| s.trim()).collect();
        let mut resolved = Vec::new();
        for id in &ids {
            match statuses.iter().position(|s| s.client.id == *id) {
                Some(idx) => resolved.push(idx),
                None => {
                    let valid: Vec<&str> = statuses.iter().map(|s| s.client.id).collect();
                    return Err(Error::config(format!(
                        "Unknown client '{}'. Valid: {}",
                        id,
                        valid.join(", ")
                    )));
                }
            }
        }
        resolved
    } else {
        // Interactive picker
        prompt_client_selection(&statuses)?
    };

    if indices.is_empty() {
        return Ok(());
    }

    println!();
    let mut needs_restart = Vec::new();

    for idx in indices {
        let status = &statuses[idx];
        let path = match &status.config_path {
            Some(p) => p,
            None => {
                println!(
                    "  {} {} — config path not found",
                    style("⚠").yellow(),
                    status.client.label
                );
                continue;
            }
        };

        if status.already_configured {
            println!(
                "  {} {} — already configured",
                style("✓").green(),
                style(status.client.label).green()
            );
            continue;
        }

        match write_config_entry(path, status.client.servers_key) {
            Ok(()) => {
                println!(
                    "  {} {} — configured",
                    style("✓").green(),
                    style(status.client.label).green().bold()
                );
                if status.client.needs_restart {
                    needs_restart.push(status.client.label);
                }
            }
            Err(e) => {
                println!(
                    "  {} {} — {}",
                    style("✗").red(),
                    status.client.label,
                    style(e).red()
                );
            }
        }
    }

    if !needs_restart.is_empty() {
        println!();
        println!(
            "{} Restart {} to activate.",
            style("→").cyan(),
            needs_restart.join(", ")
        );
    }

    println!();
    println!(
        "{} CXG MCP server provides 9 tools: search, scan, validate, create, test, and more.",
        style("ℹ").blue()
    );

    Ok(())
}

/// `cxg mcp uninstall [--client claude-desktop,cursor,...]`
pub async fn run_uninstall(client_filter: Option<String>) -> Result<()> {
    use console::style;

    let statuses = detect_clients();

    let indices = if let Some(filter) = client_filter {
        let ids: Vec<&str> = filter.split(',').map(|s| s.trim()).collect();
        let mut resolved = Vec::new();
        for id in &ids {
            match statuses.iter().position(|s| s.client.id == *id) {
                Some(idx) => resolved.push(idx),
                None => {
                    return Err(Error::config(format!("Unknown client '{}'", id)));
                }
            }
        }
        resolved
    } else {
        // Uninstall from all configured clients
        statuses
            .iter()
            .enumerate()
            .filter(|(_, s)| s.already_configured)
            .map(|(i, _)| i)
            .collect()
    };

    if indices.is_empty() {
        println!("{}", style("No clients have CXG configured.").dim());
        return Ok(());
    }

    println!();
    for idx in indices {
        let status = &statuses[idx];
        if let Some(ref path) = status.config_path {
            match remove_config_entry(path, status.client.servers_key) {
                Ok(true) => println!("  {} {} — removed", style("✓").green(), status.client.label),
                Ok(false) => println!(
                    "  {} {} — was not configured",
                    style("–").dim(),
                    style(status.client.label).dim()
                ),
                Err(e) => println!(
                    "  {} {} — {}",
                    style("✗").red(),
                    status.client.label,
                    style(e).red()
                ),
            }
        }
    }
    println!();

    Ok(())
}

/// `cxg mcp status`
pub async fn run_status() -> Result<()> {
    use console::style;

    let statuses = detect_clients();

    println!();
    println!("{}", style("CXG MCP Configuration Status").bold().cyan());
    println!("{}", style("═".repeat(50)).dim());
    println!();

    for status in &statuses {
        let path_str = status
            .config_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "—".to_string());

        if status.already_configured {
            println!(
                "  {} {:<22} {} {}",
                style("●").green(),
                style(status.client.label).green().bold(),
                style("configured").green(),
                style(format!("({})", path_str)).dim(),
            );
        } else if status.config_exists {
            println!(
                "  {} {:<22} {} {}",
                style("○").yellow(),
                style(status.client.label).white(),
                style("installed, not configured").yellow(),
                style(format!("({})", path_str)).dim(),
            );
        } else {
            println!(
                "  {} {:<22} {}",
                style("·").dim(),
                style(status.client.label).dim(),
                style("not detected").dim(),
            );
        }
    }

    let configured = statuses.iter().filter(|s| s.already_configured).count();
    let installed = statuses
        .iter()
        .filter(|s| s.config_exists && !s.already_configured)
        .count();

    println!();
    if configured > 0 {
        println!(
            "  {} {} client(s) configured",
            style("✓").green(),
            configured
        );
    }
    if installed > 0 {
        println!(
            "  {} {} client(s) can be configured — run {}",
            style("→").cyan(),
            installed,
            style("cxg mcp install").bold()
        );
    }
    if configured == 0 && installed == 0 {
        println!(
            "  {} No MCP clients detected. Install Claude Desktop, Claude Code, or Cursor first.",
            style("ℹ").blue()
        );
    }
    println!();

    Ok(())
}
