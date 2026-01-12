//! JavaScript/Node.js sandbox environment

use crate::error::{Error, Result};
use crate::sandbox::Sandbox;
use std::process::Command;
use std::fs;

/// Initialize Node.js environment
pub async fn init_environment(sandbox: &Sandbox) -> Result<()> {
    tracing::info!("Initializing JavaScript/Node.js sandbox environment");

    // Check if Node.js is available, attempt installation if missing
    use crate::sandbox::runtime_installer::ensure_runtime_available;
    
    let node_available = ensure_runtime_available("node", &["node", "nodejs"]).await?;
    
    if !node_available {
        tracing::warn!("Node.js not available and automatic installation failed");
        tracing::warn!("Skipping JavaScript sandbox initialization");
        return Ok(());
    }
    
    // Verify npm is also available
    let npm_check = Command::new("npm").arg("--version").output();
    if npm_check.is_err() {
        tracing::warn!("npm not found. Node.js installation may be incomplete.");
        tracing::info!("You may need to install npm separately or reinstall Node.js");
    }

    let js_dir = sandbox.root_dir().join("javascript");

    // Create package.json
    let package_json = r#"{
  "name": "cert-x-gen-sandbox",
  "version": "1.0.0",
  "description": "Cert-X-Gen JavaScript sandbox environment",
  "private": true,
  "dependencies": {}
}"#;

    fs::write(js_dir.join("package.json"), package_json)
        .map_err(|e| Error::config(format!("Failed to create package.json: {}", e)))?;

    // Install comprehensive packages from manifest
    let manifest = crate::sandbox::packages::javascript_manifest();
    let all_packages = manifest.all_packages();
    let package_refs: Vec<&str> = all_packages.iter().map(|s| s.as_str()).collect();
    
    tracing::info!("Installing {} npm packages (this may take a few minutes)...", package_refs.len());
    install_packages(sandbox, &package_refs).await?;

    tracing::info!("JavaScript sandbox environment initialized successfully");
    Ok(())
}

/// Install npm packages
pub async fn install_packages(sandbox: &Sandbox, packages: &[&str]) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }

    tracing::info!("Installing npm packages: {:?}", packages);

    let js_dir = sandbox.root_dir().join("javascript");
    
    // Filter out built-in Node.js modules
    let filtered_packages: Vec<&str> = packages.iter()
        .filter(|p| !is_builtin_nodejs_module(p))
        .copied()
        .collect();
    
    if filtered_packages.is_empty() {
        tracing::info!("All packages are built-in Node.js modules, nothing to install");
        return Ok(());
    }

    let mut successful = 0;
    let mut failed = 0;

    // Install packages one by one to avoid one failure stopping all others
    for package in filtered_packages {
        let output = Command::new("npm")
            .args(&["install", "--save", "--no-audit", "--no-fund", package])
            .current_dir(&js_dir)
            .output();

        match output {
            Ok(out) if out.status.success() => {
                successful += 1;
                tracing::debug!("Successfully installed package: {}", package);
            }
            Ok(out) => {
                failed += 1;
                let error_msg = String::from_utf8_lossy(&out.stderr);
                
                // Only warn, don't fail the entire process
                if error_msg.contains("404") || error_msg.contains("not found") {
                    tracing::warn!("Skipping package {} (not found in npm registry)", package);
                } else {
                    tracing::warn!("Failed to install package {}: {}", package, error_msg.lines().next().unwrap_or("Unknown error"));
                }
            }
            Err(e) => {
                failed += 1;
                tracing::warn!("Failed to execute npm install for {}: {}", package, e);
            }
        }
    }

    tracing::info!("npm packages installation complete: {} successful, {} failed/skipped", successful, failed);

    // Don't fail if at least some packages installed
    if successful > 0 || (failed == 0 && successful == 0) {
        Ok(())
    } else {
        tracing::warn!("All npm packages failed to install. JavaScript sandbox may not be fully functional.");
        Ok(()) // Still return Ok to not block other languages
    }
}

/// Check if a module is a built-in Node.js module
fn is_builtin_nodejs_module(module: &str) -> bool {
    matches!(module,
        "assert" | "buffer" | "child_process" | "cluster" | "crypto" |
        "dgram" | "dns" | "events" | "fs" | "http" | "https" | "net" |
        "os" | "path" | "querystring" | "readline" | "stream" | "string_decoder" |
        "timers" | "tls" | "tty" | "url" | "util" | "v8" | "vm" | "zlib" |
        "process" | "console" | "module" | "perf_hooks" | "worker_threads"
    )
}

/// Execute JavaScript script in sandbox
pub async fn execute_script(
    sandbox: &Sandbox,
    script_path: &std::path::Path,
    args: &[&str],
) -> Result<std::process::Output> {
    let mut cmd = Command::new("node");
    cmd.arg(script_path);
    cmd.args(args);
    
    // Set environment variables
    for (key, value) in sandbox.get_env_vars() {
        cmd.env(key, value);
    }
    
    cmd.current_dir(sandbox.root_dir().join("javascript"));
    
    cmd.output()
        .map_err(|e| Error::command(format!("Failed to execute JavaScript script: {}", e)))
}
