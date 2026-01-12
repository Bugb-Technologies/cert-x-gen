//! Python sandbox environment

use crate::error::{Error, Result};
use crate::sandbox::Sandbox;
use std::process::Command;

/// Initialize Python virtual environment
pub async fn init_environment(sandbox: &Sandbox) -> Result<()> {
    tracing::info!("Initializing Python sandbox environment");

    let venv_path = sandbox.root_dir().join("python/venv");
    
    // Check if Python is available, attempt installation if missing
    use crate::sandbox::runtime_installer::ensure_runtime_available;
    
    let python_available = ensure_runtime_available("python3", &["python3", "python"]).await?;
    
    if !python_available {
        tracing::warn!("Python3 not available and automatic installation failed");
        tracing::warn!("Skipping Python sandbox initialization");
        return Ok(());
    }

    // Create virtual environment
    tracing::info!("Creating Python virtual environment at: {}", venv_path.display());
    let output = Command::new("python3")
        .args(&["-m", "venv", venv_path.to_str().unwrap()])
        .output()
        .map_err(|e| Error::command(format!("Failed to create Python venv: {}", e)))?;

    if !output.status.success() {
        return Err(Error::command(format!(
            "Python venv creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Install comprehensive packages from manifest
    let manifest = crate::sandbox::packages::python_manifest();
    let all_packages = manifest.all_packages();
    let package_refs: Vec<&str> = all_packages.iter().map(|s| s.as_str()).collect();
    
    tracing::info!("Installing {} Python packages (this may take a few minutes)...", package_refs.len());
    install_packages(sandbox, &package_refs).await?;

    tracing::info!("Python sandbox environment initialized successfully");
    Ok(())
}

/// Install Python packages
pub async fn install_packages(sandbox: &Sandbox, packages: &[&str]) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }

    tracing::info!("Installing Python packages: {:?}", packages);

    let pip_path = sandbox.root_dir()
        .join("python/venv/bin/pip");

    let mut successful = 0;
    let mut failed = 0;
    let mut skipped_builtins = Vec::new();

    // Install packages one by one to avoid one failure stopping all others
    for package in packages {
        // Skip built-in modules that can't be installed via pip
        if is_builtin_python_module(package) {
            skipped_builtins.push(*package);
            continue;
        }

        let output = Command::new(&pip_path)
            .args(&["install", "--upgrade", package])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                successful += 1;
                tracing::debug!("Successfully installed package: {}", package);
            }
            Ok(out) => {
                failed += 1;
                let error_msg = String::from_utf8_lossy(&out.stderr);
                let stdout_msg = String::from_utf8_lossy(&out.stdout);
                let combined_msg = format!("{}{}", stdout_msg, error_msg);
                
                // Only warn, don't fail the entire process - provide helpful context
                if combined_msg.contains("No matching distribution found") || combined_msg.contains("ERROR: Could not find a version") {
                    tracing::warn!("Skipping package {} (not found in PyPI or incompatible version)", package);
                } else if combined_msg.contains("Requires-Python") || combined_msg.contains("Python version") {
                    tracing::warn!("Skipping package {} (requires different Python version)", package);
                } else if combined_msg.contains("subprocess-exited-with-error") || combined_msg.contains("error: subprocess") {
                    // Common for packages like pwntools that have complex build dependencies
                    tracing::warn!("Skipping package {} (build dependencies may be missing - this is usually safe to ignore)", package);
                    tracing::debug!("Installation error details: {}", combined_msg.lines().filter(|l| l.contains("error") || l.contains("ERROR")).take(2).collect::<Vec<_>>().join("; "));
                } else {
                    let short_error = combined_msg.lines().filter(|l| !l.trim().is_empty() && !l.contains("WARNING")).take(2).collect::<Vec<_>>().join("; ");
                    tracing::warn!("Failed to install package {}: {}", package, if short_error.is_empty() { "Unknown error" } else { &short_error });
                }
            }
            Err(e) => {
                failed += 1;
                tracing::warn!("Failed to execute pip install for {}: {}", package, e);
            }
        }
    }

    if !skipped_builtins.is_empty() {
        tracing::debug!("Skipped built-in modules: {:?}", skipped_builtins);
    }

    tracing::info!("Python packages installation complete: {} successful, {} failed/skipped, {} built-in", 
                   successful, failed, skipped_builtins.len());

    // Don't fail if at least some packages installed
    if successful > 0 {
        Ok(())
    } else if failed == packages.len() {
        tracing::warn!("All Python packages failed to install. Python sandbox may not be fully functional.");
        Ok(()) // Still return Ok to not block other languages
    } else {
        Ok(())
    }
}

/// Check if a module name is a Python built-in
fn is_builtin_python_module(module: &str) -> bool {
    matches!(module, 
        "socket" | "asyncio" | "configparser" | "json" | "csv" | 
        "os" | "sys" | "io" | "re" | "collections" | "itertools" |
        "functools" | "datetime" | "time" | "math" | "random" |
        "hashlib" | "hmac" | "base64" | "urllib" | "http" | "xml"
    )
}

/// Get Python executable path in sandbox
pub fn get_python_path(sandbox: &Sandbox) -> std::path::PathBuf {
    sandbox.root_dir().join("python/venv/bin/python")
}

/// Execute Python script in sandbox
pub async fn execute_script(
    sandbox: &Sandbox,
    script_path: &std::path::Path,
    args: &[&str],
) -> Result<std::process::Output> {
    let python_path = get_python_path(sandbox);
    
    let mut cmd = Command::new(python_path);
    cmd.arg(script_path);
    cmd.args(args);
    
    // Set environment variables
    for (key, value) in sandbox.get_env_vars() {
        cmd.env(key, value);
    }
    
    cmd.output()
        .map_err(|e| Error::command(format!("Failed to execute Python script: {}", e)))
}
