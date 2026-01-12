//! PHP sandbox environment

use crate::error::{Error, Result};
use crate::sandbox::Sandbox;
use std::fs;
use std::process::Command;

/// Initialize PHP environment
pub async fn init_environment(sandbox: &Sandbox) -> Result<()> {
    tracing::info!("Initializing PHP sandbox environment");

    // Check if PHP is available, attempt installation if missing
    use crate::sandbox::runtime_installer::ensure_runtime_available;

    let php_available = ensure_runtime_available("php", &["php"]).await?;

    if !php_available {
        tracing::warn!("PHP not available and automatic installation failed");
        tracing::warn!("Skipping PHP sandbox initialization");
        return Ok(());
    }

    let php_dir = sandbox.root_dir().join("php");

    // Create composer.json
    let composer_json = r#"{
    "name": "cert-x-gen/sandbox",
    "description": "Cert-X-Gen PHP sandbox environment",
    "require": {}
}"#;

    fs::write(php_dir.join("composer.json"), composer_json)
        .map_err(|e| Error::config(format!("Failed to create composer.json: {}", e)))?;

    // Install Composer if not available
    let composer_check = Command::new("composer").arg("--version").output();

    if composer_check.is_ok() {
        // Install comprehensive packages from manifest
        let manifest = crate::sandbox::packages::php_manifest();
        let all_packages = manifest.all_packages();
        let package_refs: Vec<&str> = all_packages.iter().map(|s| s.as_str()).collect();

        tracing::info!(
            "Installing {} PHP packages (this may take a few minutes)...",
            package_refs.len()
        );
        install_packages(sandbox, &package_refs).await?;
    } else {
        tracing::warn!("Composer not found, skipping PHP package installation");
    }

    tracing::info!("PHP sandbox environment initialized successfully");
    Ok(())
}

/// Install Composer packages
pub async fn install_packages(sandbox: &Sandbox, packages: &[&str]) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }

    tracing::info!("Installing Composer packages: {:?}", packages);

    let php_dir = sandbox.root_dir().join("php");

    for package in packages {
        let output = Command::new("composer")
            .args(&["require", package])
            .current_dir(&php_dir)
            .output()
            .map_err(|e| {
                Error::command(format!(
                    "Failed to install Composer package {}: {}",
                    package, e
                ))
            })?;

        if !output.status.success() {
            tracing::warn!(
                "Failed to install package {}: {}",
                package,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    tracing::info!("Composer packages installed successfully");
    Ok(())
}

/// Execute PHP script in sandbox
pub async fn execute_script(
    sandbox: &Sandbox,
    script_path: &std::path::Path,
    args: &[&str],
) -> Result<std::process::Output> {
    let mut cmd = Command::new("php");
    cmd.arg(script_path);
    cmd.args(args);

    for (key, value) in sandbox.get_env_vars() {
        cmd.env(key, value);
    }

    cmd.current_dir(sandbox.root_dir().join("php"));

    cmd.output()
        .map_err(|e| Error::command(format!("Failed to execute PHP script: {}", e)))
}
