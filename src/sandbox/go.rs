//! Go sandbox environment

use crate::error::{Error, Result};
use crate::sandbox::Sandbox;
use std::process::Command;

/// Initialize Go environment
pub async fn init_environment(_sandbox: &Sandbox) -> Result<()> {
    tracing::info!("Initializing Go sandbox environment");

    // Check if Go is available, attempt installation if missing
    use crate::sandbox::runtime_installer::ensure_runtime_available;

    let go_available = ensure_runtime_available("go", &["go"]).await?;

    if !go_available {
        tracing::warn!("Go not available and automatic installation failed");
        tracing::warn!("Skipping Go sandbox initialization");
        return Ok(());
    }

    tracing::info!("Go sandbox environment initialized successfully");
    Ok(())
}

/// Compile and execute Go template
pub async fn compile_and_execute(
    sandbox: &Sandbox,
    source_path: &std::path::Path,
    args: &[&str],
) -> Result<std::process::Output> {
    let pkg_dir = sandbox.root_dir().join("go/pkg");

    // Compile
    tracing::debug!("Compiling Go template: {}", source_path.display());
    let binary_name = source_path.file_stem().unwrap();
    let binary_path = pkg_dir.join(binary_name);

    let mut cmd = Command::new("go");
    cmd.arg("build");
    cmd.arg("-o");
    cmd.arg(&binary_path);
    cmd.arg(source_path);

    for (key, value) in sandbox.get_env_vars() {
        cmd.env(key, value);
    }

    let output = cmd
        .output()
        .map_err(|e| Error::command(format!("Failed to compile Go template: {}", e)))?;

    if !output.status.success() {
        return Err(Error::command(format!(
            "Go compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Execute
    let mut exec_cmd = Command::new(binary_path);
    exec_cmd.args(args);

    for (key, value) in sandbox.get_env_vars() {
        exec_cmd.env(key, value);
    }

    exec_cmd
        .output()
        .map_err(|e| Error::command(format!("Failed to execute Go binary: {}", e)))
}
