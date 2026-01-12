//! Java sandbox environment

use crate::error::{Error, Result};
use crate::sandbox::Sandbox;
use std::process::Command;

/// Initialize Java environment
pub async fn init_environment(_sandbox: &Sandbox) -> Result<()> {
    tracing::info!("Initializing Java sandbox environment");

    // Check if Java is available, attempt installation if missing
    use crate::sandbox::runtime_installer::ensure_runtime_available;

    // Check for both javac (compiler) and java (runtime)
    let java_available = ensure_runtime_available("java", &["javac", "java"]).await?;

    if !java_available {
        tracing::warn!("Java not available and automatic installation failed");
        tracing::warn!("Skipping Java sandbox initialization");
        return Ok(());
    }

    tracing::info!("Java sandbox environment initialized successfully");
    Ok(())
}

/// Compile and execute Java template
pub async fn compile_and_execute(
    sandbox: &Sandbox,
    source_path: &std::path::Path,
    args: &[&str],
) -> Result<std::process::Output> {
    let lib_dir = sandbox.root_dir().join("java/lib");

    // Compile
    tracing::debug!("Compiling Java template: {}", source_path.display());
    let output = Command::new("javac")
        .arg("-d")
        .arg(&lib_dir)
        .arg(source_path)
        .output()
        .map_err(|e| Error::command(format!("Failed to compile Java template: {}", e)))?;

    if !output.status.success() {
        return Err(Error::command(format!(
            "Java compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Execute
    let class_name = source_path.file_stem().unwrap().to_str().unwrap();

    let mut cmd = Command::new("java");
    cmd.arg("-cp");
    cmd.arg(&lib_dir);
    cmd.arg(class_name);
    cmd.args(args);

    for (key, value) in sandbox.get_env_vars() {
        cmd.env(key, value);
    }

    cmd.output()
        .map_err(|e| Error::command(format!("Failed to execute Java class: {}", e)))
}
