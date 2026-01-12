//! Rust sandbox environment

use crate::error::{Error, Result};
use crate::sandbox::Sandbox;
use std::process::Command;

/// Initialize Rust environment
pub async fn init_environment(_sandbox: &Sandbox) -> Result<()> {
    tracing::info!("Initializing Rust sandbox environment");

    // Check if Rust (cargo/rustc) is available, attempt installation if missing
    use crate::sandbox::runtime_installer::ensure_runtime_available;
    
    // Rust comes with cargo, so check for cargo
    let rust_available = ensure_runtime_available("rust", &["cargo", "rustc"]).await?;
    
    if !rust_available {
        tracing::warn!("Rust/Cargo not available and automatic installation failed");
        tracing::warn!("Skipping Rust sandbox initialization");
        tracing::info!("You can install Rust manually: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
        return Ok(());
    }

    tracing::info!("Rust sandbox environment initialized successfully");
    Ok(())
}

/// Compile and execute Rust template
pub async fn compile_and_execute(
    sandbox: &Sandbox,
    source_path: &std::path::Path,
    args: &[&str],
) -> Result<std::process::Output> {
    let target_dir = sandbox.root_dir().join("rust/target");
    
    // Compile
    tracing::debug!("Compiling Rust template: {}", source_path.display());
    let output = Command::new("rustc")
        .arg(source_path)
        .arg("--out-dir")
        .arg(&target_dir)
        .output()
        .map_err(|e| Error::command(format!("Failed to compile Rust template: {}", e)))?;

    if !output.status.success() {
        return Err(Error::command(format!(
            "Rust compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Execute
    let binary_name = source_path.file_stem().unwrap();
    let binary_path = target_dir.join(binary_name);
    
    let mut cmd = Command::new(binary_path);
    cmd.args(args);
    
    for (key, value) in sandbox.get_env_vars() {
        cmd.env(key, value);
    }
    
    cmd.output()
        .map_err(|e| Error::command(format!("Failed to execute Rust binary: {}", e)))
}
