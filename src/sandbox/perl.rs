//! Perl sandbox environment

use crate::error::{Error, Result};
use crate::sandbox::Sandbox;
use std::process::Command;

/// Initialize Perl environment
pub async fn init_environment(sandbox: &Sandbox) -> Result<()> {
    tracing::info!("Initializing Perl sandbox environment");

    // Check if Perl is available, attempt installation if missing
    use crate::sandbox::runtime_installer::ensure_runtime_available;

    let perl_available = ensure_runtime_available("perl", &["perl"]).await?;

    if !perl_available {
        tracing::warn!("Perl not available and automatic installation failed");
        tracing::warn!("Skipping Perl sandbox initialization");
        return Ok(());
    }

    // Check if cpanm is available, install if needed
    let cpanm_check = Command::new("cpanm").arg("--version").output();

    if cpanm_check.is_err() {
        tracing::info!("Installing cpanm...");

        // Check if curl is available
        let curl_check = Command::new("curl").arg("--version").output();

        if curl_check.is_err() {
            tracing::warn!("curl not found. Cannot install cpanm automatically.");
            tracing::warn!(
                "Please install cpanm manually: curl -L https://cpanmin.us | perl - App::cpanminus"
            );
            tracing::warn!("Or install via system package manager: brew install perl (macOS) or apt-get install perl (Linux)");
            tracing::warn!("Skipping Perl module installation. Perl scripts may still work if modules are already installed.");
            return Ok(()); // Don't fail, just skip Perl
        }

        // Store cpanm in sandbox directory for reuse
        let sandbox_cpanm = sandbox.root_dir().join("perl/cpanm");
        let cpanm_dir = sandbox.root_dir().join("perl");

        // Create perl directory if it doesn't exist
        if let Err(e) = std::fs::create_dir_all(&cpanm_dir) {
            tracing::warn!("Failed to create Perl sandbox directory: {}", e);
            return Ok(());
        }

        // Download cpanm to sandbox directory
        let download_result = Command::new("curl")
            .args(&[
                "-L",
                "https://cpanmin.us",
                "-o",
                sandbox_cpanm.to_str().unwrap(),
            ])
            .output();

        if download_result.is_err() || !download_result.as_ref().unwrap().status.success() {
            tracing::warn!("Failed to download cpanm. Skipping Perl module installation.");
            tracing::warn!("You can install cpanm manually: curl -L https://cpanmin.us | perl - App::cpanminus");
            return Ok(()); // Don't fail, just skip Perl
        }

        // Make cpanm executable
        let chmod_result = Command::new("chmod")
            .args(&["+x", sandbox_cpanm.to_str().unwrap()])
            .output();

        if chmod_result.is_err() {
            tracing::warn!("Failed to make cpanm executable. Skipping Perl module installation.");
            return Ok(());
        }

        // Try to install cpanm system-wide (preferred)
        let install_result = Command::new("perl")
            .arg(sandbox_cpanm.to_str().unwrap())
            .arg("App::cpanminus")
            .output();

        match install_result {
            Ok(out) if out.status.success() => {
                tracing::info!("cpanm installed successfully to system");
                // Remove downloaded file since system install succeeded
                let _ = std::fs::remove_file(&sandbox_cpanm);
            }
            Ok(_) => {
                // If system install fails, we'll use the downloaded version in install_modules
                tracing::info!(
                    "System-wide cpanm installation failed, will use sandbox-local version"
                );
            }
            Err(e) => {
                tracing::info!(
                    "System-wide cpanm installation failed ({}), will use sandbox-local version",
                    e
                );
            }
        }
    }

    // Install comprehensive modules from manifest
    let manifest = crate::sandbox::packages::perl_manifest();
    let all_modules = manifest.all_packages();
    let module_refs: Vec<&str> = all_modules.iter().map(|s| s.as_str()).collect();

    tracing::info!(
        "Installing {} Perl modules (this may take a few minutes)...",
        module_refs.len()
    );
    install_modules(sandbox, &module_refs).await?;

    tracing::info!("Perl sandbox environment initialized successfully");
    Ok(())
}

/// Install Perl modules
pub async fn install_modules(sandbox: &Sandbox, modules: &[&str]) -> Result<()> {
    if modules.is_empty() {
        return Ok(());
    }

    tracing::info!("Installing Perl modules: {:?}", modules);

    let local_lib = sandbox.root_dir().join("perl/local");

    // Create local lib directory
    if let Err(e) = std::fs::create_dir_all(&local_lib) {
        tracing::warn!("Failed to create Perl local lib directory: {}", e);
    }

    // Determine cpanm path - try system first, then sandbox-local version
    let mut cpanm_path = "cpanm".to_string();
    let cpanm_check = Command::new("cpanm").arg("--version").output();

    if cpanm_check.is_err() {
        // Try sandbox-local version (downloaded during init)
        let sandbox_cpanm = sandbox.root_dir().join("perl/cpanm");
        if sandbox_cpanm.exists() {
            cpanm_path = sandbox_cpanm.to_str().unwrap().to_string();
            tracing::debug!("Using sandbox-local cpanm at: {}", cpanm_path);
        } else {
            tracing::warn!("cpanm not found. Cannot install Perl modules.");
            tracing::warn!(
                "Please install cpanm: curl -L https://cpanmin.us | perl - App::cpanminus"
            );
            tracing::info!("Or re-run 'cxg sandbox init' to attempt automatic installation");
            return Ok(()); // Don't fail, just skip
        }
    }

    let mut successful = 0;
    let mut failed = 0;

    for module in modules {
        let output = Command::new(&cpanm_path)
            .args(&["-L", local_lib.to_str().unwrap(), module])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                successful += 1;
                tracing::debug!("Successfully installed module: {}", module);
            }
            Ok(out) => {
                failed += 1;
                let error_msg = String::from_utf8_lossy(&out.stderr);

                // Provide helpful error context but don't fail
                if error_msg.contains("No such file or directory") {
                    tracing::warn!(
                        "Skipping module {} (cpanm not properly installed or module not found)",
                        module
                    );
                    tracing::debug!(
                        "Error details: {}",
                        error_msg.lines().next().unwrap_or("Unknown error")
                    );
                } else if error_msg.contains("Could not resolve") {
                    tracing::warn!(
                        "Skipping module {} (module name may be incorrect or not available)",
                        module
                    );
                } else {
                    tracing::warn!(
                        "Failed to install module {}: {}",
                        module,
                        error_msg.lines().take(2).collect::<Vec<_>>().join("; ")
                    );
                }
            }
            Err(e) => {
                failed += 1;
                if e.kind() == std::io::ErrorKind::NotFound {
                    tracing::warn!("cpanm command not found. Cannot install Perl modules.");
                    tracing::warn!(
                        "Please install cpanm: curl -L https://cpanmin.us | perl - App::cpanminus"
                    );
                    break; // Don't continue trying if cpanm doesn't exist
                } else {
                    tracing::warn!("Failed to execute cpanm for {}: {}", module, e);
                }
            }
        }
    }

    tracing::info!(
        "Perl modules installation complete: {} successful, {} failed/skipped",
        successful,
        failed
    );

    // Don't fail if at least some modules installed, or if we had failures but it's expected
    if successful > 0 {
        Ok(())
    } else if failed == modules.len() {
        tracing::warn!(
            "All Perl modules failed to install. Perl sandbox may not be fully functional."
        );
        tracing::info!(
            "You can install modules manually later using: cpanm -L {} <module>",
            local_lib.display()
        );
        Ok(()) // Still return Ok to not block other languages
    } else {
        Ok(())
    }
}

/// Execute Perl script in sandbox
pub async fn execute_script(
    sandbox: &Sandbox,
    script_path: &std::path::Path,
    args: &[&str],
) -> Result<std::process::Output> {
    let mut cmd = Command::new("perl");
    cmd.arg(script_path);
    cmd.args(args);

    for (key, value) in sandbox.get_env_vars() {
        cmd.env(key, value);
    }

    cmd.output()
        .map_err(|e| Error::command(format!("Failed to execute Perl script: {}", e)))
}
