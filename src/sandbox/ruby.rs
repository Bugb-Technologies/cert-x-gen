//! Ruby sandbox environment

use crate::error::{Error, Result};
use crate::sandbox::Sandbox;
use std::process::Command;

/// Initialize Ruby environment
pub async fn init_environment(sandbox: &Sandbox) -> Result<()> {
    tracing::info!("Initializing Ruby sandbox environment");

    // Check if Ruby is available, attempt installation if missing
    use crate::sandbox::runtime_installer::ensure_runtime_available;

    let ruby_available = ensure_runtime_available("ruby", &["ruby"]).await?;

    if !ruby_available {
        tracing::warn!("Ruby not available and automatic installation failed");
        tracing::warn!("Skipping Ruby sandbox initialization");
        return Ok(());
    }

    // Check Ruby version
    let ruby_version = Command::new("ruby")
        .args(&["-e", "puts RUBY_VERSION"])
        .output();

    if let Ok(output) = ruby_version {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        tracing::info!("Ruby version: {}", version);

        // Parse version and warn if too old
        if let Some(major_minor) = version
            .split('.')
            .take(2)
            .collect::<Vec<_>>()
            .join(".")
            .parse::<f32>()
            .ok()
        {
            if major_minor < 3.0 {
                tracing::warn!(
                    "Ruby version {} is outdated. Some gems require Ruby 3.0+",
                    version
                );
                tracing::warn!(
                    "Consider upgrading Ruby: brew install ruby (macOS) or rbenv install 3.2.0"
                );
                tracing::warn!(
                    "Continuing with available Ruby version. Some gems may fail to install."
                );
            }
        }
    }

    let gem_check = Command::new("gem").arg("--version").output();

    if gem_check.is_err() {
        tracing::warn!("Ruby/gem not found, skipping Ruby sandbox initialization");
        return Ok(());
    }

    // Install comprehensive gems from manifest
    let manifest = crate::sandbox::packages::ruby_manifest();
    let all_gems = manifest.all_packages();
    let gem_refs: Vec<&str> = all_gems.iter().map(|s| s.as_str()).collect();

    tracing::info!(
        "Installing {} Ruby gems (this may take a few minutes)...",
        gem_refs.len()
    );
    tracing::info!("Note: Some gems may fail due to version incompatibility. This is expected and won't affect other gems.");

    install_gems(sandbox, &gem_refs).await?;

    tracing::info!("Ruby sandbox environment initialized successfully");
    Ok(())
}

/// Install Ruby gems
pub async fn install_gems(sandbox: &Sandbox, gems: &[&str]) -> Result<()> {
    if gems.is_empty() {
        return Ok(());
    }

    tracing::info!("Installing Ruby gems: {:?}", gems);

    let gem_home = sandbox.root_dir().join("ruby/gems");
    let mut successful = 0;
    let mut failed = 0;

    for gem in gems {
        let output = Command::new("gem")
            .args(&[
                "install",
                gem,
                "--install-dir",
                gem_home.to_str().unwrap(),
                "--no-document",
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                successful += 1;
                tracing::debug!("Successfully installed gem: {}", gem);
            }
            Ok(out) => {
                failed += 1;
                let error_msg = String::from_utf8_lossy(&out.stderr);
                let stdout_msg = String::from_utf8_lossy(&out.stdout);
                let combined_msg = format!("{}{}", stdout_msg, error_msg);

                // Only warn, don't fail the entire process - provide helpful context
                if combined_msg.contains("requires Ruby version")
                    || combined_msg.contains("Ruby version")
                {
                    tracing::warn!("Skipping gem {} (requires newer Ruby version - current Ruby may be too old)", gem);
                } else if combined_msg.contains("ERROR")
                    && combined_msg.contains("Error installing")
                {
                    // Extract the actual error reason
                    let error_lines: Vec<&str> = combined_msg
                        .lines()
                        .filter(|l| l.contains("ERROR") || l.trim().starts_with("Error"))
                        .collect();
                    let error_context = if !error_lines.is_empty() {
                        error_lines[0]
                    } else {
                        "Installation failed"
                    };
                    tracing::warn!("Skipping gem {} ({})", gem, error_context);
                } else {
                    let short_error = combined_msg
                        .lines()
                        .filter(|l| !l.trim().is_empty() && !l.contains("Building"))
                        .take(2)
                        .collect::<Vec<_>>()
                        .join("; ");
                    tracing::warn!(
                        "Failed to install gem {}: {}",
                        gem,
                        if short_error.is_empty() {
                            "Unknown error"
                        } else {
                            &short_error
                        }
                    );
                }
            }
            Err(e) => {
                failed += 1;
                tracing::warn!("Failed to execute gem install for {}: {}", gem, e);
            }
        }
    }

    tracing::info!(
        "Ruby gems installation complete: {} successful, {} failed/skipped",
        successful,
        failed
    );

    // Don't fail if at least some packages installed
    if successful > 0 {
        Ok(())
    } else if failed == gems.len() {
        tracing::warn!(
            "All Ruby gems failed to install. Ruby sandbox may not be fully functional."
        );
        Ok(()) // Still return Ok to not block other languages
    } else {
        Ok(())
    }
}

/// Execute Ruby script in sandbox
pub async fn execute_script(
    sandbox: &Sandbox,
    script_path: &std::path::Path,
    args: &[&str],
) -> Result<std::process::Output> {
    let mut cmd = Command::new("ruby");
    cmd.arg(script_path);
    cmd.args(args);

    for (key, value) in sandbox.get_env_vars() {
        cmd.env(key, value);
    }

    cmd.output()
        .map_err(|e| Error::command(format!("Failed to execute Ruby script: {}", e)))
}
