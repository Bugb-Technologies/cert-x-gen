//! Automatic runtime installation for missing language runtimes

use crate::error::Result;
use std::process::Command;

/// OS detection and package manager info
#[derive(Debug, Clone, Copy)]
enum PackageManager {
    Brew,
    Apt,
    Yum,
    Dnf,
    Pacman,
    #[allow(dead_code)]
    Choco,
    None,
}

/// Detect available package manager for the current OS
fn detect_package_manager() -> PackageManager {
    // Check for Homebrew (macOS/Linux)
    if Command::new("brew").arg("--version").output().is_ok() {
        return PackageManager::Brew;
    }

    // Check for apt (Debian/Ubuntu)
    if Command::new("apt-get").arg("--version").output().is_ok() {
        return PackageManager::Apt;
    }

    // Check for yum (RHEL/CentOS 7)
    if Command::new("yum").arg("--version").output().is_ok() {
        return PackageManager::Yum;
    }

    // Check for dnf (Fedora/RHEL 8+)
    if Command::new("dnf").arg("--version").output().is_ok() {
        return PackageManager::Dnf;
    }

    // Check for pacman (Arch)
    if Command::new("pacman").arg("--version").output().is_ok() {
        return PackageManager::Pacman;
    }

    // Check for Chocolatey (Windows)
    #[cfg(target_os = "windows")]
    {
        if Command::new("choco").arg("--version").output().is_ok() {
            return PackageManager::Choco;
        }
    }

    PackageManager::None
}

/// Install a runtime using the detected package manager
pub async fn install_runtime(runtime_name: &str) -> Result<bool> {
    // Special case: Rust - prefer rustup installer (more reliable than package managers)
    if runtime_name == "rust" {
        tracing::info!("Installing Rust using rustup.rs installer (recommended method)...");

        // Check if curl is available
        if Command::new("curl").arg("--version").output().is_ok() {
            // Download and execute rustup installer
            let install_result = Command::new("sh")
                .arg("-c")
                .arg("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y")
                .output();

            match install_result {
                Ok(out) if out.status.success() => {
                    tracing::info!("Rust installed successfully via rustup");
                    // Try to source cargo env
                    let cargo_path = std::env::var("HOME")
                        .map(|home| format!("{}/.cargo/bin/cargo", home))
                        .unwrap_or_else(|_| "cargo".to_string());

                    if std::path::Path::new(&cargo_path).exists()
                        || Command::new("cargo").arg("--version").output().is_ok()
                    {
                        tracing::info!("Rust installation verified");
                        return Ok(true);
                    } else {
                        tracing::info!("Rust installed but cargo not in PATH yet");
                        tracing::info!(
                            "You may need to restart your terminal or run: source $HOME/.cargo/env"
                        );
                        return Ok(true); // Installation succeeded, just PATH needs updating
                    }
                }
                Ok(out) => {
                    let error = String::from_utf8_lossy(&out.stderr);
                    tracing::warn!(
                        "rustup installer failed: {}",
                        error.lines().next().unwrap_or("Unknown error")
                    );
                    tracing::info!("Falling back to package manager...");
                }
                Err(e) => {
                    tracing::warn!("Failed to execute rustup installer: {}", e);
                    tracing::info!("Falling back to package manager...");
                }
            }
        } else {
            tracing::warn!("curl not found. Cannot use rustup installer.");
            tracing::info!("Falling back to package manager...");
        }
    }

    let pm = detect_package_manager();

    match pm {
        PackageManager::Brew => install_with_brew(runtime_name).await,
        PackageManager::Apt => install_with_apt(runtime_name).await,
        PackageManager::Yum => install_with_yum(runtime_name).await,
        PackageManager::Dnf => install_with_dnf(runtime_name).await,
        PackageManager::Pacman => install_with_pacman(runtime_name).await,
        PackageManager::Choco => install_with_choco(runtime_name).await,
        PackageManager::None => {
            tracing::warn!(
                "No package manager found. Cannot auto-install {}.",
                runtime_name
            );
            tracing::info!("Please install {} manually:", runtime_name);
            print_manual_instructions(runtime_name);
            Ok(false)
        }
    }
}

/// Install with Homebrew
async fn install_with_brew(runtime_name: &str) -> Result<bool> {
    let package_name = match runtime_name {
        "python3" | "python" => "python@3.11",
        "ruby" => "ruby",
        "perl" => "perl",
        "node" | "nodejs" => "node",
        "php" => "php",
        "go" => "go",
        "rust" => "rust",
        "java" => "openjdk",
        _ => runtime_name,
    };

    tracing::info!("Installing {} using Homebrew...", runtime_name);
    tracing::info!("This may require administrator privileges.");

    let output = Command::new("brew")
        .args(&["install", package_name])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            tracing::info!("Successfully installed {} via Homebrew", runtime_name);
            Ok(true)
        }
        Ok(out) => {
            let error = String::from_utf8_lossy(&out.stderr);
            if error.contains("Error:") || error.contains("Permission denied") {
                tracing::warn!(
                    "Failed to install {} via Homebrew: {}",
                    runtime_name,
                    error.lines().next().unwrap_or("Unknown error")
                );
                tracing::info!("You may need to run: brew install {}", package_name);
            } else {
                tracing::warn!("Installation may have succeeded, but verification failed");
            }
            Ok(false)
        }
        Err(e) => {
            tracing::warn!("Failed to execute brew install: {}", e);
            Ok(false)
        }
    }
}

/// Install with apt-get
async fn install_with_apt(runtime_name: &str) -> Result<bool> {
    let package_name = match runtime_name {
        "python3" | "python" => "python3",
        "ruby" => "ruby-full",
        "perl" => "perl",
        "node" | "nodejs" => "nodejs npm",
        "php" => "php-cli",
        "go" => "golang-go",
        "rust" => "rustc cargo",
        "java" => "default-jdk",
        _ => runtime_name,
    };

    tracing::info!("Installing {} using apt-get...", runtime_name);
    tracing::info!("This may require administrator privileges (sudo).");

    // Try apt-get update first
    let update_output = Command::new("sudo").args(&["apt-get", "update"]).output();

    // Try without sudo if sudo fails (we might be root)
    let _update_ok = if update_output.is_err() {
        Command::new("apt-get").args(&["update"]).output().is_ok()
    } else {
        update_output.as_ref().unwrap().status.success()
    };

    // Install package(s) - split package names into separate args
    let packages: Vec<&str> = package_name.split_whitespace().collect();
    let output = Command::new("sudo")
        .args(&["apt-get", "install", "-y"])
        .args(&packages)
        .output();

    // Try without sudo if sudo fails
    let output = if output.is_err() {
        Command::new("apt-get")
            .args(&["install", "-y"])
            .args(&packages)
            .output()
    } else {
        output
    };

    match output {
        Ok(out) if out.status.success() => {
            tracing::info!("Successfully installed {} via apt-get", runtime_name);
            Ok(true)
        }
        Ok(_) | Err(_) => {
            tracing::warn!(
                "Failed to install {} via apt-get. You may need to run:",
                runtime_name
            );
            tracing::info!(
                "  sudo apt-get update && sudo apt-get install -y {}",
                package_name
            );
            Ok(false)
        }
    }
}

/// Install with yum
async fn install_with_yum(runtime_name: &str) -> Result<bool> {
    let package_name = match runtime_name {
        "python3" | "python" => "python3",
        "ruby" => "ruby",
        "perl" => "perl",
        "node" | "nodejs" => "nodejs npm",
        "php" => "php-cli",
        "go" => "golang",
        "rust" => "rust cargo",
        "java" => "java-devel",
        _ => runtime_name,
    };

    tracing::info!("Installing {} using yum...", runtime_name);

    let output = Command::new("sudo")
        .args(&["yum", "install", "-y"])
        .args(package_name.split_whitespace())
        .output();

    let output = if output.is_err() {
        Command::new("yum")
            .args(&["install", "-y"])
            .args(package_name.split_whitespace())
            .output()
    } else {
        output
    };

    match output {
        Ok(out) if out.status.success() => {
            tracing::info!("Successfully installed {} via yum", runtime_name);
            Ok(true)
        }
        Ok(_) | Err(_) => {
            tracing::warn!(
                "Failed to install {} via yum. You may need to run:",
                runtime_name
            );
            tracing::info!("  sudo yum install -y {}", package_name);
            Ok(false)
        }
    }
}

/// Install with dnf
async fn install_with_dnf(runtime_name: &str) -> Result<bool> {
    let package_name = match runtime_name {
        "python3" | "python" => "python3",
        "ruby" => "ruby",
        "perl" => "perl",
        "node" | "nodejs" => "nodejs npm",
        "php" => "php-cli",
        "go" => "golang",
        "rust" => "rust cargo",
        "java" => "java-devel",
        _ => runtime_name,
    };

    tracing::info!("Installing {} using dnf...", runtime_name);

    let output = Command::new("sudo")
        .args(&["dnf", "install", "-y"])
        .args(package_name.split_whitespace())
        .output();

    let output = if output.is_err() {
        Command::new("dnf")
            .args(&["install", "-y"])
            .args(package_name.split_whitespace())
            .output()
    } else {
        output
    };

    match output {
        Ok(out) if out.status.success() => {
            tracing::info!("Successfully installed {} via dnf", runtime_name);
            Ok(true)
        }
        Ok(_) | Err(_) => {
            tracing::warn!(
                "Failed to install {} via dnf. You may need to run:",
                runtime_name
            );
            tracing::info!("  sudo dnf install -y {}", package_name);
            Ok(false)
        }
    }
}

/// Install with pacman
async fn install_with_pacman(runtime_name: &str) -> Result<bool> {
    let package_name = match runtime_name {
        "python3" | "python" => "python",
        "ruby" => "ruby",
        "perl" => "perl",
        "node" | "nodejs" => "nodejs npm",
        "php" => "php",
        "go" => "go",
        "rust" => "rust",
        "java" => "jdk-openjdk",
        _ => runtime_name,
    };

    tracing::info!("Installing {} using pacman...", runtime_name);

    let output = Command::new("sudo")
        .args(&["pacman", "-S", "--noconfirm"])
        .arg(package_name)
        .output();

    let output = if output.is_err() {
        Command::new("pacman")
            .args(&["-S", "--noconfirm"])
            .arg(package_name)
            .output()
    } else {
        output
    };

    match output {
        Ok(out) if out.status.success() => {
            tracing::info!("Successfully installed {} via pacman", runtime_name);
            Ok(true)
        }
        Ok(_) | Err(_) => {
            tracing::warn!(
                "Failed to install {} via pacman. You may need to run:",
                runtime_name
            );
            tracing::info!("  sudo pacman -S {}", package_name);
            Ok(false)
        }
    }
}

/// Install with Chocolatey (Windows)
async fn install_with_choco(runtime_name: &str) -> Result<bool> {
    let package_name = match runtime_name {
        "python3" | "python" => "python3",
        "ruby" => "ruby",
        "perl" => "strawberryperl",
        "node" | "nodejs" => "nodejs",
        "php" => "php",
        "go" => "golang",
        "rust" => "rust",
        "java" => "openjdk",
        _ => runtime_name,
    };

    tracing::info!("Installing {} using Chocolatey...", runtime_name);
    tracing::info!("This may require administrator privileges.");

    let output = Command::new("choco")
        .args(&["install", package_name, "-y"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            tracing::info!("Successfully installed {} via Chocolatey", runtime_name);
            Ok(true)
        }
        Ok(_) | Err(_) => {
            tracing::warn!(
                "Failed to install {} via Chocolatey. You may need to run:",
                runtime_name
            );
            tracing::info!("  choco install {} -y", package_name);
            Ok(false)
        }
    }
}

/// Print manual installation instructions
fn print_manual_instructions(runtime_name: &str) {
    match runtime_name {
        "python3" | "python" => {
            tracing::info!("  macOS: brew install python@3.11");
            tracing::info!("  Ubuntu/Debian: sudo apt-get install python3");
            tracing::info!("  RHEL/Fedora: sudo yum install python3 or sudo dnf install python3");
            tracing::info!("  Arch: sudo pacman -S python");
            tracing::info!("  Windows: Download from python.org");
        }
        "ruby" => {
            tracing::info!("  macOS: brew install ruby");
            tracing::info!("  Ubuntu/Debian: sudo apt-get install ruby-full");
            tracing::info!("  RHEL/Fedora: sudo yum install ruby or sudo dnf install ruby");
            tracing::info!("  Arch: sudo pacman -S ruby");
            tracing::info!("  Or use rbenv: rbenv install 3.2.0");
        }
        "perl" => {
            tracing::info!("  macOS: brew install perl");
            tracing::info!("  Ubuntu/Debian: sudo apt-get install perl");
            tracing::info!("  RHEL/Fedora: sudo yum install perl or sudo dnf install perl");
            tracing::info!("  Arch: sudo pacman -S perl");
            tracing::info!("  Windows: Download Strawberry Perl from strawberryperl.com");
        }
        "node" | "nodejs" => {
            tracing::info!("  macOS: brew install node");
            tracing::info!("  Ubuntu/Debian: sudo apt-get install nodejs npm");
            tracing::info!(
                "  RHEL/Fedora: sudo yum install nodejs npm or sudo dnf install nodejs npm"
            );
            tracing::info!("  Arch: sudo pacman -S nodejs npm");
            tracing::info!("  Or use nvm: nvm install --lts");
        }
        "go" => {
            tracing::info!("  macOS: brew install go");
            tracing::info!("  Ubuntu/Debian: sudo apt-get install golang-go");
            tracing::info!("  RHEL/Fedora: sudo yum install golang or sudo dnf install golang");
            tracing::info!("  Arch: sudo pacman -S go");
            tracing::info!("  Or download from: https://go.dev/dl/");
        }
        "rust" => {
            tracing::info!(
                "  All platforms: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
            );
            tracing::info!("  macOS: brew install rust");
            tracing::info!("  Ubuntu/Debian: sudo apt-get install rustc cargo");
            tracing::info!(
                "  RHEL/Fedora: sudo yum install rust cargo or sudo dnf install rust cargo"
            );
            tracing::info!("  Arch: sudo pacman -S rust");
        }
        "java" => {
            tracing::info!("  macOS: brew install openjdk");
            tracing::info!("  Ubuntu/Debian: sudo apt-get install default-jdk");
            tracing::info!(
                "  RHEL/Fedora: sudo yum install java-devel or sudo dnf install java-devel"
            );
            tracing::info!("  Arch: sudo pacman -S jdk-openjdk");
            tracing::info!("  Or download from: https://adoptium.net/");
        }
        "php" => {
            tracing::info!("  macOS: brew install php");
            tracing::info!("  Ubuntu/Debian: sudo apt-get install php-cli");
            tracing::info!("  RHEL/Fedora: sudo yum install php-cli or sudo dnf install php-cli");
        }
        _ => {
            tracing::info!("  Please check your system's package manager documentation");
        }
    }
}

/// Check if a runtime is available and attempt installation if missing
pub async fn ensure_runtime_available(runtime_name: &str, check_commands: &[&str]) -> Result<bool> {
    // Check if runtime is already available
    for cmd in check_commands {
        // For java, check both javac and java with appropriate version flags
        let version_flag = if *cmd == "javac" {
            "-version"
        } else if *cmd == "java" {
            "-version"
        } else {
            "--version"
        };

        if Command::new(cmd).arg(version_flag).output().is_ok() {
            tracing::debug!("{} found at: {}", runtime_name, cmd);
            return Ok(true);
        }
    }

    // Runtime not found, attempt installation
    tracing::info!(
        "{} not found. Attempting to install automatically...",
        runtime_name
    );
    tracing::info!("This may require administrator privileges and take a few minutes.");

    match install_runtime(runtime_name).await {
        Ok(true) => {
            // Give a moment for PATH to update (especially for rustup)
            // Use std::thread::sleep since we're already async
            std::thread::sleep(std::time::Duration::from_secs(1));

            // Verify installation worked
            for cmd in check_commands {
                let version_flag = if *cmd == "javac" || *cmd == "java" {
                    "-version"
                } else {
                    "--version"
                };

                if Command::new(cmd).arg(version_flag).output().is_ok() {
                    tracing::info!("{} successfully installed and verified", runtime_name);
                    return Ok(true);
                }
            }

            // For Rust, also check if cargo is in ~/.cargo/bin
            if runtime_name == "rust" {
                if let Ok(home) = std::env::var("HOME") {
                    let cargo_path = format!("{}/.cargo/bin/cargo", home);
                    if std::path::Path::new(&cargo_path).exists() {
                        tracing::info!("Rust installed but not in PATH. Add ~/.cargo/bin to PATH or restart terminal");
                        tracing::info!("Run: export PATH=\"$HOME/.cargo/bin:$PATH\"");
                        return Ok(true);
                    }
                }
            }

            tracing::warn!(
                "{} installation completed but runtime not found in PATH",
                runtime_name
            );
            tracing::info!("You may need to restart your terminal or add it to PATH");
            Ok(false)
        }
        Ok(false) => {
            tracing::warn!("Automatic installation of {} failed", runtime_name);
            tracing::info!("Manual installation instructions:");
            print_manual_instructions(runtime_name);
            Ok(false)
        }
        Err(e) => {
            tracing::warn!("Error during {} installation: {}", runtime_name, e);
            Ok(false)
        }
    }
}
