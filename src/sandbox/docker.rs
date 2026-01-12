//! Docker-based true sandbox environment

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Docker sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerConfig {
    /// Container name
    pub name: String,
    
    /// Docker image to use
    pub image: String,
    
    /// Languages to install
    pub languages: Vec<String>,
    
    /// Persist container between runs
    pub persist: bool,
    
    /// Auto-start container on CLI launch
    pub auto_start: bool,
    
    /// Resource limits
    pub resources: ResourceLimits,
    
    /// Volumes to mount (host_path -> container_path)
    pub volumes: HashMap<String, String>,
    
    /// Environment variables
    pub environment: HashMap<String, String>,
    
    /// Network mode (bridge, host, none)
    pub network_mode: String,
}

/// Resource limits for container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Memory limit (e.g., "4g", "2048m")
    pub memory: String,
    
    /// CPU limit (number of CPUs)
    pub cpus: String,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            name: "cert-x-gen-default".to_string(),
            image: "cert-x-gen/sandbox:latest".to_string(),
            languages: vec![
                "python".to_string(),
                "ruby".to_string(),
                "node".to_string(),
                "go".to_string(),
                "java".to_string(),
                "perl".to_string(),
                "php".to_string(),
                "rust".to_string(),
            ],
            persist: true,
            auto_start: true,
            resources: ResourceLimits {
                memory: "4g".to_string(),
                cpus: "2".to_string(),
            },
            volumes: HashMap::new(),
            environment: HashMap::new(),
            network_mode: "bridge".to_string(), // Use bridge for network access
        }
    }
}

/// Docker sandbox manager
#[derive(Debug)]
pub struct DockerSandbox {
    config: DockerConfig,
    container_id: Option<String>,
}

impl DockerSandbox {
    /// Create new Docker sandbox
    pub fn new(config: DockerConfig) -> Self {
        Self {
            config,
            container_id: None,
        }
    }
    
    /// Load existing sandbox by name
    pub fn load(name: &str) -> Result<Self> {
        // Check if container exists
        let output = Command::new("docker")
            .args(&["ps", "-a", "--filter", &format!("name={}", name), "--format", "{{.ID}}"])
            .output()
            .map_err(|e| Error::config(format!("Failed to check Docker container: {}", e)))?;
        
        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        if container_id.is_empty() {
            return Err(Error::config(format!("Container '{}' not found", name)));
        }
        
        let mut sandbox = Self {
            config: DockerConfig {
                name: name.to_string(),
                ..Default::default()
            },
            container_id: Some(container_id),
        };
        
        // Load container config
        sandbox.load_container_config()?;
        
        Ok(sandbox)
    }
    
    /// Check if Docker is available
    pub fn docker_available() -> bool {
        Command::new("docker")
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }
    
    /// Check if Docker daemon is running
    pub fn docker_running() -> bool {
        Command::new("docker")
            .args(&["ps"])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }
    
    /// Get Docker version
    pub fn docker_version() -> Option<String> {
        Command::new("docker")
            .arg("--version")
            .output()
            .ok()
            .and_then(|out| {
                if out.status.success() {
                    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
                } else {
                    None
                }
            })
    }
    
    /// Check if image exists locally
    fn image_exists(&self) -> bool {
        Command::new("docker")
            .args(&["images", "-q", &self.config.image])
            .output()
            .map(|out| !String::from_utf8_lossy(&out.stdout).trim().is_empty())
            .unwrap_or(false)
    }
    
    /// Build Docker image if needed
    pub async fn build_image(&self, dockerfile_path: Option<&Path>) -> Result<()> {
        tracing::info!("Building Docker image: {}", self.config.image);
        
        let dockerfile = dockerfile_path
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| {
                // Use bundled Dockerfile
                PathBuf::from("Dockerfile.sandbox")
            });
        
        if !dockerfile.exists() {
            // Create default Dockerfile
            self.create_default_dockerfile(&dockerfile)?;
        }
        
        // Fix Docker credential helper issue by temporarily disabling it
        let home_dir = std::env::var("HOME").ok();
        let docker_config_path = home_dir.as_ref().map(|h| PathBuf::from(h).join(".docker/config.json"));
        let mut backup_made = false;
        
        // Backup and modify Docker config if credential helper is causing issues
        if let Some(config_path) = docker_config_path.as_ref() {
            if config_path.exists() {
                if let Ok(content) = std::fs::read_to_string(config_path) {
                    if content.contains("credsStore") || content.contains("credStore") {
                        tracing::debug!("Temporarily disabling Docker credential helper for build");
                        let backup_path = config_path.with_extension("json.backup");
                        if std::fs::copy(config_path, &backup_path).is_ok() {
                            backup_made = true;
                            // Remove credential helper from config
                            let modified = content
                                .lines()
                                .filter(|line| !line.contains("credsStore") && !line.contains("credStore"))
                                .collect::<Vec<_>>()
                                .join("\n");
                            let _ = std::fs::write(config_path, modified);
                        }
                    }
                }
            }
        }
        
        let output = Command::new("docker")
            .args(&[
                "build",
                "-t", &self.config.image,
                "-f", dockerfile.to_str().unwrap(),
                ".",
            ])
            .output()
            .map_err(|e| Error::command(format!("Failed to build Docker image: {}", e)))?;
        
        // Restore Docker config if we modified it
        if backup_made {
            if let Some(config_path) = docker_config_path.as_ref() {
                let backup_path = config_path.with_extension("json.backup");
                if backup_path.exists() {
                    let _ = std::fs::copy(&backup_path, config_path);
                    let _ = std::fs::remove_file(&backup_path);
                }
            }
        }
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            // Check for credential helper error
            if stderr.contains("docker-credential-desktop") || stderr.contains("error getting credentials") {
                tracing::warn!("Docker credential helper error detected");
                tracing::info!("Attempting workaround: using --no-cache flag");
                
                // Try again with --no-cache and without pulling
                let retry_output = Command::new("docker")
                    .args(&[
                        "build",
                        "--no-cache",
                        "--pull=false",
                        "-t", &self.config.image,
                        "-f", dockerfile.to_str().unwrap(),
                        ".",
                    ])
                    .output()
                    .map_err(|e| Error::command(format!("Failed to build Docker image: {}", e)))?;
                
                if !retry_output.status.success() {
                    return Err(Error::command(format!(
                        "Docker build failed even with workaround.\n\nOriginal error:\n{}\n\nTo fix this issue:\n1. Open Docker Desktop settings\n2. Go to 'General' or 'Docker Engine'\n3. Remove or comment out the 'credsStore' line from config\n4. Or run: rm ~/.docker/config.json (will reset Docker config)\n5. Restart Docker Desktop",
                        stderr
                    )));
                }
            } else {
                return Err(Error::command(format!(
                    "Docker build failed: {}",
                    stderr
                )));
            }
        }
        
        tracing::info!("Docker image built successfully");
        Ok(())
    }
    
    /// Create default Dockerfile
    fn create_default_dockerfile(&self, path: &Path) -> Result<()> {
        let dockerfile_content = self.generate_dockerfile_content();
        
        std::fs::write(path, dockerfile_content)
            .map_err(|e| Error::config(format!("Failed to create Dockerfile: {}", e)))?;
        
        Ok(())
    }
    
    /// Generate Dockerfile content based on selected languages
    fn generate_dockerfile_content(&self) -> String {
        let mut content = String::from("FROM ubuntu:22.04\n\n");
        content.push_str("# Prevent interactive prompts\n");
        content.push_str("ENV DEBIAN_FRONTEND=noninteractive\n\n");
        
        content.push_str("# Update and install basic tools\n");
        content.push_str("RUN apt-get update && apt-get install -y \\\n");
        content.push_str("    curl wget git vim \\\n");
        content.push_str("    build-essential \\\n");
        content.push_str("    ca-certificates \\\n");
        content.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
        
        // Add language runtimes based on config
        if self.config.languages.contains(&"python".to_string()) {
            content.push_str("# Install Python\n");
            content.push_str("RUN apt-get update && apt-get install -y \\\n");
            content.push_str("    python3.11 python3-pip python3-venv \\\n");
            content.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
        }
        
        if self.config.languages.contains(&"ruby".to_string()) {
            content.push_str("# Install Ruby\n");
            content.push_str("RUN apt-get update && apt-get install -y \\\n");
            content.push_str("    ruby-full \\\n");
            content.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
        }
        
        if self.config.languages.contains(&"node".to_string()) {
            content.push_str("# Install Node.js\n");
            content.push_str("RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \\\n");
            content.push_str("    apt-get install -y nodejs && \\\n");
            content.push_str("    rm -rf /var/lib/apt/lists/*\n\n");
        }
        
        if self.config.languages.contains(&"go".to_string()) {
            content.push_str("# Install Go\n");
            content.push_str("RUN apt-get update && apt-get install -y \\\n");
            content.push_str("    golang-go \\\n");
            content.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
        }
        
        if self.config.languages.contains(&"java".to_string()) {
            content.push_str("# Install Java\n");
            content.push_str("RUN apt-get update && apt-get install -y \\\n");
            content.push_str("    default-jdk \\\n");
            content.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
        }
        
        if self.config.languages.contains(&"perl".to_string()) {
            content.push_str("# Install Perl\n");
            content.push_str("RUN apt-get update && apt-get install -y \\\n");
            content.push_str("    perl cpanminus \\\n");
            content.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
        }
        
        if self.config.languages.contains(&"php".to_string()) {
            content.push_str("# Install PHP\n");
            content.push_str("RUN apt-get update && apt-get install -y \\\n");
            content.push_str("    php-cli php-curl php-xml php-mbstring \\\n");
            content.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
        }
        
        if self.config.languages.contains(&"rust".to_string()) {
            content.push_str("# Install Rust\n");
            content.push_str("RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \\\n");
            content.push_str("    echo 'source $HOME/.cargo/env' >> ~/.bashrc\n");
            content.push_str("ENV PATH=\"/root/.cargo/bin:${PATH}\"\n\n");
        }
        
        // Note: cert-x-gen CLI is NOT installed inside the container
        // The host CLI uses 'docker exec' to run commands inside the container
        // This provides transparent execution without needing the binary inside
        
        // Set up workspace
        content.push_str("# Set up workspace\n");
        content.push_str("WORKDIR /workspace\n\n");
        
        // Mark as sandbox environment
        content.push_str("# Mark as sandbox\n");
        content.push_str("ENV CERT_X_GEN_SANDBOX=true\n");
        content.push_str("ENV CERT_X_GEN_SANDBOX_NAME=");
        content.push_str(&self.config.name);
        content.push_str("\n\n");
        
        // Keep container running with a long-lived process
        content.push_str("# Keep container running\n");
        content.push_str("# Use tail -f /dev/null to keep container alive\n");
        content.push_str("CMD [\"tail\", \"-f\", \"/dev/null\"]\n");
        
        content
    }
    
    /// Create container
    pub async fn create(&mut self) -> Result<()> {
        tracing::info!("Creating Docker container: {}", self.config.name);
        
        // Check if image exists, build if not
        if !self.image_exists() {
            tracing::info!("Image {} not found locally, building...", self.config.image);
            self.build_image(None).await?;
        }
        
        // Build docker run command
        let mut args = vec![
            "run".to_string(),
            "-d".to_string(), // Detached
            "--name".to_string(), self.config.name.clone(),
        ];
        
        // Add resource limits
        args.push("--memory".to_string());
        args.push(self.config.resources.memory.clone());
        args.push("--cpus".to_string());
        args.push(self.config.resources.cpus.clone());
        
        // Add network mode (important for accessing local network)
        args.push("--network".to_string());
        args.push(self.config.network_mode.clone());
        
        // Add volumes (for accessing local files)
        for (host_path, container_path) in &self.config.volumes {
            args.push("-v".to_string());
            args.push(format!("{}:{}", host_path, container_path));
        }
        
        // Add environment variables
        for (key, value) in &self.config.environment {
            args.push("-e".to_string());
            args.push(format!("{}={}", key, value));
        }
        
        // Add image
        args.push(self.config.image.clone());
        
        // Execute docker run
        let output = Command::new("docker")
            .args(&args)
            .output()
            .map_err(|e| Error::command(format!("Failed to create container: {}", e)))?;
        
        if !output.status.success() {
            return Err(Error::command(format!(
                "Failed to create container: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        
        self.container_id = Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        
        tracing::info!("Container created successfully: {}", self.container_id.as_ref().unwrap());
        Ok(())
    }
    
    /// Start container
    pub async fn start(&mut self) -> Result<()> {
        let container_id = self.container_id.as_ref()
            .ok_or_else(|| Error::config("Container ID not set"))?;
        
        tracing::info!("Starting container: {}", container_id);
        
        let output = Command::new("docker")
            .args(&["start", container_id])
            .output()
            .map_err(|e| Error::command(format!("Failed to start container: {}", e)))?;
        
        if !output.status.success() {
            return Err(Error::command(format!(
                "Failed to start container: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        
        // Wait a moment for container to fully start
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        // Verify container is actually running
        if !self.is_running() {
            // Check container logs to see why it exited
            let logs_output = Command::new("docker")
                .args(&["logs", "--tail", "20", container_id])
                .output();
            
            let logs = logs_output
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_else(|| "Could not retrieve logs".to_string());
            
            return Err(Error::command(format!(
                "Container started but immediately exited.\n\nContainer logs:\n{}\n\nThis usually means the container's CMD is not keeping it alive.\nTry rebuilding: cert-x-gen sandbox delete {} --force && cert-x-gen sandbox create {}",
                logs,
                self.config.name,
                self.config.name
            )));
        }
        
        tracing::info!("Container started successfully");
        Ok(())
    }
    
    /// Stop container
    pub async fn stop(&self) -> Result<()> {
        let container_id = self.container_id.as_ref()
            .ok_or_else(|| Error::config("Container ID not set"))?;
        
        tracing::info!("Stopping container: {}", container_id);
        
        let output = Command::new("docker")
            .args(&["stop", container_id])
            .output()
            .map_err(|e| Error::command(format!("Failed to stop container: {}", e)))?;
        
        if !output.status.success() {
            return Err(Error::command(format!(
                "Failed to stop container: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        
        tracing::info!("Container stopped successfully");
        Ok(())
    }
    
    /// Check if container is running
    pub fn is_running(&self) -> bool {
        if let Some(container_id) = &self.container_id {
            Command::new("docker")
                .args(&["ps", "-q", "--filter", &format!("id={}", container_id)])
                .output()
                .map(|out| !String::from_utf8_lossy(&out.stdout).trim().is_empty())
                .unwrap_or(false)
        } else {
            false
        }
    }
    
    /// Execute command in container
    pub async fn exec(&self, cmd: &[&str]) -> Result<Output> {
        let container_id = self.container_id.as_ref()
            .ok_or_else(|| Error::config("Container ID not set"))?;
        
        let mut args = vec!["exec", container_id];
        args.extend(cmd);
        
        Command::new("docker")
            .args(&args)
            .output()
            .map_err(|e| Error::command(format!("Failed to execute command in container: {}", e)))
    }
    
    /// Execute cert-x-gen CLI command inside container
    /// Note: This doesn't actually run cert-x-gen binary inside container
    /// Instead, it returns Ok to signal that the command should be executed
    /// by the host CLI with container context
    pub async fn exec_cli(&self, _cli_args: &[String]) -> Result<()> {
        // The actual command execution happens in the host CLI
        // This function just verifies the container is ready
        if !self.is_running() {
            return Err(Error::config("Container is not running"));
        }
        
        Ok(())
    }
    
    /// Execute a shell command inside the container
    pub async fn exec_command(&self, command: &str) -> Result<Output> {
        let container_id = self.container_id.as_ref()
            .ok_or_else(|| Error::config("Container ID not set"))?;
        
        Command::new("docker")
            .args(&["exec", container_id, "/bin/bash", "-c", command])
            .output()
            .map_err(|e| Error::command(format!("Failed to execute command in container: {}", e)))
    }
    
    /// Enter interactive shell
    pub async fn shell(&self) -> Result<()> {
        let container_id = self.container_id.as_ref()
            .ok_or_else(|| Error::config("Container ID not set"))?;
        
        tracing::info!("Entering sandbox shell...");
        tracing::info!("Type 'exit' to leave the sandbox");
        
        let status = Command::new("docker")
            .args(&["exec", "-it", container_id, "/bin/bash"])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| Error::command(format!("Failed to enter shell: {}", e)))?;
        
        if !status.success() {
            return Err(Error::command("Shell session failed"));
        }
        
        Ok(())
    }
    
    /// Delete container
    pub async fn delete(&mut self) -> Result<()> {
        let container_id = self.container_id.as_ref()
            .ok_or_else(|| Error::config("Container ID not set"))?;
        
        tracing::info!("Deleting container: {}", container_id);
        
        // Stop first if running
        if self.is_running() {
            self.stop().await?;
        }
        
        let output = Command::new("docker")
            .args(&["rm", container_id])
            .output()
            .map_err(|e| Error::command(format!("Failed to delete container: {}", e)))?;
        
        if !output.status.success() {
            return Err(Error::command(format!(
                "Failed to delete container: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        
        self.container_id = None;
        tracing::info!("Container deleted successfully");
        Ok(())
    }
    
    /// Get container status
    pub fn status(&self) -> SandboxStatus {
        if let Some(container_id) = &self.container_id {
            let running = self.is_running();
            
            SandboxStatus {
                name: self.config.name.clone(),
                container_id: Some(container_id.clone()),
                running,
                image: self.config.image.clone(),
                languages: self.config.languages.clone(),
            }
        } else {
            SandboxStatus {
                name: self.config.name.clone(),
                container_id: None,
                running: false,
                image: self.config.image.clone(),
                languages: self.config.languages.clone(),
            }
        }
    }
    
    /// Load container configuration
    fn load_container_config(&mut self) -> Result<()> {
        // In a real implementation, we'd inspect the container
        // For now, use defaults
        Ok(())
    }
    
    /// Get config
    pub fn config(&self) -> &DockerConfig {
        &self.config
    }
}

/// Sandbox status information
#[derive(Debug, Clone)]
pub struct SandboxStatus {
    /// Container name

    pub name: String,
    /// Container ID if running

    pub container_id: Option<String>,
    /// Whether the container is currently running

    pub running: bool,
    /// Docker image name

    pub image: String,
    /// Supported programming languages

    pub languages: Vec<String>,
}

/// List all sandboxes
pub fn list_sandboxes() -> Result<Vec<SandboxStatus>> {
    let output = Command::new("docker")
        .args(&["ps", "-a", "--filter", "label=cert-x-gen-sandbox", "--format", "{{.Names}}"])
        .output()
        .map_err(|e| Error::command(format!("Failed to list containers: {}", e)))?;
    
    let names: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    
    let mut sandboxes = Vec::new();
    for name in names {
        if let Ok(sandbox) = DockerSandbox::load(&name) {
            sandboxes.push(sandbox.status());
        }
    }
    
    Ok(sandboxes)
}

/// Check if we're currently inside a sandbox
pub fn inside_sandbox() -> bool {
    std::env::var("CERT_X_GEN_SANDBOX").is_ok()
}

/// Get current sandbox name (if inside one)
pub fn current_sandbox_name() -> Option<String> {
    std::env::var("CERT_X_GEN_SANDBOX_NAME").ok()
}
