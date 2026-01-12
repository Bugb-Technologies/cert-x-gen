# Sandbox Module

## Overview

The sandbox module provides isolated runtime environments for all supported programming languages in CERT-X-GEN. This ensures dependency isolation, security, and reproducibility across different systems.

## Architecture

### Core Components

```
sandbox/
├── mod.rs           # Sandbox manager and configuration
├── python.rs        # Python virtual environment
├── javascript.rs    # Node.js npm environment
├── ruby.rs          # Ruby gems environment
├── perl.rs          # Perl local::lib environment
├── php.rs           # PHP composer environment
├── rust.rs          # Rust cargo environment
├── go.rs            # Go modules environment
└── java.rs          # Java classpath environment
```

### Key Types

#### `Sandbox`
Main sandbox manager that coordinates all language environments.

```rust
pub struct Sandbox {
    config: SandboxConfig,
    initialized: bool,
}
```

#### `SandboxConfig`
Configuration for sandbox behavior and enabled languages.

```rust
pub struct SandboxConfig {
    pub root_dir: PathBuf,
    pub enable_python: bool,
    pub enable_javascript: bool,
    pub enable_ruby: bool,
    pub enable_perl: bool,
    pub enable_php: bool,
    pub enable_rust: bool,
    pub enable_go: bool,
    pub enable_java: bool,
    pub auto_init: bool,
}
```

#### `SandboxStatus`
Current status of the sandbox and all language runtimes.

```rust
pub struct SandboxStatus {
    pub initialized: bool,
    pub root_dir: PathBuf,
    pub python_ready: bool,
    pub javascript_ready: bool,
    // ... other languages
}
```

## Usage

### Basic Initialization

```rust
use cert_x_gen::sandbox::Sandbox;

// Create with default config
let mut sandbox = Sandbox::new();

// Initialize all languages
sandbox.init().await?;

// Check status
let status = sandbox.status();
println!("Ready languages: {:?}", status.ready_languages());
```

### Custom Configuration

```rust
use cert_x_gen::sandbox::{Sandbox, SandboxConfig};

let mut config = SandboxConfig::default();
config.enable_python = true;
config.enable_javascript = true;
config.enable_ruby = false; // Disable Ruby

let mut sandbox = Sandbox::with_config(config);
sandbox.init().await?;
```

### Installing Packages

```rust
use cert_x_gen::sandbox::{Sandbox, python};

let sandbox = Sandbox::new();

// Install Python packages
python::install_packages(&sandbox, &[
    "requests",
    "beautifulsoup4",
    "selenium",
]).await?;
```

### Executing Scripts

```rust
use cert_x_gen::sandbox::{Sandbox, python};
use std::path::Path;

let sandbox = Sandbox::new();

// Execute Python script in sandbox
let output = python::execute_script(
    &sandbox,
    Path::new("template.py"),
    &["arg1", "arg2"],
).await?;

println!("Output: {}", String::from_utf8_lossy(&output.stdout));
```

## Language-Specific APIs

### Python

```rust
// Initialize environment
python::init_environment(&sandbox).await?;

// Install packages
python::install_packages(&sandbox, &["requests", "beautifulsoup4"]).await?;

// Get Python executable path
let python_path = python::get_python_path(&sandbox);

// Execute script
let output = python::execute_script(&sandbox, script_path, args).await?;
```

### JavaScript/Node.js

```rust
// Initialize environment
javascript::init_environment(&sandbox).await?;

// Install packages
javascript::install_packages(&sandbox, &["axios", "cheerio"]).await?;

// Execute script
let output = javascript::execute_script(&sandbox, script_path, args).await?;
```

### Ruby

```rust
// Initialize environment
ruby::init_environment(&sandbox).await?;

// Install gems
ruby::install_gems(&sandbox, &["nokogiri", "rest-client"]).await?;

// Execute script
let output = ruby::execute_script(&sandbox, script_path, args).await?;
```

### Perl

```rust
// Initialize environment
perl::init_environment(&sandbox).await?;

// Install modules
perl::install_modules(&sandbox, &["LWP::UserAgent", "JSON"]).await?;

// Execute script
let output = perl::execute_script(&sandbox, script_path, args).await?;
```

### PHP

```rust
// Initialize environment
php::init_environment(&sandbox).await?;

// Install packages
php::install_packages(&sandbox, &["guzzlehttp/guzzle"]).await?;

// Execute script
let output = php::execute_script(&sandbox, script_path, args).await?;
```

### Rust

```rust
// Initialize environment
rust::init_environment(&sandbox).await?;

// Compile and execute
let output = rust::compile_and_execute(&sandbox, source_path, args).await?;
```

### Go

```rust
// Initialize environment
go::init_environment(&sandbox).await?;

// Compile and execute
let output = go::compile_and_execute(&sandbox, source_path, args).await?;
```

### Java

```rust
// Initialize environment
java::init_environment(&sandbox).await?;

// Compile and execute
let output = java::compile_and_execute(&sandbox, source_path, args).await?;
```

## Environment Variables

The sandbox sets language-specific environment variables:

| Language | Variable | Purpose |
|----------|----------|---------|
| Python | `VIRTUAL_ENV` | Virtual environment path |
| Python | `PYTHONUSERBASE` | User packages path |
| JavaScript | `NODE_PATH` | Node modules path |
| Ruby | `GEM_HOME` | Gems installation path |
| Perl | `PERL_LOCAL_LIB_ROOT` | Local lib path |
| PHP | `PHP_USER_INI` | PHP config path |
| Rust | `CARGO_TARGET_DIR` | Cargo build path |
| Go | `GOPATH` | Go workspace path |
| Java | `JAVA_HOME` | Java installation path |

Access environment variables:

```rust
let env_vars = sandbox.get_env_vars();
for (key, value) in env_vars {
    println!("{} = {}", key, value);
}
```

## Error Handling

All sandbox operations return `Result<T>` with appropriate error types:

```rust
use cert_x_gen::error::{Error, Result};

match sandbox.init().await {
    Ok(_) => println!("Sandbox initialized"),
    Err(Error::Config(msg)) => eprintln!("Config error: {}", msg),
    Err(Error::Command(msg)) => eprintln!("Command error: {}", msg),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sandbox_init() {
        let mut sandbox = Sandbox::new();
        assert!(sandbox.init().await.is_ok());
        assert!(sandbox.is_initialized());
    }

    #[tokio::test]
    async fn test_python_packages() {
        let sandbox = Sandbox::new();
        let result = python::install_packages(&sandbox, &["requests"]).await;
        assert!(result.is_ok());
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_full_workflow() {
    // Initialize sandbox
    let mut sandbox = Sandbox::new();
    sandbox.init().await.unwrap();

    // Install packages
    python::install_packages(&sandbox, &["requests"]).await.unwrap();

    // Execute script
    let script = r#"
import requests
print("Success!")
"#;
    
    let script_path = Path::new("/tmp/test_script.py");
    std::fs::write(script_path, script).unwrap();
    
    let output = python::execute_script(&sandbox, script_path, &[]).await.unwrap();
    assert!(output.status.success());
}
```

## Best Practices

### 1. Initialize Once

Initialize the sandbox once at startup:

```rust
// At application startup
let mut sandbox = Sandbox::new();
sandbox.init().await?;

// Reuse sandbox throughout application lifetime
```

### 2. Handle Missing Runtimes

Language runtimes may not be installed:

```rust
if let Err(e) = python::init_environment(&sandbox).await {
    tracing::warn!("Python not available: {}", e);
    // Continue without Python support
}
```

### 3. Cleanup

Clean up sandbox when no longer needed:

```rust
sandbox.clean()?;
```

### 4. Status Checks

Check sandbox status before use:

```rust
if !sandbox.is_initialized() {
    sandbox.init().await?;
}

let status = sandbox.status();
if status.python_ready {
    // Use Python
}
```

## Performance Considerations

### Initialization

- **First time**: 2-5 minutes (downloads packages)
- **Subsequent**: Instant (already initialized)

### Package Installation

- **Cache**: Packages are cached in sandbox
- **Network**: Only downloads when needed
- **Parallel**: Install multiple languages in parallel

### Script Execution

- **Overhead**: ~10ms per execution
- **No caching**: Scripts execute each time
- **Isolation**: Each execution is isolated

## Security

### Isolation Level

- ✅ **Process isolation**: Separate processes
- ✅ **Environment isolation**: Separate env vars
- ✅ **Package isolation**: Separate dependencies
- ⚠️ **Network access**: Not restricted
- ⚠️ **File system**: Host file system access

### Recommendations

1. **Use containers** for maximum isolation
2. **Run as unprivileged user**
3. **Apply resource limits** (cgroups)
4. **Restrict network access** (firewall)
5. **Monitor execution** (logging)

## Troubleshooting

### Sandbox Not Initialized

```rust
if !sandbox.is_initialized() {
    sandbox.init().await?;
}
```

### Package Installation Failed

```rust
match python::install_packages(&sandbox, &["requests"]).await {
    Ok(_) => println!("Installed"),
    Err(e) => {
        eprintln!("Failed to install: {}", e);
        // Retry or use alternative package
    }
}
```

### Runtime Not Found

```rust
// Check if runtime is available before initializing
let has_python = Command::new("python3")
    .arg("--version")
    .output()
    .is_ok();

if has_python {
    python::init_environment(&sandbox).await?;
}
```

## Future Enhancements

- [ ] Binary caching for compiled languages
- [ ] Parallel package installation
- [ ] Package version locking
- [ ] Sandbox snapshots/restore
- [ ] Container integration
- [ ] WebAssembly runtime
- [ ] Lua scripting engine

## Related Modules

- `engine` - Template execution engines
- `executor` - Job execution coordinator
- `template` - Template interface
- `types` - Core types

## External Dependencies

- `tokio` - Async runtime
- `serde` - Serialization
- `serde_yaml` - YAML configuration
- `dirs` - User directories
- `tracing` - Logging

## Documentation

- [User Guide](../../SANDBOX_GUIDE.md)
- [Implementation Details](../../SANDBOX_IMPLEMENTATION.md)
- [CLI Reference](../../CLI_REFERENCE.md)
