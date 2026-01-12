# Template Engines

This directory contains all template engine implementations for CERT-X-GEN. Each engine is responsible for loading, validating, and executing security templates written in different languages.

## Directory Structure

```
engine/
├── mod.rs              # Main module with re-exports
├── common.rs           # Shared utilities and helpers
├── yaml/               # YAML template engine
│   ├── mod.rs
│   └── README.md
├── python/             # Python template engine
│   ├── mod.rs
│   └── README.md
├── javascript/         # JavaScript/Node.js template engine
│   ├── mod.rs
│   └── README.md
├── rust/               # Rust template engine
│   ├── mod.rs
│   └── README.md
├── shell/              # Shell script template engine
│   ├── mod.rs
│   └── README.md
├── c/                  # C template engine
│   ├── mod.rs
│   └── README.md
├── cpp/                # C++ template engine
│   ├── mod.rs
│   └── README.md
├── java/               # Java template engine
│   ├── mod.rs
│   └── README.md
├── go/                 # Go template engine
│   ├── mod.rs
│   └── README.md
├── ruby/               # Ruby template engine
│   ├── mod.rs
│   └── README.md
├── perl/               # Perl template engine
│   ├── mod.rs
│   └── README.md
└── php/                # PHP template engine
    ├── mod.rs
    └── README.md
```

## Supported Engines

### Declarative Engines

#### YAML (`yaml/`)
- **Best for:** Simple HTTP/network checks, declarative templates
- **Protocols:** HTTP, HTTPS, TCP, UDP
- **Features:** Matchers, extractors, flows, no code required
- **Use when:** You want simple, maintainable templates without programming

### Scripting Engines

#### Python (`python/`)
- **Best for:** Complex logic, data processing, ML-based detection
- **Protocols:** All (via Python libraries)
- **Features:** Full Python runtime, extensive library ecosystem
- **Use when:** You need complex logic or Python-specific libraries

#### JavaScript (`javascript/`)
- **Best for:** Web-based checks, JSON APIs, async operations
- **Protocols:** All (via Node.js)
- **Features:** Async/await, npm packages, modern JavaScript
- **Use when:** You prefer JavaScript or need Node.js libraries

#### Ruby (`ruby/`)
- **Best for:** Web scraping, text processing, metasploit integration
- **Protocols:** All (via Ruby gems)
- **Features:** Full Ruby runtime, gem ecosystem
- **Use when:** You prefer Ruby or need Ruby-specific tools

#### Perl (`perl/`)
- **Best for:** Text processing, regex-heavy checks, legacy systems
- **Protocols:** All (via CPAN modules)
- **Features:** Powerful regex, CPAN modules
- **Use when:** You need Perl's text processing or legacy compatibility

#### PHP (`php/`)
- **Best for:** Web application checks, CMS vulnerabilities
- **Protocols:** All (via PHP extensions)
- **Features:** Web-focused libraries, Composer packages
- **Use when:** Testing PHP applications or need PHP-specific tools

#### Shell (`shell/`)
- **Best for:** System commands, CLI tool integration, quick checks
- **Protocols:** All (via shell commands)
- **Features:** Direct system access, pipe commands
- **Use when:** You want to use existing CLI tools

### Compiled Engines

#### Rust (`rust/`)
- **Best for:** High-performance checks, memory safety, low-level operations
- **Protocols:** All (via Rust crates)
- **Features:** Zero-cost abstractions, memory safety, speed
- **Use when:** You need maximum performance or memory safety

#### C (`c/`)
- **Best for:** Low-level network operations, performance-critical checks
- **Protocols:** All (via C libraries)
- **Features:** Direct system access, maximum performance
- **Use when:** You need low-level control or C-specific libraries

#### C++ (`cpp/`)
- **Best for:** Complex algorithms, OOP-based checks, performance
- **Protocols:** All (via C++ libraries)
- **Features:** STL, templates, OOP, performance
- **Use when:** You need C++ features or libraries

#### Java (`java/`)
- **Best for:** Enterprise checks, JVM-based applications
- **Protocols:** All (via Java libraries)
- **Features:** JVM ecosystem, Maven/Gradle packages
- **Use when:** Testing Java applications or need JVM libraries

#### Go (`go/`)
- **Best for:** Concurrent checks, cloud-native applications
- **Protocols:** All (via Go packages)
- **Features:** Goroutines, simple concurrency, fast compilation
- **Use when:** You need concurrency or prefer Go's simplicity

## Engine Interface

All engines implement the `TemplateEngine` trait:

```rust
#[async_trait]
pub trait TemplateEngine: Send + Sync {
    /// Load a template from a file
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>>;
    
    /// Validate a template
    async fn validate_template(&self, template: &dyn Template) -> Result<()>;
    
    /// Execute a template against a target
    async fn execute_template(
        &self,
        template: &dyn Template,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>>;
    
    /// Get supported protocols
    fn supported_protocols(&self) -> Vec<Protocol>;
    
    /// Get engine name
    fn name(&self) -> &str;
    
    /// Check if engine supports a file
    fn supports_file(&self, path: &Path) -> bool;
}
```

## Adding a New Engine

To add a new template engine:

1. **Create directory:** `mkdir src/engine/newlang/`
2. **Create mod.rs:** Implement the `TemplateEngine` trait
3. **Update mod.rs:** Add module declaration and re-export
4. **Create README.md:** Document the engine
5. **Add tests:** Create integration tests
6. **Update docs:** Add to this README

### Example:

```rust
// src/engine/newlang/mod.rs
use crate::template::TemplateEngine;

pub struct NewLangEngine {
    // Engine state
}

#[async_trait]
impl TemplateEngine for NewLangEngine {
    // Implement trait methods
}
```

```rust
// src/engine/mod.rs
pub mod newlang;
pub use newlang::NewLangEngine;
```

## Common Utilities

The `common.rs` file contains shared utilities used by multiple engines:

- Template metadata parsing
- File I/O helpers
- Error handling utilities
- Protocol detection
- Matcher evaluation helpers

## Performance Considerations

### Engine Startup Time

- **YAML:** Instant (no runtime)
- **Shell:** Fast (shell already available)
- **Python/Ruby/Perl/PHP:** Medium (interpreter startup)
- **JavaScript:** Medium (Node.js startup)
- **Rust/C/C++/Java/Go:** Slow (compilation required)

### Execution Speed

- **Compiled (Rust/C/C++/Go):** Fastest
- **YAML:** Fast (native Rust execution)
- **JavaScript/Java:** Fast (JIT compilation)
- **Python/Ruby/Perl/PHP:** Medium (interpreted)
- **Shell:** Variable (depends on commands)

### Memory Usage

- **YAML:** Minimal (no separate runtime)
- **Shell:** Low (shell process)
- **Compiled:** Low (native code)
- **Scripting:** Medium-High (interpreter + libraries)

## Security Considerations

### Sandboxing

- **YAML:** Safe (declarative, no code execution)
- **Scripting engines:** Requires sandboxing for untrusted templates
- **Compiled engines:** Requires code review before compilation

### Resource Limits

All engines should implement:
- Timeout limits
- Memory limits
- Network rate limiting
- Concurrent execution limits

## Testing

Each engine should have:
- Unit tests for core functionality
- Integration tests with sample templates
- Performance benchmarks
- Security tests for sandboxing

## Future Enhancements

- **Lua Engine:** Lightweight scripting
- **WebAssembly Engine:** Portable, sandboxed execution
- **GraphQL Engine:** API-specific checks
- **SQL Engine:** Database-specific checks
- **Custom DSL:** Domain-specific language for security checks
