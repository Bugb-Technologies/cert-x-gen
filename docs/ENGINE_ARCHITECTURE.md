# 🏗️ Template Engine Architecture

## Modular Design Overview

CERT-X-GEN implements a **polyglot template engine architecture** that supports **12 programming languages** for maximum flexibility in security scanning template development.

### Engine Hierarchy

```
TemplateEngine trait (interface)
    ├── Interpreted Engines
    │   ├── PythonEngine      (.py)       → python3/python
    │   ├── JavaScriptEngine  (.js, .mjs) → node
    │   ├── RubyEngine        (.rb)       → ruby
    │   ├── PerlEngine        (.pl)       → perl
    │   ├── PhpEngine         (.php)      → php
    │   └── ShellEngine       (.sh)       → bash/sh
    │
    ├── Compiled Engines
    │   ├── RustEngine        (.rs)       → rustc → binary
    │   ├── CEngine           (.c)        → gcc/clang → binary
    │   ├── CppEngine         (.cpp)      → g++/clang++ → binary
    │   ├── JavaEngine        (.java)     → javac → .class
    │   └── GoEngine          (.go)       → go build → binary
    │
    └── Declarative Engine
        └── YamlTemplateEngine (.yaml, .yml) → built-in parser
```

---

## File Organization

### Engine Module Structure

```
src/engine/
├── mod.rs              # Engine registry & exports
├── common.rs           # Shared utilities
├── yaml.rs             # YAML declarative engine
├── python.rs           # Python interpreted engine
├── javascript.rs       # JavaScript/Node.js engine
├── rust.rs             # Rust compiled engine
├── shell.rs            # Shell script engine
├── c.rs                # C compiled engine
├── cpp.rs              # C++ compiled engine
├── java.rs             # Java compiled engine
├── go.rs               # Go compiled engine
├── ruby.rs             # Ruby interpreted engine
├── perl.rs             # Perl interpreted engine
└── php.rs              # PHP interpreted engine
```

### Template Directory Structure

```
templates/
├── skeleton/           # Template skeletons for all languages
│   ├── c-template-skeleton.c
│   ├── cpp-template-skeleton.cpp
│   ├── java-template-skeleton.java
│   ├── go-template-skeleton.go
│   ├── python-template-skeleton.py
│   ├── javascript-template-skeleton.js
│   ├── rust-template-skeleton.rs
│   ├── shell-template-skeleton.sh
│   ├── ruby-template-skeleton.rb
│   ├── perl-template-skeleton.pl
│   ├── php-template-skeleton.php
│   └── yaml-template-skeleton.yaml
├── c/                  # C templates
├── cpp/                # C++ templates
├── java/               # Java templates
├── go/                 # Go templates
├── python/             # Python templates
├── javascript/         # JavaScript templates
├── rust/               # Rust templates
├── shell/              # Shell templates
├── ruby/               # Ruby templates
├── perl/               # Perl templates
├── php/                # PHP templates
└── yaml/               # YAML templates
    ├── http/           # HTTP-based templates
    └── network/        # Network service templates
```

---

## Engine Implementation Details

### 1. Common Utilities (`src/engine/common.rs`)

Shared functionality across all engines:

- **`build_env_vars()`** - Build environment variables for templates
- **`parse_findings()`** - Parse JSON output from templates
- **`create_metadata()`** - Generate template metadata from file
- **`get_ports_to_scan()`** - Extract port configuration from context

### 2. Interpreted Language Engines

#### Python Engine (`src/engine/python.rs`)
- **Interpreter**: `python3` (fallback to `python`)
- **Extension**: `.py`
- **Libraries**: `requests`, `urllib`, `json`
- **Execution**: Direct script execution with environment variables

#### JavaScript Engine (`src/engine/javascript.rs`)
- **Interpreter**: `node`
- **Extension**: `.js`, `.mjs`
- **Libraries**: Built-in `http`, `https`, `fs`
- **Execution**: Direct script execution with environment variables

#### Ruby Engine (`src/engine/ruby.rs`)
- **Interpreter**: `ruby`
- **Extension**: `.rb`
- **Libraries**: `net/http`, `json`
- **Execution**: Direct script execution with environment variables

#### Perl Engine (`src/engine/perl.rs`)
- **Interpreter**: `perl`
- **Extension**: `.pl`
- **Libraries**: `LWP::UserAgent`, `JSON`
- **Execution**: Direct script execution with environment variables

#### PHP Engine (`src/engine/php.rs`)
- **Interpreter**: `php`
- **Extension**: `.php`
- **Libraries**: Built-in `curl`, `json`
- **Execution**: Direct script execution with environment variables

#### Shell Engine (`src/engine/shell.rs`)
- **Interpreter**: `bash` (fallback to `sh`)
- **Extension**: `.sh`
- **Tools**: `curl`, `wget`, `nc`, `jq`
- **Execution**: Direct script execution with environment variables

### 3. Compiled Language Engines

#### C Engine (`src/engine/c.rs`)
- **Compiler**: `gcc` (fallback to `clang`)
- **Extension**: `.c`
- **Compilation**: `gcc -O2 -std=c11 -lcurl -ljson-c -o binary source.c`
- **Cache Directory**: `/tmp/cert-x-gen-cache/c/`
- **Execution**: Compiled binary with environment variables

#### C++ Engine (`src/engine/cpp.rs`)
- **Compiler**: `g++` (fallback to `clang++`)
- **Extension**: `.cpp`, `.cc`, `.cxx`
- **Compilation**: `g++ -O2 -std=c++17 -lcurl -o binary source.cpp`
- **Cache Directory**: `/tmp/cert-x-gen-cache/cpp/`
- **Execution**: Compiled binary with environment variables

#### Java Engine (`src/engine/java.rs`)
- **Compiler**: `javac`
- **Runtime**: `java`
- **Extension**: `.java`
- **Compilation**: `javac -d cache_dir source.java`
- **Cache Directory**: `/tmp/cert-x-gen-cache/java/`
- **Execution**: `java -cp cache_dir ClassName`

#### Go Engine (`src/engine/go.rs`)
- **Compiler**: `go build`
- **Extension**: `.go`
- **Compilation**: `go build -o binary source.go`
- **Cache Directory**: `/tmp/cert-x-gen-cache/go/`
- **Execution**: Compiled binary with environment variables

#### Rust Engine (`src/engine/rust.rs`)
- **Compiler**: `rustc` (via `cargo`)
- **Extension**: `.rs`
- **Compilation**: `cargo build --release --bin template_name`
- **Cache Directory**: `/tmp/cert-x-gen-cache/rust/`
- **Execution**: Compiled binary with environment variables

### 4. Declarative Engine

#### YAML Engine (`src/engine/yaml.rs`)
- **Parser**: Built-in YAML parser
- **Extension**: `.yaml`, `.yml`
- **Features**: HTTP requests, network probes, flow control
- **Execution**: Native Rust implementation

---

## Communication Protocol

### Environment Variables

All templates receive configuration via environment variables:

```bash
# Target configuration
CERT_X_GEN_TARGET_HOST=example.com
CERT_X_GEN_TARGET_PORT=80
CERT_X_GEN_ADD_PORTS=8080,9090,3000
CERT_X_GEN_OVERRIDE_PORTS=80,443

# Context information
CERT_X_GEN_MODE=scan
CERT_X_GEN_TEMPLATE_ID=redis-unauthenticated
CERT_X_GEN_TEMPLATE_NAME="Redis Unauthenticated Access"
CERT_X_GEN_TEMPLATE_AUTHOR="CERT-X-GEN Team"

# Additional configuration
CERT_X_GEN_TIMEOUT=30
CERT_X_GEN_RETRY_COUNT=3
CERT_X_GEN_USER_AGENT="CERT-X-GEN/1.0"
```

### JSON Output Format

All templates must output findings in this simplified JSON format:

```json
{
  "findings": [
    {
      "id": "redis-unauthenticated-access",
      "name": "Redis Unauthenticated Access",
      "severity": "critical",
      "description": "Redis instance is accessible without authentication",
      "evidence": {
        "type": "http_response",
        "data": "PONG"
      },
      "tags": ["redis", "unauthenticated", "database"],
      "cwe": "CWE-306",
      "references": ["https://redis.io/topics/security"]
    }
  ]
}
```

---

## Engine Registration

Engines are registered in `src/core.rs`:

```rust
impl CertXGen {
    pub async fn new(config: Config) -> Result<Self> {
        let mut template_loader = TemplateLoader::new();
        
        // Register interpreted language engines
        template_loader.register_engine(Box::new(crate::engine::PythonEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::JavaScriptEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::RubyEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::PerlEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::PhpEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::ShellEngine::new()));
        
        // Register compiled language engines
        template_loader.register_engine(Box::new(crate::engine::RustEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::CEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::CppEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::JavaEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::GoEngine::new()));
        
        // Register declarative engine
        template_loader.register_engine(Box::new(crate::engine::YamlTemplateEngine::new()));
        
        // ... rest of initialization
    }
}
```

---

## Template Interface

### TemplateEngine Trait

All engines implement the `TemplateEngine` trait:

```rust
#[async_trait]
pub trait TemplateEngine: Send + Sync {
    fn name(&self) -> &str;
    fn language(&self) -> TemplateLanguage;
    fn supports_file(&self, path: &Path) -> bool;
    
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>>;
    async fn execute_template(
        &self,
        template: &dyn Template,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>>;
}
```

### Template Trait

Individual templates implement the `Template` trait:

```rust
pub trait Template: Send + Sync {
    fn metadata(&self) -> &TemplateMetadata;
    fn file_path(&self) -> &Path;
    fn language(&self) -> TemplateLanguage;
}
```

---

## Compilation Caching

### Compiled Language Caching

Compiled languages (C, C++, Java, Go, Rust) implement intelligent caching:

1. **Source Hash**: Calculate SHA-256 hash of source file
2. **Cache Key**: `{language}/{hash}`
3. **Cache Check**: Look for existing binary/class file
4. **Compilation**: Only compile if cache miss
5. **Cache Storage**: Store in `/tmp/cert-x-gen-cache/{language}/`

### Cache Invalidation

- **Source Change**: Hash mismatch triggers recompilation
- **Dependency Change**: Compiler version changes invalidate cache
- **Manual Cleanup**: `make clean` removes all cached binaries

---

## Error Handling

### Graceful Degradation

- **Missing Compiler**: Engine reports as unavailable, skips templates
- **Compilation Failure**: Log error, continue with other templates
- **Runtime Error**: Capture stderr, return error finding
- **Timeout**: Kill process, return timeout finding

### Error Types

```rust
pub enum EngineError {
    CompilerNotFound(String),
    CompilationFailed(String),
    ExecutionFailed(String),
    Timeout,
    InvalidOutput(String),
}
```

---

## Performance Considerations

### Interpreted Languages
- **Startup Time**: Higher due to interpreter initialization
- **Memory Usage**: Higher due to interpreter overhead
- **Execution Speed**: Slower but more flexible

### Compiled Languages
- **Startup Time**: Lower after initial compilation
- **Memory Usage**: Lower due to native binaries
- **Execution Speed**: Faster, especially for complex operations

### YAML Engine
- **Startup Time**: Lowest (native Rust)
- **Memory Usage**: Lowest
- **Execution Speed**: Fastest for simple operations

---

## Testing Strategy

### Unit Tests
- **Engine Registration**: Verify all engines are registered
- **File Support**: Test file extension detection
- **Template Loading**: Test metadata extraction
- **Environment Variables**: Test variable passing

### Integration Tests
- **End-to-End Execution**: Test complete template execution
- **Compilation Caching**: Verify cache behavior
- **Error Handling**: Test failure scenarios
- **Multi-Language**: Test templates from all languages

### Performance Tests
- **Compilation Time**: Measure compilation overhead
- **Execution Time**: Compare language performance
- **Memory Usage**: Monitor resource consumption
- **Cache Efficiency**: Measure cache hit rates

---

## Best Practices

### Template Development
1. **Use Appropriate Language**: Choose based on requirements
2. **Follow Skeleton Structure**: Use provided skeletons as starting points
3. **Handle Errors Gracefully**: Always check for failures
4. **Output Valid JSON**: Ensure proper JSON formatting
5. **Use Environment Variables**: Don't hardcode configuration

### Engine Selection
- **Simple HTTP Requests**: YAML or Python
- **Complex Logic**: Python or JavaScript
- **Performance Critical**: Rust, C, or Go
- **System Integration**: Shell scripts
- **Rapid Prototyping**: Python or Shell

### Performance Optimization
- **Use Compiled Languages**: For frequently executed templates
- **Minimize Dependencies**: Reduce compilation time
- **Cache Effectively**: Leverage compilation caching
- **Profile Templates**: Identify bottlenecks

---

## Future Enhancements

### Planned Features
- **WASM Support**: WebAssembly template execution
- **Plugin System**: Dynamic engine loading
- **Remote Execution**: Distributed template execution
- **Template Marketplace**: Community template sharing

### Language Additions
- **C#**: .NET template support
- **Kotlin**: JVM-based templates
- **Swift**: macOS/iOS template support
- **Lua**: Lightweight scripting support

---

## Conclusion

The CERT-X-GEN template engine architecture provides unprecedented flexibility in security scanning template development. By supporting 12 programming languages, developers can choose the most appropriate tool for their specific use case while maintaining a unified interface and communication protocol.

The modular design ensures maintainability, the compilation caching system optimizes performance, and the comprehensive error handling provides reliability. This architecture positions CERT-X-GEN as the most flexible and powerful polyglot security scanning framework available.