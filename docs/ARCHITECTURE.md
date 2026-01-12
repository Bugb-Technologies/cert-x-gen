# 🏗️ CERT-X-GEN Architecture

**Technical architecture and design documentation for CERT-X-GEN**

This document provides a comprehensive overview of the CERT-X-GEN system architecture, design decisions, and implementation details.

---

## 📋 Table of Contents

- [System Overview](#system-overview)
- [Core Components](#core-components)
- [Polyglot Engine Architecture](#polyglot-engine-architecture)
- [Template Search System](#template-search-system)
- [Data Flow](#data-flow)
- [Template System](#template-system)
- [Plugin System](#plugin-system)
- [Configuration](#configuration)
- [Error Handling](#error-handling)
- [Performance](#performance)
- [Security Considerations](#security-considerations)

---

## 🎯 System Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Interface                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │    Scan     │ │   Search    │ │  Template   │           │
│  │   Command   │ │   Command   │ │  Command    │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core Engine                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   CertXGen  │ │  Executor   │ │  Scheduler  │           │
│  │   (Main)    │ │             │ │             │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                Template Engine System                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   Loader    │ │   Search    │ │   Engines   │           │
│  │             │ │   Engine    │ │  (12 langs) │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Template Execution                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Interpreted │ │  Compiled   │ │ Declarative │           │
│  │  Languages  │ │  Languages  │ │   (YAML)    │           │
│  │ (6 langs)   │ │  (5 langs)  │ │             │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Polyglot Architecture** - Support for 12 programming languages
2. **Modular Design** - Clean separation of concerns
3. **Unified Interface** - Consistent API across all engines
4. **Performance Optimization** - Compilation caching and parallel execution
5. **Extensibility** - Easy addition of new languages and features
6. **Security First** - Built-in security considerations

---

## 🔧 Core Components

### 1. CertXGen (Main Engine)

**Location**: `src/core.rs`

The central orchestrator that coordinates all scanning operations:

```rust
pub struct CertXGen {
    config: Arc<Config>,
    template_loader: Arc<TemplateLoader>,
    executor: Arc<Executor>,
    scheduler: Arc<RwLock<Scheduler>>,
}
```

**Responsibilities:**
- Initialize and configure all subsystems
- Coordinate template loading and execution
- Manage scanning workflows
- Handle error propagation and recovery

### 2. TemplateLoader

**Location**: `src/template.rs`

Manages template discovery, loading, and engine registration:

```rust
pub struct TemplateLoader {
    engines: Vec<Box<dyn TemplateEngine>>,
}
```

**Responsibilities:**
- Register template engines for all 12 languages
- Discover templates in the filesystem
- Load template metadata and content
- Provide template filtering and selection

### 3. Executor

**Location**: `src/executor.rs`

Handles the actual execution of templates:

```rust
pub struct Executor {
    config: Arc<Config>,
    network_client: Arc<NetworkClient>,
    session_manager: Arc<SessionManager>,
    flow_executor: Arc<FlowExecutor>,
    semaphore: Arc<Semaphore>,
}
```

**Responsibilities:**
- Execute templates with proper environment setup
- Manage concurrent template execution
- Handle timeouts and resource limits
- Collect and aggregate findings

### 4. Scheduler

**Location**: `src/scheduler.rs`

Manages resource allocation and execution scheduling:

```rust
pub struct Scheduler {
    config: Arc<Config>,
    priority_queue: BinaryHeap<PrioritizedTemplate>,
}
```

**Responsibilities:**
- Prioritize template execution
- Manage resource constraints
- Handle rate limiting
- Optimize execution order

---

## 🌐 Polyglot Engine Architecture

### Engine Hierarchy

```
TemplateEngine trait (interface)
    ├── Interpreted Engines (6)
    │   ├── PythonEngine      (.py)       → python3/python
    │   ├── JavaScriptEngine  (.js, .mjs) → node
    │   ├── RubyEngine        (.rb)       → ruby
    │   ├── PerlEngine        (.pl)       → perl
    │   ├── PhpEngine         (.php)      → php
    │   └── ShellEngine       (.sh)       → bash/sh
    │
    ├── Compiled Engines (5)
    │   ├── RustEngine        (.rs)       → rustc → binary
    │   ├── CEngine           (.c)        → gcc/clang → binary
    │   ├── CppEngine         (.cpp)      → g++/clang++ → binary
    │   ├── JavaEngine        (.java)     → javac → .class
    │   └── GoEngine          (.go)       → go build → binary
    │
    └── Declarative Engine (1)
        └── YamlTemplateEngine (.yaml, .yml) → built-in parser
```

### Engine Implementation

Each engine implements the `TemplateEngine` trait:

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

### Common Utilities

**Location**: `src/engine/common.rs`

Shared functionality across all engines:

- **`build_env_vars()`** - Build environment variables for templates
- **`parse_findings()`** - Parse JSON output from templates
- **`create_metadata()`** - Generate template metadata from file
- **`get_ports_to_scan()`** - Extract port configuration from context

### Compilation Caching

Compiled languages implement intelligent caching:

1. **Source Hash**: Calculate SHA-256 hash of source file
2. **Cache Key**: `{language}/{hash}`
3. **Cache Check**: Look for existing binary/class file
4. **Compilation**: Only compile if cache miss
5. **Cache Storage**: Store in `/tmp/cert-x-gen-cache/{language}/`

---

## 🔍 Template Search System

### Search Engine Architecture

**Location**: `src/search.rs`

The search system provides powerful template discovery capabilities:

```rust
pub struct TemplateSearchEngine {
    templates: Vec<SearchResult>,
    index: HashMap<String, Vec<usize>>, // word -> template indices
    content_index: HashMap<String, Vec<usize>>, // word -> template indices (content)
}
```

### Search Features

1. **Full-Text Search** - Search in names, descriptions, tags, and content
2. **Regex Support** - Advanced pattern matching
3. **Filtering** - By language, severity, tags, author, CWE
4. **Sorting** - By relevance, name, language, severity, date
5. **Multiple Output Formats** - Table, JSON, YAML, CSV, List, Detailed

### Search Integration

The search system integrates seamlessly with the scanning workflow:

```bash
# Use search results in scanning
TEMPLATES=$(cxg search --query "redis" --ids-only | tr '\n' ',')
cxg scan --target example.com --templates "$TEMPLATES"
```

---

## 📊 Data Flow

### 1. Template Discovery

```
File System → TemplateLoader → Engine Selection → Template Loading
     │              │                │                    │
     ▼              ▼                ▼                    ▼
templates/     File Extension    Engine Registry    Template Object
```

### 2. Template Execution

```
Template → Environment Setup → Execution → Output Parsing → Findings
    │              │              │            │              │
    ▼              ▼              ▼            ▼              ▼
Metadata      Env Variables   Process/HTTP   JSON Parse    Finding[]
```

### 3. Search Flow

```
Query → Search Engine → Index Lookup → Filtering → Sorting → Results
  │           │              │            │          │         │
  ▼           ▼              ▼            ▼          ▼         ▼
Text      Template DB    Word Index    Criteria   Algorithm  SearchResult[]
```

---

## 📝 Template System

### Template Structure

All templates follow a unified structure:

1. **Metadata** - Template information (ID, name, author, severity)
2. **Environment Variables** - Configuration from environment
3. **Scanning Logic** - Security checks and probes
4. **JSON Output** - Standardized findings format

### Communication Protocol

Templates communicate via environment variables and JSON output:

#### Environment Variables
```bash
CERT_X_GEN_TARGET_HOST=example.com
CERT_X_GEN_TARGET_PORT=80
CERT_X_GEN_ADD_PORTS=8080,9090
CERT_X_GEN_TEMPLATE_ID=my-template
CERT_X_GEN_TEMPLATE_NAME="My Template"
```

#### JSON Output Format
```json
{
  "findings": [
    {
      "id": "vulnerability-id",
      "name": "Vulnerability Name",
      "severity": "critical",
      "description": "Description of the vulnerability",
      "evidence": {
        "type": "http_response",
        "data": "Evidence data"
      },
      "tags": ["tag1", "tag2"],
      "cwe": "CWE-89"
    }
  ]
}
```

### Template Types

#### 1. Interpreted Templates
- **Execution**: Direct interpreter execution
- **Performance**: Slower startup, flexible
- **Languages**: Python, JavaScript, Ruby, Perl, PHP, Shell

#### 2. Compiled Templates
- **Execution**: Compile → cache → execute
- **Performance**: Faster execution, compilation overhead
- **Languages**: Rust, C, C++, Java, Go

#### 3. Declarative Templates
- **Execution**: Native parsing and execution
- **Performance**: Fastest for simple operations
- **Languages**: YAML

---

## 🔌 Plugin System

### Plugin Architecture

**Location**: `src/plugin.rs`

The plugin system allows for extensibility:

```rust
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn on_finding(&self, finding: &Finding) -> Result<()>;
    fn on_scan_start(&self, scan_id: Uuid) -> Result<()>;
    fn on_scan_complete(&self, results: &ScanResults) -> Result<()>;
    fn on_error(&self, error: &Error) -> Result<()>;
}
```

### Built-in Plugins

1. **LoggingPlugin** - Structured logging
2. **WebhookPlugin** - HTTP webhook notifications
3. **MetricsPlugin** - Performance metrics collection

---

## ⚙️ Configuration

### Configuration System

**Location**: `src/config.rs`

Supports multiple configuration formats:

```rust
pub struct Config {
    pub targets: Vec<Target>,
    pub templates: TemplateConfig,
    pub execution: ExecutionConfig,
    pub output: OutputConfig,
    pub network: NetworkConfig,
}
```

### Configuration Sources

1. **Command Line** - CLI arguments
2. **Configuration Files** - YAML, TOML, JSON
3. **Environment Variables** - Runtime configuration
4. **Defaults** - Sensible defaults

---

## 🚨 Error Handling

### Error Hierarchy

```rust
pub enum Error {
    Config(ConfigError),
    Network(NetworkError),
    Template(TemplateError),
    Execution(ExecutionError),
    Output(OutputError),
    Plugin(PluginError),
}
```

### Error Recovery

1. **Graceful Degradation** - Continue with available templates
2. **Retry Logic** - Automatic retry for transient failures
3. **Error Reporting** - Detailed error information
4. **Logging** - Comprehensive error logging

---

## ⚡ Performance

### Optimization Strategies

1. **Compilation Caching** - Avoid recompilation of templates
2. **Parallel Execution** - Concurrent template execution
3. **Resource Management** - Memory and CPU limits
4. **Connection Pooling** - Reuse HTTP connections
5. **Lazy Loading** - Load templates on demand

### Performance Metrics

- **Template Loading Time** - Time to load and parse templates
- **Compilation Time** - Time to compile templates (compiled languages)
- **Execution Time** - Time to execute templates
- **Memory Usage** - Memory consumption per template
- **Cache Hit Rate** - Compilation cache efficiency

---

## 🔒 Security Considerations

### Security Measures

1. **Input Validation** - Sanitize all inputs
2. **Sandboxing** - Isolate template execution
3. **Resource Limits** - Prevent resource exhaustion
4. **Secure Defaults** - Safe configuration defaults
5. **Error Handling** - Don't leak sensitive information

### Template Security

1. **Code Review** - Review all template code
2. **Dependency Management** - Manage external dependencies
3. **Execution Isolation** - Isolate template execution
4. **Output Validation** - Validate template output
5. **Access Control** - Control template access

---

## 🚀 Future Enhancements

### Planned Features

1. **WASM Support** - WebAssembly template execution
2. **Plugin Marketplace** - Community plugin sharing
3. **Remote Execution** - Distributed template execution
4. **Template Marketplace** - Community template sharing
5. **AI Integration** - AI-powered template generation

### Language Additions

1. **C#** - .NET template support
2. **Kotlin** - JVM-based templates
3. **Swift** - macOS/iOS template support
4. **Lua** - Lightweight scripting support

---

## 📚 Related Documentation

- **[ENGINE_ARCHITECTURE.md](ENGINE_ARCHITECTURE.md)** - Detailed engine architecture
- **[ENGINES.md](ENGINES.md)** - Language-specific documentation
- **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Complete usage guide
- **[TEMPLATE_REGISTRY.md](templates/TEMPLATE_REGISTRY.md)** - Template catalog

---

## 🎉 Conclusion

CERT-X-GEN's architecture is designed for maximum flexibility, performance, and extensibility. The polyglot template engine system supports 12 programming languages, providing unprecedented flexibility in security scanning template development.

The modular design ensures maintainability, the compilation caching system optimizes performance, and the comprehensive error handling provides reliability. This architecture positions CERT-X-GEN as the most flexible and powerful polyglot security scanning framework available.

The addition of the template search system further enhances the user experience by providing powerful template discovery and exploration capabilities, making it easy to find and use the right templates for any security scanning scenario.