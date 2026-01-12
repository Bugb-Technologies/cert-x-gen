//! Prompt engineering system for CERT-X-GEN template generation
//!
//! This module provides intelligent prompt building using embedded skeleton templates.
//! All skeleton templates are embedded at compile-time, making them always available
//! regardless of the filesystem state.

use crate::types::TemplateLanguage;
use std::collections::HashMap;

/// Skeleton templates embedded at compile-time
/// These are always available and don't require filesystem access
mod embedded_skeletons {
    // Embed all 11 skeleton templates at compile time
    // These will be included in the binary, ensuring they're always available
    
    pub const PYTHON: &str = include_str!("../../templates/skeleton/python-template-skeleton.py");
    pub const JAVASCRIPT: &str = include_str!("../../templates/skeleton/javascript-template-skeleton.js");
    pub const RUST: &str = include_str!("../../templates/skeleton/rust-template-skeleton.rs");
    pub const C: &str = include_str!("../../templates/skeleton/c-template-skeleton.c");
    pub const CPP: &str = include_str!("../../templates/skeleton/cpp-template-skeleton.cpp");
    pub const JAVA: &str = include_str!("../../templates/skeleton/java-template-skeleton.java");
    pub const GO: &str = include_str!("../../templates/skeleton/go-template-skeleton.go");
    pub const RUBY: &str = include_str!("../../templates/skeleton/ruby-template-skeleton.rb");
    pub const PERL: &str = include_str!("../../templates/skeleton/perl-template-skeleton.pl");
    pub const PHP: &str = include_str!("../../templates/skeleton/php-template-skeleton.php");
    pub const SHELL: &str = include_str!("../../templates/skeleton/shell-template-skeleton.sh");
}

/// YAML example templates for reference in prompts
/// These are hardcoded since they're small and serve as examples
#[allow(dead_code)]
mod yaml_examples {
    pub const YAML_SKELETON: &str = include_str!("../../templates/skeleton/yaml-template-skeleton.yaml");

    pub const REDIS_UNAUTH: &str = r#"id: redis-unauth
info:
  name: Redis Unauthenticated Access
  author: cert-x-gen
  severity: high
  description: Detects Redis instances running without authentication
  references:
    - https://redis.io/topics/security
  tags:
    - redis
    - database
    - unauth

protocol: tcp
port: 6379

inputs:
  - data: "INFO\r\n"
    type: text

matchers:
  - type: word
    words:
      - "redis_version"
      - "connected_clients"
    condition: and

  - type: word
    words:
      - "NOAUTH Authentication required"
    condition: not

extract:
  - redis_version
  - os
  - redis_mode
  - connected_clients
  - used_memory_human"#;

    pub const MEMCACHED_EXPOSED: &str = r#"id: memcached-exposed
info:
  name: Memcached Exposed
  author: cert-x-gen
  severity: high
  description: Detects exposed Memcached instances
  references:
    - https://memcached.org/
  tags:
    - memcached
    - cache
    - exposed

protocol: udp
port: 11211

inputs:
  - data: "stats\r\n"
    type: text

matchers:
  - type: word
    words:
      - "STAT pid"
      - "STAT version"
    condition: and

extract:
  - version
  - pid
  - uptime
  - curr_connections"#;

    pub const CLICKHOUSE_DETECT: &str = r#"id: clickhouse-detect
info:
  name: Clickhouse DB - Detect
  author: cert-x-gen
  severity: informative
  description: Detects ClickHouse database instances
  references:
    - https://clickhouse.com/

protocol: http
port: 8123

requests:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    
matchers-condition: and
matchers:
  - type: status
    status:
      - 404
  - type: word
    words:
      - "clickhouse"
    part: body"#;

    pub const CLICKHOUSE_UNAUTH: &str = r#"id: clickhouse-unauth
info:
  name: Clickhouse DB - Unauthenticated
  author: cert-x-gen
  severity: high
  description: Detects unauthenticated ClickHouse database access
  references:
    - https://clickhouse.com/docs/en/operations/settings/settings-users

protocol: http
port: 8123

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?query=SELECT%20314159"
      - "{{BaseURL}}:8123/?query=SELECT%20314159"
    
matchers-condition: and
matchers:
  - type: status
    status:
      - 200
  - type: word
    words:
      - "314159"
    part: body"#;
}

/// Prompt builder for generating context-aware LLM prompts
#[derive(Debug)]
pub struct PromptBuilder {
    /// Embedded skeleton templates (always available)
    skeleton_templates: HashMap<TemplateLanguage, &'static str>,
}

impl PromptBuilder {
    /// Create a new PromptBuilder with all skeleton templates loaded from embedded resources
    ///
    /// This never fails since all templates are embedded at compile-time.
    pub fn new() -> Self {
        let mut skeleton_templates = HashMap::new();
        
        // Load all embedded skeleton templates
        // These are available at compile-time, so this never fails
        skeleton_templates.insert(TemplateLanguage::Python, embedded_skeletons::PYTHON);
        skeleton_templates.insert(TemplateLanguage::JavaScript, embedded_skeletons::JAVASCRIPT);
        skeleton_templates.insert(TemplateLanguage::Rust, embedded_skeletons::RUST);
        skeleton_templates.insert(TemplateLanguage::C, embedded_skeletons::C);
        skeleton_templates.insert(TemplateLanguage::Cpp, embedded_skeletons::CPP);
        skeleton_templates.insert(TemplateLanguage::Java, embedded_skeletons::JAVA);
        skeleton_templates.insert(TemplateLanguage::Go, embedded_skeletons::GO);
        skeleton_templates.insert(TemplateLanguage::Ruby, embedded_skeletons::RUBY);
        skeleton_templates.insert(TemplateLanguage::Perl, embedded_skeletons::PERL);
        skeleton_templates.insert(TemplateLanguage::Php, embedded_skeletons::PHP);
        skeleton_templates.insert(TemplateLanguage::Shell, embedded_skeletons::SHELL);
        
        Self {
            skeleton_templates,
        }
    }
    
    /// Get the appropriate skeleton template for a language
    ///
    /// Returns None only for YAML (which is declarative and doesn't use skeletons)
    pub fn get_skeleton(&self, language: TemplateLanguage) -> Option<&str> {
        self.skeleton_templates.get(&language).copied()
    }
    
    /// Build a context-aware generation prompt for the LLM
    ///
    /// This creates a comprehensive prompt that includes:
    /// - User's security check request
    /// - Language-specific context and best practices
    /// - Complete skeleton template as reference
    /// - YAML examples for reference (when not generating YAML)
    /// - Specific output requirements
    pub fn build_generation_prompt(
        &self,
        user_request: &str,
        language: TemplateLanguage,
    ) -> String {
        match language {
            TemplateLanguage::Yaml => self.build_yaml_prompt(user_request),
            _ => self.build_code_prompt(user_request, language),
        }
    }
    
    /// Build prompt for YAML templates (declarative)
    fn build_yaml_prompt(&self, user_request: &str) -> String {
        format!(
            r#"You are a security researcher creating vulnerability detection templates for CERT-X-GEN.

# CERT-X-GEN Overview
CERT-X-GEN is a polyglot security scanner that supports templates in multiple formats.
YAML templates use a declarative format for defining security checks.

# Your Task
Create a YAML template for: "{user_request}"

# YAML Template Structure

A CERT-X-GEN YAML template must follow the canonical skeleton contract:
1. **Top-level metadata** (flattened TemplateMetadata):
   - id, name, author{{name,email,github}}, severity, description
   - tags, language (must be `yaml`), confidence
   - cve_ids, cwe_ids, cvss_score, version, references
2. **Execution blocks** (one or more of):
   - `http`: HTTP request definitions
   - `network`: TCP/UDP network checks with a template-level default `port`
   - `flows`: optional multi-step HTTP/token flows that manipulate context
3. **Optional extras**:
   - Template-level `matchers` / `matchers-condition`
   - `remediation` guidance text

Each template is executed by CERT-X-GEN against a **single target host and port**.
The engine expands ports based on CLI options; your YAML should not implement its
own generic port scanners.

# Canonical YAML Skeleton

Below is the canonical CERT-X-GEN YAML skeleton. Follow its structure closely
and customize only the parts that describe the specific check you are creating:

```yaml
{yaml_skeleton}
```

# Instructions

1. Create a valid YAML template following the structure above
2. Use appropriate protocol (tcp, udp, http, https)
3. Set correct default port
4. Define inputs/requests that will detect: "{user_request}"
5. Use appropriate matchers with correct conditions
6. Set accurate severity level
7. Add relevant tags
8. Include references if available
9. Add extractors if you need to capture specific data

# Output Requirements

- Output ONLY the complete YAML template
- NO markdown code blocks (```yaml)
- NO explanations before or after
- Start directly with "id:" line
- Ensure valid YAML syntax
- Use proper indentation (2 spaces)

Generate the YAML template now:
"#,
            user_request = user_request,
            yaml_skeleton = yaml_examples::YAML_SKELETON,
        )
    }
    
    /// Build prompt for code-based templates (procedural languages)
    fn build_code_prompt(&self, user_request: &str, language: TemplateLanguage) -> String {
        let skeleton = self.get_skeleton(language)
            .unwrap_or("No skeleton template available for this language");
        
        let language_name = format!("{}", language);
        let file_extension = Self::get_file_extension(language);
        let language_context = Self::get_language_context(language);
        
        format!(
            r#"You are a security researcher creating vulnerability detection templates for CERT-X-GEN.

# CERT-X-GEN Overview
CERT-X-GEN is a polyglot security scanner that supports templates in 12 programming languages.
Templates detect vulnerabilities, misconfigurations, and security issues through programmatic checks.

# Your Task
Create a {language_name} template for: "{user_request}"

# Template Requirements

## For {language_name} templates:
{language_context}

These templates must follow the CERT-X-GEN skeleton contract defined in
`SKELETON_CONTRACT.md`. Each language also has a companion AI-notes file (for
example, `python-template-ai-notes.md`, `go-template-ai-notes.md`, etc.) that
explains language-specific guidance built on that contract.

## Key Integration Points:

### 1. Environment Variables (Input)
CERT-X-GEN runs your template **once per target host and port**. Use these
environment variables:
- `CERT_X_GEN_TARGET_HOST`: Target hostname/IP for this invocation
- `CERT_X_GEN_TARGET_PORT`: Target port number for this invocation
- `CERT_X_GEN_CONTEXT`: JSON context data (advanced/optional)
- `CERT_X_GEN_ADD_PORTS` / `CERT_X_GEN_OVERRIDE_PORTS`: Scan-level port hints,
  exposed only for advanced/custom logic. Do **not** implement a generic port
  scanner; rely on `CERT_X_GEN_TARGET_PORT` for the port to use.
- `CERT_X_GEN_MODE`: Set to "engine" when CERT-X-GEN invokes the template;
  in this mode, stdout must be JSON-only and human output should go to stderr.

### 2. JSON Output (Required)
Output findings as a JSON array to stdout:
```json
[
  {{
    "template_id": "unique-template-id",
    "severity": "critical|high|medium|low|info",
    "confidence": 90,
    "title": "Vulnerability Title",
    "description": "Detailed description of the finding",
    "evidence": {{
      "response": "actual data captured",
      "headers": {{}},
      "body": "response body"
    }},
    "cwe": "CWE-XXX",
    "cvss_score": 7.5,
    "remediation": "Steps to fix the issue",
    "references": ["https://..."]
  }}
]
```

### 3. Error Handling
- Handle errors gracefully - don't crash
- Log errors to stderr (not stdout)
- Continue execution even if individual checks fail
- Use reasonable timeouts (5-10 seconds)

### 4. Security Best Practices
- Don't execute arbitrary code from responses
- Validate all inputs
- Use secure connections when appropriate
- Handle edge cases and malformed responses
- Be careful with resource consumption

## YAML Template Examples (for reference):

### Redis Unauthenticated:
```yaml
{redis_example}
```

### Memcached Exposed:
```yaml
{memcached_example}
```

## Complete {language_name} Skeleton Template:

The following is a complete skeleton template that shows the expected structure.
Study it carefully and follow the same pattern:

```{file_extension}
{skeleton}
```

# Instructions

**IMPORTANT: You must CUSTOMIZE the skeleton for the specific security check: "{user_request}"**

1. Use the skeleton structure as a guide (don't copy it verbatim!)
2. **Implement ACTUAL detection logic for: "{user_request}"**
3. Change the class/function names to match the security check
4. Use the appropriate protocol (HTTP, TCP, Redis, MongoDB, etc.)
5. Read target from environment variables (CERT_X_GEN_TARGET_HOST, CERT_X_GEN_TARGET_PORT)
6. Treat this as **single-target-per-run**: use the given host+port only and do
   **not** implement a generic multi-port scanner (CERT-X-GEN already expands
   ports and invokes your template once per host+port).
7. **Write REAL code that performs the specific security check**
8. Set correct severity level based on the vulnerability
9. Add the relevant CWE if applicable
10. Output findings as JSON array to stdout
11. Handle errors gracefully with try-catch/error handling

**Example of what to do:**
- If checking Redis without auth: Connect to Redis port 6379, send INFO command, check if AUTH required
- If checking exposed Memcached: Connect to port 11211, send stats command, check response
- If checking SQL injection: Send SQL payloads, analyze responses for SQL errors

**What NOT to do:**
- Don't just copy the skeleton template with generic placeholder logic
- Don't leave TODO comments or placeholder functions
- Don't use generic "MyCustomTemplate" names
- Don't leave example code that doesn't match the security check

# Output Requirements

**CRITICAL: Output ONLY executable code - NO prose, NO explanations, NO notes!**

- Output ONLY the complete, CUSTOMIZED template code
- NO markdown formatting (no ```{file_extension})
- NO explanations before or after the code
- NO "Please note" or "Remember to" or "This code" statements
- NO usage instructions or examples after the code
- NO comments explaining what you did
- Start directly with the shebang or first line of code
- End with the last line of executable code (usually `template.run()` or similar)
- Ensure the code implements the ACTUAL security check requested
- The code must be complete, runnable, and specific to: "{user_request}"

**If you add ANY text after the code, it will cause a syntax error and fail!**

Generate the CUSTOMIZED {language_name} template for "{user_request}" now:
"#,
            language_name = language_name,
            user_request = user_request,
            language_context = language_context,
            file_extension = file_extension,
            skeleton = skeleton,
            redis_example = yaml_examples::REDIS_UNAUTH,
            memcached_example = yaml_examples::MEMCACHED_EXPOSED,
        )
    }
    
    /// Get language-specific context and requirements
    fn get_language_context(language: TemplateLanguage) -> &'static str {
        match language {
            TemplateLanguage::Python => {
                "- Use Python 3 with standard library (json, os, sys, socket, urllib, etc.)\n\
                 - Import `requests` for HTTP (assumed available)\n\
                 - Follow the skeleton class structure\n\
                 - Implement the `execute()` method with your detection logic\n\
                 - Use proper error handling with try/except\n\
                 - Output JSON array to stdout"
            }
            TemplateLanguage::JavaScript => {
                "- Use Node.js with built-in modules (http, https, net, dgram)\n\
                 - No external dependencies except built-ins\n\
                 - Follow the skeleton structure\n\
                 - Implement async functions for network operations\n\
                 - Use proper error handling with try/catch\n\
                 - Output JSON array to stdout with console.log()"
            }
            TemplateLanguage::Rust => {
                "- Use Rust with standard library\n\
                 - Add minimal dependencies (serde_json, reqwest if needed)\n\
                 - Follow the skeleton structure\n\
                 - Implement proper error handling with Result\n\
                 - Use tokio for async operations\n\
                 - Output JSON to stdout using println!"
            }
            TemplateLanguage::C => {
                "- Use standard C library (stdio.h, stdlib.h, string.h)\n\
                 - Use POSIX sockets for networking (sys/socket.h, netinet/in.h)\n\
                 - Follow the skeleton structure\n\
                 - Use proper error checking\n\
                 - Build JSON output manually using printf\n\
                 - Free all allocated memory"
            }
            TemplateLanguage::Cpp => {
                "- Use C++11 or later\n\
                 - Use standard library (iostream, string, vector)\n\
                 - Use POSIX sockets or platform-appropriate networking\n\
                 - Follow the skeleton class structure\n\
                 - Use proper error handling with exceptions\n\
                 - Build JSON output and write to stdout"
            }
            TemplateLanguage::Java => {
                "- Use Java 8 or later\n\
                 - Use java.net for networking\n\
                 - Follow the skeleton class structure\n\
                 - Use proper exception handling\n\
                 - Use org.json or build JSON manually\n\
                 - Write JSON to System.out"
            }
            TemplateLanguage::Go => {
                "- Use Go with standard library\n\
                 - Use net/http, net packages for networking\n\
                 - Use encoding/json for JSON output\n\
                 - Follow the skeleton structure\n\
                 - Use proper error handling\n\
                 - Write JSON to stdout using fmt.Println"
            }
            TemplateLanguage::Ruby => {
                "- Use Ruby 2.x or later\n\
                 - Use standard library (net/http, socket, json)\n\
                 - Follow the skeleton class structure\n\
                 - Use proper error handling with rescue\n\
                 - Output JSON array using puts\n\
                 - Handle encoding properly"
            }
            TemplateLanguage::Perl => {
                "- Use Perl 5.x with strict and warnings\n\
                 - Use core modules (Socket, JSON, HTTP::Tiny)\n\
                 - Follow the skeleton structure\n\
                 - Use proper error handling with eval\n\
                 - Output JSON using JSON module\n\
                 - Print to STDOUT"
            }
            TemplateLanguage::Php => {
                "- Use PHP 7.x or later\n\
                 - Use built-in functions (curl, socket, json_encode)\n\
                 - Follow the skeleton class structure\n\
                 - Use proper error handling with try/catch\n\
                 - Output JSON array using echo json_encode()\n\
                 - Handle errors gracefully"
            }
            TemplateLanguage::Shell => {
                "- Use bash shell (#!/bin/bash)\n\
                 - Use common utilities (curl, nc, grep, sed)\n\
                 - Follow the skeleton structure\n\
                 - Use proper error checking ($?)\n\
                 - Build JSON output manually or use jq\n\
                 - Echo JSON to stdout"
            }
            TemplateLanguage::Yaml => {
                "YAML is declarative - this shouldn't be called"
            }
        }
    }
    
    /// Get file extension for code blocks in prompts
    fn get_file_extension(language: TemplateLanguage) -> &'static str {
        match language {
            TemplateLanguage::Python => "python",
            TemplateLanguage::JavaScript => "javascript",
            TemplateLanguage::Rust => "rust",
            TemplateLanguage::Yaml => "yaml",
            TemplateLanguage::C => "c",
            TemplateLanguage::Cpp => "cpp",
            TemplateLanguage::Java => "java",
            TemplateLanguage::Go => "go",
            TemplateLanguage::Ruby => "ruby",
            TemplateLanguage::Perl => "perl",
            TemplateLanguage::Php => "php",
            TemplateLanguage::Shell => "bash",
        }
    }
    
    /// Get a list of all supported languages that have skeleton templates
    pub fn supported_languages(&self) -> Vec<TemplateLanguage> {
        self.skeleton_templates.keys().copied().collect()
    }
    
    /// Check if a language has a skeleton template available
    pub fn has_skeleton(&self, language: TemplateLanguage) -> bool {
        self.skeleton_templates.contains_key(&language)
    }
}

impl Default for PromptBuilder {
    fn default() -> Self {
        Self::new()
    }
}
