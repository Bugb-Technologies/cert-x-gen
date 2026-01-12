//! Language-specific validation patterns
//!
//! This module provides a centralized registry of patterns for each supported language.
//! The patterns are used by the common validator to perform checks across all languages
//! using a unified approach.

use crate::types::TemplateLanguage;
use std::collections::HashMap;

/// Pattern categories for validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternCategory {
    /// Network/socket library imports
    NetworkImport,
    /// JSON library imports
    JsonImport,
    /// JSON output/serialization functions
    JsonOutput,
    /// Error handling constructs
    ErrorHandling,
    /// Timeout configuration patterns
    TimeoutHandling,
    /// Entry point (main function)
    EntryPoint,
    /// Package/module declaration
    PackageDeclaration,
    /// Shebang line
    Shebang,
    /// Environment variable access
    EnvVarAccess,
    /// Command execution (potential injection)
    CommandExecution,
    /// File path operations (potential traversal)
    FilePathOps,
    /// Unsafe functions (language-specific)
    UnsafeFunctions,
    /// Comment syntax (single line)
    CommentSingle,
    /// Comment syntax (multi-line start)
    CommentMultiStart,
    /// Comment syntax (multi-line end)
    CommentMultiEnd,
}

/// A validation pattern with metadata
#[derive(Debug, Clone)]
pub struct ValidationPattern {
    /// The pattern to match (can be literal string or regex)
    pub pattern: String,
    /// Whether this is a regex pattern
    pub is_regex: bool,
    /// Human-readable description
    pub description: String,
    /// Suggested fix or addition
    pub suggestion: Option<String>,
}

impl ValidationPattern {
    /// Create a new literal pattern
    pub fn literal(pattern: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            is_regex: false,
            description: description.into(),
            suggestion: None,
        }
    }

    /// Create a new regex pattern
    pub fn regex(pattern: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            is_regex: true,
            description: description.into(),
            suggestion: None,
        }
    }

    /// Add a suggestion for fixing
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    /// Check if code contains this pattern
    pub fn matches(&self, code: &str) -> bool {
        if self.is_regex {
            if let Ok(re) = regex::Regex::new(&self.pattern) {
                re.is_match(code)
            } else {
                false
            }
        } else {
            code.contains(&self.pattern)
        }
    }

    /// Find all line numbers where pattern matches
    pub fn find_lines(&self, code: &str) -> Vec<usize> {
        let mut lines = Vec::new();

        if self.is_regex {
            if let Ok(re) = regex::Regex::new(&self.pattern) {
                for (idx, line) in code.lines().enumerate() {
                    if re.is_match(line) {
                        lines.push(idx + 1);
                    }
                }
            }
        } else {
            for (idx, line) in code.lines().enumerate() {
                if line.contains(&self.pattern) {
                    lines.push(idx + 1);
                }
            }
        }

        lines
    }
}

/// Registry of patterns for all languages
#[derive(Debug)]
pub struct PatternRegistry {
    patterns: HashMap<TemplateLanguage, HashMap<PatternCategory, Vec<ValidationPattern>>>,
}

impl PatternRegistry {
    /// Create a new pattern registry with all language patterns
    pub fn new() -> Self {
        let mut registry = Self {
            patterns: HashMap::new(),
        };

        registry.register_python_patterns();
        registry.register_javascript_patterns();
        registry.register_rust_patterns();
        registry.register_go_patterns();
        registry.register_c_patterns();
        registry.register_cpp_patterns();
        registry.register_java_patterns();
        registry.register_ruby_patterns();
        registry.register_perl_patterns();
        registry.register_php_patterns();
        registry.register_shell_patterns();
        registry.register_yaml_patterns();

        registry
    }

    /// Get patterns for a specific language and category
    pub fn get_patterns(
        &self,
        language: TemplateLanguage,
        category: PatternCategory,
    ) -> &[ValidationPattern] {
        self.patterns
            .get(&language)
            .and_then(|lang_patterns| lang_patterns.get(&category))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Check if any pattern in category matches
    pub fn has_any_match(
        &self,
        code: &str,
        language: TemplateLanguage,
        category: PatternCategory,
    ) -> bool {
        self.get_patterns(language, category)
            .iter()
            .any(|p| p.matches(code))
    }

    /// Get all matching patterns in a category
    pub fn get_matches(
        &self,
        code: &str,
        language: TemplateLanguage,
        category: PatternCategory,
    ) -> Vec<&ValidationPattern> {
        self.get_patterns(language, category)
            .iter()
            .filter(|p| p.matches(code))
            .collect()
    }

    /// Helper to add patterns for a language
    fn add_patterns(
        &mut self,
        language: TemplateLanguage,
        category: PatternCategory,
        patterns: Vec<ValidationPattern>,
    ) {
        self.patterns
            .entry(language)
            .or_insert_with(HashMap::new)
            .insert(category, patterns);
    }

    // ========================================================================
    // PYTHON PATTERNS
    // ========================================================================
    fn register_python_patterns(&mut self) {
        // Network imports
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("import socket", "socket module")
                    .with_suggestion("import socket"),
                ValidationPattern::literal("from socket import", "socket module")
                    .with_suggestion("import socket"),
                ValidationPattern::literal("import requests", "requests library")
                    .with_suggestion("import requests"),
                ValidationPattern::literal("import urllib", "urllib module")
                    .with_suggestion("import urllib.request"),
                ValidationPattern::literal("import http.client", "http.client module")
                    .with_suggestion("import http.client"),
                ValidationPattern::literal("import aiohttp", "aiohttp library")
                    .with_suggestion("import aiohttp"),
            ],
        );

        // JSON imports
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::JsonImport,
            vec![
                ValidationPattern::literal("import json", "json module")
                    .with_suggestion("import json"),
                ValidationPattern::literal("from json import", "json module")
                    .with_suggestion("import json"),
            ],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal("json.dumps", "JSON serialization"),
                ValidationPattern::literal("json.dump(", "JSON file output"),
                ValidationPattern::regex(r"print\s*\(\s*json\.", "JSON print output"),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("try:", "try block")
                    .with_suggestion("try:\n    # code\nexcept Exception as e:\n    pass"),
                ValidationPattern::literal("except ", "except clause"),
                ValidationPattern::regex(r"except\s+\w+", "typed exception handling"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal(".settimeout(", "socket timeout"),
                ValidationPattern::literal("timeout=", "timeout parameter"),
                ValidationPattern::literal("Timeout", "Timeout class/exception"),
                ValidationPattern::regex(r"requests\.[a-z]+\([^)]*timeout", "requests timeout"),
            ],
        );

        // Entry point
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::EntryPoint,
            vec![
                ValidationPattern::literal("def main(", "main function").with_suggestion(
                    "def main():\n    pass\n\nif __name__ == '__main__':\n    main()",
                ),
                ValidationPattern::literal("if __name__ == '__main__'", "main guard"),
                ValidationPattern::literal("if __name__ == \"__main__\"", "main guard"),
            ],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::EnvVarAccess,
            vec![
                ValidationPattern::literal("os.environ", "environment access")
                    .with_suggestion("os.environ.get('CERT_X_GEN_TARGET_HOST')"),
                ValidationPattern::literal("os.getenv", "getenv function")
                    .with_suggestion("os.getenv('CERT_X_GEN_TARGET_HOST')"),
            ],
        );

        // Command execution (security)
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("os.system(", "os.system - unsafe"),
                ValidationPattern::literal("os.popen(", "os.popen - unsafe"),
                ValidationPattern::literal("subprocess.call(", "subprocess.call"),
                ValidationPattern::literal("subprocess.run(", "subprocess.run"),
                ValidationPattern::literal("subprocess.Popen(", "subprocess.Popen"),
                ValidationPattern::regex(r"eval\s*\(", "eval - dangerous"),
                ValidationPattern::regex(r"exec\s*\(", "exec - dangerous"),
            ],
        );

        // File path operations
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::FilePathOps,
            vec![
                ValidationPattern::literal("open(", "file open"),
                ValidationPattern::literal("os.path.join(", "path join"),
                ValidationPattern::literal("pathlib", "pathlib module"),
                ValidationPattern::regex(r"with\s+open\s*\(", "file context manager"),
            ],
        );

        // Unsafe functions
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::literal("pickle.load", "pickle deserialization - unsafe"),
                ValidationPattern::literal("pickle.loads", "pickle deserialization - unsafe"),
                ValidationPattern::literal("yaml.load(", "yaml.load without Loader - unsafe"),
                ValidationPattern::regex(r"input\s*\(", "input() in script"),
            ],
        );

        // Comments
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("#", "single line comment")],
        );
        self.add_patterns(
            TemplateLanguage::Python,
            PatternCategory::CommentMultiStart,
            vec![
                ValidationPattern::literal("\"\"\"", "docstring/multiline"),
                ValidationPattern::literal("'''", "docstring/multiline"),
            ],
        );
    }

    // ========================================================================
    // JAVASCRIPT PATTERNS
    // ========================================================================
    fn register_javascript_patterns(&mut self) {
        // Network imports
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("require('net')", "net module")
                    .with_suggestion("const net = require('net');"),
                ValidationPattern::literal("require(\"net\")", "net module"),
                ValidationPattern::literal("require('http')", "http module")
                    .with_suggestion("const http = require('http');"),
                ValidationPattern::literal("require('https')", "https module"),
                ValidationPattern::literal("require('axios')", "axios library"),
                ValidationPattern::literal("require('node-fetch')", "node-fetch"),
                ValidationPattern::literal("import net from", "net module (ESM)"),
                ValidationPattern::literal("import http from", "http module (ESM)"),
                ValidationPattern::regex(r"fetch\s*\(", "fetch API"),
            ],
        );

        // JSON handling (built-in, no import needed)
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::JsonImport,
            vec![ValidationPattern::literal("JSON", "JSON global object")],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal("JSON.stringify", "JSON serialization")
                    .with_suggestion("console.log(JSON.stringify(findings));"),
                ValidationPattern::regex(
                    r"console\.log\s*\(\s*JSON\.stringify",
                    "JSON console output",
                ),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("try {", "try block")
                    .with_suggestion("try {\n  // code\n} catch (e) {\n  // handle error\n}"),
                ValidationPattern::literal("catch (", "catch clause"),
                ValidationPattern::literal("catch(", "catch clause"),
                ValidationPattern::literal(".catch(", "Promise catch"),
                ValidationPattern::literal("finally {", "finally block"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal("setTimeout(", "setTimeout"),
                ValidationPattern::literal("socket.setTimeout(", "socket timeout"),
                ValidationPattern::literal("timeout:", "timeout option"),
                ValidationPattern::literal("AbortController", "AbortController for fetch"),
                ValidationPattern::literal("signal:", "abort signal"),
            ],
        );

        // Entry point
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::EntryPoint,
            vec![
                ValidationPattern::literal("function main(", "main function"),
                ValidationPattern::literal("const main =", "main const"),
                ValidationPattern::literal("async function main(", "async main"),
                ValidationPattern::regex(r"^\s*main\s*\(\s*\)", "main() call"),
            ],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::EnvVarAccess,
            vec![
                ValidationPattern::literal("process.env", "environment access")
                    .with_suggestion("process.env.CERT_X_GEN_TARGET_HOST"),
            ],
        );

        // Command execution (security)
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("child_process", "child_process module"),
                ValidationPattern::literal("exec(", "exec function"),
                ValidationPattern::literal("execSync(", "execSync function"),
                ValidationPattern::literal("spawn(", "spawn function"),
                ValidationPattern::regex(r"eval\s*\(", "eval - dangerous"),
                ValidationPattern::literal("Function(", "Function constructor - dangerous"),
            ],
        );

        // File path operations
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::FilePathOps,
            vec![
                ValidationPattern::literal("require('fs')", "fs module"),
                ValidationPattern::literal("require('path')", "path module"),
                ValidationPattern::literal("fs.readFile", "file read"),
                ValidationPattern::literal("fs.writeFile", "file write"),
                ValidationPattern::literal("path.join(", "path join"),
            ],
        );

        // Unsafe functions
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::regex(r"eval\s*\(", "eval - dangerous"),
                ValidationPattern::literal("Function(", "Function constructor"),
                ValidationPattern::literal("innerHTML", "innerHTML - XSS risk"),
                ValidationPattern::literal("document.write", "document.write - unsafe"),
            ],
        );

        // Comments
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("//", "single line comment")],
        );
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::CommentMultiStart,
            vec![ValidationPattern::literal("/*", "multi-line comment start")],
        );
        self.add_patterns(
            TemplateLanguage::JavaScript,
            PatternCategory::CommentMultiEnd,
            vec![ValidationPattern::literal("*/", "multi-line comment end")],
        );
    }

    // ========================================================================
    // RUST PATTERNS
    // ========================================================================
    fn register_rust_patterns(&mut self) {
        // Network imports
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("use std::net", "std::net module")
                    .with_suggestion("use std::net::{TcpStream, SocketAddr};"),
                ValidationPattern::literal("use tokio::net", "tokio networking"),
                ValidationPattern::literal("use reqwest", "reqwest HTTP client"),
                ValidationPattern::literal("use hyper", "hyper HTTP"),
                ValidationPattern::literal("TcpStream", "TcpStream"),
                ValidationPattern::literal("UdpSocket", "UdpSocket"),
            ],
        );

        // JSON imports
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::JsonImport,
            vec![
                ValidationPattern::literal("use serde_json", "serde_json crate")
                    .with_suggestion("use serde_json::{json, Value};"),
                ValidationPattern::literal("serde_json::", "serde_json usage"),
                ValidationPattern::literal("json!", "json! macro"),
            ],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal("serde_json::to_string", "JSON serialization"),
                ValidationPattern::literal("json!", "json! macro"),
                ValidationPattern::literal("to_string_pretty", "pretty JSON"),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("Result<", "Result type")
                    .with_suggestion("fn main() -> Result<(), Box<dyn std::error::Error>>"),
                ValidationPattern::literal("?", "? operator"),
                ValidationPattern::literal(".unwrap()", "unwrap - panics on error"),
                ValidationPattern::literal(".expect(", "expect - panics with message"),
                ValidationPattern::literal("match ", "match expression"),
                ValidationPattern::literal("if let Err(", "error handling"),
                ValidationPattern::literal("Ok(", "Ok variant"),
                ValidationPattern::literal("Err(", "Err variant"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal("set_read_timeout", "read timeout"),
                ValidationPattern::literal("set_write_timeout", "write timeout"),
                ValidationPattern::literal("timeout(", "timeout function"),
                ValidationPattern::literal("Duration::", "Duration type"),
                ValidationPattern::literal("tokio::time::timeout", "tokio timeout"),
            ],
        );

        // Entry point
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::EntryPoint,
            vec![
                ValidationPattern::literal("fn main()", "main function").with_suggestion(
                    "fn main() -> Result<(), Box<dyn std::error::Error>> {\n    Ok(())\n}",
                ),
                ValidationPattern::regex(r"fn\s+main\s*\(", "main function"),
                ValidationPattern::literal("#[tokio::main]", "async main"),
            ],
        );

        // Package declaration (not required in Rust single files)
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::PackageDeclaration,
            vec![],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::EnvVarAccess,
            vec![
                ValidationPattern::literal("std::env::var", "env::var")
                    .with_suggestion("std::env::var(\"CERT_X_GEN_TARGET_HOST\")"),
                ValidationPattern::literal("env::var(", "env::var"),
                ValidationPattern::literal("env::args()", "command line args"),
            ],
        );

        // Command execution
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("std::process::Command", "Command"),
                ValidationPattern::literal("Command::new(", "Command::new"),
                ValidationPattern::literal(".spawn()", "process spawn"),
                ValidationPattern::literal(".output()", "process output"),
            ],
        );

        // Unsafe functions
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::literal("unsafe {", "unsafe block"),
                ValidationPattern::literal("unsafe fn", "unsafe function"),
                ValidationPattern::literal(".unwrap()", "unwrap - can panic"),
            ],
        );

        // Comments
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("//", "single line comment")],
        );
        self.add_patterns(
            TemplateLanguage::Rust,
            PatternCategory::CommentMultiStart,
            vec![ValidationPattern::literal("/*", "multi-line comment start")],
        );
    }

    // ========================================================================
    // GO PATTERNS
    // ========================================================================
    fn register_go_patterns(&mut self) {
        // Network imports
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("\"net\"", "net package")
                    .with_suggestion("import \"net\""),
                ValidationPattern::literal("\"net/http\"", "net/http package"),
                ValidationPattern::literal("net.Dial", "net.Dial"),
                ValidationPattern::literal("http.Get", "http.Get"),
                ValidationPattern::literal("http.Post", "http.Post"),
            ],
        );

        // JSON imports
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::JsonImport,
            vec![
                ValidationPattern::literal("\"encoding/json\"", "encoding/json package")
                    .with_suggestion("import \"encoding/json\""),
            ],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal("json.Marshal", "JSON marshal"),
                ValidationPattern::literal("json.MarshalIndent", "JSON marshal indented"),
                ValidationPattern::literal("json.NewEncoder", "JSON encoder"),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("if err != nil", "error check")
                    .with_suggestion("if err != nil {\n    return err\n}"),
                ValidationPattern::regex(r"if\s+\w+\s*!=\s*nil", "nil check"),
                ValidationPattern::literal("error", "error type"),
                ValidationPattern::literal("panic(", "panic - avoid in production"),
                ValidationPattern::literal("recover()", "recover from panic"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal("context.WithTimeout", "context timeout")
                    .with_suggestion(
                        "ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)",
                    ),
                ValidationPattern::literal("context.WithDeadline", "context deadline"),
                ValidationPattern::literal("SetDeadline(", "connection deadline"),
                ValidationPattern::literal("SetReadDeadline(", "read deadline"),
                ValidationPattern::literal("SetWriteDeadline(", "write deadline"),
                ValidationPattern::literal("time.After(", "time.After"),
            ],
        );

        // Entry point
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::EntryPoint,
            vec![ValidationPattern::literal("func main()", "main function")
                .with_suggestion("func main() {\n}")],
        );

        // Package declaration
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::PackageDeclaration,
            vec![ValidationPattern::literal("package main", "package main")
                .with_suggestion("package main")],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::EnvVarAccess,
            vec![
                ValidationPattern::literal("os.Getenv(", "os.Getenv")
                    .with_suggestion("os.Getenv(\"CERT_X_GEN_TARGET_HOST\")"),
                ValidationPattern::literal("os.LookupEnv(", "os.LookupEnv"),
            ],
        );

        // Command execution
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("exec.Command(", "exec.Command"),
                ValidationPattern::literal("os/exec", "os/exec package"),
            ],
        );

        // Unsafe functions
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::literal("unsafe.", "unsafe package"),
                ValidationPattern::literal("panic(", "panic"),
            ],
        );

        // Comments
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("//", "single line comment")],
        );
        self.add_patterns(
            TemplateLanguage::Go,
            PatternCategory::CommentMultiStart,
            vec![ValidationPattern::literal("/*", "multi-line comment start")],
        );
    }

    // ========================================================================
    // C PATTERNS
    // ========================================================================
    fn register_c_patterns(&mut self) {
        // Network imports
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("#include <sys/socket.h>", "socket header")
                    .with_suggestion("#include <sys/socket.h>"),
                ValidationPattern::literal("#include <netinet/in.h>", "network header"),
                ValidationPattern::literal("#include <arpa/inet.h>", "inet header"),
                ValidationPattern::literal("#include <netdb.h>", "netdb header"),
                ValidationPattern::literal("#include <unistd.h>", "unistd header"),
                ValidationPattern::literal("socket(", "socket function"),
                ValidationPattern::literal("connect(", "connect function"),
            ],
        );

        // JSON imports
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::JsonImport,
            vec![
                ValidationPattern::literal("#include <json-c", "json-c library")
                    .with_suggestion("#include <json-c/json.h>"),
                ValidationPattern::literal("#include <cjson", "cJSON library"),
                ValidationPattern::literal("#include \"cJSON.h\"", "cJSON header"),
                ValidationPattern::literal("json_object", "json-c usage"),
                ValidationPattern::literal("cJSON", "cJSON usage"),
            ],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal("json_object_to_json_string", "json-c serialize"),
                ValidationPattern::literal("cJSON_Print", "cJSON serialize"),
                ValidationPattern::regex(r#"printf\s*\(\s*"\s*\{"#, "manual JSON printf"),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("if (", "conditional check")
                    .with_suggestion("if (result < 0) { perror(\"error\"); return 1; }"),
                ValidationPattern::literal("perror(", "perror"),
                ValidationPattern::literal("strerror(", "strerror"),
                ValidationPattern::literal("errno", "errno"),
                ValidationPattern::literal("return -1", "error return"),
                ValidationPattern::literal("return 1", "error return"),
                ValidationPattern::literal("exit(", "exit"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal("setsockopt(", "setsockopt").with_suggestion(
                    "setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));",
                ),
                ValidationPattern::literal("SO_RCVTIMEO", "receive timeout"),
                ValidationPattern::literal("SO_SNDTIMEO", "send timeout"),
                ValidationPattern::literal("select(", "select for timeout"),
                ValidationPattern::literal("poll(", "poll for timeout"),
                ValidationPattern::literal("alarm(", "alarm signal"),
            ],
        );

        // Entry point
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::EntryPoint,
            vec![
                ValidationPattern::literal("int main(", "main function")
                    .with_suggestion("int main(int argc, char *argv[]) {\n    return 0;\n}"),
                ValidationPattern::regex(r"int\s+main\s*\(", "main function"),
            ],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::EnvVarAccess,
            vec![ValidationPattern::literal("getenv(", "getenv")
                .with_suggestion("getenv(\"CERT_X_GEN_TARGET_HOST\")")],
        );

        // Command execution
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("system(", "system - unsafe"),
                ValidationPattern::literal("popen(", "popen"),
                ValidationPattern::literal("execve(", "execve"),
                ValidationPattern::literal("execl(", "execl"),
                ValidationPattern::literal("fork(", "fork"),
            ],
        );

        // Unsafe functions
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::literal("gets(", "gets - buffer overflow"),
                ValidationPattern::literal("strcpy(", "strcpy - use strncpy"),
                ValidationPattern::literal("strcat(", "strcat - use strncat"),
                ValidationPattern::literal("sprintf(", "sprintf - use snprintf"),
                ValidationPattern::literal("scanf(", "scanf - format string"),
                ValidationPattern::regex(
                    r#"printf\s*\(\s*[^"]"#,
                    "printf without format - dangerous",
                ),
            ],
        );

        // Comments
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("//", "single line comment")],
        );
        self.add_patterns(
            TemplateLanguage::C,
            PatternCategory::CommentMultiStart,
            vec![ValidationPattern::literal("/*", "multi-line comment start")],
        );
    }

    // ========================================================================
    // C++ PATTERNS
    // ========================================================================
    fn register_cpp_patterns(&mut self) {
        // Network imports (same as C plus C++ specific)
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("#include <sys/socket.h>", "socket header")
                    .with_suggestion("#include <sys/socket.h>"),
                ValidationPattern::literal("#include <netinet/in.h>", "network header"),
                ValidationPattern::literal("#include <boost/asio", "Boost.Asio"),
                ValidationPattern::literal("boost::asio", "Boost.Asio usage"),
                ValidationPattern::literal("#include <asio.hpp>", "standalone Asio"),
                ValidationPattern::literal("socket(", "socket function"),
            ],
        );

        // JSON imports
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::JsonImport,
            vec![
                ValidationPattern::literal("#include <nlohmann/json.hpp>", "nlohmann/json")
                    .with_suggestion("#include <nlohmann/json.hpp>\nusing json = nlohmann::json;"),
                ValidationPattern::literal("#include <rapidjson", "RapidJSON"),
                ValidationPattern::literal("nlohmann::json", "nlohmann usage"),
                ValidationPattern::literal("using json = nlohmann", "json alias"),
            ],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal(".dump()", "nlohmann dump"),
                ValidationPattern::literal("json j", "json object"),
                ValidationPattern::literal("rapidjson::StringBuffer", "RapidJSON output"),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("try {", "try block").with_suggestion(
                    "try {\n    // code\n} catch (const std::exception& e) {\n    // handle\n}",
                ),
                ValidationPattern::literal("catch (", "catch block"),
                ValidationPattern::literal("std::exception", "exception handling"),
                ValidationPattern::literal("throw ", "throw exception"),
                ValidationPattern::literal("noexcept", "noexcept specifier"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal("setsockopt(", "setsockopt"),
                ValidationPattern::literal("SO_RCVTIMEO", "receive timeout"),
                ValidationPattern::literal("std::chrono::", "chrono for time"),
                ValidationPattern::literal("async_wait", "async timeout"),
                ValidationPattern::literal("deadline_timer", "Asio deadline timer"),
            ],
        );

        // Entry point
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::EntryPoint,
            vec![
                ValidationPattern::literal("int main(", "main function")
                    .with_suggestion("int main(int argc, char* argv[]) {\n    return 0;\n}"),
                ValidationPattern::regex(r"int\s+main\s*\(", "main function"),
            ],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::EnvVarAccess,
            vec![
                ValidationPattern::literal("std::getenv(", "std::getenv")
                    .with_suggestion("std::getenv(\"CERT_X_GEN_TARGET_HOST\")"),
                ValidationPattern::literal("getenv(", "getenv"),
            ],
        );

        // Command execution
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("system(", "system - unsafe"),
                ValidationPattern::literal("popen(", "popen"),
                ValidationPattern::literal("std::system(", "std::system"),
            ],
        );

        // Unsafe functions
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::literal("gets(", "gets - buffer overflow"),
                ValidationPattern::literal("strcpy(", "strcpy - use strncpy"),
                ValidationPattern::literal("sprintf(", "sprintf - use snprintf"),
                ValidationPattern::literal("new ", "raw new - prefer smart pointers"),
                ValidationPattern::literal("delete ", "raw delete"),
            ],
        );

        // Comments (same as C)
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("//", "single line comment")],
        );
        self.add_patterns(
            TemplateLanguage::Cpp,
            PatternCategory::CommentMultiStart,
            vec![ValidationPattern::literal("/*", "multi-line comment start")],
        );
    }

    // ========================================================================
    // JAVA PATTERNS
    // ========================================================================
    fn register_java_patterns(&mut self) {
        // Network imports
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("import java.net.Socket", "Socket import"),
                ValidationPattern::literal(
                    "import java.net.HttpURLConnection",
                    "HttpURLConnection",
                ),
                ValidationPattern::literal("import java.net.URL", "URL import"),
                ValidationPattern::literal("import java.io.InputStream", "InputStream"),
                ValidationPattern::literal("import java.io.OutputStream", "OutputStream"),
                ValidationPattern::literal("new Socket(", "Socket creation"),
            ],
        );

        // JSON imports
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::JsonImport,
            vec![
                ValidationPattern::literal("import org.json", "org.json"),
                ValidationPattern::literal("import com.google.gson", "Gson"),
                ValidationPattern::literal("import com.fasterxml.jackson", "Jackson"),
                ValidationPattern::literal("import javax.json", "javax.json"),
                ValidationPattern::literal("new JSONObject", "JSONObject creation"),
                ValidationPattern::literal("new JSONArray", "JSONArray creation"),
            ],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal(".toString()", "JSON toString"),
                ValidationPattern::literal("toJson(", "Gson toJson"),
                ValidationPattern::literal("writeValueAsString", "Jackson write"),
                ValidationPattern::literal("System.out.println", "stdout output"),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("try {", "try block"),
                ValidationPattern::literal("catch (", "catch block"),
                ValidationPattern::literal("catch(", "catch block"),
                ValidationPattern::literal("finally {", "finally block"),
                ValidationPattern::literal("throws ", "throws declaration"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal(".setSoTimeout(", "Socket timeout"),
                ValidationPattern::literal(".setConnectTimeout(", "Connect timeout"),
                ValidationPattern::literal(".setReadTimeout(", "Read timeout"),
                ValidationPattern::literal("Duration.ofSeconds", "Duration"),
            ],
        );

        // Entry point
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::EntryPoint,
            vec![
                ValidationPattern::literal("public static void main", "main method"),
                ValidationPattern::literal("public static void main(String[]", "main with args"),
            ],
        );

        // Package declaration
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::PackageDeclaration,
            vec![
                ValidationPattern::literal("package ", "package declaration"),
                ValidationPattern::literal("public class ", "public class"),
            ],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::EnvVarAccess,
            vec![ValidationPattern::literal("System.getenv(", "getenv")],
        );

        // Unsafe functions
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::literal(
                    "Runtime.getRuntime().exec",
                    "Runtime exec - command injection risk",
                ),
                ValidationPattern::literal("ProcessBuilder", "ProcessBuilder - command execution"),
            ],
        );

        // Command execution
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("Runtime.exec", "Runtime exec"),
                ValidationPattern::literal("ProcessBuilder", "ProcessBuilder"),
            ],
        );

        // Comments
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("//", "single line comment")],
        );
        self.add_patterns(
            TemplateLanguage::Java,
            PatternCategory::CommentMultiStart,
            vec![ValidationPattern::literal("/*", "multi-line comment start")],
        );
    }

    // ========================================================================
    // RUBY PATTERNS
    // ========================================================================
    fn register_ruby_patterns(&mut self) {
        // Network imports
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("require 'socket'", "socket require"),
                ValidationPattern::literal("require 'net/http'", "net/http require"),
                ValidationPattern::literal("require 'net/https'", "net/https require"),
                ValidationPattern::literal("require 'open-uri'", "open-uri require"),
                ValidationPattern::literal("require 'uri'", "uri require"),
                ValidationPattern::literal("TCPSocket.new", "TCPSocket creation"),
                ValidationPattern::literal("TCPSocket.open", "TCPSocket open"),
            ],
        );

        // JSON imports
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::JsonImport,
            vec![
                ValidationPattern::literal("require 'json'", "json require"),
                ValidationPattern::literal("require 'oj'", "oj require (fast JSON)"),
            ],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal(".to_json", "to_json method"),
                ValidationPattern::literal("JSON.generate", "JSON.generate"),
                ValidationPattern::literal("JSON.dump", "JSON.dump"),
                ValidationPattern::literal("puts ", "puts output"),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("begin", "begin block"),
                ValidationPattern::literal("rescue ", "rescue clause"),
                ValidationPattern::literal("rescue =>", "rescue with variable"),
                ValidationPattern::literal("ensure", "ensure block"),
                ValidationPattern::literal("raise ", "raise exception"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal("require 'timeout'", "timeout require"),
                ValidationPattern::literal("Timeout.timeout", "Timeout.timeout"),
                ValidationPattern::literal("Timeout::timeout", "Timeout::timeout"),
                ValidationPattern::literal("open_timeout", "open_timeout option"),
                ValidationPattern::literal("read_timeout", "read_timeout option"),
            ],
        );

        // Entry point (Ruby scripts run directly)
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::EntryPoint,
            vec![
                ValidationPattern::literal("#!/usr/bin/ruby", "ruby shebang"),
                ValidationPattern::literal("#!/usr/bin/env ruby", "env ruby shebang"),
                ValidationPattern::literal("if __FILE__ == $0", "main guard"),
                ValidationPattern::literal("if $PROGRAM_NAME == __FILE__", "program name guard"),
            ],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::EnvVarAccess,
            vec![
                ValidationPattern::literal("ENV[", "ENV hash"),
                ValidationPattern::literal("ENV.fetch", "ENV.fetch"),
            ],
        );

        // Unsafe functions
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::literal("eval(", "eval - dangerous"),
                ValidationPattern::literal("instance_eval", "instance_eval - dangerous"),
                ValidationPattern::literal("class_eval", "class_eval - dangerous"),
                ValidationPattern::literal("send(", "send - dynamic method"),
                ValidationPattern::literal("__send__", "__send__ - dynamic method"),
            ],
        );

        // Command execution
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("system(", "system - command execution"),
                ValidationPattern::literal("`", "backticks - command execution"),
                ValidationPattern::literal("exec(", "exec - command execution"),
                ValidationPattern::literal("%x{", "percent x - command execution"),
                ValidationPattern::literal("Open3", "Open3 - command execution"),
            ],
        );

        // Comments
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("#", "single line comment")],
        );
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::CommentMultiStart,
            vec![ValidationPattern::literal(
                "=begin",
                "multi-line comment start",
            )],
        );
        self.add_patterns(
            TemplateLanguage::Ruby,
            PatternCategory::CommentMultiEnd,
            vec![ValidationPattern::literal("=end", "multi-line comment end")],
        );
    }

    // ========================================================================
    // PERL PATTERNS
    // ========================================================================
    fn register_perl_patterns(&mut self) {
        // Network imports
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("use IO::Socket", "IO::Socket module")
                    .with_suggestion("use IO::Socket::INET;"),
                ValidationPattern::literal("use Socket", "Socket module"),
                ValidationPattern::literal("use LWP::UserAgent", "LWP::UserAgent"),
                ValidationPattern::literal("use HTTP::Request", "HTTP::Request"),
                ValidationPattern::literal("use Net::HTTP", "Net::HTTP"),
                ValidationPattern::literal("IO::Socket::INET->new", "Socket creation"),
            ],
        );

        // JSON imports
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::JsonImport,
            vec![
                ValidationPattern::literal("use JSON", "JSON module").with_suggestion("use JSON;"),
                ValidationPattern::literal("use JSON::XS", "JSON::XS module"),
                ValidationPattern::literal("use JSON::PP", "JSON::PP module"),
                ValidationPattern::literal("use Cpanel::JSON::XS", "Cpanel::JSON::XS"),
            ],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal("encode_json", "encode_json"),
                ValidationPattern::literal("to_json", "to_json"),
                ValidationPattern::literal("JSON->new", "JSON object"),
                ValidationPattern::literal("->encode(", "JSON encode method"),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("eval {", "eval block")
                    .with_suggestion("eval {\n    # code\n};\nif ($@) {\n    # handle error\n}"),
                ValidationPattern::literal("if ($@)", "error check"),
                ValidationPattern::literal("or die", "or die"),
                ValidationPattern::literal("|| die", "|| die"),
                ValidationPattern::literal("use Try::Tiny", "Try::Tiny module"),
                ValidationPattern::literal("try {", "Try::Tiny try"),
                ValidationPattern::literal("catch {", "Try::Tiny catch"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal("Timeout =>", "timeout option")
                    .with_suggestion("Timeout => 10"),
                ValidationPattern::literal("timeout =>", "timeout option"),
                ValidationPattern::literal("alarm(", "alarm signal"),
                ValidationPattern::literal("$SIG{ALRM}", "ALRM signal handler"),
            ],
        );

        // Entry point (Perl scripts run directly)
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::EntryPoint,
            vec![
                ValidationPattern::literal("#!/usr/bin/perl", "perl shebang"),
                ValidationPattern::literal("#!/usr/bin/env perl", "env perl shebang"),
            ],
        );

        // Package declaration
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::PackageDeclaration,
            vec![
                ValidationPattern::literal("use strict", "use strict")
                    .with_suggestion("use strict;\nuse warnings;"),
                ValidationPattern::literal("use warnings", "use warnings"),
            ],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::EnvVarAccess,
            vec![ValidationPattern::literal("$ENV{", "ENV hash")
                .with_suggestion("$ENV{'CERT_X_GEN_TARGET_HOST'}")],
        );

        // Command execution
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("system(", "system - command execution"),
                ValidationPattern::literal("`", "backticks - command execution"),
                ValidationPattern::literal("qx(", "qx - command execution"),
                ValidationPattern::literal("exec(", "exec"),
                ValidationPattern::literal("open(", "open with pipe"),
            ],
        );

        // Unsafe functions
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::regex(r"eval\s+\$", "eval with variable - dangerous"),
                ValidationPattern::regex(r#"eval\s+["']"#, "eval string - dangerous"),
                ValidationPattern::literal("no strict", "no strict - unsafe"),
            ],
        );

        // Comments
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("#", "single line comment")],
        );
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::CommentMultiStart,
            vec![
                ValidationPattern::literal("=pod", "POD start"),
                ValidationPattern::literal("=head", "POD heading"),
            ],
        );
        self.add_patterns(
            TemplateLanguage::Perl,
            PatternCategory::CommentMultiEnd,
            vec![ValidationPattern::literal("=cut", "POD end")],
        );
    }

    // ========================================================================
    // PHP PATTERNS
    // ========================================================================
    fn register_php_patterns(&mut self) {
        // Network imports (PHP has built-in functions)
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("fsockopen(", "fsockopen")
                    .with_suggestion("$fp = fsockopen($host, $port, $errno, $errstr, $timeout);"),
                ValidationPattern::literal("socket_create(", "socket_create"),
                ValidationPattern::literal("curl_init(", "cURL"),
                ValidationPattern::literal("file_get_contents(", "file_get_contents for HTTP"),
                ValidationPattern::literal("stream_socket_client(", "stream socket"),
            ],
        );

        // JSON (built-in since PHP 5.2)
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::JsonImport,
            vec![ValidationPattern::literal(
                "json_",
                "JSON functions available",
            )],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal("json_encode(", "json_encode")
                    .with_suggestion("echo json_encode($findings);"),
                ValidationPattern::literal("JSON_PRETTY_PRINT", "pretty print flag"),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("try {", "try block").with_suggestion(
                    "try {\n    // code\n} catch (Exception $e) {\n    // handle\n}",
                ),
                ValidationPattern::literal("catch (", "catch block"),
                ValidationPattern::literal("finally {", "finally block"),
                ValidationPattern::literal("throw new", "throw exception"),
                ValidationPattern::literal("set_error_handler", "error handler"),
                ValidationPattern::literal("error_reporting(", "error reporting"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal("stream_set_timeout(", "stream timeout")
                    .with_suggestion("stream_set_timeout($fp, 10);"),
                ValidationPattern::literal("CURLOPT_TIMEOUT", "cURL timeout"),
                ValidationPattern::literal("CURLOPT_CONNECTTIMEOUT", "cURL connect timeout"),
                ValidationPattern::literal("ini_set('default_socket_timeout'", "socket timeout"),
                ValidationPattern::literal("set_time_limit(", "script time limit"),
            ],
        );

        // Entry point
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::EntryPoint,
            vec![
                ValidationPattern::literal("<?php", "PHP opening tag").with_suggestion("<?php\n"),
                ValidationPattern::literal("<?=", "PHP short echo tag"),
            ],
        );

        // Shebang
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::Shebang,
            vec![
                ValidationPattern::literal("#!/usr/bin/php", "PHP shebang"),
                ValidationPattern::literal("#!/usr/bin/env php", "env PHP shebang"),
            ],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::EnvVarAccess,
            vec![
                ValidationPattern::literal("getenv(", "getenv")
                    .with_suggestion("getenv('CERT_X_GEN_TARGET_HOST')"),
                ValidationPattern::literal("$_ENV[", "$_ENV superglobal"),
                ValidationPattern::literal("$_SERVER[", "$_SERVER superglobal"),
            ],
        );

        // Command execution
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("shell_exec(", "shell_exec - unsafe"),
                ValidationPattern::literal("exec(", "exec"),
                ValidationPattern::literal("system(", "system"),
                ValidationPattern::literal("passthru(", "passthru"),
                ValidationPattern::literal("popen(", "popen"),
                ValidationPattern::literal("`", "backticks - command execution"),
                ValidationPattern::literal("proc_open(", "proc_open"),
            ],
        );

        // Unsafe functions
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::literal("eval(", "eval - dangerous"),
                ValidationPattern::literal("unserialize(", "unserialize - unsafe deserialization"),
                ValidationPattern::literal("assert(", "assert - can execute code"),
                ValidationPattern::literal("preg_replace(", "preg_replace with /e - dangerous"),
                ValidationPattern::literal("create_function(", "create_function - deprecated"),
                ValidationPattern::literal("extract(", "extract - variable injection"),
                ValidationPattern::literal("include($", "dynamic include - LFI risk"),
                ValidationPattern::literal("require($", "dynamic require - LFI risk"),
            ],
        );

        // Comments
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::CommentSingle,
            vec![
                ValidationPattern::literal("//", "single line comment"),
                ValidationPattern::literal("#", "shell-style comment"),
            ],
        );
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::CommentMultiStart,
            vec![ValidationPattern::literal("/*", "multi-line comment start")],
        );
        self.add_patterns(
            TemplateLanguage::Php,
            PatternCategory::CommentMultiEnd,
            vec![ValidationPattern::literal("*/", "multi-line comment end")],
        );
    }

    // ========================================================================
    // SHELL PATTERNS
    // ========================================================================
    fn register_shell_patterns(&mut self) {
        // Network tools (Shell uses external commands)
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("nc ", "netcat").with_suggestion("nc -z $HOST $PORT"),
                ValidationPattern::literal("netcat", "netcat"),
                ValidationPattern::literal("curl ", "curl command"),
                ValidationPattern::literal("wget ", "wget command"),
                ValidationPattern::literal("nmap ", "nmap"),
                ValidationPattern::literal("telnet ", "telnet"),
                ValidationPattern::literal("/dev/tcp/", "bash TCP")
                    .with_suggestion("exec 3<>/dev/tcp/$HOST/$PORT"),
                ValidationPattern::literal("/dev/udp/", "bash UDP"),
            ],
        );

        // JSON handling
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::JsonImport,
            vec![
                ValidationPattern::literal("jq ", "jq command"),
                ValidationPattern::literal("| jq", "jq pipe"),
            ],
        );

        // JSON output
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::JsonOutput,
            vec![
                ValidationPattern::literal("cat <<EOF", "heredoc for JSON")
                    .with_suggestion("cat <<EOF\n{\"findings\": []}\nEOF"),
                ValidationPattern::literal("cat << EOF", "heredoc for JSON"),
                ValidationPattern::literal("cat <<-EOF", "heredoc (indented)"),
                ValidationPattern::regex(r#"echo\s+['"]\s*\{"#, "echo JSON"),
                ValidationPattern::regex(r#"printf\s+['"]\s*\{"#, "printf JSON"),
            ],
        );

        // Error handling
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::ErrorHandling,
            vec![
                ValidationPattern::literal("set -e", "exit on error")
                    .with_suggestion("set -e  # Exit on error"),
                ValidationPattern::literal("set -o errexit", "exit on error"),
                ValidationPattern::literal("set -o pipefail", "pipe fail"),
                ValidationPattern::literal("|| exit", "exit on failure"),
                ValidationPattern::literal("|| return", "return on failure"),
                ValidationPattern::literal("if [ $? ", "exit code check"),
                ValidationPattern::literal("trap ", "trap for cleanup"),
            ],
        );

        // Timeout handling
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::TimeoutHandling,
            vec![
                ValidationPattern::literal("timeout ", "timeout command")
                    .with_suggestion("timeout 10 command"),
                ValidationPattern::literal("gtimeout ", "GNU timeout (macOS)"),
                ValidationPattern::literal("-w ", "wait timeout flag"),
                ValidationPattern::literal("--timeout", "timeout flag"),
                ValidationPattern::literal("-t ", "timeout flag (various)"),
            ],
        );

        // Entry point (shebang)
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::EntryPoint,
            vec![
                ValidationPattern::literal("#!/bin/bash", "bash shebang")
                    .with_suggestion("#!/bin/bash"),
                ValidationPattern::literal("#!/bin/sh", "sh shebang"),
                ValidationPattern::literal("#!/usr/bin/env bash", "env bash"),
                ValidationPattern::literal("#!/usr/bin/env sh", "env sh"),
            ],
        );

        // Shebang
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::Shebang,
            vec![
                ValidationPattern::literal("#!/bin/bash", "bash shebang"),
                ValidationPattern::literal("#!/bin/sh", "sh shebang"),
                ValidationPattern::literal("#!/usr/bin/env bash", "env bash"),
            ],
        );

        // Environment variable access
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::EnvVarAccess,
            vec![
                ValidationPattern::literal("$CERT_X_GEN_TARGET_HOST", "target host var")
                    .with_suggestion("HOST=\"$CERT_X_GEN_TARGET_HOST\""),
                ValidationPattern::literal("${CERT_X_GEN_TARGET_HOST", "target host var"),
                ValidationPattern::regex(r"\$\{?\w+\}?", "environment variable"),
            ],
        );

        // Command execution (inherent to shell)
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::CommandExecution,
            vec![
                ValidationPattern::literal("eval ", "eval - be careful"),
                ValidationPattern::literal("$(", "command substitution"),
                ValidationPattern::literal("`", "backticks"),
            ],
        );

        // Unsafe patterns
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::UnsafeFunctions,
            vec![
                ValidationPattern::regex(r"eval\s+\$", "eval with variable - dangerous"),
                ValidationPattern::regex(r#"echo\s+-e"#, "echo -e (ANSI) - avoid for JSON"),
                ValidationPattern::regex(r"\\x1b\[", "ANSI escape codes"),
                ValidationPattern::regex(r"\\033\[", "ANSI escape codes"),
                ValidationPattern::regex(r"\\e\[", "ANSI escape codes"),
            ],
        );

        // Comments
        self.add_patterns(
            TemplateLanguage::Shell,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("#", "single line comment")],
        );
    }

    // ========================================================================
    // YAML PATTERNS
    // ========================================================================
    fn register_yaml_patterns(&mut self) {
        // YAML doesn't have network imports in the same sense
        // but we check for protocol definitions
        self.add_patterns(
            TemplateLanguage::Yaml,
            PatternCategory::NetworkImport,
            vec![
                ValidationPattern::literal("protocol:", "protocol definition"),
                ValidationPattern::literal("http:", "HTTP protocol section"),
                ValidationPattern::literal("network:", "network protocol section"),
                ValidationPattern::literal("tcp:", "TCP protocol"),
                ValidationPattern::literal("dns:", "DNS protocol"),
            ],
        );

        // JSON output (not applicable for YAML templates)
        self.add_patterns(TemplateLanguage::Yaml, PatternCategory::JsonOutput, vec![]);

        // Comments
        self.add_patterns(
            TemplateLanguage::Yaml,
            PatternCategory::CommentSingle,
            vec![ValidationPattern::literal("#", "YAML comment")],
        );
    }
}

impl Default for PatternRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let pattern = ValidationPattern::literal("import json", "json import");
        assert!(pattern.matches("import json"));
        assert!(!pattern.matches("import sys"));
    }

    #[test]
    fn test_regex_pattern_matching() {
        let pattern = ValidationPattern::regex(r"def\s+main\s*\(", "main function");
        assert!(pattern.matches("def main():"));
        assert!(pattern.matches("def main( ):"));
        assert!(!pattern.matches("def other():"));
    }

    #[test]
    fn test_registry_has_patterns() {
        let registry = PatternRegistry::new();

        // Check Python has network imports
        let python_network =
            registry.get_patterns(TemplateLanguage::Python, PatternCategory::NetworkImport);
        assert!(!python_network.is_empty());

        // Check Go has entry point
        let go_entry = registry.get_patterns(TemplateLanguage::Go, PatternCategory::EntryPoint);
        assert!(!go_entry.is_empty());
    }

    #[test]
    fn test_has_any_match() {
        let registry = PatternRegistry::new();
        let code = "import socket\nimport json\n";

        assert!(registry.has_any_match(
            code,
            TemplateLanguage::Python,
            PatternCategory::NetworkImport
        ));
        assert!(registry.has_any_match(
            code,
            TemplateLanguage::Python,
            PatternCategory::JsonImport
        ));
    }

    #[test]
    fn test_find_lines() {
        let pattern = ValidationPattern::literal("TODO", "todo marker");
        let code = "line 1\n# TODO: fix this\nline 3\n# TODO: another\n";
        let lines = pattern.find_lines(code);
        assert_eq!(lines, vec![2, 4]);
    }
}
