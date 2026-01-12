//! Syntax checking using external tools
//!
//! This module provides syntax validation by invoking external compilers/interpreters.
//! Each language has its own syntax checking command:
//! - Python: py_compile module
//! - JavaScript: node --check
//! - Ruby: ruby -c
//! - Perl: perl -c
//! - PHP: php -l
//! - Shell: bash -n or shellcheck
//! - Go: gofmt -e
//! - Rust: rustc --emit=metadata (limited)
//! - C/C++: gcc/g++ -fsyntax-only

use super::TemplateDiagnostic;
use crate::types::TemplateLanguage;
use anyhow::Result;
use std::io::Write;
use std::process::{Command, Stdio};

/// Syntax checker using external tools
#[derive(Debug)]
pub struct SyntaxChecker {
    /// Whether to skip syntax checking for languages without available tools
    skip_unavailable: bool,
}

impl SyntaxChecker {
    /// Create a new syntax checker
    pub fn new() -> Self {
        Self {
            skip_unavailable: true,
        }
    }

    /// Create a syntax checker that reports missing tools
    pub fn new_strict() -> Self {
        Self {
            skip_unavailable: false,
        }
    }

    /// Check syntax for the given code and language
    pub fn check(&self, code: &str, language: TemplateLanguage) -> Result<Vec<TemplateDiagnostic>> {
        match language {
            TemplateLanguage::Python => self.check_python(code),
            TemplateLanguage::JavaScript => self.check_javascript(code),
            TemplateLanguage::Ruby => self.check_ruby(code),
            TemplateLanguage::Perl => self.check_perl(code),
            TemplateLanguage::Php => self.check_php(code),
            TemplateLanguage::Shell => self.check_shell(code),
            TemplateLanguage::Go => self.check_go(code),
            TemplateLanguage::Rust => self.check_rust(code),
            TemplateLanguage::C => self.check_c(code),
            TemplateLanguage::Cpp => self.check_cpp(code),
            TemplateLanguage::Java => self.check_java(code),
            TemplateLanguage::Yaml => Ok(vec![]), // YAML handled elsewhere
        }
    }

    /// Check Python syntax using py_compile
    fn check_python(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        let python_cmd = self.find_python()?;
        
        let script = format!(
            r#"
import sys
import py_compile
import tempfile
import os

code = sys.stdin.read()
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write(code)
    temp_path = f.name

try:
    py_compile.compile(temp_path, doraise=True)
    print("OK")
except py_compile.PyCompileError as e:
    print(f"ERROR:{{e.lineno}}:{{e.msg}}")
finally:
    os.unlink(temp_path)
"#
        );

        self.run_syntax_check(&python_cmd, &["-c", &script], code, "python")
    }

    /// Check JavaScript syntax using node --check
    fn check_javascript(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        if !self.is_command_available("node") {
            return self.handle_missing_tool("node", TemplateLanguage::JavaScript);
        }

        self.run_syntax_check("node", &["--check", "-"], code, "javascript")
    }

    /// Check Ruby syntax using ruby -c
    fn check_ruby(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        if !self.is_command_available("ruby") {
            return self.handle_missing_tool("ruby", TemplateLanguage::Ruby);
        }

        self.run_syntax_check("ruby", &["-c", "-"], code, "ruby")
    }

    /// Check Perl syntax using perl -c
    fn check_perl(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        if !self.is_command_available("perl") {
            return self.handle_missing_tool("perl", TemplateLanguage::Perl);
        }

        self.run_syntax_check("perl", &["-c", "-"], code, "perl")
    }

    /// Check PHP syntax using php -l
    fn check_php(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        if !self.is_command_available("php") {
            return self.handle_missing_tool("php", TemplateLanguage::Php);
        }

        self.run_syntax_check("php", &["-l", "-"], code, "php")
    }

    /// Check Shell syntax using bash -n or shellcheck
    fn check_shell(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        // Prefer shellcheck if available
        if self.is_command_available("shellcheck") {
            return self.run_shellcheck(code);
        }

        // Fall back to bash -n
        if self.is_command_available("bash") {
            return self.run_syntax_check("bash", &["-n", "-"], code, "shell");
        }

        self.handle_missing_tool("bash or shellcheck", TemplateLanguage::Shell)
    }

    /// Check Go syntax using gofmt
    fn check_go(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        if !self.is_command_available("gofmt") {
            return self.handle_missing_tool("gofmt", TemplateLanguage::Go);
        }

        self.run_syntax_check("gofmt", &["-e"], code, "go")
    }

    /// Check Rust syntax (limited - can't fully compile without cargo)
    fn check_rust(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        // Rust syntax checking is limited without a full cargo project
        // We do basic bracket matching and some pattern checks
        let mut diagnostics = Vec::new();

        // Check for unbalanced braces
        let mut brace_count = 0;
        let mut paren_count = 0;
        let mut bracket_count = 0;

        for (line_num, line) in code.lines().enumerate() {
            for ch in line.chars() {
                match ch {
                    '{' => brace_count += 1,
                    '}' => brace_count -= 1,
                    '(' => paren_count += 1,
                    ')' => paren_count -= 1,
                    '[' => bracket_count += 1,
                    ']' => bracket_count -= 1,
                    _ => {}
                }

                if brace_count < 0 || paren_count < 0 || bracket_count < 0 {
                    diagnostics.push(
                        TemplateDiagnostic::error(
                            "syntax.unbalanced_brackets",
                            "Unbalanced brackets detected",
                        )
                        .with_location(line_num + 1, None),
                    );
                    return Ok(diagnostics);
                }
            }
        }

        if brace_count != 0 {
            diagnostics.push(TemplateDiagnostic::error(
                "syntax.unbalanced_braces",
                format!("Unbalanced braces: {} unclosed", brace_count),
            ));
        }

        Ok(diagnostics)
    }

    /// Check C syntax using gcc -fsyntax-only
    fn check_c(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        // Try gcc first, then clang
        let compiler = if self.is_command_available("gcc") {
            "gcc"
        } else if self.is_command_available("clang") {
            "clang"
        } else {
            return self.handle_missing_tool("gcc or clang", TemplateLanguage::C);
        };

        self.run_syntax_check(compiler, &["-fsyntax-only", "-x", "c", "-"], code, "c")
    }

    /// Check C++ syntax using g++ -fsyntax-only
    fn check_cpp(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        let compiler = if self.is_command_available("g++") {
            "g++"
        } else if self.is_command_available("clang++") {
            "clang++"
        } else {
            return self.handle_missing_tool("g++ or clang++", TemplateLanguage::Cpp);
        };

        self.run_syntax_check(compiler, &["-fsyntax-only", "-x", "c++", "-"], code, "cpp")
    }

    /// Check Java syntax (limited - needs file)
    fn check_java(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        // Java requires files with matching class names, so we do basic checks
        let mut diagnostics = Vec::new();

        // Check for class definition
        if !code.contains("class ") {
            diagnostics.push(TemplateDiagnostic::error(
                "syntax.java.no_class",
                "Java code must contain a class definition",
            ));
        }

        // Check for balanced braces
        let brace_count: i32 = code.chars().map(|c| match c {
            '{' => 1,
            '}' => -1,
            _ => 0,
        }).sum();

        if brace_count != 0 {
            diagnostics.push(TemplateDiagnostic::error(
                "syntax.unbalanced_braces",
                format!("Unbalanced braces: {} unclosed", brace_count),
            ));
        }

        Ok(diagnostics)
    }

    // ========================================================================
    // Helper methods
    // ========================================================================

    /// Find Python executable (python3 or python)
    fn find_python(&self) -> Result<String> {
        if self.is_command_available("python3") {
            Ok("python3".to_string())
        } else if self.is_command_available("python") {
            Ok("python".to_string())
        } else {
            anyhow::bail!("Python not found")
        }
    }

    /// Check if a command is available in PATH
    fn is_command_available(&self, cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Handle missing tool
    fn handle_missing_tool(&self, tool: &str, language: TemplateLanguage) -> Result<Vec<TemplateDiagnostic>> {
        if self.skip_unavailable {
            Ok(vec![])
        } else {
            Ok(vec![TemplateDiagnostic::info(
                "syntax.tool_unavailable",
                format!(
                    "Syntax checking for {} requires '{}' which is not available",
                    language, tool
                ),
            )])
        }
    }

    /// Run a syntax check command
    fn run_syntax_check(
        &self,
        cmd: &str,
        args: &[&str],
        code: &str,
        lang: &str,
    ) -> Result<Vec<TemplateDiagnostic>> {
        let mut diagnostics = Vec::new();

        let mut child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Write code to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(code.as_bytes())?;
        }

        let output = child.wait_with_output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let error_output = if stderr.is_empty() { stdout } else { stderr };

            // Parse error output
            diagnostics.extend(self.parse_error_output(&error_output, lang));
        }

        Ok(diagnostics)
    }

    /// Run shellcheck with JSON output for better parsing
    fn run_shellcheck(&self, code: &str) -> Result<Vec<TemplateDiagnostic>> {
        let mut diagnostics = Vec::new();

        let mut child = Command::new("shellcheck")
            .args(["--format=gcc", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(code.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse GCC-style output: file:line:col: severity: message
        for line in stdout.lines() {
            if let Some(diag) = self.parse_gcc_style_error(line) {
                diagnostics.push(diag);
            }
        }

        Ok(diagnostics)
    }

    /// Parse error output from various tools
    fn parse_error_output(&self, output: &str, lang: &str) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Try to parse line number from common formats
            if let Some(diag) = self.parse_gcc_style_error(line) {
                diagnostics.push(diag);
            } else if let Some(diag) = self.parse_python_style_error(line) {
                diagnostics.push(diag);
            } else if line.to_lowercase().contains("error") 
                || line.to_lowercase().contains("syntax") 
            {
                // Generic error
                diagnostics.push(TemplateDiagnostic::error(
                    format!("syntax.{}", lang),
                    line.to_string(),
                ));
            }
        }

        // If no specific errors parsed but we have output, add generic error
        if diagnostics.is_empty() && !output.trim().is_empty() {
            // Check if it's just "Syntax OK" or similar success message
            let lower = output.to_lowercase();
            if !lower.contains("ok") && !lower.contains("syntax correct") {
                diagnostics.push(TemplateDiagnostic::error(
                    format!("syntax.{}", lang),
                    output.lines().next().unwrap_or("Syntax error").to_string(),
                ));
            }
        }

        diagnostics
    }

    /// Parse GCC-style error: file:line:col: severity: message
    fn parse_gcc_style_error(&self, line: &str) -> Option<TemplateDiagnostic> {
        // Pattern: <file>:<line>:<col>: <type>: <message>
        // Or: <file>:<line>: <type>: <message>
        let re = regex::Regex::new(
            r"^[^:]+:(\d+):(?:\d+:)?\s*(error|warning|note|info):\s*(.+)$"
        ).ok()?;

        let caps = re.captures(line)?;
        let line_num: usize = caps.get(1)?.as_str().parse().ok()?;
        let severity = caps.get(2)?.as_str();
        let message = caps.get(3)?.as_str();

        let diag = match severity.to_lowercase().as_str() {
            "error" => TemplateDiagnostic::error("syntax.error", message),
            "warning" => TemplateDiagnostic::warning("syntax.warning", message),
            _ => TemplateDiagnostic::info("syntax.info", message),
        };

        Some(diag.with_location(line_num, None))
    }

    /// Parse Python-style error: File "<stdin>", line X
    fn parse_python_style_error(&self, line: &str) -> Option<TemplateDiagnostic> {
        // Pattern: File "...", line N
        let re = regex::Regex::new(r#"File "[^"]+", line (\d+)"#).ok()?;
        
        if let Some(caps) = re.captures(line) {
            let line_num: usize = caps.get(1)?.as_str().parse().ok()?;
            return Some(
                TemplateDiagnostic::error("syntax.python", line)
                    .with_location(line_num, None)
            );
        }

        // Also check for SyntaxError: ...
        if line.contains("SyntaxError:") || line.contains("IndentationError:") {
            return Some(TemplateDiagnostic::error("syntax.python", line));
        }

        None
    }
}

impl Default for SyntaxChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syntax_checker_creation() {
        let checker = SyntaxChecker::new();
        assert!(checker.skip_unavailable);

        let strict = SyntaxChecker::new_strict();
        assert!(!strict.skip_unavailable);
    }

    #[test]
    fn test_parse_gcc_style_error() {
        let checker = SyntaxChecker::new();
        
        let line = "-:5:10: error: expected ';' before 'return'";
        let diag = checker.parse_gcc_style_error(line);
        assert!(diag.is_some());
        let d = diag.unwrap();
        assert_eq!(d.line, Some(5));
        assert!(d.message.contains("expected"));
    }

    #[test]
    fn test_rust_brace_check() {
        let checker = SyntaxChecker::new();
        
        // Balanced code
        let balanced = "fn main() { let x = { 1 }; }";
        let diags = checker.check_rust(balanced).unwrap();
        assert!(diags.is_empty());

        // Unbalanced code
        let unbalanced = "fn main() { let x = { 1 };";
        let diags = checker.check_rust(unbalanced).unwrap();
        assert!(!diags.is_empty());
    }
}
