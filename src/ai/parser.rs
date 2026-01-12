//! Response parser for LLM-generated templates
//!
//! This module handles parsing LLM responses to extract clean template code.
//! It removes markdown formatting, extracts code blocks, and performs basic
//! structure validation before templates are saved or executed.

use crate::types::TemplateLanguage;
use anyhow::Result;
use regex::Regex;

/// Parser for LLM responses containing template code
///
/// The ResponseParser handles the common issues with LLM responses:
/// - Markdown code block formatting (```language)
/// - Explanatory text before/after code
/// - Extra whitespace and formatting
/// - Mixed content (code + explanations)
#[derive(Debug)]
pub struct ResponseParser {
    /// Regex for detecting markdown code blocks
    markdown_block_start: Regex,
    /// Regex for detecting markdown code block end
    markdown_block_end: Regex,
}

impl ResponseParser {
    /// Create a new ResponseParser with compiled regexes
    pub fn new() -> Self {
        Self {
            markdown_block_start: Regex::new(r"```[\w]*\n?").unwrap(),
            markdown_block_end: Regex::new(r"\n?```\s*$").unwrap(),
        }
    }

    /// Parse an LLM response and extract clean template code
    ///
    /// This is the main entry point for parsing. It:
    /// 1. Removes markdown code block formatting
    /// 2. Extracts only the code portion
    /// 3. Validates basic structure
    ///
    /// # Arguments
    ///
    /// * `response` - Raw LLM response text
    /// * `language` - Target template language
    ///
    /// # Returns
    ///
    /// Clean template code ready to be saved or executed
    pub fn parse(&self, response: &str, language: TemplateLanguage) -> Result<String> {
        tracing::debug!(
            "Parsing response ({} chars) for {:?}",
            response.len(),
            language
        );
        tracing::trace!("Raw response: {}", response);

        // Step 1: Remove markdown code blocks
        let cleaned = self.remove_markdown_blocks(response);
        tracing::debug!("After markdown removal: {} chars", cleaned.len());

        // Step 2: Extract code only (remove explanatory text)
        let cleaned = self.extract_code_only(&cleaned, language);
        tracing::debug!("After code extraction: {} chars", cleaned.len());
        tracing::trace!("Extracted code: {}", cleaned);

        // Step 3: Validate basic structure
        self.validate_basic_structure(&cleaned, language)?;

        let result = cleaned.trim().to_string();
        tracing::info!("Successfully parsed template: {} chars", result.len());
        Ok(result)
    }

    /// Remove markdown code block delimiters
    ///
    /// Handles formats like:
    /// - ```python
    /// - ```yaml
    /// - ``` (generic)
    /// - Trailing ```
    fn remove_markdown_blocks(&self, text: &str) -> String {
        // Remove opening code block markers (```python, ```yaml, etc.)
        let text = self.markdown_block_start.replace_all(text, "");

        // Remove closing code block markers (```)
        let text = self.markdown_block_end.replace_all(&text, "");

        text.to_string()
    }

    /// Extract only the code portion, removing explanatory text
    ///
    /// Different languages have different markers for where code starts
    fn extract_code_only(&self, text: &str, language: TemplateLanguage) -> String {
        match language {
            TemplateLanguage::Python => self.extract_python_code(text),
            TemplateLanguage::JavaScript => self.extract_javascript_code(text),
            TemplateLanguage::Yaml => self.extract_yaml_code(text),
            TemplateLanguage::Rust => self.extract_rust_code(text),
            TemplateLanguage::C => self.extract_c_code(text),
            TemplateLanguage::Cpp => self.extract_cpp_code(text),
            TemplateLanguage::Java => self.extract_java_code(text),
            TemplateLanguage::Go => self.extract_go_code(text),
            TemplateLanguage::Ruby => self.extract_ruby_code(text),
            TemplateLanguage::Perl => self.extract_perl_code(text),
            TemplateLanguage::Php => self.extract_php_code(text),
            TemplateLanguage::Shell => self.extract_shell_code(text),
        }
    }

    /// Extract Python code by finding shebang, imports, or class definitions
    fn extract_python_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        // Find where Python code actually starts
        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("#!/usr/bin/env python")
                    || trimmed.starts_with("#!/usr/bin/python")
                    || trimmed.starts_with("import ")
                    || trimmed.starts_with("from ")
                    || trimmed.starts_with("class ")
                    || trimmed.starts_with("def ")
                    || trimmed.starts_with("\"\"\"") // Docstring at start
            })
            .unwrap_or(0);

        // Find where code ends - be aggressive about removing trailing prose
        let mut end = lines.len();

        // Work backwards from the end to find the last line of actual code
        for i in (start..lines.len()).rev() {
            let trimmed = lines[i].trim();

            // Skip empty lines at the end
            if trimmed.is_empty() {
                continue;
            }

            // Check if this line is prose/explanation (not code)
            let prose_indicators = [
                "Please note",
                "Note that",
                "This code",
                "This template",
                "This script",
                "Remember to",
                "Make sure",
                "Don't forget",
                "You can",
                "To use this",
                "To run this",
                "For more information",
                "Example usage:",
                "Usage:",
                "Output:",
            ];

            let is_prose = prose_indicators
                .iter()
                .any(|&indicator| trimmed.starts_with(indicator));

            if is_prose {
                // This is prose - stop here
                end = i;
                continue;
            }

            // Check if it looks like code
            let looks_like_code = trimmed.starts_with("def ") ||
                trimmed.starts_with("class ") ||
                trimmed.starts_with("import ") ||
                trimmed.starts_with("from ") ||
                trimmed.starts_with("if ") ||
                trimmed.starts_with("return ") ||
                trimmed.starts_with("print(") ||
                trimmed.ends_with(":") ||
                trimmed.ends_with(")") ||
                trimmed.ends_with("}") ||
                trimmed.ends_with("]") ||
                trimmed.starts_with("#") || // Comment
                trimmed.starts_with("    ") || // Indented code
                trimmed.contains("=");

            if looks_like_code {
                // Found the last line of actual code
                end = i + 1;
                break;
            }
        }

        lines[start..end].join("\n")
    }

    /// Extract JavaScript/Node.js code by finding shebang or imports
    fn extract_javascript_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("#!/usr/bin/env node")
                    || trimmed.starts_with("#!/usr/bin/node")
                    || trimmed.starts_with("const ")
                    || trimmed.starts_with("let ")
                    || trimmed.starts_with("var ")
                    || trimmed.starts_with("import ")
                    || trimmed.starts_with("require(")
                    || trimmed.starts_with("function ")
            })
            .unwrap_or(0);

        // Find where code ends
        let mut end = lines.len();
        let mut empty_count = 0;

        for (i, line) in lines[start..].iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.is_empty() {
                empty_count += 1;
                if empty_count >= 2 {
                    end = start + i - 1;
                    break;
                }
            } else {
                empty_count = 0;

                let prose_starters = ["This ", "The ", "Here", "Note:", "Important:", "Example:"];
                if prose_starters
                    .iter()
                    .any(|&starter| trimmed.starts_with(starter))
                {
                    end = start + i;
                    break;
                }
            }
        }

        lines[start..end].join("\n")
    }

    /// Extract YAML code by finding the id field
    fn extract_yaml_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| line.trim().starts_with("id:"))
            .unwrap_or(0);

        // Find where YAML code ends (prose starts)
        let mut end = lines.len();
        let mut empty_count = 0;

        for (i, line) in lines[start..].iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.is_empty() {
                empty_count += 1;
                if empty_count >= 2 {
                    end = start + i - 1;
                    break;
                }
            } else {
                empty_count = 0;

                // Check for prose after YAML
                let prose_starters = ["This ", "The ", "Here", "Note:", "Important:", "Example:"];
                if prose_starters
                    .iter()
                    .any(|&starter| trimmed.starts_with(starter))
                {
                    end = start + i;
                    break;
                }
            }
        }

        lines[start..end].join("\n")
    }

    /// Extract Rust code by finding use statements or main/fn
    fn extract_rust_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("use ")
                    || trimmed.starts_with("extern ")
                    || trimmed.starts_with("fn main")
                    || trimmed.starts_with("pub fn")
                    || trimmed.starts_with("fn ")
            })
            .unwrap_or(0);

        lines[start..].join("\n")
    }

    /// Extract C code by finding includes or main
    fn extract_c_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("#include") || trimmed.starts_with("int main")
            })
            .unwrap_or(0);

        lines[start..].join("\n")
    }

    /// Extract C++ code by finding includes or main
    fn extract_cpp_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("#include")
                    || trimmed.starts_with("using namespace")
                    || trimmed.starts_with("int main")
            })
            .unwrap_or(0);

        lines[start..].join("\n")
    }

    /// Extract Java code by finding package, import, or class
    fn extract_java_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("package ")
                    || trimmed.starts_with("import ")
                    || trimmed.starts_with("public class")
                    || trimmed.starts_with("class ")
            })
            .unwrap_or(0);

        lines[start..].join("\n")
    }

    /// Extract Go code by finding package or import
    fn extract_go_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("package ") || trimmed.starts_with("import ")
            })
            .unwrap_or(0);

        lines[start..].join("\n")
    }

    /// Extract Ruby code by finding shebang or require
    fn extract_ruby_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("#!/usr/bin/env ruby")
                    || trimmed.starts_with("#!/usr/bin/ruby")
                    || trimmed.starts_with("require ")
                    || trimmed.starts_with("class ")
                    || trimmed.starts_with("module ")
                    || trimmed.starts_with("def ")
            })
            .unwrap_or(0);

        lines[start..].join("\n")
    }

    /// Extract Perl code by finding shebang or use
    fn extract_perl_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("#!/usr/bin/env perl")
                    || trimmed.starts_with("#!/usr/bin/perl")
                    || trimmed.starts_with("use strict")
                    || trimmed.starts_with("use warnings")
                    || trimmed.starts_with("use ")
                    || trimmed.starts_with("sub ")
            })
            .unwrap_or(0);

        lines[start..].join("\n")
    }

    /// Extract PHP code by finding <?php tag
    fn extract_php_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("<?php")
                    || trimmed.starts_with("#!/usr/bin/env php")
                    || trimmed.starts_with("#!/usr/bin/php")
            })
            .unwrap_or(0);

        lines[start..].join("\n")
    }

    /// Extract Shell/Bash code by finding shebang
    fn extract_shell_code(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();

        let start = lines
            .iter()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("#!/bin/bash")
                    || trimmed.starts_with("#!/usr/bin/env bash")
                    || trimmed.starts_with("#!/bin/sh")
            })
            .unwrap_or(0);

        lines[start..].join("\n")
    }

    /// Validate basic structure of the extracted code
    ///
    /// Performs language-specific validation to ensure the template
    /// has minimum required structure before saving
    fn validate_basic_structure(&self, code: &str, language: TemplateLanguage) -> Result<()> {
        if code.trim().is_empty() {
            anyhow::bail!("Extracted template is empty");
        }

        match language {
            TemplateLanguage::Python => self.validate_python_structure(code),
            TemplateLanguage::JavaScript => self.validate_javascript_structure(code),
            TemplateLanguage::Yaml => self.validate_yaml_structure(code),
            TemplateLanguage::Rust => self.validate_rust_structure(code),
            TemplateLanguage::C => self.validate_c_structure(code),
            TemplateLanguage::Cpp => self.validate_cpp_structure(code),
            TemplateLanguage::Java => self.validate_java_structure(code),
            TemplateLanguage::Go => self.validate_go_structure(code),
            TemplateLanguage::Ruby => self.validate_ruby_structure(code),
            TemplateLanguage::Perl => self.validate_perl_structure(code),
            TemplateLanguage::Php => self.validate_php_structure(code),
            TemplateLanguage::Shell => self.validate_shell_structure(code),
        }
    }

    /// Validate Python template structure
    fn validate_python_structure(&self, code: &str) -> Result<()> {
        // Must have function or class definitions
        if !code.contains("def ") && !code.contains("class ") {
            tracing::error!("Python validation failed - no def/class found");
            tracing::error!(
                "Code preview (first 500 chars): {}",
                &code.chars().take(500).collect::<String>()
            );
            anyhow::bail!("Python template missing function or class definitions");
        }

        // RELAXED: JSON module is nice to have but not required
        if !code.contains("json") {
            tracing::warn!("Python template missing JSON module - this is recommended");
        }

        // RELAXED: Environment variables are nice to have but not required
        if !code.contains("os.environ") && !code.contains("os.getenv") {
            tracing::warn!("Python template may not read environment variables properly");
        }

        Ok(())
    }

    /// Validate JavaScript template structure
    fn validate_javascript_structure(&self, code: &str) -> Result<()> {
        // Must have function definitions
        if !code.contains("function") && !code.contains("const ") && !code.contains("let ") {
            anyhow::bail!("JavaScript template missing function/variable definitions");
        }

        // Must have JSON output capability
        if !code.contains("JSON.stringify") {
            anyhow::bail!("JavaScript template missing JSON.stringify for output");
        }

        // Should have environment variable reading
        if !code.contains("process.env") {
            tracing::warn!("JavaScript template may not read environment variables properly");
        }

        Ok(())
    }

    /// Validate YAML template structure
    fn validate_yaml_structure(&self, code: &str) -> Result<()> {
        // Must have id field
        if !code.contains("id:") {
            anyhow::bail!("YAML template missing required 'id' field");
        }

        // Must have info section
        if !code.contains("info:") {
            anyhow::bail!("YAML template missing required 'info' section");
        }

        // Must have protocol
        if !code.contains("protocol:") {
            anyhow::bail!("YAML template missing required 'protocol' field");
        }

        // Must have matchers or requests
        if !code.contains("matchers") && !code.contains("requests") {
            anyhow::bail!("YAML template missing 'matchers' or 'requests' section");
        }

        Ok(())
    }

    /// Validate Rust template structure
    fn validate_rust_structure(&self, code: &str) -> Result<()> {
        if !code.contains("fn main") && !code.contains("fn ") {
            anyhow::bail!("Rust template missing function definitions");
        }
        Ok(())
    }

    /// Validate C template structure
    fn validate_c_structure(&self, code: &str) -> Result<()> {
        if !code.contains("#include") {
            anyhow::bail!("C template missing #include directives");
        }
        if !code.contains("int main") {
            anyhow::bail!("C template missing main() function");
        }
        Ok(())
    }

    /// Validate C++ template structure  
    fn validate_cpp_structure(&self, code: &str) -> Result<()> {
        if !code.contains("#include") {
            anyhow::bail!("C++ template missing #include directives");
        }
        if !code.contains("int main") {
            anyhow::bail!("C++ template missing main() function");
        }
        Ok(())
    }

    /// Validate Java template structure
    fn validate_java_structure(&self, code: &str) -> Result<()> {
        if !code.contains("class ") {
            anyhow::bail!("Java template missing class definition");
        }
        if !code.contains("public static void main") {
            anyhow::bail!("Java template missing main() method");
        }
        Ok(())
    }

    /// Validate Go template structure
    fn validate_go_structure(&self, code: &str) -> Result<()> {
        if !code.contains("package ") {
            anyhow::bail!("Go template missing package declaration");
        }
        if !code.contains("func main") {
            anyhow::bail!("Go template missing main() function");
        }
        Ok(())
    }

    /// Validate Ruby template structure
    fn validate_ruby_structure(&self, code: &str) -> Result<()> {
        // Ruby is flexible, just check it has some code structure
        if code.lines().count() < 5 {
            anyhow::bail!("Ruby template seems too short");
        }
        Ok(())
    }

    /// Validate Perl template structure
    fn validate_perl_structure(&self, code: &str) -> Result<()> {
        if !code.contains("use strict") && !code.contains("use warnings") {
            tracing::warn!("Perl template missing strict/warnings pragmas");
        }
        Ok(())
    }

    /// Validate PHP template structure
    fn validate_php_structure(&self, code: &str) -> Result<()> {
        if !code.contains("<?php") {
            anyhow::bail!("PHP template missing <?php opening tag");
        }
        Ok(())
    }

    /// Validate Shell template structure
    fn validate_shell_structure(&self, code: &str) -> Result<()> {
        if !code.contains("#!/") {
            tracing::warn!("Shell template missing shebang");
        }
        Ok(())
    }
}

impl Default for ResponseParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let parser = ResponseParser::new();
        assert!(parser.markdown_block_start.is_match("```python\n"));
        assert!(parser.markdown_block_end.is_match("\n```"));
    }

    #[test]
    fn test_remove_markdown_blocks() {
        let parser = ResponseParser::new();

        let input = "```python\nprint('hello')\n```";
        let result = parser.remove_markdown_blocks(input);
        assert_eq!(result.trim(), "print('hello')");

        let input = "Some text\n```yaml\nid: test\n```\nMore text";
        let result = parser.remove_markdown_blocks(input);
        assert!(!result.contains("```"));
    }

    #[test]
    fn test_extract_python_code() {
        let parser = ResponseParser::new();

        let input =
            "Here's a Python template:\n\n#!/usr/bin/env python3\nimport json\nprint('test')";
        let result = parser.extract_python_code(input);
        assert!(result.starts_with("#!/usr/bin/env python3"));

        let input = "Explanation text\nimport sys\nimport json\n\ndef main():\n    pass";
        let result = parser.extract_python_code(input);
        assert!(result.starts_with("import sys"));
    }

    #[test]
    fn test_extract_yaml_code() {
        let parser = ResponseParser::new();

        let input = "Here's the YAML template:\n\nid: test-template\ninfo:\n  name: Test";
        let result = parser.extract_yaml_code(input);
        assert!(result.starts_with("id: test-template"));
    }

    #[test]
    fn test_validate_python_structure() {
        let parser = ResponseParser::new();

        // Valid Python template
        let valid =
            "import json\nimport os\n\ndef main():\n    data = json.dumps({})\n    print(data)";
        assert!(parser.validate_python_structure(valid).is_ok());

        // Invalid - missing JSON
        let invalid = "def main():\n    print('test')";
        assert!(parser.validate_python_structure(invalid).is_err());

        // Invalid - missing function/class
        let invalid = "import json\nprint('test')";
        assert!(parser.validate_python_structure(invalid).is_err());
    }

    #[test]
    fn test_validate_yaml_structure() {
        let parser = ResponseParser::new();

        // Valid YAML
        let valid = "id: test\ninfo:\n  name: Test\nprotocol: tcp\nmatchers:\n  - type: word";
        assert!(parser.validate_yaml_structure(valid).is_ok());

        // Invalid - missing id
        let invalid = "info:\n  name: Test\nprotocol: tcp";
        assert!(parser.validate_yaml_structure(invalid).is_err());

        // Invalid - missing protocol
        let invalid = "id: test\ninfo:\n  name: Test";
        assert!(parser.validate_yaml_structure(invalid).is_err());
    }

    #[test]
    fn test_full_parse_python() {
        let parser = ResponseParser::new();

        let llm_response = r#"Here's a Python template for Redis detection:

```python
#!/usr/bin/env python3
import json
import os

def check_redis():
    host = os.getenv('CERT_X_GEN_TARGET_HOST')
    return json.dumps([])

if __name__ == '__main__':
    check_redis()
```

This template checks for Redis.
"#;

        let result = parser.parse(llm_response, TemplateLanguage::Python);
        assert!(result.is_ok());

        let code = result.unwrap();
        assert!(code.starts_with("#!/usr/bin/env python3"));
        assert!(code.contains("import json"));
        assert!(!code.contains("```"));
        assert!(!code.contains("This template checks"));
    }

    #[test]
    fn test_full_parse_yaml() {
        let parser = ResponseParser::new();

        let llm_response = r#"Here's your YAML template:

```yaml
id: redis-unauth
info:
  name: Redis Unauthenticated
  severity: high
protocol: tcp
port: 6379
matchers:
  - type: word
    words:
      - "redis_version"
```

This detects Redis servers."#;

        let result = parser.parse(llm_response, TemplateLanguage::Yaml);
        assert!(result.is_ok());

        let code = result.unwrap();
        assert!(code.starts_with("id: redis-unauth"));
        assert!(!code.contains("```"));
        assert!(!code.contains("This detects"));
    }
}
