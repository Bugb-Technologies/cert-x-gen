//! Enhanced validator using the pattern registry
//!
//! This module provides unified validation across all languages using
//! the centralized pattern registry. It performs checks for:
//! - Network/socket code presence
//! - JSON output capabilities
//! - Error handling
//! - Timeout handling
//! - Security issues (command injection, unsafe functions)

use super::{PatternCategory, PatternRegistry, TemplateDiagnostic};
use crate::types::TemplateLanguage;
use anyhow::Result;

/// Enhanced validator using pattern registry for unified cross-language validation
#[derive(Debug)]
pub struct EnhancedValidator {
    registry: PatternRegistry,
}

impl EnhancedValidator {
    /// Create a new enhanced validator
    pub fn new() -> Self {
        Self {
            registry: PatternRegistry::new(),
        }
    }

    /// Run all enhanced validations
    pub fn validate(
        &self,
        code: &str,
        language: TemplateLanguage,
    ) -> Result<Vec<TemplateDiagnostic>> {
        let mut diagnostics = Vec::new();

        // Skip YAML as it has different validation needs
        if language == TemplateLanguage::Yaml {
            return Ok(diagnostics);
        }

        // Check for network/socket code
        diagnostics.extend(self.check_network_code(code, language));

        // Check for JSON handling
        diagnostics.extend(self.check_json_handling(code, language));

        // Check for error handling
        diagnostics.extend(self.check_error_handling(code, language));

        // Check for timeout handling
        diagnostics.extend(self.check_timeout_handling(code, language));

        // Check for entry point
        diagnostics.extend(self.check_entry_point(code, language));

        // Check for unsafe functions (security)
        diagnostics.extend(self.check_unsafe_functions(code, language));

        // Check for command execution (security)
        diagnostics.extend(self.check_command_execution(code, language));

        Ok(diagnostics)
    }

    /// Check for network/socket code presence
    ///
    /// "Security templates typically need network connectivity" holds for a
    /// template pointed at a host and port. It does not hold for one pointed at
    /// a local binary through `cli://`, which reaches its target by executing
    /// it -- suggesting `nc -z $HOST $PORT` there is wrong advice, and the whole
    /// CLI Security Baseline is that category.
    ///
    /// `shell.rs` and `common.rs` already ask `reaches_its_target` before
    /// giving target-shaped advice; this rule was the one that never did, so
    /// the s15 A3 exemption missed it.
    fn check_network_code(
        &self,
        code: &str,
        language: TemplateLanguage,
    ) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        // Exempt only a template that both declares the CLI kind and actually
        // reaches its target. Requiring the declaration keeps the rule's real
        // signal: a *network* template that reads the target host but never
        // opens a socket is still warned, which is what it is for.
        if super::common::declares_cli_target_kind(code) && super::common::reaches_its_target(code)
        {
            return diagnostics;
        }

        if !self
            .registry
            .has_any_match(code, language, PatternCategory::NetworkImport)
        {
            let patterns = self
                .registry
                .get_patterns(language, PatternCategory::NetworkImport);
            let suggestion = patterns
                .first()
                .and_then(|p| p.suggestion.clone())
                .unwrap_or_else(|| "Add network/socket imports".to_string());

            diagnostics.push(
                TemplateDiagnostic::warning(
                    "enhanced.missing_network_code",
                    format!(
                        "Template does not appear to have network/socket code. \
                         Security templates typically need network connectivity. \
                         Suggestion: {}",
                        suggestion
                    ),
                )
                .with_location(1, None),
            );
        }

        diagnostics
    }

    /// Check for JSON handling capabilities
    fn check_json_handling(
        &self,
        code: &str,
        language: TemplateLanguage,
    ) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        // Skip compiled languages that use native structs
        if matches!(
            language,
            TemplateLanguage::Rust
                | TemplateLanguage::C
                | TemplateLanguage::Cpp
                | TemplateLanguage::Go
        ) {
            // For compiled languages, just check for JSON library presence
            if !self
                .registry
                .has_any_match(code, language, PatternCategory::JsonImport)
            {
                let patterns = self
                    .registry
                    .get_patterns(language, PatternCategory::JsonImport);
                let suggestion = patterns
                    .first()
                    .and_then(|p| p.suggestion.clone())
                    .unwrap_or_else(|| "Add JSON library".to_string());

                diagnostics.push(
                    TemplateDiagnostic::info(
                        "enhanced.no_json_library",
                        format!(
                            "No JSON library detected. Templates should output JSON findings. \
                             Suggestion: {}",
                            suggestion
                        ),
                    )
                    .with_location(1, None),
                );
            }
            return diagnostics;
        }

        // For scripting languages, check import
        if !self
            .registry
            .has_any_match(code, language, PatternCategory::JsonImport)
        {
            let patterns = self
                .registry
                .get_patterns(language, PatternCategory::JsonImport);
            let suggestion = patterns
                .first()
                .and_then(|p| p.suggestion.clone())
                .unwrap_or_else(|| "Add JSON import".to_string());

            diagnostics.push(
                TemplateDiagnostic::warning(
                    "enhanced.missing_json_import",
                    format!(
                        "No JSON import detected. Templates must output JSON findings. \
                         Add: {}",
                        suggestion
                    ),
                )
                .with_location(1, None),
            );
        }

        // Check for JSON output
        if !self
            .registry
            .has_any_match(code, language, PatternCategory::JsonOutput)
        {
            diagnostics.push(
                TemplateDiagnostic::info(
                    "enhanced.no_json_output",
                    "No JSON serialization detected. Ensure template outputs valid JSON findings.",
                )
                .with_location(1, None),
            );
        }

        diagnostics
    }

    /// Check for error handling
    fn check_error_handling(
        &self,
        code: &str,
        language: TemplateLanguage,
    ) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        if !self
            .registry
            .has_any_match(code, language, PatternCategory::ErrorHandling)
        {
            let patterns = self
                .registry
                .get_patterns(language, PatternCategory::ErrorHandling);
            let suggestion = patterns
                .first()
                .and_then(|p| p.suggestion.clone())
                .unwrap_or_else(|| "Add error handling".to_string());

            diagnostics.push(
                TemplateDiagnostic::warning(
                    "enhanced.missing_error_handling",
                    format!(
                        "No error handling detected. Templates should handle errors gracefully \
                         to avoid crashes during scanning. Suggestion: {}",
                        suggestion
                    ),
                )
                .with_location(1, None),
            );
        }

        diagnostics
    }

    /// Check for timeout handling
    fn check_timeout_handling(
        &self,
        code: &str,
        language: TemplateLanguage,
    ) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        // Only warn if there's network code but no timeout
        let has_network =
            self.registry
                .has_any_match(code, language, PatternCategory::NetworkImport);
        let has_timeout =
            self.registry
                .has_any_match(code, language, PatternCategory::TimeoutHandling);

        if has_network && !has_timeout {
            let patterns = self
                .registry
                .get_patterns(language, PatternCategory::TimeoutHandling);
            let suggestion = patterns
                .first()
                .and_then(|p| p.suggestion.clone())
                .unwrap_or_else(|| "Add connection timeout".to_string());

            diagnostics.push(
                TemplateDiagnostic::info(
                    "enhanced.missing_timeout",
                    format!(
                        "Network code detected but no timeout handling found. \
                         Templates should have timeouts to avoid hanging. Suggestion: {}",
                        suggestion
                    ),
                )
                .with_location(1, None),
            );
        }

        diagnostics
    }

    /// Check for entry point (main function)
    fn check_entry_point(&self, code: &str, language: TemplateLanguage) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        // Languages that require explicit entry points
        let requires_entry_point = matches!(
            language,
            TemplateLanguage::Python
                | TemplateLanguage::Go
                | TemplateLanguage::Rust
                | TemplateLanguage::C
                | TemplateLanguage::Cpp
                | TemplateLanguage::Java
        );

        if requires_entry_point
            && !self
                .registry
                .has_any_match(code, language, PatternCategory::EntryPoint)
        {
            let patterns = self
                .registry
                .get_patterns(language, PatternCategory::EntryPoint);
            let suggestion = patterns
                .first()
                .and_then(|p| p.suggestion.clone())
                .unwrap_or_else(|| "Add main function".to_string());

            // For Python, it's an info (can run without main)
            // For compiled languages, it's an error
            let diagnostic = if language == TemplateLanguage::Python {
                TemplateDiagnostic::info(
                    "enhanced.no_entry_point",
                    format!(
                        "No main() function or __name__ guard found. \
                         Recommendation: {}",
                        suggestion
                    ),
                )
            } else {
                TemplateDiagnostic::error(
                    "enhanced.missing_entry_point",
                    format!(
                        "No main function found. {} templates require an entry point. \
                         Add: {}",
                        language, suggestion
                    ),
                )
            };

            diagnostics.push(diagnostic.with_location(1, None));
        }

        // Check for package declaration in Go
        if language == TemplateLanguage::Go
            && !self
                .registry
                .has_any_match(code, language, PatternCategory::PackageDeclaration)
        {
            diagnostics.push(
                TemplateDiagnostic::error(
                    "enhanced.missing_package_main",
                    "Go templates must have 'package main' declaration.",
                )
                .with_location(1, None),
            );
        }

        // Check for shebang in shell scripts
        if language == TemplateLanguage::Shell
            && !self
                .registry
                .has_any_match(code, language, PatternCategory::Shebang)
        {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "enhanced.missing_shebang",
                    "Shell script missing shebang (#!/bin/bash). Add at the first line.",
                )
                .with_location(1, None),
            );
        }

        // Check for <?php tag
        if language == TemplateLanguage::Php
            && !self
                .registry
                .has_any_match(code, language, PatternCategory::EntryPoint)
        {
            diagnostics.push(
                TemplateDiagnostic::error(
                    "enhanced.missing_php_tag",
                    "PHP template missing <?php opening tag.",
                )
                .with_location(1, None),
            );
        }

        diagnostics
    }

    /// Check for unsafe functions (security checks)
    fn check_unsafe_functions(
        &self,
        code: &str,
        language: TemplateLanguage,
    ) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        let matches = self
            .registry
            .get_matches(code, language, PatternCategory::UnsafeFunctions);

        for pattern in matches {
            let lines = pattern.find_lines(code);
            for line_num in lines {
                // Skip if in a comment (basic check)
                if let Some(line) = code.lines().nth(line_num - 1) {
                    if self.is_comment_line(line, language) {
                        continue;
                    }
                }

                diagnostics.push(
                    TemplateDiagnostic::warning(
                        "enhanced.unsafe_function",
                        format!(
                            "Potentially unsafe function detected: {}. {}",
                            pattern.description,
                            pattern
                                .suggestion
                                .as_deref()
                                .unwrap_or("Review for security implications.")
                        ),
                    )
                    .with_location(line_num, None),
                );
            }
        }

        diagnostics
    }

    /// Check for command execution patterns (security)
    fn check_command_execution(
        &self,
        code: &str,
        language: TemplateLanguage,
    ) -> Vec<TemplateDiagnostic> {
        let mut diagnostics = Vec::new();

        // Skip shell - command execution is expected
        if language == TemplateLanguage::Shell {
            return diagnostics;
        }

        let matches = self
            .registry
            .get_matches(code, language, PatternCategory::CommandExecution);

        for pattern in matches {
            let lines = pattern.find_lines(code);
            for line_num in lines {
                // Skip if in a comment
                if let Some(line) = code.lines().nth(line_num - 1) {
                    if self.is_comment_line(line, language) {
                        continue;
                    }
                }

                diagnostics.push(
                    TemplateDiagnostic::info(
                        "enhanced.command_execution",
                        format!(
                            "Command execution detected: {}. \
                             Ensure user input is properly sanitized to prevent injection.",
                            pattern.description
                        ),
                    )
                    .with_location(line_num, None),
                );
            }
        }

        diagnostics
    }

    /// Helper to check if a line is a comment
    fn is_comment_line(&self, line: &str, language: TemplateLanguage) -> bool {
        let trimmed = line.trim();

        match language {
            TemplateLanguage::Python
            | TemplateLanguage::Ruby
            | TemplateLanguage::Perl
            | TemplateLanguage::Shell
            | TemplateLanguage::Yaml => trimmed.starts_with('#'),
            TemplateLanguage::JavaScript
            | TemplateLanguage::Rust
            | TemplateLanguage::Go
            | TemplateLanguage::C
            | TemplateLanguage::Cpp
            | TemplateLanguage::Java
            | TemplateLanguage::Php => {
                trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
            }
        }
    }
}

impl Default for EnhancedValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CLI baseline template reaches its target by *running* it. Telling it
    /// to add `nc -z $HOST $PORT` is wrong advice, and it fired on all four of
    /// the s16 proof templates.
    #[test]
    fn a_declared_cli_template_is_not_told_to_open_a_socket() {
        let validator = EnhancedValidator::new();

        let by_target_host = concat!(
            "#!/bin/bash\n",
            "# @id: cli-baseline-b03-path-traversal\n",
            "# @target_kinds: cli\n",
            "BIN=\"$CERT_X_GEN_TARGET_HOST\"\n",
            "\"$BIN\" show ../outside.txt\n",
        );
        assert!(validator
            .check_network_code(by_target_host, TemplateLanguage::Shell)
            .is_empty());

        // The other way a CLI template may reach its target (s15 A3).
        let by_argv = concat!(
            "#!/bin/bash\n",
            "# @id: probe\n",
            "# @target_kinds: cli\n",
            "run \"$CERT_X_GEN_ARGV\"\n",
        );
        assert!(validator
            .check_network_code(by_argv, TemplateLanguage::Shell)
            .is_empty());
    }

    /// The exemption must not swallow the rule's real signal: a network
    /// template that reads the target host but never opens a socket is exactly
    /// what this rule is for, and is still warned.
    #[test]
    fn a_network_template_without_socket_code_is_still_warned() {
        let validator = EnhancedValidator::new();

        let no_declaration = concat!(
            "#!/bin/bash\n",
            "# @id: some-network-probe\n",
            "HOST=\"$CERT_X_GEN_TARGET_HOST\"\n",
            "echo \"$HOST\"\n",
        );
        let diags = validator.check_network_code(no_declaration, TemplateLanguage::Shell);
        assert!(!diags.is_empty(), "{:?}", diags);
        assert!(diags[0].code.contains("missing_network"));

        // Declaring a kind that is not `cli` earns nothing either.
        let other_kind = concat!(
            "#!/bin/bash\n",
            "# @id: probe\n",
            "# @target_kinds: https\n",
            "HOST=\"$CERT_X_GEN_TARGET_HOST\"\n",
        );
        assert!(!validator
            .check_network_code(other_kind, TemplateLanguage::Shell)
            .is_empty());
    }

    #[test]
    fn test_python_network_check() {
        let validator = EnhancedValidator::new();

        // Code without network imports
        let code_no_net = "import json\nprint('hello')";
        let diags = validator.check_network_code(code_no_net, TemplateLanguage::Python);
        assert!(!diags.is_empty());
        assert!(diags[0].code.contains("missing_network"));

        // Code with network imports
        let code_with_net = "import socket\nimport json";
        let diags = validator.check_network_code(code_with_net, TemplateLanguage::Python);
        assert!(diags.is_empty());
    }

    #[test]
    fn test_error_handling_check() {
        let validator = EnhancedValidator::new();

        // Python without error handling
        let code_no_err = "import socket\ns = socket.socket()";
        let diags = validator.check_error_handling(code_no_err, TemplateLanguage::Python);
        assert!(!diags.is_empty());

        // Python with error handling
        let code_with_err = "try:\n    s = socket.socket()\nexcept Exception as e:\n    pass";
        let diags = validator.check_error_handling(code_with_err, TemplateLanguage::Python);
        assert!(diags.is_empty());
    }

    #[test]
    fn test_go_entry_point_check() {
        let validator = EnhancedValidator::new();

        // Go without main
        let code_no_main = "package main\nimport \"fmt\"";
        let diags = validator.check_entry_point(code_no_main, TemplateLanguage::Go);
        assert!(!diags.is_empty());

        // Go with main
        let code_with_main = "package main\nfunc main() {}";
        let diags = validator.check_entry_point(code_with_main, TemplateLanguage::Go);
        // Should have no error about entry point (might have one about package)
        let entry_errors: Vec<_> = diags
            .iter()
            .filter(|d| d.code.contains("entry_point"))
            .collect();
        assert!(entry_errors.is_empty());
    }

    #[test]
    #[ignore] // TODO: Pattern registry needs unsafe function patterns
    fn test_unsafe_function_detection() {
        let validator = EnhancedValidator::new();

        // Python with eval
        let code = "result = eval(user_input)";
        let diags = validator.check_unsafe_functions(code, TemplateLanguage::Python);
        assert!(!diags.is_empty());
        assert!(diags[0].code.contains("unsafe"));
    }
}
