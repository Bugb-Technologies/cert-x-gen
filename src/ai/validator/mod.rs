//! Template validation framework with per-language validators
//!
//! This module provides comprehensive template validation including:
//! - Language detection from filename and content
//! - Language-specific syntax and structural validation
//! - Common validation across all languages (empty code, skeleton patterns, etc.)
//! - Language mismatch detection
//! - Unsupported language detection

#![allow(missing_docs)]

use crate::types::TemplateLanguage;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

mod common;
mod detect;
mod patterns;
mod enhanced;
mod syntax_check;
mod finding_schema;
mod python;
mod javascript;
mod rust_lang;
mod shell;
mod c_lang;
mod cpp;
mod java;
mod go_lang;
mod ruby;
mod perl;
mod php;
mod yaml;

pub use common::CommonValidator;
pub use patterns::{PatternRegistry, PatternCategory, ValidationPattern};
pub use enhanced::EnhancedValidator;
pub use syntax_check::SyntaxChecker;
pub use finding_schema::FindingSchemaValidator;
pub use detect::{detect_language_from_content, detect_language_from_filename};

/// Severity of a validation diagnostic
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
}

/// Diagnostic message with location and severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateDiagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl TemplateDiagnostic {
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: DiagnosticSeverity::Error,
            code: code.into(),
            message: message.into(),
            line: None,
            column: None,
        }
    }

    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: DiagnosticSeverity::Warning,
            code: code.into(),
            message: message.into(),
            line: None,
            column: None,
        }
    }

    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: DiagnosticSeverity::Info,
            code: code.into(),
            message: message.into(),
            line: None,
            column: None,
        }
    }

    pub fn with_location(mut self, line: usize, column: Option<usize>) -> Self {
        self.line = Some(line);
        self.column = column;
        self
    }
}

/// Main template validator
#[derive(Debug)]
pub struct TemplateValidator {
    pub strict: bool,
    /// Enable syntax checking with external tools
    pub syntax_check_enabled: bool,
    /// Enable enhanced pattern-based validation
    pub enhanced_validation_enabled: bool,
    /// Enable Finding schema validation
    pub schema_validation_enabled: bool,
    common: CommonValidator,
    enhanced: EnhancedValidator,
    syntax_checker: SyntaxChecker,
    schema_validator: FindingSchemaValidator,
}

impl TemplateValidator {
    /// Create a new validator with default settings
    pub fn new() -> Self {
        Self {
            strict: false,
            syntax_check_enabled: false, // Off by default for speed
            enhanced_validation_enabled: true,
            schema_validation_enabled: true,
            common: CommonValidator::new(),
            enhanced: EnhancedValidator::new(),
            syntax_checker: SyntaxChecker::new(),
            schema_validator: FindingSchemaValidator::new(),
        }
    }

    /// Create a strict validator (fails on warnings)
    pub fn new_strict() -> Self {
        Self {
            strict: true,
            syntax_check_enabled: true,
            enhanced_validation_enabled: true,
            schema_validation_enabled: true,
            common: CommonValidator::new(),
            enhanced: EnhancedValidator::new(),
            syntax_checker: SyntaxChecker::new_strict(),
            schema_validator: FindingSchemaValidator::new(),
        }
    }

    /// Enable or disable syntax checking
    pub fn with_syntax_check(mut self, enabled: bool) -> Self {
        self.syntax_check_enabled = enabled;
        self
    }

    /// Enable or disable enhanced validation
    pub fn with_enhanced_validation(mut self, enabled: bool) -> Self {
        self.enhanced_validation_enabled = enabled;
        self
    }

    /// Enable or disable schema validation
    pub fn with_schema_validation(mut self, enabled: bool) -> Self {
        self.schema_validation_enabled = enabled;
        self
    }

    /// Validate template with diagnostics
    pub fn validate_with_diagnostics(
        &self,
        code: &str,
        language: TemplateLanguage,
        filename: Option<&Path>,
    ) -> Result<Vec<TemplateDiagnostic>> {
        let mut diagnostics = Vec::new();

        // Run common validators
        diagnostics.extend(self.common.validate(code, language)?);

        // Detect language mismatch if filename provided
        if let Some(path) = filename {
            if let Some(detected_lang) = detect_language_from_filename(path) {
                if detected_lang != language {
                    diagnostics.push(TemplateDiagnostic::warning(
                        "language.mismatch",
                        format!(
                            "File extension suggests {} but language field is {}",
                            detected_lang, language
                        ),
                    ));
                }
            }
        }

        // Run enhanced pattern-based validation
        if self.enhanced_validation_enabled {
            diagnostics.extend(self.enhanced.validate(code, language)?);
        }

        // Run syntax checking if enabled
        if self.syntax_check_enabled {
            diagnostics.extend(self.syntax_checker.check(code, language)?);
        }

        // Run Finding schema validation (skip for YAML which has different structure)
        if self.schema_validation_enabled && language != TemplateLanguage::Yaml {
            diagnostics.extend(self.schema_validator.validate(code)?);
        }

        // Run language-specific validation
        let lang_diagnostics = match language {
            TemplateLanguage::Python => python::validate(code)?,
            TemplateLanguage::JavaScript => javascript::validate(code)?,
            TemplateLanguage::Rust => rust_lang::validate(code)?,
            TemplateLanguage::Shell => shell::validate(code)?,
            TemplateLanguage::C => c_lang::validate(code)?,
            TemplateLanguage::Cpp => cpp::validate(code)?,
            TemplateLanguage::Java => java::validate(code)?,
            TemplateLanguage::Go => go_lang::validate(code)?,
            TemplateLanguage::Ruby => ruby::validate(code)?,
            TemplateLanguage::Perl => perl::validate(code)?,
            TemplateLanguage::Php => php::validate(code)?,
            TemplateLanguage::Yaml => yaml::validate(code)?,
        };
        diagnostics.extend(lang_diagnostics);

        Ok(diagnostics)
    }

    /// Legacy validate method (for backwards compatibility)
    pub fn validate(&self, code: &str, language: TemplateLanguage) -> Result<()> {
        let diagnostics = self.validate_with_diagnostics(code, language, None)?;
        
        // Check for errors
        let has_errors = diagnostics.iter().any(|d| d.severity == DiagnosticSeverity::Error);
        
        if has_errors {
            let error_msg = diagnostics
                .iter()
                .filter(|d| d.severity == DiagnosticSeverity::Error)
                .map(|d| format!("{}: {}", d.code, d.message))
                .collect::<Vec<_>>()
                .join("; ");
            anyhow::bail!("{}", error_msg);
        }

        // In strict mode, warnings are also errors
        if self.strict {
            let has_warnings = diagnostics.iter().any(|d| d.severity == DiagnosticSeverity::Warning);
            if has_warnings {
                let warning_msg = diagnostics
                    .iter()
                    .filter(|d| d.severity == DiagnosticSeverity::Warning)
                    .map(|d| format!("{}: {}", d.code, d.message))
                    .collect::<Vec<_>>()
                    .join("; ");
                anyhow::bail!("Strict mode: {}", warning_msg);
            }
        }

        Ok(())
    }

    /// Detect if code language matches expected language
    pub fn detect_language_mismatch(
        &self,
        code: &str,
        declared_language: TemplateLanguage,
        filename: Option<&Path>,
    ) -> Option<TemplateDiagnostic> {
        // Check filename
        if let Some(path) = filename {
            if let Some(detected_lang) = detect_language_from_filename(path) {
                if detected_lang != declared_language {
                    return Some(TemplateDiagnostic::warning(
                        "language.filename_mismatch",
                        format!(
                            "Filename extension '.{}' suggests {} but declared language is {}",
                            path.extension()?.to_str()?,
                            detected_lang,
                            declared_language
                        ),
                    ));
                }
            }
        }

        // Check content heuristics
        if let Some(detected_lang) = detect_language_from_content(code) {
            if detected_lang != declared_language {
                return Some(TemplateDiagnostic::warning(
                    "language.content_mismatch",
                    format!(
                        "Code content suggests {} but declared language is {}",
                        detected_lang, declared_language
                    ),
                ));
            }
        }

        None
    }
}

impl Default for TemplateValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_creation() {
        let validator = TemplateValidator::new();
        assert!(!validator.strict);

        let strict_validator = TemplateValidator::new_strict();
        assert!(strict_validator.strict);
    }

    #[test]
    fn test_empty_code_validation() {
        let validator = TemplateValidator::new();
        let result = validator.validate("", TemplateLanguage::Python);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("empty"));
    }

    #[test]
    fn test_language_mismatch_detection() {
        let validator = TemplateValidator::new();
        let python_code = "import json\nprint('hello')";
        let path = Path::new("test.py");
        
        // No mismatch when correct
        let mismatch = validator.detect_language_mismatch(
            python_code,
            TemplateLanguage::Python,
            Some(path),
        );
        assert!(mismatch.is_none());
        
        // Detects mismatch
        let path_wrong = Path::new("test.js");
        let mismatch = validator.detect_language_mismatch(
            python_code,
            TemplateLanguage::Python,
            Some(path_wrong),
        );
        assert!(mismatch.is_some());
    }
}
