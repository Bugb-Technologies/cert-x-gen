//! Language detection from filename and content

use crate::types::TemplateLanguage;
use std::path::Path;

/// Supported file extensions for each language
const EXTENSIONS: &[(&str, TemplateLanguage)] = &[
    ("py", TemplateLanguage::Python),
    ("js", TemplateLanguage::JavaScript),
    ("rs", TemplateLanguage::Rust),
    ("sh", TemplateLanguage::Shell),
    ("bash", TemplateLanguage::Shell),
    ("c", TemplateLanguage::C),
    ("h", TemplateLanguage::C),
    ("cpp", TemplateLanguage::Cpp),
    ("cc", TemplateLanguage::Cpp),
    ("cxx", TemplateLanguage::Cpp),
    ("hpp", TemplateLanguage::Cpp),
    ("hxx", TemplateLanguage::Cpp),
    ("java", TemplateLanguage::Java),
    ("go", TemplateLanguage::Go),
    ("rb", TemplateLanguage::Ruby),
    ("pl", TemplateLanguage::Perl),
    ("pm", TemplateLanguage::Perl),
    ("php", TemplateLanguage::Php),
    ("yaml", TemplateLanguage::Yaml),
    ("yml", TemplateLanguage::Yaml),
];

/// Detect language from filename extension
pub fn detect_language_from_filename(path: &Path) -> Option<TemplateLanguage> {
    let extension = path.extension()?.to_str()?.to_lowercase();

    EXTENSIONS
        .iter()
        .find(|(ext, _)| *ext == extension)
        .map(|(_, lang)| *lang)
}

/// Detect language from code content using heuristics
pub fn detect_language_from_content(code: &str) -> Option<TemplateLanguage> {
    let code_lower = code.to_lowercase();
    let first_lines: Vec<&str> = code.lines().take(10).collect();
    let first_10_lines = first_lines.join("\n").to_lowercase();

    // Check shebang first
    if let Some(first_line) = code.lines().next() {
        if first_line.starts_with("#!") {
            if first_line.contains("python") {
                return Some(TemplateLanguage::Python);
            } else if first_line.contains("node") || first_line.contains("nodejs") {
                return Some(TemplateLanguage::JavaScript);
            } else if first_line.contains("bash") || first_line.contains("sh") {
                return Some(TemplateLanguage::Shell);
            } else if first_line.contains("ruby") {
                return Some(TemplateLanguage::Ruby);
            } else if first_line.contains("perl") {
                return Some(TemplateLanguage::Perl);
            } else if first_line.contains("php") {
                return Some(TemplateLanguage::Php);
            }
        }
    }

    // Python indicators
    if (code_lower.contains("import ")
        || code_lower.contains("from ")
        || code_lower.contains("def "))
        && (first_10_lines.contains("import json")
            || first_10_lines.contains("import sys")
            || first_10_lines.contains("import os")
            || code_lower.contains("if __name__"))
    {
        return Some(TemplateLanguage::Python);
    }

    // JavaScript/Node indicators
    if (code_lower.contains("const ") || code_lower.contains("let ") || code_lower.contains("var "))
        && (first_10_lines.contains("require(")
            || first_10_lines.contains("import ")
            || code_lower.contains("console.log")
            || code_lower.contains("async "))
    {
        return Some(TemplateLanguage::JavaScript);
    }

    // Rust indicators
    if first_10_lines.contains("fn main()")
        || (code_lower.contains("fn ") && code_lower.contains("use "))
        || code_lower.contains("impl ")
        || code_lower.contains("struct ")
        || first_10_lines.contains("extern crate")
    {
        return Some(TemplateLanguage::Rust);
    }

    // Shell indicators
    if code_lower.contains("#!/bin/bash")
        || code_lower.contains("#!/bin/sh")
        || (code_lower.contains("echo ") && code_lower.contains("if ["))
    {
        return Some(TemplateLanguage::Shell);
    }

    // C indicators
    if (first_10_lines.contains("#include <stdio.h>")
        || first_10_lines.contains("#include <stdlib.h>"))
        && code_lower.contains("int main(")
        && !code_lower.contains("std::")
    {
        return Some(TemplateLanguage::C);
    }

    // C++ indicators
    if (first_10_lines.contains("#include <iostream>")
        || first_10_lines.contains("std::")
        || code_lower.contains("namespace "))
        && code_lower.contains("int main(")
    {
        return Some(TemplateLanguage::Cpp);
    }

    // Java indicators
    if (code_lower.contains("public class ") || code_lower.contains("public static void main"))
        && (first_10_lines.contains("import java.") || code_lower.contains("package "))
    {
        return Some(TemplateLanguage::Java);
    }

    // Go indicators
    if first_10_lines.contains("package main")
        || (code_lower.contains("func main()") && code_lower.contains("import ("))
    {
        return Some(TemplateLanguage::Go);
    }

    // Ruby indicators
    if code_lower.contains("require ")
        || (code_lower.contains("def ") && code_lower.contains("end"))
        || code_lower.contains("puts ")
    {
        return Some(TemplateLanguage::Ruby);
    }

    // Perl indicators
    if first_10_lines.contains("use strict;")
        || first_10_lines.contains("use warnings;")
        || (code_lower.contains("my ") && code_lower.contains("$"))
    {
        return Some(TemplateLanguage::Perl);
    }

    // PHP indicators
    if code_lower.starts_with("<?php") || code_lower.contains("<?php") {
        return Some(TemplateLanguage::Php);
    }

    // YAML indicators
    if (first_10_lines.contains("id:") || first_10_lines.contains("name:"))
        && (first_10_lines.contains("severity:") || first_10_lines.contains("description:"))
        && (code_lower.contains("http:")
            || code_lower.contains("network:")
            || code_lower.contains("flows:"))
    {
        return Some(TemplateLanguage::Yaml);
    }

    None
}

/// Check if an extension is supported by CERT-X-GEN
#[allow(dead_code)]
pub fn is_supported_extension(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        EXTENSIONS
            .iter()
            .any(|(supported, _)| *supported == ext.to_lowercase())
    } else {
        false
    }
}

/// Get all supported extensions as a list
#[allow(dead_code)]
pub fn supported_extensions() -> Vec<&'static str> {
    let mut exts: Vec<&str> = EXTENSIONS.iter().map(|(ext, _)| *ext).collect();
    exts.sort();
    exts.dedup();
    exts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_from_filename() {
        assert_eq!(
            detect_language_from_filename(Path::new("test.py")),
            Some(TemplateLanguage::Python)
        );
        assert_eq!(
            detect_language_from_filename(Path::new("test.js")),
            Some(TemplateLanguage::JavaScript)
        );
        assert_eq!(
            detect_language_from_filename(Path::new("test.rs")),
            Some(TemplateLanguage::Rust)
        );
        assert_eq!(
            detect_language_from_filename(Path::new("test.yaml")),
            Some(TemplateLanguage::Yaml)
        );
        assert_eq!(detect_language_from_filename(Path::new("test.txt")), None);
    }

    #[test]
    fn test_detect_from_content_python() {
        let python_code =
            "#!/usr/bin/env python3\nimport json\nimport sys\n\ndef main():\n    pass";
        assert_eq!(
            detect_language_from_content(python_code),
            Some(TemplateLanguage::Python)
        );
    }

    #[test]
    fn test_detect_from_content_javascript() {
        let js_code = "const http = require('http');\nconst fs = require('fs');";
        assert_eq!(
            detect_language_from_content(js_code),
            Some(TemplateLanguage::JavaScript)
        );
    }

    #[test]
    fn test_detect_from_content_shell() {
        let shell_code = "#!/bin/bash\necho 'test'\nif [ -f /tmp/test ]; then\n  echo 'found'\nfi";
        assert_eq!(
            detect_language_from_content(shell_code),
            Some(TemplateLanguage::Shell)
        );
    }

    #[test]
    fn test_detect_from_content_yaml() {
        let yaml_code = "id: test\nname: Test\nseverity: high\nhttp:\n  - method: GET";
        assert_eq!(
            detect_language_from_content(yaml_code),
            Some(TemplateLanguage::Yaml)
        );
    }

    #[test]
    fn test_supported_extension() {
        assert!(is_supported_extension(Path::new("test.py")));
        assert!(is_supported_extension(Path::new("test.yaml")));
        assert!(!is_supported_extension(Path::new("test.txt")));
        assert!(!is_supported_extension(Path::new("test.md")));
    }
}
