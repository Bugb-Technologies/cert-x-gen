//! CSRF token detection and testing module
//!
//! Provides functionality to detect, analyze, and test CSRF protection mechanisms.

use crate::types::Severity;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// CSRF token detector
#[derive(Debug)]
pub struct CsrfDetector {
    /// Common CSRF token names
    #[allow(dead_code)]
    token_names: Vec<String>,
    /// Token patterns
    patterns: Vec<Regex>,
}

impl CsrfDetector {
    /// Create a new CSRF detector
    pub fn new() -> Self {
        let token_names = vec![
            "csrf_token".to_string(),
            "csrf-token".to_string(),
            "_csrf".to_string(),
            "csrfToken".to_string(),
            "authenticity_token".to_string(),
            "_token".to_string(),
            "token".to_string(),
            "anti-csrf".to_string(),
        ];

        let patterns = vec![
            Regex::new(r#"<input[^>]*name\s*=\s*["']([^"']*csrf[^"']*)["'][^>]*>"#).unwrap(),
            Regex::new(r#"<input[^>]*name\s*=\s*["'](_token|token)["'][^>]*>"#).unwrap(),
            Regex::new(r#"<meta[^>]*name\s*=\s*["']csrf-token["'][^>]*>"#).unwrap(),
        ];

        Self {
            token_names,
            patterns,
        }
    }

    /// Detect CSRF tokens in HTML content
    pub fn detect_tokens(&self, html: &str) -> Vec<CsrfToken> {
        let mut tokens = Vec::new();

        // Search for tokens in forms
        for pattern in &self.patterns {
            for captures in pattern.captures_iter(html) {
                if let Some(name_match) = captures.get(1) {
                    let name = name_match.as_str();
                    if let Some(value) = self.extract_token_value(html, name) {
                        tokens.push(CsrfToken {
                            name: name.to_string(),
                            value,
                            location: TokenLocation::HiddenInput,
                        });
                    }
                }
            }
        }

        // Search for tokens in meta tags
        if let Some(meta_token) = self.extract_meta_token(html) {
            tokens.push(meta_token);
        }

        // Search for tokens in JavaScript
        if let Some(js_token) = self.extract_js_token(html) {
            tokens.push(js_token);
        }

        tokens
    }

    /// Extract token value from HTML
    fn extract_token_value(&self, html: &str, name: &str) -> Option<String> {
        let pattern = format!(r#"name\s*=\s*["']{name}["'][^>]*value\s*=\s*["']([^"']*)["']"#);
        if let Ok(re) = Regex::new(&pattern) {
            if let Some(captures) = re.captures(html) {
                return captures.get(1).map(|m| m.as_str().to_string());
            }
        }
        None
    }

    /// Extract CSRF token from meta tag
    fn extract_meta_token(&self, html: &str) -> Option<CsrfToken> {
        let re = Regex::new(r#"<meta[^>]*name\s*=\s*["']csrf-token["'][^>]*content\s*=\s*["']([^"']*)["'][^>]*>"#).ok()?;
        re.captures(html).and_then(|cap| {
            cap.get(1).map(|m| CsrfToken {
                name: "csrf-token".to_string(),
                value: m.as_str().to_string(),
                location: TokenLocation::MetaTag,
            })
        })
    }

    /// Extract CSRF token from JavaScript
    fn extract_js_token(&self, html: &str) -> Option<CsrfToken> {
        let re = Regex::new(r#"csrf[Tt]oken\s*[:=]\s*["']([^"']{20,})["']"#).ok()?;
        re.captures(html).and_then(|cap| {
            cap.get(1).map(|m| CsrfToken {
                name: "csrfToken".to_string(),
                value: m.as_str().to_string(),
                location: TokenLocation::JavaScript,
            })
        })
    }

    /// Analyze forms for CSRF protection
    pub fn analyze_forms(&self, html: &str) -> Vec<CsrfFinding> {
        let mut findings = Vec::new();

        // Extract all forms
        let form_re = Regex::new(r#"<form[^>]*>([\s\S]*?)</form>"#).unwrap();
        
        for form_match in form_re.captures_iter(html) {
            let form_html = form_match.get(1).map(|m| m.as_str()).unwrap_or("");
            
            // Check if form has CSRF token
            let has_csrf = self.detect_tokens(form_html).is_empty() == false;
            
            // Check if form modifies state (POST, PUT, DELETE)
            let is_state_changing = self.is_state_changing_form(&form_match[0]);
            
            if is_state_changing && !has_csrf {
                findings.push(CsrfFinding {
                    severity: Severity::High,
                    title: "Missing CSRF Token in Form".to_string(),
                    description: "State-changing form lacks CSRF protection".to_string(),
                    form_action: self.extract_form_action(&form_match[0]),
                    recommendation: "Add CSRF token to protect against cross-site request forgery".to_string(),
                });
            }
        }

        findings
    }

    /// Check if form is state-changing
    fn is_state_changing_form(&self, form_html: &str) -> bool {
        let method_re = Regex::new(r#"method\s*=\s*["'](POST|PUT|DELETE)["']"#).unwrap();
        method_re.is_match(&form_html.to_uppercase())
    }

    /// Extract form action
    fn extract_form_action(&self, form_html: &str) -> Option<String> {
        let action_re = Regex::new(r#"action\s*=\s*["']([^"']*)["']"#).ok()?;
        action_re.captures(form_html)
            .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
    }

    /// Generate CSRF test cases
    pub fn generate_test_cases(&self, token: &CsrfToken) -> Vec<CsrfTestCase> {
        vec![
            CsrfTestCase {
                name: "Empty Token Test".to_string(),
                token_value: "".to_string(),
                description: "Test if empty CSRF token is accepted".to_string(),
                expected_blocked: true,
            },
            CsrfTestCase {
                name: "Invalid Token Test".to_string(),
                token_value: "INVALID_TOKEN_12345".to_string(),
                description: "Test if invalid CSRF token is accepted".to_string(),
                expected_blocked: true,
            },
            CsrfTestCase {
                name: "Token Reuse Test".to_string(),
                token_value: token.value.clone(),
                description: "Test if CSRF token can be reused multiple times".to_string(),
                expected_blocked: false,
            },
            CsrfTestCase {
                name: "Modified Token Test".to_string(),
                token_value: self.modify_token(&token.value),
                description: "Test if slightly modified token is accepted".to_string(),
                expected_blocked: true,
            },
        ]
    }

    /// Modify token slightly for testing
    fn modify_token(&self, token: &str) -> String {
        if token.is_empty() {
            return "MODIFIED".to_string();
        }
        
        let mut chars: Vec<char> = token.chars().collect();
        if let Some(first) = chars.first_mut() {
            *first = if first.is_uppercase() { 'X' } else { 'x' };
        }
        chars.into_iter().collect()
    }
}

impl Default for CsrfDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// CSRF token representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfToken {
    /// Token name
    pub name: String,
    /// Token value
    pub value: String,
    /// Location where token was found
    pub location: TokenLocation,
}

/// Token location
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenLocation {
    /// Hidden input field
    HiddenInput,
    /// Meta tag
    MetaTag,
    /// JavaScript variable
    JavaScript,
    /// HTTP header
    Header,
    /// Cookie
    Cookie,
}

/// CSRF finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfFinding {
    /// Severity
    pub severity: Severity,
    /// Finding title
    pub title: String,
    /// Description
    pub description: String,
    /// Form action
    pub form_action: Option<String>,
    /// Recommendation
    pub recommendation: String,
}

/// CSRF test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfTestCase {
    /// Test name
    pub name: String,
    /// Token value to test
    pub token_value: String,
    /// Description
    pub description: String,
    /// Whether this should be blocked
    pub expected_blocked: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_csrf_token() {
        let detector = CsrfDetector::new();
        let html = r#"
            <form method="POST">
                <input type="hidden" name="csrf_token" value="abc123xyz" />
                <input type="text" name="username" />
            </form>
        "#;

        let tokens = detector.detect_tokens(html);
        assert!(!tokens.is_empty());
        assert_eq!(tokens[0].name, "csrf_token");
    }

    #[test]
    fn test_missing_csrf_detection() {
        let detector = CsrfDetector::new();
        let html = r#"
            <form method="POST" action="/delete">
                <input type="text" name="username" />
            </form>
        "#;

        let findings = detector.analyze_forms(html);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::High);
    }
}
