//! Matcher system for detecting vulnerabilities
//!
//! Provides various matcher types for identifying security issues.

use crate::error::{Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Matcher types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum MatcherType {
    /// Status code matcher
    Status {
        /// Status codes to match
        status: Vec<u16>,
    },
    /// Word matcher
    Word {
        /// Words to match
        words: Vec<String>,
        /// Match condition (and/or)
        #[serde(default = "default_condition")]
        condition: MatchCondition,
        /// Part of response to match (body/header/all)
        #[serde(default = "default_part")]
        part: ResponsePart,
    },
    /// Regex matcher
    Regex {
        /// Regex patterns
        regex: Vec<String>,
        /// Capture group
        #[serde(default)]
        group: Option<usize>,
    },
    /// Binary matcher
    Binary {
        /// Binary patterns (hex encoded)
        binary: Vec<String>,
    },
    /// Time-based matcher
    Time {
        /// Condition (greater/less)
        condition: TimeCondition,
        /// Time threshold
        time: Duration,
    },
    /// Size matcher
    Size {
        /// Condition (greater/less/equal)
        condition: SizeCondition,
        /// Size in bytes
        size: usize,
    },
    /// Hash matcher
    Hash {
        /// Hash algorithm
        algorithm: HashAlgorithm,
        /// Expected hash
        hash: String,
    },
    /// TLS/SSL matcher
    Tls {
        /// TLS versions to detect (e.g., ["1.0", "1.1"])
        versions: Option<Vec<String>>,
        /// Cipher suites to detect
        ciphers: Option<Vec<String>>,
        /// Check for specific vulnerabilities
        vulnerabilities: Option<Vec<String>>,
    },
    /// DNS matcher
    Dns {
        /// DNS record types (A, AAAA, CNAME, MX, TXT, etc.)
        record_type: String,
        /// Pattern to match in DNS response
        pattern: Option<String>,
        /// Specific value to match
        value: Option<String>,
    },
    /// Diff matcher (compare with baseline)
    Diff {
        /// Baseline response to compare against
        baseline: String,
        /// Similarity threshold (0-100)
        threshold: u8,
    },
    /// Custom matcher (code-based)
    Custom {
        /// Language for custom code
        language: String,
        /// Custom matching code
        code: String,
    },
}

fn default_condition() -> MatchCondition {
    MatchCondition::Or
}

fn default_part() -> ResponsePart {
    ResponsePart::Body
}

/// Match condition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchCondition {
    /// All matchers must match
    And,
    /// At least one matcher must match
    Or,
}

/// Response part to match against
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponsePart {
    /// Match against response body
    Body,
    /// Match against response headers
    Header,
    /// Match against entire response
    All,
}

/// Time-based condition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeCondition {
    /// Greater than threshold
    Greater,
    /// Less than threshold
    Less,
}

/// Size-based condition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SizeCondition {
    /// Greater than threshold
    Greater,
    /// Less than threshold
    Less,
    /// Equal to threshold
    Equal,
}

/// Hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// MD5 hash
    Md5,
    /// SHA1 hash
    Sha1,
    /// SHA256 hash
    Sha256,
    /// SHA512 hash
    Sha512,
    /// Blake3 hash
    Blake3,
}

/// HTTP response for matching
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code
    pub status: u16,
    /// Response headers
    pub headers: Vec<(String, String)>,
    /// Response body
    pub body: Vec<u8>,
    /// Response time
    pub response_time: Duration,
}

impl HttpResponse {
    /// Get response body as string
    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Get headers as string
    pub fn headers_string(&self) -> String {
        self.headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get all content (headers + body)
    pub fn all_string(&self) -> String {
        format!("{}\n\n{}", self.headers_string(), self.body_string())
    }
}

/// Matcher for vulnerability detection
#[derive(Debug)]
pub struct Matcher {
    matcher_type: MatcherType,
}

impl Matcher {
    /// Create a new matcher
    pub fn new(matcher_type: MatcherType) -> Self {
        Self { matcher_type }
    }

    /// Match against an HTTP response
    pub fn matches(&self, response: &HttpResponse) -> Result<bool> {
        match &self.matcher_type {
            MatcherType::Status { status } => Ok(status.contains(&response.status)),

            MatcherType::Word {
                words,
                condition,
                part,
            } => {
                let content = match part {
                    ResponsePart::Body => response.body_string(),
                    ResponsePart::Header => response.headers_string(),
                    ResponsePart::All => response.all_string(),
                };

                let matches: Vec<bool> = words.iter().map(|word| content.contains(word)).collect();

                Ok(match condition {
                    MatchCondition::And => matches.iter().all(|&m| m),
                    MatchCondition::Or => matches.iter().any(|&m| m),
                })
            }

            MatcherType::Regex { regex, group } => {
                let content = response.body_string();
                for pattern in regex {
                    let re = Regex::new(pattern)
                        .map_err(|e| Error::Matcher(format!("Invalid regex: {}", e)))?;

                    if let Some(captures) = re.captures(&content) {
                        if let Some(g) = group {
                            if captures.get(*g).is_some() {
                                return Ok(true);
                            }
                        } else {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }

            MatcherType::Binary { binary } => {
                for pattern in binary {
                    let bytes = hex::decode(pattern.trim_start_matches("0x"))
                        .map_err(|e| Error::Matcher(format!("Invalid hex pattern: {}", e)))?;

                    if response.body.windows(bytes.len()).any(|w| w == bytes) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }

            MatcherType::Time { condition, time } => Ok(match condition {
                TimeCondition::Greater => response.response_time > *time,
                TimeCondition::Less => response.response_time < *time,
            }),

            MatcherType::Size { condition, size } => {
                let body_size = response.body.len();
                Ok(match condition {
                    SizeCondition::Greater => body_size > *size,
                    SizeCondition::Less => body_size < *size,
                    SizeCondition::Equal => body_size == *size,
                })
            }

            MatcherType::Hash { algorithm, hash } => {
                let computed_hash = match algorithm {
                    HashAlgorithm::Sha256 => {
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(&response.body);
                        format!("{:x}", hasher.finalize())
                    }
                    HashAlgorithm::Blake3 => {
                        let hash = blake3::hash(&response.body);
                        hash.to_hex().to_string()
                    }
                    _ => {
                        return Err(Error::Matcher(format!(
                            "Hash algorithm {:?} not yet implemented",
                            algorithm
                        )))
                    }
                };

                Ok(computed_hash.eq_ignore_ascii_case(hash))
            }

            MatcherType::Tls {
                versions,
                ciphers: _,
                vulnerabilities,
            } => {
                // TLS matching requires connection metadata
                // For now, we'll check if the response headers indicate TLS info
                // Full implementation would require integration with TLS handshake analysis
                
                // Check for TLS version in headers (some servers expose this)
                let headers_str = response.headers_string().to_lowercase();
                
                let mut matched = false;
                
                if let Some(tls_versions) = versions {
                    for version in tls_versions {
                        if headers_str.contains(&format!("tls {}", version.to_lowercase())) {
                            matched = true;
                            break;
                        }
                    }
                }
                
                if let Some(vuln_checks) = vulnerabilities {
                    for vuln in vuln_checks {
                        match vuln.to_lowercase().as_str() {
                            "heartbleed" => {
                                // Check for heartbleed indicators
                                if headers_str.contains("heartbeat") {
                                    matched = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                
                // Note: Full TLS matching requires access to connection metadata
                // This is a simplified implementation
                tracing::warn!("TLS matcher requires connection metadata for accurate detection");
                Ok(matched)
            }

            MatcherType::Dns {
                record_type,
                pattern,
                value,
            } => {
                // DNS matching requires DNS resolution
                // This would be implemented with DNS-specific responses
                // For now, we check if the response contains DNS-related information
                
                let body_str = response.body_string();
                let mut matched = false;
                
                // Check if record type is mentioned
                if body_str.contains(record_type) {
                    matched = true;
                }
                
                // Check pattern if provided
                if let Some(p) = pattern {
                    if let Ok(re) = Regex::new(p) {
                        matched = matched && re.is_match(&body_str);
                    }
                }
                
                // Check specific value if provided
                if let Some(v) = value {
                    matched = matched && body_str.contains(v);
                }
                
                // Note: Full DNS matching requires DNS query responses
                tracing::warn!("DNS matcher requires DNS-specific protocol handler");
                Ok(matched)
            }

            MatcherType::Diff { baseline, threshold } => {
                // Calculate difference between current response and baseline
                let current = response.body_string();
                let similarity = calculate_similarity(&current, baseline);
                
                // If similarity is below threshold, responses are different
                let difference_percentage = 100 - similarity;
                Ok(difference_percentage >= *threshold as usize)
            }

            MatcherType::Custom { .. } => {
                // Custom matchers would be evaluated by the template engine
                Err(Error::NotImplemented(
                    "Custom matchers require template engine support".to_string(),
                ))
            }
        }
    }

    /// Get matcher type
    pub fn matcher_type(&self) -> &MatcherType {
        &self.matcher_type
    }
}

/// Match multiple matchers against a response
pub fn match_all(
    matchers: &[Matcher],
    response: &HttpResponse,
    condition: MatchCondition,
) -> Result<bool> {
    if matchers.is_empty() {
        return Ok(false);
    }

    let results: Result<Vec<bool>> = matchers.iter().map(|m| m.matches(response)).collect();
    let results = results?;

    Ok(match condition {
        MatchCondition::And => results.iter().all(|&r| r),
        MatchCondition::Or => results.iter().any(|&r| r),
    })
}

/// Calculate similarity between two strings (0-100)
/// Uses a simple character-based comparison
fn calculate_similarity(s1: &str, s2: &str) -> usize {
    if s1.is_empty() && s2.is_empty() {
        return 100;
    }
    
    if s1.is_empty() || s2.is_empty() {
        return 0;
    }
    
    // Simple character-based similarity
    let chars1: Vec<char> = s1.chars().collect();
    let chars2: Vec<char> = s2.chars().collect();
    
    let max_len = chars1.len().max(chars2.len());
    let min_len = chars1.len().min(chars2.len());
    
    let mut matches = 0;
    for i in 0..min_len {
        if chars1.get(i) == chars2.get(i) {
            matches += 1;
        }
    }
    
    ((matches as f64 / max_len as f64) * 100.0) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_response(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("Content-Type".to_string(), "text/html".to_string())],
            body: body.as_bytes().to_vec(),
            response_time: Duration::from_millis(100),
        }
    }

    #[test]
    fn test_status_matcher() {
        let matcher = Matcher::new(MatcherType::Status {
            status: vec![200, 201],
        });
        let response = create_test_response(200, "test");
        assert!(matcher.matches(&response).unwrap());

        let response = create_test_response(404, "test");
        assert!(!matcher.matches(&response).unwrap());
    }

    #[test]
    fn test_word_matcher() {
        let matcher = Matcher::new(MatcherType::Word {
            words: vec!["vulnerable".to_string(), "error".to_string()],
            condition: MatchCondition::Or,
            part: ResponsePart::Body,
        });

        let response = create_test_response(200, "This is vulnerable");
        assert!(matcher.matches(&response).unwrap());

        let response = create_test_response(200, "This is safe");
        assert!(!matcher.matches(&response).unwrap());
    }

    #[test]
    fn test_size_matcher() {
        let matcher = Matcher::new(MatcherType::Size {
            condition: SizeCondition::Greater,
            size: 10,
        });

        let response = create_test_response(200, "This is a long response");
        assert!(matcher.matches(&response).unwrap());

        let response = create_test_response(200, "short");
        assert!(!matcher.matches(&response).unwrap());
    }

    #[test]
    fn test_regex_matcher() {
        let matcher = Matcher::new(MatcherType::Regex {
            regex: vec![r"version:\s*(\d+\.\d+)".to_string()],
            group: Some(1),
        });

        let response = create_test_response(200, "Server version: 2.5.30");
        assert!(matcher.matches(&response).unwrap());
    }
}
