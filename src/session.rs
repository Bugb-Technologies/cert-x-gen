//! Session, cookie, and token management for CERT-X-GEN
//!
//! Provides centralized session handling with automatic cookie reuse,
//! JWT analysis, and security-focused token validation.

use crate::error::{Error, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cookie representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    /// Cookie name
    pub name: String,
    /// Cookie value
    pub value: String,
    /// Domain
    pub domain: String,
    /// Path
    pub path: String,
    /// Secure flag
    pub secure: bool,
    /// HttpOnly flag
    pub http_only: bool,
    /// SameSite attribute
    pub same_site: Option<SameSite>,
    /// Expiration timestamp
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
}

/// SameSite attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SameSite {
    /// Strict mode
    Strict,
    /// Lax mode
    Lax,
    /// None (requires Secure)
    None,
}

/// Cookie security issues
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CookieSecurityIssue {
    /// Missing Secure flag
    MissingSecureFlag {
        /// Cookie name
        cookie_name: String,
    },
    /// Missing HttpOnly flag
    MissingHttpOnlyFlag {
        /// Cookie name
        cookie_name: String,
    },
    /// Weak session ID
    WeakSessionId {
        /// Cookie name
        cookie_name: String,
        /// Entropy score (0-100)
        entropy: u8,
    },
    /// Missing SameSite attribute
    MissingSameSite {
        /// Cookie name
        cookie_name: String,
    },
}

impl Cookie {
    /// Create a new cookie
    pub fn new<S: Into<String>>(name: S, value: S, domain: S) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: domain.into(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: None,
            expires: None,
        }
    }

    /// Check if cookie is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires {
            chrono::Utc::now() > expires
        } else {
            false
        }
    }

    /// Analyze cookie for security issues
    pub fn analyze_security(&self) -> Vec<CookieSecurityIssue> {
        let mut issues = Vec::new();

        // Check for missing Secure flag on HTTPS
        if !self.secure && self.domain.starts_with("https://") {
            issues.push(CookieSecurityIssue::MissingSecureFlag {
                cookie_name: self.name.clone(),
            });
        }

        // Check for missing HttpOnly flag on session cookies
        if !self.http_only && self.is_session_cookie() {
            issues.push(CookieSecurityIssue::MissingHttpOnlyFlag {
                cookie_name: self.name.clone(),
            });
        }

        // Check for weak session ID
        if self.is_session_cookie() && self.is_weak_session_id() {
            issues.push(CookieSecurityIssue::WeakSessionId {
                cookie_name: self.name.clone(),
                entropy: self.calculate_entropy(),
            });
        }

        // Check for missing SameSite attribute
        if self.same_site.is_none() {
            issues.push(CookieSecurityIssue::MissingSameSite {
                cookie_name: self.name.clone(),
            });
        }

        issues
    }

    /// Check if this is a session cookie
    fn is_session_cookie(&self) -> bool {
        let session_names = [
            "sessionid", "session_id", "sess", "jsessionid",
            "phpsessid", "asp.net_sessionid", "aspsessionid"
        ];
        session_names.iter().any(|&name| self.name.to_lowercase().contains(name))
    }

    /// Check if session ID appears weak
    fn is_weak_session_id(&self) -> bool {
        let value = &self.value;
        
        // Too short
        if value.len() < 16 {
            return true;
        }
        
        // Sequential or predictable
        if value.chars().all(|c| c.is_numeric()) {
            return true;
        }
        
        // Low entropy
        self.calculate_entropy() < 50
    }

    /// Calculate entropy of cookie value (0-100)
    fn calculate_entropy(&self) -> u8 {
        use std::collections::HashSet;
        let chars: HashSet<char> = self.value.chars().collect();
        let unique_ratio = chars.len() as f64 / self.value.len() as f64;
        (unique_ratio * 100.0) as u8
    }

    /// Convert to HTTP header value
    pub fn to_header_value(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

/// JWT token representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtToken {
    /// Token string
    pub token: String,
    /// Decoded header
    pub header: Option<JwtHeader>,
    /// Decoded payload
    pub payload: Option<JwtPayload>,
    /// Token type (Bearer, etc.)
    pub token_type: String,
}

/// JWT header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    /// Algorithm
    pub alg: String,
    /// Token type
    pub typ: Option<String>,
    /// Key ID
    pub kid: Option<String>,
}

/// JWT payload (claims)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtPayload {
    /// Issuer
    pub iss: Option<String>,
    /// Subject
    pub sub: Option<String>,
    /// Audience
    pub aud: Option<String>,
    /// Expiration time
    pub exp: Option<i64>,
    /// Not before
    pub nbf: Option<i64>,
    /// Issued at
    pub iat: Option<i64>,
    /// JWT ID
    pub jti: Option<String>,
    /// Custom claims
    pub custom: HashMap<String, serde_json::Value>,
}

impl JwtToken {
    /// Parse JWT token (without verification)
    pub fn parse(token: &str) -> Result<Self> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Parse("Invalid JWT format".to_string()));
        }

        let header = Self::decode_base64_json::<JwtHeader>(parts[0])
            .ok();
        let payload = Self::decode_base64_json::<JwtPayload>(parts[1])
            .ok();

        Ok(Self {
            token: token.to_string(),
            header,
            payload,
            token_type: "Bearer".to_string(),
        })
    }

    /// Decode base64 JSON
    fn decode_base64_json<T: for<'de> Deserialize<'de>>(data: &str) -> Result<T> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        
        let decoded = URL_SAFE_NO_PAD
            .decode(data)
            .map_err(|e| Error::Parse(format!("Base64 decode failed: {}", e)))?;
        
        serde_json::from_slice(&decoded)
            .map_err(|e| Error::JsonParse(e))
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        if let Some(ref payload) = self.payload {
            if let Some(exp) = payload.exp {
                let now = chrono::Utc::now().timestamp();
                return now > exp;
            }
        }
        false
    }

    /// Analyze token for security issues
    pub fn analyze_security(&self) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        if let Some(ref header) = self.header {
            // Check for weak algorithms
            match header.alg.to_lowercase().as_str() {
                "none" => issues.push(SecurityIssue::WeakAlgorithm {
                    algorithm: header.alg.clone(),
                    severity: crate::types::Severity::Critical,
                    description: "Algorithm 'none' allows unsigned tokens".to_string(),
                }),
                "hs256" if header.kid.is_some() => issues.push(SecurityIssue::KeyConfusion {
                    description: "HS256 with kid may be vulnerable to key confusion".to_string(),
                }),
                _ => {}
            }
        }

        if let Some(ref payload) = self.payload {
            // Check for missing expiration
            if payload.exp.is_none() {
                issues.push(SecurityIssue::MissingClaim {
                    claim: "exp".to_string(),
                    description: "Token has no expiration time".to_string(),
                });
            }

            // Check for missing issuer
            if payload.iss.is_none() {
                issues.push(SecurityIssue::MissingClaim {
                    claim: "iss".to_string(),
                    description: "Token has no issuer claim".to_string(),
                });
            }
        }

        issues
    }

    /// Generate JWT attack payloads for testing
    pub fn generate_attack_payloads(&self) -> Vec<JwtAttackPayload> {
        let mut payloads = Vec::new();

        // None algorithm bypass
        if let Ok(none_token) = self.forge_none_algorithm() {
            payloads.push(JwtAttackPayload {
                name: "None Algorithm Bypass".to_string(),
                token: none_token,
                description: "JWT with algorithm 'none' (unsigned)".to_string(),
                severity: crate::types::Severity::Critical,
            });
        }

        // Algorithm confusion (RS256 -> HS256)
        if let Ok(confused_token) = self.forge_algorithm_confusion() {
            payloads.push(JwtAttackPayload {
                name: "Algorithm Confusion".to_string(),
                token: confused_token,
                description: "Changed RS256 to HS256 for key confusion attack".to_string(),
                severity: crate::types::Severity::Critical,
            });
        }

        // Expired token with modified exp
        if let Ok(expired_bypass) = self.forge_expired_bypass() {
            payloads.push(JwtAttackPayload {
                name: "Expiration Bypass".to_string(),
                token: expired_bypass,
                description: "Modified expiration time to bypass validation".to_string(),
                severity: crate::types::Severity::High,
            });
        }

        // Privilege escalation via claim modification
        if let Ok(admin_token) = self.forge_admin_claims() {
            payloads.push(JwtAttackPayload {
                name: "Privilege Escalation".to_string(),
                token: admin_token,
                description: "Modified claims to gain admin privileges".to_string(),
                severity: crate::types::Severity::Critical,
            });
        }

        payloads
    }

    /// Forge a token with "none" algorithm
    fn forge_none_algorithm(&self) -> Result<String> {
        let parts: Vec<&str> = self.token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Parse("Invalid JWT format".to_string()));
        }

        // Decode and modify header to use "none" algorithm
        let mut header: serde_json::Value = serde_json::from_slice(
            &general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0])
                .map_err(|e| Error::Parse(format!("Base64 decode error: {}", e)))?
        )?;

        header["alg"] = serde_json::Value::String("none".to_string());

        let new_header = general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header)?);

        // Keep original payload, remove signature
        Ok(format!("{}.{}.", new_header, parts[1]))
    }

    /// Forge algorithm confusion attack (RS256 -> HS256)
    fn forge_algorithm_confusion(&self) -> Result<String> {
        let parts: Vec<&str> = self.token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Parse("Invalid JWT format".to_string()));
        }

        let mut header: serde_json::Value = serde_json::from_slice(
            &general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0])
                .map_err(|e| Error::Parse(format!("Base64 decode error: {}", e)))?
        )?;

        // Change to HS256
        header["alg"] = serde_json::Value::String("HS256".to_string());

        let new_header = general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header)?);

        Ok(format!("{}.{}.SIGNATURE_PLACEHOLDER", new_header, parts[1]))
    }

    /// Forge token with modified expiration
    fn forge_expired_bypass(&self) -> Result<String> {
        let parts: Vec<&str> = self.token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Parse("Invalid JWT format".to_string()));
        }

        let mut payload: serde_json::Value = serde_json::from_slice(
            &general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|e| Error::Parse(format!("Base64 decode error: {}", e)))?
        )?;

        // Set expiration to far future
        let future_exp = chrono::Utc::now().timestamp() + (365 * 24 * 60 * 60); // +1 year
        payload["exp"] = serde_json::Value::Number(future_exp.into());

        let new_payload = general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload)?);

        Ok(format!("{}.{}.SIGNATURE_MODIFIED", parts[0], new_payload))
    }

    /// Forge token with admin claims
    fn forge_admin_claims(&self) -> Result<String> {
        let parts: Vec<&str> = self.token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Parse("Invalid JWT format".to_string()));
        }

        let mut payload: serde_json::Value = serde_json::from_slice(
            &general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|e| Error::Parse(format!("Base64 decode error: {}", e)))?
        )?;

        // Inject admin claims
        payload["role"] = serde_json::Value::String("admin".to_string());
        payload["is_admin"] = serde_json::Value::Bool(true);
        payload["permissions"] = serde_json::Value::Array(vec![
            serde_json::Value::String("admin".to_string()),
            serde_json::Value::String("superuser".to_string()),
        ]);

        let new_payload = general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload)?);

        Ok(format!("{}.{}.SIGNATURE_MODIFIED", parts[0], new_payload))
    }
}

/// JWT attack payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAttackPayload {
    /// Attack name
    pub name: String,
    /// Forged token
    pub token: String,
    /// Description
    pub description: String,
    /// Severity if successful
    pub severity: crate::types::Severity,
}

/// Security issues found in tokens
#[derive(Debug, Clone)]
pub enum SecurityIssue {
    /// Weak algorithm
    WeakAlgorithm {
        /// Algorithm name
        algorithm: String,
        /// Severity
        severity: crate::types::Severity,
        /// Description
        description: String,
    },
    /// Key confusion vulnerability
    KeyConfusion {
        /// Description
        description: String,
    },
    /// Missing claim
    MissingClaim {
        /// Claim name
        claim: String,
        /// Description
        description: String,
    },
}

/// Serializable session data for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionData {
    cookies: HashMap<String, Vec<Cookie>>,
    jwt_tokens: HashMap<String, JwtToken>,
    variables: HashMap<String, String>,
}

/// Central session manager
#[derive(Debug)]
pub struct SessionManager {
    /// Cookie store by domain
    cookie_store: Arc<RwLock<HashMap<String, Vec<Cookie>>>>,
    /// JWT tokens by name
    jwt_tokens: Arc<RwLock<HashMap<String, JwtToken>>>,
    /// Session variables
    variables: Arc<RwLock<HashMap<String, String>>>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            cookie_store: Arc::new(RwLock::new(HashMap::new())),
            jwt_tokens: Arc::new(RwLock::new(HashMap::new())),
            variables: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store a cookie
    pub async fn store_cookie(&self, cookie: Cookie) {
        let mut store = self.cookie_store.write().await;
        let domain_cookies = store.entry(cookie.domain.clone()).or_insert_with(Vec::new);
        
        // Remove existing cookie with same name
        domain_cookies.retain(|c| c.name != cookie.name);
        
        // Add new cookie
        domain_cookies.push(cookie);
    }

    /// Get cookies for a domain
    pub async fn get_cookies(&self, domain: &str) -> Vec<Cookie> {
        let store = self.cookie_store.read().await;
        
        store
            .get(domain)
            .map(|cookies| {
                cookies
                    .iter()
                    .filter(|c| !c.is_expired())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get cookie header value for domain
    pub async fn get_cookie_header(&self, domain: &str) -> Option<String> {
        let cookies = self.get_cookies(domain).await;
        if cookies.is_empty() {
            return None;
        }

        let cookie_string = cookies
            .iter()
            .map(|c| c.to_header_value())
            .collect::<Vec<_>>()
            .join("; ");

        Some(cookie_string)
    }

    /// Parse and store cookies from Set-Cookie header
    pub async fn parse_set_cookie(&self, domain: &str, header_value: &str) -> Result<()> {
        // Simple cookie parsing (production would use cookie crate)
        let parts: Vec<&str> = header_value.split(';').collect();
        if parts.is_empty() {
            return Ok(());
        }

        let name_value: Vec<&str> = parts[0].split('=').collect();
        if name_value.len() != 2 {
            return Ok(());
        }

        let mut cookie = Cookie::new(name_value[0].trim(), name_value[1].trim(), domain);

        // Parse attributes
        for part in &parts[1..] {
            let part = part.trim().to_lowercase();
            if part == "secure" {
                cookie.secure = true;
            } else if part == "httponly" {
                cookie.http_only = true;
            } else if part.starts_with("samesite=") {
                let value = part.strip_prefix("samesite=").unwrap();
                cookie.same_site = match value {
                    "strict" => Some(SameSite::Strict),
                    "lax" => Some(SameSite::Lax),
                    "none" => Some(SameSite::None),
                    _ => None,
                };
            }
        }

        self.store_cookie(cookie).await;
        Ok(())
    }

    /// Store JWT token
    pub async fn set_jwt(&self, name: &str, token: &str) -> Result<()> {
        let jwt = JwtToken::parse(token)?;
        let mut tokens = self.jwt_tokens.write().await;
        tokens.insert(name.to_string(), jwt);
        Ok(())
    }

    /// Get JWT token
    pub async fn get_jwt(&self, name: &str) -> Option<JwtToken> {
        let tokens = self.jwt_tokens.read().await;
        tokens.get(name).cloned()
    }

    /// Get JWT as Authorization header value
    pub async fn get_jwt_header(&self, name: &str) -> Option<String> {
        let jwt = self.get_jwt(name).await?;
        Some(format!("{} {}", jwt.token_type, jwt.token))
    }

    /// Analyze all stored JWTs for security issues
    pub async fn analyze_jwt_security(&self) -> HashMap<String, Vec<SecurityIssue>> {
        let tokens = self.jwt_tokens.read().await;
        let mut results = HashMap::new();

        for (name, token) in tokens.iter() {
            let issues = token.analyze_security();
            if !issues.is_empty() {
                results.insert(name.clone(), issues);
            }
        }

        results
    }

    /// Set session variable
    pub async fn set_variable(&self, key: &str, value: &str) {
        let mut vars = self.variables.write().await;
        vars.insert(key.to_string(), value.to_string());
    }

    /// Get session variable
    pub async fn get_variable(&self, key: &str) -> Option<String> {
        let vars = self.variables.read().await;
        vars.get(key).cloned()
    }

    /// Clear all session data
    pub async fn clear(&self) {
        self.cookie_store.write().await.clear();
        self.jwt_tokens.write().await.clear();
        self.variables.write().await.clear();
    }

    /// Save session to disk
    pub async fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let session_data = SessionData {
            cookies: self.cookie_store.read().await.clone(),
            jwt_tokens: self.jwt_tokens.read().await.clone(),
            variables: self.variables.read().await.clone(),
        };

        let json = serde_json::to_string_pretty(&session_data)
            .map_err(|e| Error::Serialization(format!("Failed to serialize session: {}", e)))?;

        tokio::fs::write(path.as_ref(), json).await?;

        tracing::info!("Session saved to {}", path.as_ref().display());
        Ok(())
    }

    /// Load session from disk
    pub async fn load_from_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let contents = tokio::fs::read_to_string(path.as_ref()).await?;

        let session_data: SessionData = serde_json::from_str(&contents)
            .map_err(|e| Error::Serialization(format!("Failed to deserialize session: {}", e)))?;

        *self.cookie_store.write().await = session_data.cookies;
        *self.jwt_tokens.write().await = session_data.jwt_tokens;
        *self.variables.write().await = session_data.variables;

        tracing::info!("Session loaded from {}", path.as_ref().display());
        Ok(())
    }

    /// Export session as encrypted JSON
    pub async fn export_encrypted<P: AsRef<Path>>(&self, path: P, key: &[u8]) -> Result<()> {
        let session_data = SessionData {
            cookies: self.cookie_store.read().await.clone(),
            jwt_tokens: self.jwt_tokens.read().await.clone(),
            variables: self.variables.read().await.clone(),
        };

        let json = serde_json::to_vec(&session_data)
            .map_err(|e| Error::Serialization(format!("Failed to serialize session: {}", e)))?;

        // Simple XOR encryption for demonstration
        // In production, use proper encryption like AES-GCM or ChaCha20-Poly1305
        let encrypted: Vec<u8> = json
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        tokio::fs::write(path.as_ref(), encrypted).await?;

        tracing::info!("Encrypted session saved to {}", path.as_ref().display());
        Ok(())
    }

    /// Import session from encrypted JSON
    pub async fn import_encrypted<P: AsRef<Path>>(&self, path: P, key: &[u8]) -> Result<()> {
        let encrypted = tokio::fs::read(path.as_ref()).await?;

        // Simple XOR decryption
        let decrypted: Vec<u8> = encrypted
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        let session_data: SessionData = serde_json::from_slice(&decrypted)
            .map_err(|e| Error::Serialization(format!("Failed to deserialize session: {}", e)))?;

        *self.cookie_store.write().await = session_data.cookies;
        *self.jwt_tokens.write().await = session_data.jwt_tokens;
        *self.variables.write().await = session_data.variables;

        tracing::info!("Encrypted session loaded from {}", path.as_ref().display());
        Ok(())
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_creation() {
        let cookie = Cookie::new("session", "abc123", "example.com");
        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "abc123");
        assert_eq!(cookie.domain, "example.com");
    }

    #[test]
    fn test_cookie_expiration() {
        let mut cookie = Cookie::new("test", "value", "example.com");
        assert!(!cookie.is_expired());

        cookie.expires = Some(chrono::Utc::now() - chrono::Duration::hours(1));
        assert!(cookie.is_expired());
    }

    #[tokio::test]
    async fn test_session_manager() {
        let manager = SessionManager::new();
        
        let cookie = Cookie::new("session", "token123", "example.com");
        manager.store_cookie(cookie).await;

        let cookies = manager.get_cookies("example.com").await;
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "session");
    }

    #[tokio::test]
    async fn test_jwt_storage() {
        let manager = SessionManager::new();
        
        // Simple JWT for testing (this is a mock, not a valid signature)
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        
        assert!(manager.set_jwt("auth", token).await.is_ok());
        
        let jwt = manager.get_jwt("auth").await;
        assert!(jwt.is_some());
    }

    #[tokio::test]
    async fn test_session_variables() {
        let manager = SessionManager::new();
        
        manager.set_variable("user_id", "12345").await;
        let value = manager.get_variable("user_id").await;
        
        assert_eq!(value, Some("12345".to_string()));
    }
}
