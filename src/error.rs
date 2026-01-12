//! Error types for CERT-X-GEN
//!
//! Comprehensive error handling system with context-rich error messages.

use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Result type alias for CERT-X-GEN operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for CERT-X-GEN
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Template errors
    #[error("Template error in {template}: {message}")]
    Template {
        /// Template ID or path
        template: String,
        /// Error message
        message: String,
    },

    /// Template not found
    #[error("Template not found: {0}")]
    TemplateNotFound(String),

    /// Template validation failed
    #[error("Template validation failed for {template}: {reason}")]
    TemplateValidation {
        /// Template ID
        template: String,
        /// Validation failure reason
        reason: String,
    },

    /// Template execution error
    #[error("Template execution failed: {0}")]
    TemplateExecution(String),

    /// Template compilation error
    #[error("Template compilation failed for {template}: {error}")]
    TemplateCompilation {
        /// Template path
        template: PathBuf,
        /// Compilation error
        error: String,
    },

    /// Network errors
    #[error("Network error: {0}")]
    Network(String),

    /// HTTP request error
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),

    /// Target errors
    #[error("Invalid target: {target} - {reason}")]
    InvalidTarget {
        /// Target specification
        target: String,
        /// Reason for invalidity
        reason: String,
    },

    /// Target unreachable
    #[error("Target unreachable: {0}")]
    TargetUnreachable(String),

    /// Parsing errors
    #[error("Parse error: {0}")]
    Parse(String),

    /// YAML parsing error
    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    /// JSON parsing error
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// File not found
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    /// Plugin errors
    #[error("Plugin error in {plugin}: {message}")]
    Plugin {
        /// Plugin name
        plugin: String,
        /// Error message
        message: String,
    },

    /// Plugin not found
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    /// Scheduler errors
    #[error("Scheduler error: {0}")]
    Scheduler(String),

    /// Resource limit exceeded
    #[error("Resource limit exceeded: {resource} (limit: {limit}, current: {current})")]
    ResourceLimitExceeded {
        /// Resource type
        resource: String,
        /// Limit value
        limit: String,
        /// Current value
        current: String,
    },

    /// Timeout error
    #[error("Operation timed out after {duration}")]
    Timeout {
        /// Timeout duration
        duration: String,
    },

    /// Execution errors
    #[error("Execution error: {0}")]
    Execution(String),

    /// Command execution error
    #[error("Command execution error: {0}")]
    Command(String),

    /// Sandbox violation
    #[error("Sandbox violation: {0}")]
    SandboxViolation(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// Authentication error
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Authorization error
    #[error("Authorization failed: {0}")]
    Authorization(String),

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Output format error
    #[error("Output format error: {format} - {message}")]
    OutputFormat {
        /// Output format
        format: String,
        /// Error message
        message: String,
    },

    /// Protocol error
    #[error("Protocol error for {protocol}: {message}")]
    Protocol {
        /// Protocol name
        protocol: String,
        /// Error message
        message: String,
    },

    /// DNS resolution error
    #[error("DNS resolution failed for {hostname}: {error}")]
    DnsResolution {
        /// Hostname
        hostname: String,
        /// Error details
        error: String,
    },

    /// TLS error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Certificate error
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// Matcher error
    #[error("Matcher error: {0}")]
    Matcher(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Cache error
    #[error("Cache error: {0}")]
    Cache(String),

    /// Metrics error
    #[error("Metrics error: {0}")]
    Metrics(String),

    /// Distributed system error
    #[error("Distributed system error: {0}")]
    Distributed(String),

    /// Worker error
    #[error("Worker {worker_id} error: {message}")]
    Worker {
        /// Worker ID
        worker_id: String,
        /// Error message
        message: String,
    },

    /// Coordinator error
    #[error("Coordinator error: {0}")]
    Coordinator(String),

    /// AI/LLM errors
    #[error("AI error: {0}")]
    Ai(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),

    /// Generic error with context
    #[error("{context}: {source}")]
    WithContext {
        /// Error context
        context: String,
        /// Source error
        source: Box<Error>,
    },

    /// Multiple errors
    #[error("Multiple errors occurred: {}", .0.len())]
    Multiple(Vec<Error>),
}

// Implement From for prometheus::Error
impl From<prometheus::Error> for Error {
    fn from(err: prometheus::Error) -> Self {
        Error::Metrics(err.to_string())
    }
}

impl Error {
    /// Add context to an error
    pub fn context<S: Into<String>>(self, context: S) -> Self {
        Error::WithContext {
            context: context.into(),
            source: Box::new(self),
        }
    }

    /// Create a configuration error
    pub fn config<S: Into<String>>(message: S) -> Self {
        Error::Config(message.into())
    }

    /// Create a template error
    pub fn template<S: Into<String>, M: Into<String>>(template: S, message: M) -> Self {
        Error::Template {
            template: template.into(),
            message: message.into(),
        }
    }

    /// Create an invalid target error
    pub fn invalid_target<S: Into<String>, R: Into<String>>(target: S, reason: R) -> Self {
        Error::InvalidTarget {
            target: target.into(),
            reason: reason.into(),
        }
    }

    /// Create a resource limit exceeded error
    pub fn resource_limit<R, L, C>(resource: R, limit: L, current: C) -> Self
    where
        R: Into<String>,
        L: Into<String>,
        C: Into<String>,
    {
        Error::ResourceLimitExceeded {
            resource: resource.into(),
            limit: limit.into(),
            current: current.into(),
        }
    }

    /// Create a command execution error
    pub fn command<S: Into<String>>(message: S) -> Self {
        Error::Command(message.into())
    }

    /// Check if error is fatal (should stop execution)
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Error::Internal(_)
                | Error::SandboxViolation(_)
                | Error::ResourceLimitExceeded { .. }
                | Error::Coordinator(_)
        )
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Network(_)
                | Error::TargetUnreachable(_)
                | Error::Timeout { .. }
                | Error::RateLimitExceeded(_)
                | Error::HttpRequest(_)
        )
    }
}

/// Trait for adding context to results
pub trait ResultExt<T> {
    /// Add context to the error
    fn context<C: Into<String>>(self, context: C) -> Result<T>;

    /// Add context using a closure (only called on error)
    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: Into<String>,
        F: FnOnce() -> C;
}

impl<T> ResultExt<T> for Result<T> {
    fn context<C: Into<String>>(self, context: C) -> Result<T> {
        self.map_err(|e| e.context(context))
    }

    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: Into<String>,
        F: FnOnce() -> C,
    {
        self.map_err(|e| e.context(f()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_context() {
        let err = Error::Parse("invalid syntax".to_string());
        let err_with_context = err.context("parsing configuration file");
        assert!(matches!(err_with_context, Error::WithContext { .. }));
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(Error::Network("connection reset".to_string()).is_retryable());
        assert!(!Error::Internal("panic".to_string()).is_retryable());
    }

    #[test]
    fn test_error_is_fatal() {
        assert!(Error::Internal("critical failure".to_string()).is_fatal());
        assert!(!Error::Network("timeout".to_string()).is_fatal());
    }
}
