//! YAML template engine implementation with full matcher support

use crate::error::{Error, Result};
use crate::flows::{Flow, FlowContext, FlowExecutor};
use crate::matcher::{HttpResponse, MatchCondition, Matcher, MatcherType};
use crate::network::NetworkClient;
use crate::template::{Template, TemplateEngine};
use crate::types::{Context, Evidence, Finding, Protocol, Target, TemplateMetadata};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// YAML template engine
#[derive(Debug)]
pub struct YamlTemplateEngine {
    network_client: Option<Arc<NetworkClient>>,
    flow_executor: Option<Arc<FlowExecutor>>,
}

impl YamlTemplateEngine {
    /// Create a new YAML template engine
    pub fn new() -> Self {
        Self {
            network_client: None,
            flow_executor: None,
        }
    }

    /// Set network client
    pub fn with_network_client(mut self, client: Arc<NetworkClient>) -> Self {
        self.network_client = Some(client.clone());
        self.flow_executor = Some(Arc::new(FlowExecutor::new(client)));
        self
    }
}

impl Default for YamlTemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TemplateEngine for YamlTemplateEngine {
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::template(
                path.display().to_string(),
                format!("Failed to read template: {}", e),
            )
        })?;

        let template_data: YamlTemplateData = serde_yaml::from_str(&content)?;

        Ok(Box::new(YamlTemplateImpl {
            data: template_data,
            network_client: self.network_client.clone(),
            flow_executor: self.flow_executor.clone(),
        }))
    }

    async fn validate_template(&self, template: &dyn Template) -> Result<()> {
        template.validate()
    }

    async fn execute_template(
        &self,
        template: &dyn Template,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>> {
        template.execute(target, context).await
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        // Return all protocols that YAML templates CAN support
        // Individual templates will report their specific protocols via detect_protocols()
        vec![
            Protocol::Http,
            Protocol::Https,
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Dns,
            Protocol::Ssh,
            Protocol::Ftp,
            Protocol::Smtp,
            Protocol::Smb,
            Protocol::Rdp,
            // Custom protocols are handled dynamically
        ]
    }

    fn name(&self) -> &str {
        "yaml"
    }

    fn supports_file(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|s| s.to_str())
            .map(|ext| ext == "yaml" || ext == "yml")
            .unwrap_or(false)
    }
}

/// YAML template data structure
#[derive(Debug, Clone, Deserialize, Serialize)]
struct YamlTemplateData {
    /// Template metadata
    #[serde(flatten)]
    metadata: TemplateMetadata,

    /// HTTP requests
    http: Option<Vec<HttpRequestSpec>>,

    /// Network/TCP requests
    network: Option<Vec<NetworkRequestSpec>>,

    /// Matchers
    matchers: Option<Vec<MatcherType>>,

    /// Matcher condition (and/or)
    #[serde(rename = "matchers-condition")]
    matchers_condition: Option<MatchCondition>,

    /// Flows (multi-step execution)
    flows: Option<Vec<Flow>>,
}

/// HTTP request specification
#[derive(Debug, Clone, Deserialize, Serialize)]
struct HttpRequestSpec {
    /// HTTP method
    #[serde(default = "default_method")]
    method: String,

    /// Request paths
    path: Option<Vec<String>>,

    /// Headers
    #[serde(default)]
    headers: HashMap<String, String>,

    /// Request body
    body: Option<String>,

    /// Matchers for this request
    matchers: Option<Vec<MatcherType>>,

    /// Matcher condition
    #[serde(rename = "matchers-condition")]
    matchers_condition: Option<MatchCondition>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// Network/TCP request specification
#[derive(Debug, Clone, Deserialize, Serialize)]
struct NetworkRequestSpec {
    /// Protocol (tcp/udp)
    #[serde(default = "default_protocol")]
    protocol: String,

    /// Port number
    port: u16,

    /// Payloads to send
    #[serde(default)]
    payloads: Vec<String>,

    /// Matchers for this request
    matchers: Option<Vec<MatcherType>>,

    /// Matcher condition
    #[serde(rename = "matchers-condition")]
    matchers_condition: Option<MatchCondition>,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

/// YAML template implementation
struct YamlTemplateImpl {
    data: YamlTemplateData,
    network_client: Option<Arc<NetworkClient>>,
    flow_executor: Option<Arc<FlowExecutor>>,
}

impl YamlTemplateImpl {
    /// Dynamically detect supported protocols from template content
    fn detect_protocols(&self) -> Vec<Protocol> {
        let mut protocols = Vec::new();

        // Check for HTTP requests - supports both HTTP and HTTPS
        if self.data.http.is_some() {
            protocols.push(Protocol::Http);
            protocols.push(Protocol::Https);
        }

        // Check for network requests and parse their protocols
        if let Some(ref network_requests) = self.data.network {
            for request in network_requests {
                let protocol = match request.protocol.to_lowercase().as_str() {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    "dns" => Protocol::Dns,
                    "ssh" => Protocol::Ssh,
                    "ftp" => Protocol::Ftp,
                    "smtp" => Protocol::Smtp,
                    "smb" => Protocol::Smb,
                    "rdp" => Protocol::Rdp,
                    other => Protocol::Custom(other.to_string()),
                };

                if !protocols.contains(&protocol) {
                    protocols.push(protocol);
                }
            }
        }

        // Check flows for protocol hints
        if let Some(ref flows) = self.data.flows {
            for flow in flows {
                for step in &flow.steps {
                    use crate::flows::FlowStep;
                    match step {
                        FlowStep::HttpRequest { .. } => {
                            if !protocols.contains(&Protocol::Http) {
                                protocols.push(Protocol::Http);
                                protocols.push(Protocol::Https);
                            }
                        }
                        _ => {
                            // Other flow steps don't indicate specific protocols
                        }
                    }
                }
            }
        }

        // If no protocols detected, default to HTTP/HTTPS for backward compatibility
        if protocols.is_empty() {
            tracing::warn!(
                "Template {} has no protocol indicators, defaulting to HTTP/HTTPS",
                self.data.metadata.id
            );
            protocols.push(Protocol::Http);
            protocols.push(Protocol::Https);
        }

        protocols
    }
}

#[async_trait]
impl Template for YamlTemplateImpl {
    fn metadata(&self) -> &TemplateMetadata {
        &self.data.metadata
    }

    async fn execute(&self, target: &Target, context: &Context) -> Result<Vec<Finding>> {
        tracing::debug!(
            "Executing YAML template {} against {}",
            self.id(),
            target.address
        );

        let mut findings = Vec::new();

        // Execute flows if present
        if let Some(ref flows) = self.data.flows {
            if let (Some(ref flow_executor), Some(ref network_client)) =
                (&self.flow_executor, &self.network_client)
            {
                let mut flow_context = FlowContext::new(
                    target.clone(),
                    network_client.session_manager().clone(),
                    context.clone(),
                );

                let flow_findings = flow_executor
                    .execute_flows(flows, &mut flow_context)
                    .await?;
                findings.extend(flow_findings);
            }
        }

        // Execute network/TCP requests if present
        if let Some(ref network_requests) = self.data.network {
            if let Some(ref network_client) = self.network_client {
                for request_spec in network_requests {
                    let request_findings = self
                        .execute_network_request(request_spec, target, network_client, context)
                        .await?;
                    findings.extend(request_findings);
                }
            }
        }

        // Execute HTTP requests if present
        if let Some(ref http_requests) = self.data.http {
            if let Some(ref network_client) = self.network_client {
                for request_spec in http_requests {
                    let request_findings = self
                        .execute_http_request(request_spec, target, network_client)
                        .await?;
                    findings.extend(request_findings);
                }
            }
        }

        Ok(findings)
    }

    fn validate(&self) -> Result<()> {
        // Validate that we have either HTTP requests, network requests, or flows
        if self.data.http.is_none() && self.data.network.is_none() && self.data.flows.is_none() {
            return Err(Error::TemplateValidation {
                template: self.id().to_string(),
                reason: "Template must have either 'http', 'network', or 'flows' defined"
                    .to_string(),
            });
        }

        Ok(())
    }

    /// Get supported protocols (dynamically detected from template content)
    fn supported_protocols(&self) -> Vec<Protocol> {
        self.detect_protocols()
    }
}

impl YamlTemplateImpl {
    /// Execute a single HTTP request specification
    /// Supports both HTTP and HTTPS automatically
    async fn execute_http_request(
        &self,
        spec: &HttpRequestSpec,
        target: &Target,
        network_client: &NetworkClient,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // For HTTP templates, try both HTTP and HTTPS schemes
        let target_variants = if matches!(target.protocol, Protocol::Http | Protocol::Https) {
            // Try inferred scheme first, then the other
            let inferred = target.infer_scheme();
            if inferred == Protocol::Https {
                vec![
                    Target {
                        protocol: Protocol::Https,
                        ..target.clone()
                    },
                    Target {
                        protocol: Protocol::Http,
                        ..target.clone()
                    },
                ]
            } else {
                vec![
                    Target {
                        protocol: Protocol::Http,
                        ..target.clone()
                    },
                    Target {
                        protocol: Protocol::Https,
                        ..target.clone()
                    },
                ]
            }
        } else {
            vec![target.clone()]
        };

        // Try each scheme variant - smart fallback logic
        // If first scheme connects successfully, skip the other (even without findings)
        // Only try fallback scheme if connection/timeout error occurs
        for target_variant in target_variants {
            match self
                .execute_http_request_single(&target_variant, spec, network_client)
                .await
            {
                Ok(mut variant_findings) => {
                    // SUCCESS: Connection worked - this is the right protocol
                    findings.append(&mut variant_findings);
                    if !findings.is_empty() {
                        tracing::debug!(
                            "Found {} findings with {} scheme, skipping fallback",
                            findings.len(),
                            target_variant.protocol
                        );
                    } else {
                        tracing::debug!(
                            "No findings but {} scheme connected successfully, skipping fallback",
                            target_variant.protocol
                        );
                    }
                    // Always break on successful connection - no need to try other scheme
                    break;
                }
                Err(e) => {
                    let error_str = e.to_string().to_lowercase();
                    // Check if this is a connection/protocol error that warrants trying another scheme
                    let is_connection_error = error_str.contains("connection refused")
                        || error_str.contains("connection reset")
                        || error_str.contains("ssl")
                        || error_str.contains("tls")
                        || error_str.contains("certificate")
                        || error_str.contains("handshake")
                        || error_str.contains("protocol")
                        || error_str.contains("timeout")
                        || error_str.contains("record overflow")  // TLS record layer error
                        || error_str.contains("overflow")         // Generic overflow errors
                        || error_str.contains("invalid data")     // Protocol mismatch
                        || error_str.contains("unexpected eof")   // Connection dropped
                        || error_str.contains("eof"); // Unexpected end of connection

                    if is_connection_error {
                        tracing::debug!(
                            "{} scheme failed for {} ({}), trying fallback scheme",
                            target_variant.protocol,
                            target_variant.url(),
                            e
                        );
                        // Continue to try next scheme variant
                    } else {
                        // Non-connection error (e.g., HTTP 4xx/5xx) means the protocol worked
                        // but the request itself had issues - no point trying other scheme
                        tracing::debug!(
                            "{} scheme connected but request failed: {}",
                            target_variant.protocol,
                            e
                        );
                        break;
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Execute HTTP request against a single target variant
    async fn execute_http_request_single(
        &self,
        target: &Target,
        spec: &HttpRequestSpec,
        network_client: &NetworkClient,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // NOTE: We intentionally do NOT filter by port number here.
        // If a template explicitly defines an `http:` section, we trust that the
        // template author knows the target service speaks HTTP on that port.
        // Many services run HTTP APIs on non-standard ports (e.g., Ollama on 11434,
        // Elasticsearch on 9200, custom APIs on arbitrary ports).
        // The connection will simply fail if the port doesn't speak HTTP.

        // Get paths to test
        let paths = spec
            .path
            .as_ref()
            .map(|p| p.clone())
            .unwrap_or_else(|| vec!["/".to_string()]);

        for path in paths {
            let url = format!("{}{}", target.url(), path);
            tracing::debug!("{} {}", spec.method, url);

            // Execute HTTP request
            let start = std::time::Instant::now();
            let response = match spec.method.to_uppercase().as_str() {
                "GET" => {
                    network_client
                        .get_with_headers(&url, spec.headers.clone())
                        .await?
                }
                "POST" => {
                    network_client
                        .post_with_headers(
                            &url,
                            spec.body.clone().unwrap_or_default(),
                            spec.headers.clone(),
                        )
                        .await?
                }
                _ => {
                    tracing::warn!("Unsupported HTTP method: {}", spec.method);
                    continue;
                }
            };
            let response_time = start.elapsed();

            // Convert to HttpResponse for matching
            let status = response.status().as_u16();
            let headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let body = response
                .bytes()
                .await
                .map_err(|e| Error::Network(format!("Failed to read response: {}", e)))?
                .to_vec();

            let http_response = HttpResponse {
                status,
                headers,
                body,
                response_time,
            };

            // Get matchers (either from request spec or template level)
            let matchers = spec.matchers.as_ref().or(self.data.matchers.as_ref());

            let condition = spec
                .matchers_condition
                .or(self.data.matchers_condition)
                .unwrap_or(MatchCondition::Or);

            // Evaluate matchers
            if let Some(matcher_types) = matchers {
                let matchers: Vec<Matcher> = matcher_types
                    .iter()
                    .map(|mt| Matcher::new(mt.clone()))
                    .collect();

                if crate::matcher::match_all(&matchers, &http_response, condition)? {
                    // Create evidence with request and response data
                    let mut evidence = Evidence::new();

                    // Capture the request
                    let request_str = format!(
                        "{} {}\n{}",
                        spec.method.to_uppercase(),
                        url,
                        spec.body.clone().unwrap_or_default()
                    );
                    evidence.request = Some(request_str);

                    // Capture the response
                    evidence.response = Some(http_response.body_string());

                    // Capture matched patterns from matchers
                    for matcher in &matchers {
                        if matcher.matches(&http_response)? {
                            let matcher_type = matcher.matcher_type();
                            match matcher_type {
                                MatcherType::Word { words, .. } => {
                                    let response_str = http_response.body_string();
                                    for word in words {
                                        if response_str.contains(word) {
                                            evidence.matched_patterns.push(word.clone());
                                        }
                                    }
                                }
                                MatcherType::Regex { regex, .. } => {
                                    for pattern in regex {
                                        evidence.matched_patterns.push(pattern.clone());
                                    }
                                }
                                MatcherType::Status {
                                    status: statuses, ..
                                } => {
                                    for s in statuses {
                                        if *s == status {
                                            evidence.matched_patterns.push(format!("status:{}", s));
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    // Add metadata
                    evidence.add_data("status_code", serde_json::json!(status));
                    evidence.add_data(
                        "response_time_ms",
                        serde_json::json!(response_time.as_millis()),
                    );
                    evidence.add_data("method", serde_json::json!(spec.method.to_uppercase()));
                    evidence.add_data("url", serde_json::json!(url));

                    let finding = Finding::new(
                        target.url(),
                        self.id().to_string(),
                        self.metadata().severity,
                        self.metadata().name.clone(),
                        self.metadata().description.clone(),
                    )
                    .with_confidence(self.metadata().confidence.unwrap_or(90) as u8)
                    .with_evidence(evidence);

                    findings.push(finding);

                    tracing::info!(
                        "Template {} matched for target {}",
                        self.id(),
                        target.address
                    );
                }
            }
        }

        Ok(findings)
    }

    /// Execute a single network/TCP request specification
    /// Supports multiple ports from --add-ports or uses template's default port
    async fn execute_network_request(
        &self,
        spec: &NetworkRequestSpec,
        target: &Target,
        _network_client: &NetworkClient,
        _context: &Context,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Determine ports to test:
        // 1. If target has port (from --add-ports or target:port) → use it
        // 2. Otherwise, use template's default port
        let port = target.port.unwrap_or(spec.port);

        // Execute the network request on the determined port
        let port_findings = self
            .execute_network_request_on_port(spec, target, port)
            .await?;
        findings.extend(port_findings);

        Ok(findings)
    }

    /// Execute network request on a specific port
    async fn execute_network_request_on_port(
        &self,
        spec: &NetworkRequestSpec,
        target: &Target,
        port: u16,
    ) -> Result<Vec<Finding>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        let mut findings = Vec::new();

        let addr = format!("{}:{}", target.address, port);
        tracing::debug!("{} {}", spec.protocol.to_uppercase(), addr);

        // Connect to the target
        let timeout_duration = std::time::Duration::from_secs(10);
        let stream = match timeout(timeout_duration, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                tracing::debug!("Failed to connect to {}: {}", addr, e);
                return Ok(findings);
            }
            Err(_) => {
                tracing::debug!("Connection to {} timed out", addr);
                return Ok(findings);
            }
        };

        let (mut reader, mut writer) = stream.into_split();
        let mut response_data = Vec::new();

        // Send payloads and collect responses
        for payload in &spec.payloads {
            // Parse escape sequences in payload
            let payload_bytes = payload
                .replace("\\r\\n", "\r\n")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .into_bytes();

            // Send payload
            if let Err(e) = writer.write_all(&payload_bytes).await {
                tracing::debug!("Failed to send payload to {}: {}", addr, e);
                continue;
            }

            // Read response with timeout
            let mut buffer = vec![0u8; 8192];
            match timeout(std::time::Duration::from_secs(5), reader.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    response_data.extend_from_slice(&buffer[..n]);
                }
                Ok(Ok(_)) => {
                    tracing::debug!("Connection closed by {}", addr);
                    break;
                }
                Ok(Err(e)) => {
                    tracing::debug!("Failed to read response from {}: {}", addr, e);
                    break;
                }
                Err(_) => {
                    tracing::debug!("Read timeout from {}", addr);
                    break;
                }
            }
        }

        // Convert response to string (lossy for binary data)
        let response_str = String::from_utf8_lossy(&response_data).to_string();

        tracing::debug!(
            "Received {} bytes from {}:{}: {:?}",
            response_data.len(),
            target.address,
            port,
            &response_str[..response_str.len().min(200)]
        );

        // Create a pseudo HTTP response for matcher compatibility
        let network_response = HttpResponse {
            status: 200, // Dummy status for network responses
            headers: vec![],
            body: response_data.clone(),
            response_time: std::time::Duration::from_secs(0),
        };

        // Get matchers (either from request spec or template level)
        let matchers = spec.matchers.as_ref().or(self.data.matchers.as_ref());

        let condition = spec
            .matchers_condition
            .or(self.data.matchers_condition)
            .unwrap_or(MatchCondition::Or);

        tracing::debug!(
            "Evaluating {} matchers with condition {:?}",
            matchers.as_ref().map(|m| m.len()).unwrap_or(0),
            condition
        );

        // Evaluate matchers
        if let Some(matcher_types) = matchers {
            let matchers: Vec<Matcher> = matcher_types
                .iter()
                .map(|mt| Matcher::new(mt.clone()))
                .collect();

            if crate::matcher::match_all(&matchers, &network_response, condition)? {
                // Create evidence with request and response data
                let mut evidence = Evidence::new();

                // Capture the request (payloads sent)
                let request_str = spec.payloads.join("\n");
                evidence.request = Some(request_str);

                // Capture the response
                evidence.response = Some(response_str.clone());

                // Capture matched patterns from matchers
                for matcher in &matchers {
                    if matcher.matches(&network_response)? {
                        let matcher_type = matcher.matcher_type();
                        match matcher_type {
                            MatcherType::Word { words, .. } => {
                                for word in words {
                                    if response_str.contains(word) {
                                        evidence.matched_patterns.push(word.clone());
                                    }
                                }
                            }
                            MatcherType::Regex { regex, .. } => {
                                for pattern in regex {
                                    evidence.matched_patterns.push(pattern.clone());
                                }
                            }
                            MatcherType::Status { .. } => {
                                evidence.matched_patterns.push("status_match".to_string());
                            }
                            _ => {}
                        }
                    }
                }

                // Add metadata
                evidence.add_data("protocol", serde_json::json!(spec.protocol));
                evidence.add_data("port", serde_json::json!(port));
                evidence.add_data("response_length", serde_json::json!(response_data.len()));

                // Create finding with evidence
                let finding = Finding::new(
                    format!("{}:{}", target.address, port),
                    self.id().to_string(),
                    self.metadata().severity,
                    self.metadata().name.clone(),
                    self.metadata().description.clone(),
                )
                .with_confidence(self.metadata().confidence.unwrap_or(90) as u8)
                .with_evidence(evidence);

                findings.push(finding);

                tracing::info!(
                    "Template {} matched for target {}:{}",
                    self.id(),
                    target.address,
                    port
                );
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaml_engine_supports_file() {
        let engine = YamlTemplateEngine::new();
        assert!(engine.supports_file(Path::new("test.yaml")));
        assert!(engine.supports_file(Path::new("test.yml")));
        assert!(!engine.supports_file(Path::new("test.py")));
    }
}
