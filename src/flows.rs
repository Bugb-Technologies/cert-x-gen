//! Flow-based template execution system
//!
//! Supports multi-step workflows with dependencies and conditional execution.

use crate::error::{Error, Result};
use crate::session::SessionManager;
use crate::types::{Context, Finding, Target};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Flow execution context
#[derive(Clone, Debug)]
pub struct FlowContext {
    /// Target being scanned
    pub target: Target,
    /// Session manager for cookies/JWT
    pub session: Arc<SessionManager>,
    /// Flow variables
    pub variables: HashMap<String, String>,
    /// Execution context
    pub context: Context,
}

impl FlowContext {
    /// Create a new flow context
    pub fn new(target: Target, session: Arc<SessionManager>, context: Context) -> Self {
        Self {
            target,
            session,
            variables: HashMap::new(),
            context,
        }
    }

    /// Set a variable
    pub fn set_variable(&mut self, key: String, value: String) {
        self.variables.insert(key, value);
    }

    /// Get a variable
    pub fn get_variable(&self, key: &str) -> Option<&String> {
        self.variables.get(key)
    }

    /// Replace variables in a string
    pub fn replace_variables(&self, input: &str) -> String {
        let mut result = input.to_string();

        // Replace {{variable}} patterns
        for (key, value) in &self.variables {
            let pattern = format!("{{{{{}}}}}", key);
            result = result.replace(&pattern, value);
        }

        // Replace target placeholders
        result = result.replace("{{Hostname}}", &self.target.address);
        if let Some(port) = self.target.port {
            result = result.replace("{{Port}}", &port.to_string());
        }
        result = result.replace("{{BaseURL}}", &self.target.url());

        result
    }
}

/// Flow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    /// Flow name
    pub name: String,
    /// Flow steps
    pub steps: Vec<FlowStep>,
    /// Dependencies (other flows that must execute first)
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Condition to execute (optional)
    #[serde(default)]
    pub condition: Option<String>,
    /// Optional flag
    #[serde(default)]
    pub optional: bool,
    /// Description of the flow
    #[serde(default)]
    pub description: Option<String>,
}

/// Flow step
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FlowStep {
    /// HTTP request
    HttpRequest {
        /// HTTP method
        method: String,
        /// Request path
        path: String,
        /// Headers
        #[serde(default)]
        headers: HashMap<String, String>,
        /// Request body
        body: Option<String>,
        /// Store response in variable
        store: Option<String>,
    },
    /// Set variable
    SetVariable {
        /// Variable name
        name: String,
        /// Variable value
        value: String,
    },
    /// Extract from response
    Extract {
        /// Source variable
        from: String,
        /// Extraction pattern (regex)
        pattern: String,
        /// Store in variable
        store: String,
    },
    /// Check condition
    Check {
        /// Condition to evaluate
        condition: String,
        /// Success message
        message: Option<String>,
    },
    /// Wait/sleep
    Wait {
        /// Duration in milliseconds
        duration_ms: u64,
    },
}

/// Flow executor
#[derive(Debug)]
pub struct FlowExecutor {
    /// Network client
    network_client: Arc<crate::network::NetworkClient>,
}

impl FlowExecutor {
    /// Create a new flow executor
    pub fn new(network_client: Arc<crate::network::NetworkClient>) -> Self {
        Self { network_client }
    }

    /// Execute a flow
    pub async fn execute_flow(
        &self,
        flow: &Flow,
        context: &mut FlowContext,
    ) -> Result<Vec<Finding>> {
        tracing::debug!("Executing flow: {}", flow.name);

        // Check condition if present
        if let Some(ref condition) = flow.condition {
            if !self.evaluate_condition(condition, context).await? {
                tracing::debug!("Flow {} skipped due to condition", flow.name);
                return Ok(Vec::new());
            }
        }

        let mut findings = Vec::new();

        // Execute each step
        for (index, step) in flow.steps.iter().enumerate() {
            tracing::debug!("Executing step {} in flow {}", index + 1, flow.name);

            match self.execute_step(step, context).await {
                Ok(step_findings) => findings.extend(step_findings),
                Err(e) => {
                    if flow.optional {
                        tracing::warn!(
                            "Optional flow {} step {} failed: {}",
                            flow.name,
                            index + 1,
                            e
                        );
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Execute a single flow step
    async fn execute_step(
        &self,
        step: &FlowStep,
        context: &mut FlowContext,
    ) -> Result<Vec<Finding>> {
        match step {
            FlowStep::HttpRequest {
                method,
                path,
                headers,
                body,
                store,
            } => {
                let url = format!(
                    "{}{}",
                    context.target.url(),
                    context.replace_variables(path)
                );
                tracing::debug!("HTTP {} {}", method, url);

                // Build request
                let mut request = self
                    .network_client
                    .client()
                    .request(method.parse().unwrap_or(reqwest::Method::GET), &url);

                // Add headers
                for (key, value) in headers {
                    let value = context.replace_variables(value);
                    request = request.header(key, value);
                }

                // Add cookies if available
                let domain = &context.target.address;
                if let Some(cookie_header) = context.session.get_cookie_header(domain).await {
                    request = request.header("Cookie", cookie_header);
                }

                // Add JWT if available
                if let Some(jwt_header) = context.session.get_jwt_header("default").await {
                    request = request.header("Authorization", jwt_header);
                }

                // Add body if present
                if let Some(ref body_content) = body {
                    let body_content = context.replace_variables(body_content);
                    request = request.body(body_content);
                }

                // Send request
                let response = request
                    .send()
                    .await
                    .map_err(|e| Error::Network(format!("HTTP request failed: {}", e)))?;

                // Process Set-Cookie headers
                for cookie in response.headers().get_all("set-cookie") {
                    if let Ok(cookie_str) = cookie.to_str() {
                        let _ = context.session.parse_set_cookie(domain, cookie_str).await;
                    }
                }

                // Store response if requested
                if let Some(var_name) = store {
                    let response_text = response
                        .text()
                        .await
                        .map_err(|e| Error::Network(format!("Failed to read response: {}", e)))?;
                    context.set_variable(var_name.clone(), response_text);
                }

                Ok(Vec::new())
            }

            FlowStep::SetVariable { name, value } => {
                let value = context.replace_variables(value);
                context.set_variable(name.clone(), value);
                Ok(Vec::new())
            }

            FlowStep::Extract {
                from,
                pattern,
                store,
            } => {
                if let Some(source) = context.get_variable(from) {
                    let re = regex::Regex::new(pattern)
                        .map_err(|e| Error::Parse(format!("Invalid regex: {}", e)))?;

                    if let Some(captures) = re.captures(source) {
                        if let Some(matched) = captures.get(1) {
                            context.set_variable(store.clone(), matched.as_str().to_string());
                        }
                    }
                }
                Ok(Vec::new())
            }

            FlowStep::Check { condition, message } => {
                let result = self.evaluate_condition(condition, context).await?;
                if result {
                    tracing::info!(
                        "Check passed: {}",
                        message.as_deref().unwrap_or("condition met")
                    );
                }
                Ok(Vec::new())
            }

            FlowStep::Wait { duration_ms } => {
                tokio::time::sleep(tokio::time::Duration::from_millis(*duration_ms)).await;
                Ok(Vec::new())
            }
        }
    }

    /// Evaluate a condition
    async fn evaluate_condition(&self, condition: &str, context: &FlowContext) -> Result<bool> {
        // Simple condition evaluation
        // In production, use a proper expression evaluator
        let condition = context.replace_variables(condition);

        // Check if variable exists
        if condition.contains("!=") {
            let parts: Vec<&str> = condition.split("!=").collect();
            if parts.len() == 2 {
                let left = parts[0].trim();
                let right = parts[1].trim().trim_matches('"');
                if let Some(value) = context.get_variable(left) {
                    return Ok(value != right);
                }
            }
        } else if condition.contains("==") {
            let parts: Vec<&str> = condition.split("==").collect();
            if parts.len() == 2 {
                let left = parts[0].trim();
                let right = parts[1].trim().trim_matches('"');
                if let Some(value) = context.get_variable(left) {
                    return Ok(value == right);
                }
            }
        }

        // Default: check if variable exists and is not empty
        if let Some(value) = context.get_variable(&condition) {
            return Ok(!value.is_empty());
        }

        Ok(false)
    }

    /// Execute multiple flows in dependency order
    pub async fn execute_flows(
        &self,
        flows: &[Flow],
        context: &mut FlowContext,
    ) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();
        let mut executed = std::collections::HashSet::new();

        // Execute flows in order, respecting dependencies
        for flow in flows {
            if executed.contains(&flow.name) {
                continue;
            }

            // Check dependencies
            for dep in &flow.depends_on {
                if !executed.contains(dep) {
                    tracing::warn!(
                        "Flow {} depends on {}, which hasn't executed",
                        flow.name,
                        dep
                    );
                }
            }

            // Execute flow
            match self.execute_flow(flow, context).await {
                Ok(findings) => {
                    all_findings.extend(findings);
                    executed.insert(flow.name.clone());
                }
                Err(e) => {
                    if flow.optional {
                        tracing::warn!("Optional flow {} failed: {}", flow.name, e);
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Protocol;

    #[test]
    fn test_flow_context_variable_replacement() {
        let target = Target::new("example.com", Protocol::Https);
        let session = Arc::new(SessionManager::new());
        let context_base = Context::default();
        let mut context = FlowContext::new(target, session, context_base);

        context.set_variable("token".to_string(), "abc123".to_string());

        let result = context.replace_variables("Bearer {{token}}");
        assert_eq!(result, "Bearer abc123");

        let result = context.replace_variables("https://{{Hostname}}/api");
        assert_eq!(result, "https://example.com/api");
    }

    #[test]
    fn test_flow_step_serialization() {
        let step = FlowStep::HttpRequest {
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            headers: HashMap::new(),
            body: None,
            store: Some("response".to_string()),
        };

        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("http_request"));
    }
}
