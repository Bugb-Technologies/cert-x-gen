//! Plugin system for extensibility

use crate::error::{Error, Result};
use crate::types::{Finding, ScanResults};
use std::collections::HashMap;
use std::sync::Arc;

/// Plugin trait that all plugins must implement
pub trait Plugin: Send + Sync {
    /// Get plugin name
    fn name(&self) -> &str;

    /// Get plugin version
    fn version(&self) -> &str;

    /// Initialize the plugin
    fn initialize(&mut self, config: &crate::config::Config) -> Result<()>;

    /// Called when a finding is discovered
    fn on_finding(&self, _finding: &Finding) -> Result<()> {
        Ok(())
    }

    /// Called when a scan is started
    fn on_scan_start(&self, _scan_id: uuid::Uuid) -> Result<()> {
        Ok(())
    }

    /// Called when a scan is completed
    fn on_scan_complete(&self, _results: &ScanResults) -> Result<()> {
        Ok(())
    }

    /// Called when an error occurs
    fn on_error(&self, _error: &Error) -> Result<()> {
        Ok(())
    }

    /// Shutdown the plugin
    fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Plugin manager for loading and managing plugins
#[allow(missing_debug_implementations)]
pub struct PluginManager {
    plugins: HashMap<String, Arc<dyn Plugin>>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Register a plugin
    pub fn register(&mut self, plugin: Arc<dyn Plugin>) {
        let name = plugin.name().to_string();
        tracing::info!("Registering plugin: {} v{}", name, plugin.version());
        self.plugins.insert(name, plugin);
    }

    /// Get a plugin by name
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Plugin>> {
        self.plugins.get(name)
    }

    /// Get all plugins
    pub fn plugins(&self) -> Vec<&Arc<dyn Plugin>> {
        self.plugins.values().collect()
    }

    /// Notify all plugins of a finding
    pub fn notify_finding(&self, finding: &Finding) {
        for plugin in self.plugins.values() {
            if let Err(e) = plugin.on_finding(finding) {
                tracing::error!("Plugin {} error on finding: {}", plugin.name(), e);
            }
        }
    }

    /// Notify all plugins of scan start
    pub fn notify_scan_start(&self, scan_id: uuid::Uuid) {
        for plugin in self.plugins.values() {
            if let Err(e) = plugin.on_scan_start(scan_id) {
                tracing::error!("Plugin {} error on scan start: {}", plugin.name(), e);
            }
        }
    }

    /// Notify all plugins of scan completion
    pub fn notify_scan_complete(&self, results: &ScanResults) {
        for plugin in self.plugins.values() {
            if let Err(e) = plugin.on_scan_complete(results) {
                tracing::error!("Plugin {} error on scan complete: {}", plugin.name(), e);
            }
        }
    }

    /// Notify all plugins of an error
    pub fn notify_error(&self, error: &Error) {
        for plugin in self.plugins.values() {
            if let Err(e) = plugin.on_error(error) {
                tracing::error!("Plugin {} error on error notification: {}", plugin.name(), e);
            }
        }
    }

    /// Shutdown all plugins
    pub fn shutdown(&mut self) {
        for (name, plugin) in &mut self.plugins {
            if let Some(plugin) = Arc::get_mut(plugin) {
                if let Err(e) = plugin.shutdown() {
                    tracing::error!("Plugin {} error on shutdown: {}", name, e);
                }
            }
        }
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Example logging plugin
#[derive(Debug)]
pub struct LoggingPlugin {
    name: String,
}

impl LoggingPlugin {
    /// Create a new logging plugin
    pub fn new() -> Self {
        Self {
            name: "logging".to_string(),
        }
    }
}

impl Default for LoggingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for LoggingPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn initialize(&mut self, _config: &crate::config::Config) -> Result<()> {
        tracing::info!("Logging plugin initialized");
        Ok(())
    }

    fn on_finding(&self, finding: &Finding) -> Result<()> {
        tracing::info!(
            "Finding: {} - {} ({})",
            finding.severity,
            finding.title,
            finding.target
        );
        Ok(())
    }

    fn on_scan_start(&self, scan_id: uuid::Uuid) -> Result<()> {
        tracing::info!("Scan started: {}", scan_id);
        Ok(())
    }

    fn on_scan_complete(&self, results: &ScanResults) -> Result<()> {
        tracing::info!(
            "Scan completed: {} findings in {} targets",
            results.findings.len(),
            results.statistics.targets_scanned
        );
        Ok(())
    }
}

/// Example notification plugin (webhook)
#[derive(Debug)]
pub struct WebhookPlugin {
    name: String,
    webhook_url: Option<String>,
    client: Option<reqwest::Client>,
}

impl WebhookPlugin {
    /// Create a new webhook plugin
    pub fn new(webhook_url: String) -> Self {
        Self {
            name: "webhook".to_string(),
            webhook_url: Some(webhook_url),
            client: None,
        }
    }
}

impl Plugin for WebhookPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn initialize(&mut self, _config: &crate::config::Config) -> Result<()> {
        self.client = Some(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| Error::Plugin {
                    plugin: self.name.clone(),
                    message: format!("Failed to create HTTP client: {}", e),
                })?,
        );
        tracing::info!("Webhook plugin initialized");
        Ok(())
    }

    fn on_finding(&self, finding: &Finding) -> Result<()> {
        // Only send critical and high severity findings
        if finding.severity < crate::types::Severity::High {
            return Ok(());
        }

        if let (Some(client), Some(url)) = (&self.client, &self.webhook_url) {
            let payload = serde_json::json!({
                "severity": finding.severity.to_string(),
                "title": finding.title,
                "target": finding.target,
                "template_id": finding.template_id,
                "timestamp": finding.timestamp,
            });

            // Send webhook asynchronously (fire and forget)
            let client = client.clone();
            let url = url.clone();
            tokio::spawn(async move {
                match client.post(&url).json(&payload).send().await {
                    Ok(_) => tracing::debug!("Webhook sent successfully"),
                    Err(e) => tracing::error!("Failed to send webhook: {}", e),
                }
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_plugin_manager() {
        let mut manager = PluginManager::new();
        let plugin = Arc::new(LoggingPlugin::new());
        
        manager.register(plugin);
        assert_eq!(manager.plugins().len(), 1);
    }

    #[test]
    fn test_logging_plugin() {
        let mut plugin = LoggingPlugin::new();
        let config = crate::config::Config::default();
        
        assert!(plugin.initialize(&config).is_ok());
        assert_eq!(plugin.name(), "logging");
        assert_eq!(plugin.version(), "1.0.0");
    }
}
