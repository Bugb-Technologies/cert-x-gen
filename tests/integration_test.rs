//! Integration tests for CERT-X-GEN

use cert_x_gen::{
    config::Config,
    core::{CertXGen, ScanJob},
    types::{Protocol, Severity, Target},
};
use std::sync::Arc;

#[tokio::test]
async fn test_engine_initialization() {
    let config = Config::default();
    let engine = CertXGen::new(config).await;
    assert!(engine.is_ok());
}

#[tokio::test]
async fn test_config_validation() {
    let config = Config::default();
    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn test_target_creation() {
    let target = Target::new("example.com", Protocol::Https);
    assert_eq!(target.address, "example.com");
    assert_eq!(target.url(), "https://example.com");
}

#[tokio::test]
async fn test_target_with_port() {
    let target = Target::with_port("example.com", 8443, Protocol::Https);
    assert_eq!(target.port, Some(8443));
    assert_eq!(target.url(), "https://example.com:8443");
}

#[tokio::test]
async fn test_scan_job_creation() {
    let config = Arc::new(Config::default());
    let targets = vec![
        Target::new("example.com", Protocol::Https),
        Target::new("test.com", Protocol::Http),
    ];
    let templates = Vec::new();

    let job = ScanJob::new(targets, templates, config);
    assert_eq!(job.targets.len(), 2);
    assert_eq!(job.templates.len(), 0);
}

#[tokio::test]
async fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[tokio::test]
async fn test_config_save_and_load() {
    use tempfile::NamedTempFile;

    let config = Config::default();
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path().with_extension("yaml");

    // Save config
    assert!(config.save(&path).is_ok());

    // Load config
    let loaded_config = Config::from_file(&path);
    assert!(loaded_config.is_ok());

    // Clean up
    std::fs::remove_file(&path).ok();
}

#[test]
fn test_protocol_display() {
    assert_eq!(Protocol::Http.to_string(), "http");
    assert_eq!(Protocol::Https.to_string(), "https");
    assert_eq!(Protocol::Dns.to_string(), "dns");
}

#[test]
fn test_severity_score() {
    assert_eq!(Severity::Critical.score(), 4);
    assert_eq!(Severity::High.score(), 3);
    assert_eq!(Severity::Medium.score(), 2);
    assert_eq!(Severity::Low.score(), 1);
    assert_eq!(Severity::Info.score(), 0);
}
