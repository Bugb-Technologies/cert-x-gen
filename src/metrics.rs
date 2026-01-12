//! Metrics collection and instrumentation

use crate::error::Result;
use prometheus::{Counter, CounterVec, Gauge, Histogram, HistogramVec, Opts, Registry};
use std::sync::Arc;

/// Metrics collector for CERT-X-GEN
#[derive(Debug)]
pub struct MetricsCollector {
    registry: Arc<Registry>,

    // Counters
    scans_total: Counter,
    templates_executed: Counter,
    findings_total: CounterVec,
    errors_total: CounterVec,

    // Gauges
    active_scans: Gauge,
    active_workers: Gauge,
    templates_loaded: Gauge,

    // Histograms
    scan_duration: Histogram,
    template_execution_duration: HistogramVec,
    network_request_duration: Histogram,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Result<Self> {
        let registry = Arc::new(Registry::new());

        // Counters
        let scans_total = Counter::with_opts(Opts::new(
            "certxgen_scans_total",
            "Total number of scans executed",
        ))?;
        registry.register(Box::new(scans_total.clone()))?;

        let templates_executed = Counter::with_opts(Opts::new(
            "certxgen_templates_executed_total",
            "Total number of templates executed",
        ))?;
        registry.register(Box::new(templates_executed.clone()))?;

        let findings_total = CounterVec::new(
            Opts::new(
                "certxgen_findings_total",
                "Total number of findings by severity",
            ),
            &["severity"],
        )?;
        registry.register(Box::new(findings_total.clone()))?;

        let errors_total = CounterVec::new(
            Opts::new("certxgen_errors_total", "Total number of errors by type"),
            &["error_type"],
        )?;
        registry.register(Box::new(errors_total.clone()))?;

        // Gauges
        let active_scans = Gauge::with_opts(Opts::new(
            "certxgen_active_scans",
            "Number of currently active scans",
        ))?;
        registry.register(Box::new(active_scans.clone()))?;

        let active_workers = Gauge::with_opts(Opts::new(
            "certxgen_active_workers",
            "Number of active worker threads",
        ))?;
        registry.register(Box::new(active_workers.clone()))?;

        let templates_loaded = Gauge::with_opts(Opts::new(
            "certxgen_templates_loaded",
            "Number of templates currently loaded",
        ))?;
        registry.register(Box::new(templates_loaded.clone()))?;

        // Histograms
        let scan_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "certxgen_scan_duration_seconds",
                "Duration of scan execution in seconds",
            )
            .buckets(vec![
                1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0,
            ]),
        )?;
        registry.register(Box::new(scan_duration.clone()))?;

        let template_execution_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "certxgen_template_execution_duration_seconds",
                "Duration of template execution in seconds",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0]),
            &["template_id"],
        )?;
        registry.register(Box::new(template_execution_duration.clone()))?;

        let network_request_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "certxgen_network_request_duration_seconds",
                "Duration of network requests in seconds",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]),
        )?;
        registry.register(Box::new(network_request_duration.clone()))?;

        Ok(Self {
            registry,
            scans_total,
            templates_executed,
            findings_total,
            errors_total,
            active_scans,
            active_workers,
            templates_loaded,
            scan_duration,
            template_execution_duration,
            network_request_duration,
        })
    }

    /// Increment scans counter
    pub fn inc_scans(&self) {
        self.scans_total.inc();
    }

    /// Increment templates executed counter
    pub fn inc_templates_executed(&self) {
        self.templates_executed.inc();
    }

    /// Increment findings counter
    pub fn inc_findings(&self, severity: &str) {
        self.findings_total.with_label_values(&[severity]).inc();
    }

    /// Increment errors counter
    pub fn inc_errors(&self, error_type: &str) {
        self.errors_total.with_label_values(&[error_type]).inc();
    }

    /// Set active scans gauge
    pub fn set_active_scans(&self, count: i64) {
        self.active_scans.set(count as f64);
    }

    /// Set active workers gauge
    pub fn set_active_workers(&self, count: i64) {
        self.active_workers.set(count as f64);
    }

    /// Set templates loaded gauge
    pub fn set_templates_loaded(&self, count: i64) {
        self.templates_loaded.set(count as f64);
    }

    /// Observe scan duration
    pub fn observe_scan_duration(&self, duration_secs: f64) {
        self.scan_duration.observe(duration_secs);
    }

    /// Observe template execution duration
    pub fn observe_template_execution(&self, template_id: &str, duration_secs: f64) {
        self.template_execution_duration
            .with_label_values(&[template_id])
            .observe(duration_secs);
    }

    /// Observe network request duration
    pub fn observe_network_request(&self, duration_secs: f64) {
        self.network_request_duration.observe(duration_secs);
    }

    /// Get registry for Prometheus export
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> Result<String> {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|e| crate::error::Error::Metrics(e.to_string()))?;
        String::from_utf8(buffer).map_err(|e| crate::error::Error::Metrics(e.to_string()))
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics collector")
    }
}

/// Metrics guard for automatic timing
#[allow(missing_debug_implementations)]
pub struct TimingGuard<'a> {
    start: std::time::Instant,
    observer: Option<Box<dyn FnOnce(f64) + 'a>>,
}

impl<'a> TimingGuard<'a> {
    /// Create a new timing guard
    pub fn new<F>(observer: F) -> Self
    where
        F: FnOnce(f64) + 'a,
    {
        Self {
            start: std::time::Instant::now(),
            observer: Some(Box::new(observer)),
        }
    }
}

impl<'a> Drop for TimingGuard<'a> {
    fn drop(&mut self) {
        if let Some(observer) = self.observer.take() {
            let duration = self.start.elapsed().as_secs_f64();
            observer(duration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::new().unwrap();

        collector.inc_scans();
        collector.inc_templates_executed();
        collector.inc_findings("critical");
        collector.set_active_scans(5);
        collector.observe_scan_duration(10.5);

        let export = collector.export_prometheus();
        assert!(export.is_ok());
    }

    #[test]
    fn test_timing_guard() {
        let collector = MetricsCollector::new().unwrap();

        {
            let _guard = TimingGuard::new(|duration| {
                assert!(duration >= 0.0);
            });
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
