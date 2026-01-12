// Copyright (c) 2024 CERT-X-GEN Core Team
//! Progress bar module for visual scan progress tracking

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Progress tracker for scan operations
#[derive(Debug)]
pub struct ProgressTracker {
    /// Multi-progress container for multiple bars
    multi: Arc<MultiProgress>,
    /// Main progress bar (overall scan progress) - created on init()
    main_bar: RwLock<Option<ProgressBar>>,
    /// Current target being scanned - created on init()
    current_target: RwLock<Option<ProgressBar>>,
    /// Whether progress is enabled
    enabled: AtomicBool,
    /// Total work units
    total_units: AtomicU64,
    /// Completed work units
    completed_units: AtomicU64,
    /// Findings count
    findings_count: AtomicU64,
}

impl ProgressTracker {
    /// Create a new progress tracker (bars are created when init() is called)
    pub fn new(enabled: bool) -> Self {
        Self {
            multi: Arc::new(MultiProgress::new()),
            main_bar: RwLock::new(None),
            current_target: RwLock::new(None),
            enabled: AtomicBool::new(enabled),
            total_units: AtomicU64::new(0),
            completed_units: AtomicU64::new(0),
            findings_count: AtomicU64::new(0),
        }
    }

    /// Create a disabled progress tracker
    pub fn disabled() -> Self {
        Self::new(false)
    }

    /// Check if progress is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Initialize progress with total work units - creates and shows the progress bars
    pub fn init(&self, targets: usize, templates: usize) {
        if !self.is_enabled() {
            return;
        }

        let total = (targets * templates) as u64;
        self.total_units.store(total, Ordering::Relaxed);

        // Main progress bar style
        let main_style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
            .unwrap()
            .progress_chars("█▓▒░  ");

        // Status bar style
        let status_style = ProgressStyle::default_bar()
            .template("  {prefix:.bold.dim} {wide_msg}")
            .unwrap();

        // Create and add the main progress bar
        let main_bar = self.multi.add(ProgressBar::new(total));
        main_bar.set_style(main_style);
        main_bar.set_message(format!(
            "Scanning {} targets × {} templates",
            targets, templates
        ));
        main_bar.enable_steady_tick(Duration::from_millis(100));
        *self.main_bar.write() = Some(main_bar);

        // Create and add the status bar
        let status_bar = self.multi.add(ProgressBar::new(0));
        status_bar.set_style(status_style);
        status_bar.set_prefix("Target");
        *self.current_target.write() = Some(status_bar);
    }

    /// Set current target being processed
    pub fn set_target(&self, target: &str) {
        if !self.is_enabled() {
            return;
        }
        if let Some(bar) = self.current_target.read().as_ref() {
            bar.set_message(target.to_string());
        }
    }

    /// Set current template being executed
    pub fn set_template(&self, template_id: &str, target: &str) {
        if !self.is_enabled() {
            return;
        }
        if let Some(bar) = self.current_target.read().as_ref() {
            bar.set_message(format!("{} → {}", target, template_id));
        }
    }

    /// Increment completed work units
    pub fn inc(&self, delta: u64) {
        if !self.is_enabled() {
            return;
        }
        self.completed_units.fetch_add(delta, Ordering::Relaxed);
        if let Some(bar) = self.main_bar.read().as_ref() {
            bar.inc(delta);
        }
    }

    /// Add findings count
    pub fn add_findings(&self, count: usize) {
        if !self.is_enabled() {
            return;
        }
        let new_count = self
            .findings_count
            .fetch_add(count as u64, Ordering::Relaxed)
            + count as u64;
        self.update_message(new_count);
    }

    /// Update the main bar message with findings count
    fn update_message(&self, findings: u64) {
        let completed = self.completed_units.load(Ordering::Relaxed);
        let total = self.total_units.load(Ordering::Relaxed);

        if findings > 0 {
            if let Some(bar) = self.main_bar.read().as_ref() {
                bar.set_message(format!(
                    "🔍 Found {} findings ({}/{})",
                    findings, completed, total
                ));
            }
        }
    }

    /// Mark a template as completed (success or failure)
    pub fn template_done(&self, _target: &str, _template_id: &str, findings: usize) {
        if !self.is_enabled() {
            return;
        }

        self.inc(1);

        if findings > 0 {
            self.add_findings(findings);
        }
    }

    /// Mark scan as complete
    pub fn finish(&self) {
        if !self.is_enabled() {
            return;
        }

        let findings = self.findings_count.load(Ordering::Relaxed);
        if let Some(bar) = self.main_bar.read().as_ref() {
            bar.finish_with_message(format!("✓ Scan complete - {} findings", findings));
        }
        if let Some(bar) = self.current_target.read().as_ref() {
            bar.finish_and_clear();
        }
    }

    /// Finish with an error
    pub fn finish_with_error(&self, msg: &str) {
        if !self.is_enabled() {
            return;
        }

        if let Some(bar) = self.main_bar.read().as_ref() {
            bar.abandon_with_message(format!("✗ {}", msg));
        }
        if let Some(bar) = self.current_target.read().as_ref() {
            bar.finish_and_clear();
        }
    }

    /// Suspend progress for logging output
    pub fn suspend<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        if self.is_enabled() {
            self.multi.suspend(f)
        } else {
            f()
        }
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Global progress state for use across modules
pub static PROGRESS: std::sync::OnceLock<ProgressTracker> = std::sync::OnceLock::new();

/// Initialize global progress tracker
pub fn init_progress(enabled: bool) -> &'static ProgressTracker {
    PROGRESS.get_or_init(|| ProgressTracker::new(enabled))
}

/// Get global progress tracker
pub fn get_progress() -> Option<&'static ProgressTracker> {
    PROGRESS.get()
}
