// Auto-Update System for Templates
// Implements Nuclei-like auto-update functionality with progress indicators

use crate::error::Result;
use crate::template::paths::PathResolver;
use crate::template::repository::RepositoryManager;
use crate::template::stats::TemplateStats;
use crate::template::version::TemplateVersion;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use std::time::Duration;

#[derive(Debug)]
/// Automatic template repository updater
pub struct AutoUpdater {
    version_config: TemplateVersion,
    config_path: std::path::PathBuf,
}

impl AutoUpdater {
    /// Create a new AutoUpdater instance
    pub fn new() -> Result<Self> {
        let config_path = TemplateVersion::default_config_path()?;
        let version_config = TemplateVersion::load(&config_path)?;

        Ok(Self {
            version_config,
            config_path,
        })
    }

    /// Check if templates need to be downloaded (first run)
    pub fn needs_initial_install(&self) -> bool {
        // Check if user template directory exists and has templates
        let user_dir = PathResolver::user_template_dir();
        if user_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&user_dir) {
                if entries.count() > 0 {
                    return false;
                }
            }
        }

        // Check if system template directory has templates
        let system_dir = PathResolver::system_template_dir();
        if system_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&system_dir) {
                if entries.count() > 0 {
                    return false;
                }
            }
        }

        true
    }

    /// Perform first-run auto-install with progress indicator
    pub fn auto_install(&mut self) -> Result<()> {
        println!();
        println!(
            "{}",
            "╭─────────────────────────────────────────────────────────────╮".bright_blue()
        );
        println!(
            "{}",
            "│  📦 First run detected! Installing templates from GitHub...│".bright_blue()
        );
        println!(
            "{}",
            "╰─────────────────────────────────────────────────────────────╯".bright_blue()
        );
        println!();

        self.perform_update_with_progress()?;

        // Show success with template count
        let stats = TemplateStats::from_all_directories();
        self.print_success_summary(&stats);

        Ok(())
    }

    /// Check if templates should be updated (hourly check)
    pub fn should_check_for_updates(&self) -> bool {
        self.version_config.should_check_for_updates()
    }

    /// Perform startup update check
    pub fn check_for_updates(&mut self) -> Result<bool> {
        // Mark that we've checked
        self.version_config.mark_checked();
        self.save_version_config()?;

        // Get latest version from Git repository
        let latest_version = self.get_latest_version()?;

        // Compare with current version
        if latest_version != self.version_config.current_version {
            println!(
                "{}",
                format!(
                    "[INF] Templates outdated (current: {}, latest: {})",
                    self.version_config.current_version, latest_version
                )
                .yellow()
            );
            println!(
                "{}",
                "[INF] Run 'cxg -ut' or 'cxg template update' to get the latest templates".yellow()
            );
            return Ok(true); // Updates available
        }

        Ok(false) // Up to date
    }

    /// Perform template update with progress bar
    pub fn perform_update(&mut self) -> Result<()> {
        self.perform_update_with_progress()
    }

    /// Perform template update with progress indicator
    fn perform_update_with_progress(&mut self) -> Result<()> {
        // Create progress bar
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(80));
        pb.set_message("Connecting to template repository...");

        // Initialize repository manager
        let mut repo_manager = RepositoryManager::new()?;

        pb.set_message("Downloading templates...");

        // Update all repositories
        let updated = repo_manager.update_all()?;

        pb.set_message("Indexing templates...");

        // Get latest version after update
        let latest_version = self.get_latest_version()?;

        // Update version config
        self.version_config.update_version(latest_version.clone());
        self.save_version_config()?;

        pb.finish_and_clear();

        // Show results
        if !updated.is_empty() {
            println!(
                "{}",
                format!("[INF] Updated repositories: {}", updated.join(", ")).bright_blue()
            );
        }

        Ok(())
    }

    /// Print success summary with template breakdown
    fn print_success_summary(&self, stats: &TemplateStats) {
        println!();
        println!(
            "{}",
            "╭─────────────────────────────────────────────────────────────╮".green()
        );
        println!(
            "{}",
            format!(
                "│  ✅ Templates installed successfully!                       │"
            )
            .green()
        );
        println!(
            "{}",
            "├─────────────────────────────────────────────────────────────┤".green()
        );

        // Total count
        println!(
            "{}",
            format!("│  📊 Total: {} templates                                     ", stats.total)
                .bright_white()
                .to_string()
                .chars()
                .take(63)
                .collect::<String>()
                + "│"
        );

        // Language breakdown (sorted by count)
        let mut langs: Vec<_> = stats.by_language.iter().collect();
        langs.sort_by(|a, b| b.1.cmp(a.1));

        for (lang, count) in langs.iter().take(6) {
            let icon = match lang.as_str() {
                "python" => "🐍",
                "javascript" => "📜",
                "rust" => "🦀",
                "go" => "🐹",
                "c" | "cpp" => "⚙️",
                "java" => "☕",
                "ruby" => "💎",
                "yaml" => "📄",
                "shell" => "🐚",
                "perl" => "🐪",
                "php" => "🐘",
                _ => "📁",
            };
            let line = format!("│     {} {}: {}", icon, lang, count);
            let padded = format!("{:<62}│", line);
            println!("{}", padded.bright_white());
        }

        println!(
            "{}",
            "╰─────────────────────────────────────────────────────────────╯".green()
        );
        println!();
    }

    /// Get latest version from repository
    fn get_latest_version(&self) -> Result<String> {
        // Try to get version from user template directory
        let user_dir = PathResolver::user_template_dir();
        if let Some(version) = self.get_git_version(&user_dir) {
            return Ok(version);
        }

        // Fallback to unknown if can't determine
        Ok("unknown".to_string())
    }

    /// Get Git version (commit hash or tag) from a directory
    fn get_git_version(&self, dir: &Path) -> Option<String> {
        let repo_path = dir.join("official"); // Official repository

        if !repo_path.exists() {
            return None;
        }

        // Try to open Git repository
        if let Ok(repo) = git2::Repository::open(&repo_path) {
            // Get HEAD commit
            if let Ok(head) = repo.head() {
                if let Some(commit) = head.target() {
                    let short_hash = commit.to_string()[..8].to_string();
                    return Some(short_hash);
                }
            }
        }

        None
    }

    /// Save version config to disk
    fn save_version_config(&self) -> Result<()> {
        self.version_config.save(&self.config_path)
    }

    /// Disable auto-update checks
    pub fn disable_auto_check(&mut self) -> Result<()> {
        self.version_config.disable_auto_check();
        self.save_version_config()?;
        println!("{}", "[INF] Auto-update checks disabled".blue());
        Ok(())
    }

    /// Enable auto-update checks
    pub fn enable_auto_check(&mut self) -> Result<()> {
        self.version_config.enable_auto_check();
        self.save_version_config()?;
        println!("{}", "[INF] Auto-update checks enabled".blue());
        Ok(())
    }

    /// Get current version
    pub fn current_version(&self) -> &str {
        &self.version_config.current_version
    }

    /// Get template statistics
    pub fn get_stats(&self) -> TemplateStats {
        TemplateStats::from_all_directories()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_updater_creation() -> Result<()> {
        let updater = AutoUpdater::new()?;
        assert!(updater.config_path.ends_with(".templates-config.json"));
        Ok(())
    }

    #[test]
    fn test_version_tracking() -> Result<()> {
        let updater = AutoUpdater::new()?;
        let version = updater.current_version().to_string();
        assert!(!version.is_empty());
        Ok(())
    }
}
