//! Banner and branding for CERT-X-GEN CLI

use crate::template::{PathResolver, TemplateStats};
use console::{style, Term};

/// Display the CERT-X-GEN banner with template stats
pub fn display_banner() {
    let term = Term::stdout();
    let version = env!("CARGO_PKG_VERSION");

    let banner = format!(
        r#"
 ██████╗███████╗██████╗ ████████╗     ██╗  ██╗      ██████╗ ███████╗███╗   ██╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝     ╚██╗██╔╝     ██╔════╝ ██╔════╝████╗  ██║
██║     █████╗  ██████╔╝   ██║  █████╗ ╚███╔╝█████╗██║  ███╗█████╗  ██╔██╗ ██║
██║     ██╔══╝  ██╔══██╗   ██║  ╚════╝ ██╔██╗╚════╝██║   ██║██╔══╝  ██║╚██╗██║
╚██████╗███████╗██║  ██║   ██║        ██╔╝ ██╗     ╚██████╔╝███████╗██║ ╚████║
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝        ╚═╝  ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═══╝
"#
    );

    // Print banner in cyan
    let _ = term.write_line(&style(banner).cyan().to_string());
    
    // Print version and template info line
    let stats = TemplateStats::from_all_directories();
    let template_info = if stats.total > 0 {
        format_template_stats(&stats)
    } else {
        "No templates installed. Run: cxg template update".to_string()
    };
    
    let info_line = format!(
        "                     {} v{} | {}",
        style("cxg").bold(),
        version,
        template_info
    );
    let _ = term.write_line(&style(info_line).dim().to_string());
    
    let _ = term.write_line(&style("=".repeat(80)).dim().to_string());
    let _ = term.write_line("");
}

/// Format template stats for display (compact)
fn format_template_stats(stats: &TemplateStats) -> String {
    let mut parts: Vec<String> = Vec::new();
    
    // Sort by count descending, take top 4
    let mut langs: Vec<_> = stats.by_language.iter().collect();
    langs.sort_by(|a, b| b.1.cmp(a.1));
    
    for (lang, count) in langs.iter().take(4) {
        let short_lang = match lang.as_str() {
            "javascript" => "js",
            "python" => "py",
            "shell" => "sh",
            _ => lang.as_str(),
        };
        parts.push(format!("{}: {}", short_lang, count));
    }
    
    format!("{} templates ({})", stats.total, parts.join(", "))
}

/// Display minimal banner (for quiet mode)
pub fn display_minimal_banner() {
    let version = env!("CARGO_PKG_VERSION");
    let stats = TemplateStats::from_all_directories();
    
    let template_info = if stats.total > 0 {
        format!(" | {} templates", stats.total)
    } else {
        String::new()
    };
    
    println!(
        "{}",
        style(format!("cxg v{}{}", version, template_info))
            .cyan()
            .bold()
    );
}

/// Get template version info (for display)
pub fn get_template_version() -> Option<String> {
    let user_dir = PathResolver::user_template_dir().join("official");
    
    if !user_dir.exists() {
        return None;
    }

    // Try to get git commit hash
    if let Ok(repo) = git2::Repository::open(&user_dir) {
        if let Ok(head) = repo.head() {
            if let Some(commit) = head.target() {
                return Some(commit.to_string()[..8].to_string());
            }
        }
    }
    
    None
}
