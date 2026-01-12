//! Banner and branding for CERT-X-GEN CLI

use console::{style, Term};

/// Display the CERT-X-GEN banner
pub fn display_banner() {
    let term = Term::stdout();
    let version = env!("CARGO_PKG_VERSION");
    
    let banner = format!(r#"
 ██████╗███████╗██████╗ ████████╗     ██╗  ██╗      ██████╗ ███████╗███╗   ██╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝     ╚██╗██╔╝     ██╔════╝ ██╔════╝████╗  ██║
██║     █████╗  ██████╔╝   ██║  █████╗ ╚███╔╝█████╗██║  ███╗█████╗  ██╔██╗ ██║
██║     ██╔══╝  ██╔══██╗   ██║  ╚════╝ ██╔██╗╚════╝██║   ██║██╔══╝  ██║╚██╗██║
╚██████╗███████╗██║  ██║   ██║        ██╔╝ ██╗     ╚██████╔╝███████╗██║ ╚████║
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝        ╚═╝  ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═══╝
                     Security Scanner v{} - by Bugb
"#, version);

    // Print banner in cyan
    let _ = term.write_line(&style(banner).cyan().to_string());
    let _ = term.write_line(&style("=".repeat(80)).dim().to_string());
    let _ = term.write_line("");
}

/// Display minimal banner (for quiet mode)
pub fn display_minimal_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!("{}", style(format!("CERT-X-GEN v{} - Security Scanner", version)).cyan().bold());
    println!("{}", style("=".repeat(80)).dim());
}
