//! CERT-X-GEN Rust Template Skeleton
//!
//! @id: rust-template-skeleton
//! @name: Rust Template Skeleton
//! @author: CERT-X-GEN Security Team
//! @severity: info
//! @description: Skeleton template for writing security scanning templates in Rust. Copy this file and customize it for your specific security check.
//! @tags: skeleton, example, template, rust
//! @cwe: CWE-1008
//! @confidence: 90
//! @references: https://cwe.mitre.org/data/definitions/1008.html, https://github.com/cert-x-gen/templates
//!
//! Compilation:
//!   rustc template.rs -o template
//!   ./template --target example.com --json
//!
//! When run by CERT-X-GEN engine, environment variables are set:
//!   CERT_X_GEN_TARGET_HOST - Target host/IP
//!   CERT_X_GEN_TARGET_PORT - Target port
//!   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)

use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

// JSON serialization
#[derive(Debug, Clone)]
struct Finding {
    template_id: String,
    severity: String,
    confidence: u8,
    title: String,
    description: String,
    evidence: HashMap<String, String>,
    cwe: String,
    cvss_score: f32,
    remediation: String,
    references: Vec<String>,
}

impl Finding {
    fn to_json(&self) -> String {
        format!(
            r#"{{
    "template_id": "{}",
    "severity": "{}",
    "confidence": {},
    "title": "{}",
    "description": "{}",
    "evidence": {},
    "cwe": "{}",
    "cvss_score": {},
    "remediation": "{}",
    "references": {}
}}"#,
            self.template_id,
            self.severity,
            self.confidence,
            self.title,
            self.description,
            self.evidence_to_json(),
            self.cwe,
            self.cvss_score,
            self.remediation,
            self.references_to_json()
        )
    }
    
    fn evidence_to_json(&self) -> String {
        if self.evidence.is_empty() {
            return "{}".to_string();
        }
        
        let items: Vec<String> = self.evidence
            .iter()
            .map(|(k, v)| format!(r#""{}": "{}""#, k, v))
            .collect();
        
        format!("{{{}}}", items.join(", "))
    }
    
    fn references_to_json(&self) -> String {
        if self.references.is_empty() {
            return "[]".to_string();
        }
        
        let refs: Vec<String> = self.references
            .iter()
            .map(|r| format!(r#""{}""#, r))
            .collect();
        
        format!("[{}]", refs.join(", "))
    }
}

// Template configuration
struct TemplateConfig {
    id: String,
    name: String,
    author: String,
    severity: String,
    confidence: u8,
    tags: Vec<String>,
    cwe: String,
}

impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            id: "template-skeleton".to_string(),
            name: "Rust Template Skeleton".to_string(),
            author: "Your Name".to_string(),
            severity: "high".to_string(),
            confidence: 90,
            tags: vec!["skeleton".to_string(), "example".to_string()],
            cwe: "CWE-XXX".to_string(),
        }
    }
}

// Main template struct
struct CertXGenTemplate {
    config: TemplateConfig,
    target: String,
    port: u16,
    json_output: bool,
    context: HashMap<String, String>,
}

impl CertXGenTemplate {
    fn new() -> Self {
        Self {
            config: TemplateConfig::default(),
            target: String::new(),
            port: 80,
            json_output: false,
            context: HashMap::new(),
        }
    }
    
    // ========================================
    // CUSTOMIZE THIS SECTION
    // ========================================
    
    /// Main scanning logic - override this with your implementation
    fn execute(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Example: Test network connectivity
        if let Some(finding) = self.test_network_service() {
            findings.push(finding);
        }
        
        // Example: Test HTTP endpoint
        if let Some(finding) = self.test_http_endpoint() {
            findings.push(finding);
        }
        
        // Add your custom scanning logic here
        // ...
        
        findings
    }
    
    /// Example: Test network service
    fn test_network_service(&self) -> Option<Finding> {
        let addr = format!("{}:{}", self.target, self.port);
        
        // Try to connect to the service
        match TcpStream::connect_timeout(
            &addr.to_socket_addrs().ok()?.next()?,
            Duration::from_secs(5)
        ) {
            Ok(mut stream) => {
                // Send probe
                let _ = stream.write_all(b"PROBE\r\n");
                
                // Create finding
                let mut evidence = HashMap::new();
                evidence.insert("host".to_string(), self.target.clone());
                evidence.insert("port".to_string(), self.port.to_string());
                evidence.insert("status".to_string(), "open".to_string());
                
                Some(Finding {
                    template_id: self.config.id.clone(),
                    severity: "info".to_string(),
                    confidence: self.config.confidence,
                    title: "Service Accessible".to_string(),
                    description: format!("Service on {}:{} is accessible", self.target, self.port),
                    evidence,
                    cwe: self.config.cwe.clone(),
                    cvss_score: 0.0,
                    remediation: "Review service exposure".to_string(),
                    references: vec![
                        "https://example.com/reference".to_string()
                    ],
                })
            }
            Err(_) => None
        }
    }
    
    /// Example: Test HTTP endpoint
    fn test_http_endpoint(&self) -> Option<Finding> {
        // Simple HTTP request (you'd use a proper HTTP client in production)
        let addr = format!("{}:{}", self.target, self.port);
        
        match TcpStream::connect_timeout(
            &addr.to_socket_addrs().ok()?.next()?,
            Duration::from_secs(5)
        ) {
            Ok(mut stream) => {
                // Send HTTP request
                let request = format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    self.target
                );
                let _ = stream.write_all(request.as_bytes());
                
                // Read response
                let mut buffer = [0; 1024];
                use std::io::Read;
                let _ = stream.read(&mut buffer);
                
                let response = String::from_utf8_lossy(&buffer);
                
                // Check for vulnerability indicators
                if response.contains("vulnerable") || response.contains("exposed") {
                    let mut evidence = HashMap::new();
                    evidence.insert("endpoint".to_string(), format!("http://{}:{}/", self.target, self.port));
                    evidence.insert("indicator".to_string(), "vulnerable keyword found".to_string());
                    
                    return Some(Finding {
                        template_id: self.config.id.clone(),
                        severity: self.config.severity.clone(),
                        confidence: self.config.confidence,
                        title: "Potential Vulnerability Detected".to_string(),
                        description: format!("Found potential vulnerability on {}:{}", self.target, self.port),
                        evidence,
                        cwe: self.config.cwe.clone(),
                        cvss_score: self.calculate_cvss_score(&self.config.severity),
                        remediation: self.get_remediation(),
                        references: self.get_references(),
                    });
                }
            }
            Err(_) => {}
        }
        
        None
    }
    
    // ========================================
    // HELPER METHODS
    // ========================================
    
    fn calculate_cvss_score(&self, severity: &str) -> f32 {
        match severity.to_lowercase().as_str() {
            "critical" => 9.0,
            "high" => 7.5,
            "medium" => 5.0,
            "low" => 3.0,
            "info" => 0.0,
            _ => 5.0,
        }
    }
    
    fn get_remediation(&self) -> String {
        "1. Review the identified issue\n2. Apply security patches\n3. Follow security best practices".to_string()
    }
    
    fn get_references(&self) -> Vec<String> {
        vec![
            "https://cwe.mitre.org/".to_string(),
            "https://nvd.nist.gov/".to_string(),
        ]
    }
    
    // ========================================
    // CLI AND EXECUTION
    // ========================================
    
    fn parse_args(&mut self) -> Result<(), String> {
        let args: Vec<String> = env::args().collect();
        
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--target" => {
                    if i + 1 < args.len() {
                        self.target = args[i + 1].clone();
                        i += 1;
                    } else {
                        return Err("--target requires an argument".to_string());
                    }
                }
                "--port" => {
                    if i + 1 < args.len() {
                        self.port = args[i + 1].parse()
                            .map_err(|_| "Invalid port number".to_string())?;
                        i += 1;
                    } else {
                        return Err("--port requires an argument".to_string());
                    }
                }
                "--json" => {
                    self.json_output = true;
                }
                "--help" | "-h" => {
                    self.print_usage();
                    std::process::exit(0);
                }
                _ => {
                    if self.target.is_empty() && !args[i].starts_with('-') {
                        self.target = args[i].clone();
                    }
                }
            }
            i += 1;
        }
        
        // Check environment variables (for CERT-X-GEN engine integration)
        if self.target.is_empty() {
            if let Ok(host) = env::var("CERT_X_GEN_TARGET_HOST") {
                self.target = host;
            }
        }
        
        if let Ok(port_str) = env::var("CERT_X_GEN_TARGET_PORT") {
            if let Ok(port) = port_str.parse() {
                self.port = port;
            }
        }
        
        if env::var("CERT_X_GEN_MODE").unwrap_or_default() == "engine" {
            self.json_output = true;
        }

        if let Ok(ctx) = env::var("CERT_X_GEN_CONTEXT") {
            self.context.insert("raw_context".to_string(), ctx);
        }

        if let Ok(add) = env::var("CERT_X_GEN_ADD_PORTS") {
            self.context.insert("add_ports".to_string(), add);
        }

        if let Ok(override_ports) = env::var("CERT_X_GEN_OVERRIDE_PORTS") {
            self.context.insert("override_ports".to_string(), override_ports);
        }
        
        if self.target.is_empty() {
            return Err("No target specified".to_string());
        }
        
        Ok(())
    }
    
    fn print_usage(&self) {
        println!("Usage: {} [OPTIONS] <target>", env::args().next().unwrap_or_default());
        println!("\n{}", self.config.name);
        println!("\nOptions:");
        println!("  --target <HOST>  Target host or IP address");
        println!("  --port <PORT>    Target port (default: 80)");
        println!("  --json           Output findings as JSON");
        println!("  --help           Show this help message");
        println!("\nExample:");
        println!("  {} --target example.com --port 443 --json", env::args().next().unwrap_or_default());
    }
    
    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Parse arguments
        self.parse_args()?;
        
        // Print banner (if not JSON output)
        if !self.json_output {
            println!("\n╔════════════════════════════════════════════════════════════╗");
            println!("║  {}                                    ", self.config.name);
            println!("║  CERT-X-GEN Security Template                              ║");
            println!("╚════════════════════════════════════════════════════════════╝\n");
            println!("Target: {}:{}", self.target, self.port);
            println!("Started: {}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
        }
        
        // Execute the scan
        let findings = self.execute();
        
        // Output results
        if self.json_output {
            // JSON output for CERT-X-GEN engine
            print!("[");
            for (i, finding) in findings.iter().enumerate() {
                if i > 0 {
                    print!(",");
                }
                print!("{}", finding.to_json());
            }
            println!("]");
        } else {
            // Human-readable output
            if findings.is_empty() {
                println!("[-] No issues found\n");
            } else {
                println!("[+] Found {} issue(s):\n", findings.len());
                
                for finding in &findings {
                    println!("[{}] {}", finding.severity.to_uppercase(), finding.title);
                    println!("    {}", finding.description);
                    if !finding.evidence.is_empty() {
                        println!("    Evidence: {:?}", finding.evidence);
                    }
                    println!();
                }
            }
            
            println!("Completed: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
        }
        
        Ok(())
    }
}

// ========================================
// MAIN ENTRY POINT
// ========================================

fn main() {
    let mut template = CertXGenTemplate::new();
    
    // ========================================
    // CUSTOMIZE METADATA HERE
    // ========================================
    template.config.id = "my-custom-check".to_string();
    template.config.name = "My Custom Security Check".to_string();
    template.config.author = "Security Researcher".to_string();
    template.config.severity = "high".to_string();
    template.config.cwe = "CWE-89".to_string();  // Example: SQL Injection
    
    // Run the template
    if let Err(e) = template.run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

// Note: To compile this template with minimal dependencies:
// rustc template.rs -o template
//
// For production use, consider using:
// - reqwest for HTTP requests
// - serde/serde_json for JSON handling
// - clap for argument parsing
// - tokio for async operations
