//! @id: couchdb-default-credentials
//! @name: CouchDB Default Credentials Detection
//! @author: CERT-X-GEN Security Team
//! @severity: critical
//! @description: Detects CouchDB instances using default credentials or running in Party Mode
//! @tags: couchdb, database, default-credentials, nosql, authentication
//! @cwe: CWE-798
//! @confidence: 95

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const TEMPLATE_ID: &str = "couchdb-default-credentials";
const TIMEOUT_SECS: u64 = 5;

fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {}
            c => result.push(c),
        }
    }
    result
}

fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();
    
    for chunk in bytes.chunks(3) {
        let mut n: u32 = 0;
        for (i, &b) in chunk.iter().enumerate() {
            n |= (b as u32) << (16 - 8 * i);
        }
        
        let chars = match chunk.len() {
            3 => 4,
            2 => 3,
            1 => 2,
            _ => 0,
        };
        
        for i in 0..chars {
            let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
            result.push(ALPHABET[idx] as char);
        }
        
        for _ in chars..4 {
            result.push('=');
        }
    }
    
    result
}

fn make_http_request(host: &str, port: u16, method: &str, path: &str, auth: Option<(&str, &str)>) -> Option<(u16, String)> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_secs(TIMEOUT_SECS)
    ).ok()?;
    
    stream.set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECS))).ok()?;
    
    let auth_header = if let Some((user, pass)) = auth {
        let credentials = format!("{}:{}", user, pass);
        format!("Authorization: Basic {}\r\n", base64_encode(&credentials))
    } else {
        String::new()
    };
    
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: cert-x-gen/1.0\r\n{}Accept: application/json\r\n\r\n",
        method, path, host, auth_header
    );
    
    stream.write_all(request.as_bytes()).ok()?;
    
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    
    // Parse status code
    let status_line = response.lines().next()?;
    let status_code: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    
    // Extract body
    if let Some(idx) = response.find("\r\n\r\n") {
        return Some((status_code, response[idx + 4..].to_string()));
    }
    
    None
}

struct Finding {
    severity: &'static str,
    confidence: u8,
    title: String,
    description: String,
    evidence: String,
}

impl Finding {
    fn to_json(&self) -> String {
        format!(
            r#"{{"template_id":"{}","severity":"{}","confidence":{},"title":"{}","description":"{}","evidence":{},"cwe":"CWE-798","remediation":"Disable Party Mode and change default credentials"}}"#,
            TEMPLATE_ID,
            self.severity,
            self.confidence,
            escape_json(&self.title),
            escape_json(&self.description),
            self.evidence
        )
    }
}

// Default/weak credentials to test
const CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "couchdb"),
    ("couchdb", "couchdb"),
    ("administrator", "password"),
    ("root", "root"),
];

fn check_party_mode(host: &str, port: u16) -> Option<Finding> {
    // Try to access /_all_dbs without auth
    if let Some((status, body)) = make_http_request(host, port, "GET", "/_all_dbs", None) {
        if status == 200 && body.starts_with('[') {
            let db_count = body.matches(',').count() + 1;
            
            return Some(Finding {
                severity: "critical",
                confidence: 95,
                title: "CouchDB Party Mode Enabled (No Authentication)".to_string(),
                description: format!(
                    "CouchDB on {}:{} is running in Party Mode - no authentication required. {} databases accessible.",
                    host, port, db_count
                ),
                evidence: format!(
                    r#"{{"party_mode":true,"host":"{}","port":{},"database_count":{}}}"#,
                    host, port, db_count
                ),
            });
        }
    }
    None
}

fn check_credentials(host: &str, port: u16, user: &str, pass: &str) -> Option<Finding> {
    // Try to access root endpoint with credentials
    if let Some((status, body)) = make_http_request(host, port, "GET", "/", Some((user, pass))) {
        if status == 200 && body.contains("couchdb") {
            // Extract version
            let version = body
                .split("\"version\"")
                .nth(1)
                .and_then(|s| s.split('"').nth(2))
                .unwrap_or("unknown");
            
            return Some(Finding {
                severity: "critical",
                confidence: 95,
                title: format!("CouchDB Default Credentials: {}:{}", user, pass),
                description: format!(
                    "Successfully authenticated to CouchDB v{} on {}:{} with credentials {}:{}",
                    version, host, port, user, pass
                ),
                evidence: format!(
                    r#"{{"host":"{}","port":{},"username":"{}","password":"{}","version":"{}"}}"#,
                    host, port, user, pass, escape_json(version)
                ),
            });
        }
    }
    None
}

fn enumerate_databases(host: &str, port: u16, user: &str, pass: &str) -> Option<Finding> {
    if let Some((status, body)) = make_http_request(host, port, "GET", "/_all_dbs", Some((user, pass))) {
        if status == 200 && body.starts_with('[') {
            let db_count = body.matches('"').count() / 2;
            
            // Check for sensitive databases
            let sensitive = ["_users", "_replicator", "admin", "passwords", "secrets"];
            let found_sensitive: Vec<&str> = sensitive.iter()
                .filter(|db| body.contains(*db))
                .copied()
                .collect();
            
            if !found_sensitive.is_empty() {
                return Some(Finding {
                    severity: "high",
                    confidence: 90,
                    title: "CouchDB Sensitive Databases Accessible".to_string(),
                    description: format!(
                        "Found {} databases including sensitive: {:?}",
                        db_count, found_sensitive
                    ),
                    evidence: format!(
                        r#"{{"database_count":{},"sensitive_databases":{:?}}}"#,
                        db_count, found_sensitive
                    ),
                });
            }
        }
    }
    None
}

fn check_couchdb(host: &str, port: u16) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    // Test 1: Check for Party Mode (no auth)
    if let Some(finding) = check_party_mode(host, port) {
        findings.push(finding);
        
        // In party mode, enumerate databases without auth
        if let Some(db_finding) = enumerate_databases(host, port, "", "") {
            findings.push(db_finding);
        }
        
        return findings;
    }
    
    // Test 2: Try default credentials
    for (user, pass) in CREDENTIALS {
        if let Some(finding) = check_credentials(host, port, user, pass) {
            findings.push(finding);
            
            // Enumerate databases with these credentials
            if let Some(db_finding) = enumerate_databases(host, port, user, pass) {
                findings.push(db_finding);
            }
            
            break; // Stop after first successful auth
        }
    }
    
    findings
}

fn main() {
    // Get target from environment or args
    let host = env::var("CERT_X_GEN_TARGET_HOST")
        .ok()
        .or_else(|| env::args().nth(1))
        .unwrap_or_default();
    
    let port: u16 = env::var("CERT_X_GEN_TARGET_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5984);
    
    if host.is_empty() {
        eprintln!("Error: No target specified");
        eprintln!("Set CERT_X_GEN_TARGET_HOST or pass as argument");
        println!("[]");
        return;
    }
    
    let mut all_findings = Vec::new();
    
    // Check primary port
    all_findings.extend(check_couchdb(&host, port));
    
    // Also check HTTPS port if not already checked
    let https_port = 6984;
    if port != https_port {
        all_findings.extend(check_couchdb(&host, https_port));
    }
    
    // Output JSON
    print!("[");
    for (i, finding) in all_findings.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{}", finding.to_json());
    }
    println!("]");
}
