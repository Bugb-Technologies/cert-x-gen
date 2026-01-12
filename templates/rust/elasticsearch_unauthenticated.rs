//! @id: elasticsearch-unauthenticated
//! @name: Elasticsearch Unauthenticated Access Detection
//! @author: CERT-X-GEN Security Team
//! @severity: critical
//! @description: Detects Elasticsearch clusters accessible without authentication, exposing indexed data
//! @tags: elasticsearch, search-engine, authentication, nosql, data-exposure, cwe-306
//! @cwe: CWE-306
//! @cvss: 9.8
//! @references: https://cwe.mitre.org/data/definitions/306.html, https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html
//! @confidence: 95

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const TEMPLATE_ID: &str = "elasticsearch-unauthenticated";
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

fn make_http_request(host: &str, port: u16, path: &str) -> Option<String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_secs(TIMEOUT_SECS)
    ).ok()?;
    
    stream.set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECS))).ok()?;
    
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: cert-x-gen/1.0\r\n\r\n",
        path, host
    );
    
    stream.write_all(request.as_bytes()).ok()?;
    
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    
    // Extract body from HTTP response
    if let Some(idx) = response.find("\r\n\r\n") {
        let headers = &response[..idx];
        if headers.contains("200 OK") || headers.contains("200") {
            return Some(response[idx + 4..].to_string());
        }
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
            r#"{{"template_id":"{}","severity":"{}","confidence":{},"title":"{}","description":"{}","evidence":{},"cwe":"CWE-306","remediation":"Enable X-Pack security and configure authentication"}}"#,
            TEMPLATE_ID,
            self.severity,
            self.confidence,
            escape_json(&self.title),
            escape_json(&self.description),
            self.evidence
        )
    }
}

fn check_elasticsearch(host: &str, port: u16) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    // Test 1: Root endpoint - cluster info
    if let Some(body) = make_http_request(host, port, "/") {
        if body.contains("cluster_name") && body.contains("version") {
            // Extract cluster name
            let cluster_name = body
                .split("\"cluster_name\"")
                .nth(1)
                .and_then(|s| s.split('"').nth(2))
                .unwrap_or("unknown");
            
            // Extract version
            let version = body
                .split("\"number\"")
                .nth(1)
                .and_then(|s| s.split('"').nth(2))
                .unwrap_or("unknown");
            
            findings.push(Finding {
                severity: "critical",
                confidence: 95,
                title: "Elasticsearch Unauthenticated Access".to_string(),
                description: format!(
                    "Elasticsearch cluster '{}' (v{}) accessible without authentication on {}:{}",
                    cluster_name, version, host, port
                ),
                evidence: format!(
                    r#"{{"cluster_name":"{}","version":"{}","host":"{}","port":{}}}"#,
                    escape_json(cluster_name), escape_json(version), host, port
                ),
            });
        }
    }
    
    // Test 2: List indices
    if let Some(body) = make_http_request(host, port, "/_cat/indices?format=json") {
        if body.starts_with('[') && body.contains("index") {
            let index_count = body.matches("\"index\"").count();
            
            findings.push(Finding {
                severity: "high",
                confidence: 90,
                title: "Elasticsearch Index Enumeration".to_string(),
                description: format!(
                    "Successfully enumerated {} indices without authentication on {}:{}",
                    index_count, host, port
                ),
                evidence: format!(
                    r#"{{"index_count":{},"endpoint":"/_cat/indices"}}"#,
                    index_count
                ),
            });
        }
    }
    
    // Test 3: Search endpoint - data access
    if let Some(body) = make_http_request(host, port, "/_search?size=1") {
        if body.contains("\"hits\"") && body.contains("\"total\"") {
            findings.push(Finding {
                severity: "critical",
                confidence: 95,
                title: "Elasticsearch Data Access Without Authentication".to_string(),
                description: format!(
                    "Successfully queried data from Elasticsearch without credentials on {}:{}",
                    host, port
                ),
                evidence: r#"{"search_endpoint":"/_search","data_accessible":true}"#.to_string(),
            });
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
        .unwrap_or(9200);
    
    if host.is_empty() {
        eprintln!("Error: No target specified");
        eprintln!("Set CERT_X_GEN_TARGET_HOST or pass as argument");
        println!("[]");
        return;
    }
    
    let mut all_findings = Vec::new();
    
    // Check primary port
    all_findings.extend(check_elasticsearch(&host, port));
    
    // Also check common Elasticsearch ports if not already checked
    let common_ports = [9200, 9201];
    for &p in &common_ports {
        if p != port {
            all_findings.extend(check_elasticsearch(&host, p));
        }
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
