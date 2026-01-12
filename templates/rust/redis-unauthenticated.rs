// @id: redis-unauthenticated-rust
// @name: Redis Unauthenticated Access Detection (Rust)
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects Redis instances exposed without authentication using Rust
// @tags: redis, unauthenticated, database, nosql, cwe-306
// @cwe: CWE-306
// @cvss: 9.8
// @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
// @confidence: 95
// @version: 1.0.0

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
struct Metadata {
    id: String,
    name: String,
    severity: String,
    description: String,
    tags: Vec<String>,
    language: String,
    confidence: u8,
    cwe: Vec<String>,
    references: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Evidence {
    request: String,
    response: String,
    matched_patterns: Vec<String>,
    data: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct Finding {
    target: String,
    template_id: String,
    severity: String,
    confidence: u8,
    title: String,
    description: String,
    evidence: Evidence,
    cwe_ids: Vec<String>,
    tags: Vec<String>,
    timestamp: String,
}

#[derive(Serialize, Deserialize)]
struct Output {
    findings: Vec<Finding>,
    metadata: Metadata,
}

fn test_redis(host: &str, port: u16) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();
    
    let address = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &address.parse()?,
        Duration::from_secs(10)
    )?;
    
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    
    // Send test commands
    let commands = vec![
        "INFO\r\n",
        "PING\r\n",
        "*1\r\n$4\r\nINFO\r\n",
        "*1\r\n$4\r\nPING\r\n",
    ];
    
    for cmd in &commands {
        stream.write_all(cmd.as_bytes())?;
    }
    stream.flush()?;
    
    // Wait a bit for response
    std::thread::sleep(Duration::from_millis(300));
    
    // Read response
    let mut response_data = Vec::new();
    let mut buffer = [0u8; 4096];
    
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                response_data.extend_from_slice(&buffer[..n]);
                if n < buffer.len() {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    
    let response_str = String::from_utf8_lossy(&response_data).to_string();
    
    // Check for Redis indicators
    let indicators = vec![
        "redis_version",
        "redis_mode",
        "used_memory",
        "connected_clients",
        "role:master",
        "role:slave",
        "+PONG",
    ];
    
    let matched_patterns: Vec<String> = indicators
        .iter()
        .filter(|ind| response_str.contains(*ind))
        .map(|s| s.to_string())
        .collect();
    
    if !matched_patterns.is_empty() {
        let finding = Finding {
            target: format!("{}:{}", host, port),
            template_id: "redis-unauthenticated-rust".to_string(),
            severity: "critical".to_string(),
            confidence: 95,
            title: "Redis Unauthenticated Access Detection (Rust)".to_string(),
            description: "Detects Redis instances exposed without authentication using Rust".to_string(),
            evidence: Evidence {
                request: commands.join("\\n"),
                response: response_str[..response_str.len().min(1000)].to_string(),
                matched_patterns,
                data: json!({
                    "protocol": "tcp",
                    "port": port,
                    "response_length": response_data.len()
                }),
            },
            cwe_ids: vec!["CWE-306".to_string()],
            tags: vec![
                "redis".to_string(),
                "unauthenticated".to_string(),
                "database".to_string(),
                "nosql".to_string(),
                "rust".to_string(),
            ],
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        };
        findings.push(finding);
    }
    
    Ok(findings)
}

fn main() {
    // Support both CLI args and environment variables (for engine mode)
    let (host, port) = if env::var("CERT_X_GEN_MODE").unwrap_or_default() == "engine" {
        // Engine mode - read from environment variables
        let host = env::var("CERT_X_GEN_TARGET_HOST")
            .expect("CERT_X_GEN_TARGET_HOST not set");
        let port = env::var("CERT_X_GEN_TARGET_PORT")
            .unwrap_or_else(|_| "6379".to_string())
            .parse::<u16>()
            .unwrap_or(6379);
        (host, port)
    } else {
        // CLI mode - read from command-line arguments
        let args: Vec<String> = env::args().collect();
        if args.len() < 2 {
            eprintln!("{{\"error\": \"Usage: redis-unauthenticated <host> [port]\"}}");
            std::process::exit(1);
        }
        let host = args[1].clone();
        let port = args.get(2)
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(6379);
        (host, port)
    };
    
    let findings = test_redis(&host, port).unwrap_or_else(|_| Vec::new());
    
    let metadata = Metadata {
        id: "redis-unauthenticated-rust".to_string(),
        name: "Redis Unauthenticated Access Detection (Rust)".to_string(),
        severity: "critical".to_string(),
        description: "Detects Redis instances exposed without authentication using Rust".to_string(),
        tags: vec!["redis".to_string(), "unauthenticated".to_string(), "database".to_string()],
        language: "rust".to_string(),
        confidence: 95,
        cwe: vec!["CWE-306".to_string()],
        references: vec![
            "https://redis.io/docs/management/security/".to_string(),
            "https://cwe.mitre.org/data/definitions/306.html".to_string(),
        ],
    };
    
    let output = Output { findings, metadata };
    
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
