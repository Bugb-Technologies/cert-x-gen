# CERT-X-GEN Rust Template – AI Generation Guide

## Purpose
This document provides authoritative guidance for AI systems generating Rust security templates for CERT-X-GEN. Follow these rules exactly to ensure templates pass validation and execute correctly.

## Metadata Format (CRITICAL)

Templates MUST include metadata in the header using `@field:` annotations. The CLI parser extracts metadata from the first 50 lines.

```rust
//! CERT-X-GEN Rust Template
//!
//! @id: my-vulnerability-check
//! @name: My Vulnerability Check
//! @author: Your Name
//! @severity: high
//! @description: Detects XYZ vulnerability in ABC service
//! @tags: web, injection, cve-2024-xxxx
//! @cwe: CWE-89
//! @confidence: 85
//! @references: https://example.com/advisory
```

### Required Fields
| Field | Format | Example |
|-------|--------|---------|
| `@id` | lowercase-with-dashes | `redis-unauth-access` |
| `@name` | Human readable | `Redis Unauthenticated Access` |
| `@author` | Name or handle | `Security Team` |
| `@severity` | critical/high/medium/low/info | `high` |
| `@description` | Single line description | `Detects Redis without auth` |
| `@tags` | Comma-separated, lowercase | `redis, database, unauth` |

### Optional Fields
| Field | Format | Example |
|-------|--------|---------|
| `@cwe` | CWE-NNN | `CWE-306` |
| `@confidence` | 0-100 | `90` |
| `@references` | Comma-separated URLs | `https://cve.org/...` |

## Runtime Contract

### Environment Variables (Set by Engine)
```
CERT_X_GEN_TARGET_HOST  - Target hostname or IP
CERT_X_GEN_TARGET_PORT  - Target port number
CERT_X_GEN_MODE         - "engine" when run by CLI
CERT_X_GEN_CONTEXT      - Optional JSON context
```

### Single Target Rule
- **ONE target per execution** - the engine handles multi-target scanning
- Do NOT implement target list parsing or port scanning loops
- Do NOT expand `ADD_PORTS` or `OVERRIDE_PORTS` into scan loops

## Output Format (CRITICAL)

### JSON Output to stdout
When `CERT_X_GEN_MODE=engine` or `--json` flag is used, output MUST be valid JSON:

```json
[
  {
    "template_id": "my-vulnerability-check",
    "severity": "high",
    "confidence": 85,
    "title": "Vulnerability Found",
    "description": "Detailed description of the finding",
    "evidence": {
      "request": "GET /vulnerable HTTP/1.1",
      "response": "HTTP/1.1 200 OK...",
      "matched_patterns": ["pattern1", "pattern2"]
    },
    "cwe": "CWE-89",
    "cvss_score": 7.5,
    "remediation": "Steps to fix",
    "references": ["https://..."]
  }
]
```

### Required Finding Fields
- `template_id` - Must match `@id` from metadata
- `severity` - critical/high/medium/low/info
- `title` - Short finding title
- `description` - Detailed description

### Output Rules
- JSON goes to **stdout** via `println!()` only
- Logs/errors go to **stderr** via `eprintln!()` only
- Empty findings vector `[]` is valid (no vulnerability found)
- Do NOT mix human-readable text with JSON output

## Validation Requirements

Templates are validated before execution. Ensure:

### 1. Network/Socket Code
Include proper use statements for network operations:
```rust
use std::net::TcpStream;
use std::io::{Read, Write};
```

### 2. Error Handling
Use Result types and proper error handling:
```rust
let mut stream = match TcpStream::connect(&address) {
    Ok(s) => s,
    Err(e) => {
        eprintln!("Connection error: {}", e);
        return None;
    }
};
```

### 3. Timeout Handling
Always set timeouts on network calls:
```rust
use std::time::Duration;

stream.set_read_timeout(Some(Duration::from_secs(5)))?;
stream.set_write_timeout(Some(Duration::from_secs(5)))?;
```

### 4. JSON Output
Use manual JSON formatting or serde if available:
```rust
// Manual JSON (no external deps)
println!("[{}]", findings.join(","));

// Or with serde (if available)
println!("{}", serde_json::to_string(&findings)?);
```

### 5. Entry Point
Must have `fn main()`:
```rust
fn main() {
    // Template logic
}
```

## Code Structure (No External Dependencies)

```rust
//! @id: template-id
//! @name: Template Name
//! ... (metadata)

use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

struct Finding {
    template_id: String,
    severity: String,
    confidence: u8,
    title: String,
    description: String,
    evidence: HashMap<String, String>,
    cwe: String,
    remediation: String,
}

impl Finding {
    fn to_json(&self) -> String {
        let evidence_json: Vec<String> = self.evidence
            .iter()
            .map(|(k, v)| format!(r#""{}": "{}""#, k, v.replace('"', "\\\"")))
            .collect();
        
        format!(
            r#"{{"template_id":"{}","severity":"{}","confidence":{},"title":"{}","description":"{}","evidence":{{{}}},"cwe":"{}","remediation":"{}"}}"#,
            self.template_id,
            self.severity,
            self.confidence,
            self.title.replace('"', "\\\""),
            self.description.replace('"', "\\\""),
            evidence_json.join(","),
            self.cwe,
            self.remediation.replace('"', "\\\"")
        )
    }
}

fn check_vulnerability(host: &str, port: u16) -> Option<Finding> {
    let address = format!("{}:{}", host, port);
    
    let mut stream = match TcpStream::connect(&address) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Connection error: {}", e);
            return None;
        }
    };
    
    // Set timeouts
    let timeout = Duration::from_secs(5);
    if stream.set_read_timeout(Some(timeout)).is_err() 
        || stream.set_write_timeout(Some(timeout)).is_err() {
        return None;
    }
    
    // Send probe
    if stream.write_all(b"PROBE\r\n").is_err() {
        return None;
    }
    
    // Read response
    let mut buffer = vec![0u8; 4096];
    let n = match stream.read(&mut buffer) {
        Ok(n) => n,
        Err(_) => return None,
    };
    
    let response = String::from_utf8_lossy(&buffer[..n]).to_string();
    
    if is_vulnerable(&response) {
        let mut evidence = HashMap::new();
        evidence.insert("response".to_string(), response);
        
        return Some(Finding {
            template_id: "template-id".to_string(),
            severity: "high".to_string(),
            confidence: 90,
            title: "Vulnerability Found".to_string(),
            description: format!("Found issue on {}", address),
            evidence,
            cwe: "CWE-XXX".to_string(),
            remediation: "Apply security patch".to_string(),
        });
    }
    
    None
}

fn is_vulnerable(response: &str) -> bool {
    // Your detection logic here
    response.contains("VULNERABLE_INDICATOR")
}

fn main() {
    let target = env::var("CERT_X_GEN_TARGET_HOST")
        .ok()
        .or_else(|| env::args().nth(1));
    
    let port: u16 = env::var("CERT_X_GEN_TARGET_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(80);
    
    let target = match target {
        Some(t) => t,
        None => {
            eprintln!("Error: No target specified");
            println!("[]");
            return;
        }
    };
    
    let mut findings = Vec::new();
    
    if let Some(finding) = check_vulnerability(&target, port) {
        findings.push(finding.to_json());
    }
    
    println!("[{}]", findings.join(","));
}
```

## Things to AVOID

1. **No println!() for debugging** - use eprintln!() instead
2. **No panic!() or unwrap()** - handle errors gracefully with match/if-let
3. **No expect() with vague messages** - use descriptive error handling
4. **No .clone() in loops** - optimize for performance
5. **No hardcoded targets** - always use environment/args
6. **No multi-target loops** - engine handles this
7. **No external crates** unless absolutely necessary (templates are compiled standalone)

## Example: FTP Anonymous Check

```rust
//! @id: ftp-anonymous-check
//! @name: FTP Anonymous Login
//! @author: Security Team
//! @severity: medium
//! @description: Detects FTP servers allowing anonymous login
//! @tags: ftp, anonymous, misconfiguration
//! @cwe: CWE-284
//! @confidence: 95

use std::collections::HashMap;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

struct Finding {
    template_id: String,
    severity: String,
    confidence: u8,
    title: String,
    description: String,
    evidence: HashMap<String, String>,
    cwe: String,
    remediation: String,
}

impl Finding {
    fn to_json(&self) -> String {
        let evidence_json: Vec<String> = self.evidence
            .iter()
            .map(|(k, v)| {
                let escaped = v.replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r");
                format!(r#""{}":"{}""#, k, escaped)
            })
            .collect();
        
        format!(
            r#"{{"template_id":"{}","severity":"{}","confidence":{},"title":"{}","description":"{}","evidence":{{{}}},"cwe":"{}","remediation":"{}"}}"#,
            self.template_id,
            self.severity,
            self.confidence,
            self.title,
            self.description.replace('"', "\\\""),
            evidence_json.join(","),
            self.cwe,
            self.remediation.replace('"', "\\\"")
        )
    }
}

fn check_ftp_anonymous(host: &str, port: u16) -> Option<Finding> {
    let address = format!("{}:{}", host, port);
    
    let stream = match TcpStream::connect(&address) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Connection error: {}", e);
            return None;
        }
    };
    
    let timeout = Duration::from_secs(10);
    if stream.set_read_timeout(Some(timeout)).is_err() 
        || stream.set_write_timeout(Some(timeout)).is_err() {
        return None;
    }
    
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut writer = stream;
    let mut response_log = String::new();
    
    // Read banner
    let mut banner = String::new();
    if reader.read_line(&mut banner).is_err() {
        return None;
    }
    response_log.push_str(&banner);
    
    if !banner.starts_with("220") {
        return None;
    }
    
    // Send anonymous login
    if writer.write_all(b"USER anonymous\r\n").is_err() {
        return None;
    }
    
    let mut user_response = String::new();
    if reader.read_line(&mut user_response).is_err() {
        return None;
    }
    response_log.push_str(&user_response);
    
    // Check if password requested (331) or already logged in (230)
    if !user_response.starts_with("331") && !user_response.starts_with("230") {
        return None;
    }
    
    // Send password
    if writer.write_all(b"PASS anonymous@example.com\r\n").is_err() {
        return None;
    }
    
    let mut pass_response = String::new();
    if reader.read_line(&mut pass_response).is_err() {
        return None;
    }
    response_log.push_str(&pass_response);
    
    // Check for successful login
    if pass_response.starts_with("230") {
        let mut evidence = HashMap::new();
        evidence.insert("response".to_string(), response_log);
        
        return Some(Finding {
            template_id: "ftp-anonymous-check".to_string(),
            severity: "medium".to_string(),
            confidence: 95,
            title: "FTP Anonymous Login Allowed".to_string(),
            description: format!("FTP server at {} allows anonymous login", address),
            evidence,
            cwe: "CWE-284".to_string(),
            remediation: "Disable anonymous FTP access or restrict to specific directories".to_string(),
        });
    }
    
    None
}

fn main() {
    let target = env::var("CERT_X_GEN_TARGET_HOST")
        .ok()
        .or_else(|| env::args().nth(1));
    
    let port: u16 = env::var("CERT_X_GEN_TARGET_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(21);
    
    let target = match target {
        Some(t) => t,
        None => {
            eprintln!("Error: No target specified");
            println!("[]");
            return;
        }
    };
    
    let mut findings = Vec::new();
    
    if let Some(finding) = check_ftp_anonymous(&target, port) {
        findings.push(finding.to_json());
    }
    
    println!("[{}]", findings.join(","));
}
```
