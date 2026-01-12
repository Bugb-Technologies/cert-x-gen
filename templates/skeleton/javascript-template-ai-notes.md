# CERT-X-GEN JavaScript Template – AI Generation Guide

## Purpose
This document provides authoritative guidance for AI systems generating JavaScript/Node.js security templates for CERT-X-GEN. Follow these rules exactly to ensure templates pass validation and execute correctly.

## Metadata Format (CRITICAL)

Templates MUST include metadata in the header using `@field:` annotations. The CLI parser extracts metadata from the first 50 lines.

```javascript
#!/usr/bin/env node
// @id: my-vulnerability-check
// @name: My Vulnerability Check
// @author: Your Name
// @severity: high
// @description: Detects XYZ vulnerability in ABC service
// @tags: web, injection, cve-2024-xxxx
// @cwe: CWE-89
// @confidence: 85
// @references: https://example.com/advisory
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
- JSON goes to **stdout** via `console.log()` only
- Logs/errors go to **stderr** via `console.error()` only
- Empty findings array `[]` is valid (no vulnerability found)
- Do NOT mix human-readable text with JSON output

## Validation Requirements

Templates are validated before execution. Ensure:

### 1. Network/Socket Code
Include proper requires for network operations:
```javascript
const http = require('http');
const https = require('https');
const net = require('net');
```

### 2. Error Handling
Use try/catch blocks around async operations:
```javascript
try {
    const response = await fetch(url);
} catch (error) {
    console.error(`Error: ${error.message}`);
}
```

### 3. Timeout Handling
Always set timeouts on network calls:
```javascript
const options = { timeout: 5000 };
http.get(url, options, callback);

// Or with socket
socket.setTimeout(5000);
```

### 4. JSON Output
Use JSON.stringify for output:
```javascript
console.log(JSON.stringify(findings));
```

## Code Structure

```javascript
#!/usr/bin/env node
// @id: template-id
// @name: Template Name
// ... (metadata)

const net = require('net');
const http = require('http');

function checkVulnerability(host, port) {
    return new Promise((resolve, reject) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);
        
        socket.connect(port, host, () => {
            socket.write('PROBE\r\n');
        });
        
        socket.on('data', (data) => {
            socket.destroy();
            resolve(data.toString());
        });
        
        socket.on('error', reject);
        socket.on('timeout', () => reject(new Error('Timeout')));
    });
}

async function main() {
    const target = process.env.CERT_X_GEN_TARGET_HOST || process.argv[2];
    const port = parseInt(process.env.CERT_X_GEN_TARGET_PORT || '80');
    
    if (!target) {
        console.error('Error: No target specified');
        console.log('[]');
        return;
    }
    
    const findings = [];
    
    try {
        const result = await checkVulnerability(target, port);
        if (isVulnerable(result)) {
            findings.push({
                template_id: 'template-id',
                severity: 'high',
                confidence: 90,
                title: 'Vulnerability Found',
                description: `Found issue on ${target}:${port}`,
                evidence: { response: result }
            });
        }
    } catch (error) {
        console.error(`Error: ${error.message}`);
    }
    
    console.log(JSON.stringify(findings));
}

main();
```

## Things to AVOID

1. **No console.log() for debugging** - use console.error() instead
2. **No ANSI color codes** - breaks JSON parsing
3. **No ASCII art or banners** in engine mode
4. **No synchronous blocking operations** - use async/await
5. **No hardcoded targets** - always use environment/args
6. **No multi-target loops** - engine handles this
7. **No == comparisons** - use === for strict equality
8. **No var declarations** - use const/let

## Example: MongoDB Auth Check

```javascript
#!/usr/bin/env node
// @id: mongodb-unauth-check
// @name: MongoDB Unauthenticated Access
// @author: Security Team
// @severity: high
// @description: Detects MongoDB instances without authentication
// @tags: mongodb, database, unauth, misconfiguration
// @cwe: CWE-306
// @confidence: 95

const net = require('net');

function checkMongoDB(host, port) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);
        
        // MongoDB wire protocol: isMaster command
        const query = Buffer.from([
            0x3f, 0x00, 0x00, 0x00, // messageLength
            0x00, 0x00, 0x00, 0x00, // requestID
            0x00, 0x00, 0x00, 0x00, // responseTo
            0xd4, 0x07, 0x00, 0x00, // opCode (OP_QUERY)
            0x00, 0x00, 0x00, 0x00, // flags
            0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // admin.$cmd
            0x00, 0x00, 0x00, 0x00, // numberToSkip
            0x01, 0x00, 0x00, 0x00, // numberToReturn
            0x13, 0x00, 0x00, 0x00, // document length
            0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // "isMaster":
            0x01, 0x00, 0x00, 0x00, // 1
            0x00 // null terminator
        ]);
        
        socket.connect(port, host, () => {
            socket.write(query);
        });
        
        socket.on('data', (data) => {
            socket.destroy();
            const response = data.toString('utf8', 0, Math.min(data.length, 500));
            if (response.includes('ismaster') || response.includes('maxBsonObjectSize')) {
                resolve({ vulnerable: true, response });
            } else {
                resolve(null);
            }
        });
        
        socket.on('error', () => resolve(null));
        socket.on('timeout', () => {
            socket.destroy();
            resolve(null);
        });
    });
}

async function main() {
    const target = process.env.CERT_X_GEN_TARGET_HOST || process.argv[2];
    const port = parseInt(process.env.CERT_X_GEN_TARGET_PORT || '27017');
    
    if (!target) {
        console.error('Error: No target specified');
        console.log('[]');
        return;
    }
    
    const findings = [];
    const result = await checkMongoDB(target, port);
    
    if (result && result.vulnerable) {
        findings.push({
            template_id: 'mongodb-unauth-check',
            severity: 'high',
            confidence: 95,
            title: 'MongoDB Unauthenticated Access',
            description: `MongoDB on ${target}:${port} allows unauthenticated access`,
            evidence: { response: result.response },
            cwe: 'CWE-306',
            remediation: 'Enable MongoDB authentication and create admin user'
        });
    }
    
    console.log(JSON.stringify(findings));
}

main();
```
