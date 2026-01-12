# CERT-X-GEN Python Template – AI Generation Guide

## Purpose
This document provides authoritative guidance for AI systems generating Python security templates for CERT-X-GEN. Follow these rules exactly to ensure templates pass validation and execute correctly.

## Metadata Format (CRITICAL)

Templates MUST include metadata in the header using `@field:` annotations. The CLI parser extracts metadata from the first 50 lines.

```python
#!/usr/bin/env python3
# @id: my-vulnerability-check
# @name: My Vulnerability Check
# @author: Your Name
# @severity: high
# @description: Detects XYZ vulnerability in ABC service
# @tags: web, injection, cve-2024-xxxx
# @cwe: CWE-89
# @confidence: 85
# @references: https://example.com/advisory
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
- JSON goes to **stdout** only
- Logs/errors go to **stderr** only
- Empty findings array `[]` is valid (no vulnerability found)
- Do NOT mix human-readable text with JSON output

## Validation Requirements

Templates are validated before execution. Ensure:

### 1. Network/Socket Code
Include proper imports for network operations:
```python
import socket
import requests  # or urllib.request
```

### 2. Error Handling
Use try/except blocks around network operations:
```python
try:
    response = requests.get(url, timeout=5)
except requests.RequestException as e:
    print(f"Error: {e}", file=sys.stderr)
```

### 3. Timeout Handling
Always set timeouts on network calls:
```python
socket.settimeout(5)
requests.get(url, timeout=5)
```

### 4. JSON Output
Import json and use proper serialization:
```python
import json
print(json.dumps(findings))
```

## Code Structure

```python
#!/usr/bin/env python3
# @id: template-id
# @name: Template Name
# ... (metadata)

import json
import sys
import os
import socket
import requests

def main():
    # Get target from environment or args
    target = os.environ.get("CERT_X_GEN_TARGET_HOST") or sys.argv[1]
    port = int(os.environ.get("CERT_X_GEN_TARGET_PORT", "80"))
    
    findings = []
    
    try:
        # Your detection logic here
        result = check_vulnerability(target, port)
        if result:
            findings.append(create_finding(target, result))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    
    # Output JSON
    print(json.dumps(findings))

if __name__ == "__main__":
    main()
```

## Things to AVOID

1. **No ANSI color codes** - breaks JSON parsing
2. **No ASCII art or banners** in engine mode
3. **No print() without file=sys.stderr** except final JSON
4. **No interactive prompts** (input())
5. **No hardcoded targets** - always use environment/args
6. **No multi-target loops** - engine handles this
7. **No bare except:** - always specify exception type

## Example: Redis Auth Check

```python
#!/usr/bin/env python3
# @id: redis-unauth-check
# @name: Redis Unauthenticated Access
# @author: Security Team
# @severity: high
# @description: Detects Redis instances without authentication
# @tags: redis, database, unauth, misconfiguration
# @cwe: CWE-306
# @confidence: 95

import json
import sys
import os
import socket

def check_redis(host: str, port: int) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.send(b"INFO\r\n")
        response = sock.recv(4096).decode('utf-8', errors='ignore')
        sock.close()
        
        if "redis_version" in response and "NOAUTH" not in response:
            return {"response": response[:500], "vulnerable": True}
    except socket.error as e:
        print(f"Connection error: {e}", file=sys.stderr)
    return None

def main():
    target = os.environ.get("CERT_X_GEN_TARGET_HOST") or (sys.argv[1] if len(sys.argv) > 1 else None)
    port = int(os.environ.get("CERT_X_GEN_TARGET_PORT", "6379"))
    
    if not target:
        print("Error: No target specified", file=sys.stderr)
        print("[]")
        return
    
    findings = []
    result = check_redis(target, port)
    
    if result:
        findings.append({
            "template_id": "redis-unauth-check",
            "severity": "high",
            "confidence": 95,
            "title": "Redis Unauthenticated Access",
            "description": f"Redis on {target}:{port} allows unauthenticated access",
            "evidence": result,
            "cwe": "CWE-306",
            "remediation": "Enable Redis AUTH with a strong password"
        })
    
    print(json.dumps(findings))

if __name__ == "__main__":
    main()
```
