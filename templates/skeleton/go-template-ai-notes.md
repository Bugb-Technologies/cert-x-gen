# CERT-X-GEN Go Template – AI Generation Guide

## Purpose
This document provides authoritative guidance for AI systems generating Go security templates for CERT-X-GEN. Follow these rules exactly to ensure templates pass validation and execute correctly.

## Metadata Format (CRITICAL)

Templates MUST include metadata in the header using `@field:` annotations. The CLI parser extracts metadata from the first 50 lines.

```go
// CERT-X-GEN Go Template
//
// @id: my-vulnerability-check
// @name: My Vulnerability Check
// @author: Your Name
// @severity: high
// @description: Detects XYZ vulnerability in ABC service
// @tags: web, injection, cve-2024-xxxx
// @cwe: CWE-89
// @confidence: 85
// @references: https://example.com/advisory

package main
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
- JSON goes to **stdout** via `fmt.Println()` only
- Logs/errors go to **stderr** via `fmt.Fprintln(os.Stderr, ...)` only
- Empty findings slice `[]` is valid (no vulnerability found)
- Do NOT mix human-readable text with JSON output

## Validation Requirements

Templates are validated before execution. Ensure:

### 1. Network/Socket Code
Include proper imports for network operations:
```go
import (
    "net"
    "net/http"
)
```

### 2. Error Handling
Always check and handle errors:
```go
conn, err := net.DialTimeout("tcp", address, 5*time.Second)
if err != nil {
    fmt.Fprintln(os.Stderr, "Connection error:", err)
    return nil
}
defer conn.Close()
```

### 3. Timeout Handling
Always set timeouts on network calls:
```go
conn.SetDeadline(time.Now().Add(5 * time.Second))

client := &http.Client{Timeout: 5 * time.Second}
```

### 4. JSON Output
Use encoding/json for output:
```go
import "encoding/json"

output, _ := json.Marshal(findings)
fmt.Println(string(output))
```

### 5. Entry Point
Must have `func main()`:
```go
func main() {
    // Template logic
}
```

## Code Structure

```go
// @id: template-id
// @name: Template Name
// ... (metadata)

package main

import (
    "encoding/json"
    "fmt"
    "net"
    "os"
    "strconv"
    "time"
)

type Finding struct {
    TemplateID  string                 `json:"template_id"`
    Severity    string                 `json:"severity"`
    Confidence  int                    `json:"confidence"`
    Title       string                 `json:"title"`
    Description string                 `json:"description"`
    Evidence    map[string]interface{} `json:"evidence,omitempty"`
    CWE         string                 `json:"cwe,omitempty"`
    Remediation string                 `json:"remediation,omitempty"`
}

func checkVulnerability(host string, port int) *Finding {
    address := fmt.Sprintf("%s:%d", host, port)
    
    conn, err := net.DialTimeout("tcp", address, 5*time.Second)
    if err != nil {
        fmt.Fprintln(os.Stderr, "Connection error:", err)
        return nil
    }
    defer conn.Close()
    
    conn.SetDeadline(time.Now().Add(5 * time.Second))
    
    // Send probe
    conn.Write([]byte("PROBE\r\n"))
    
    // Read response
    buffer := make([]byte, 4096)
    n, err := conn.Read(buffer)
    if err != nil {
        return nil
    }
    
    response := string(buffer[:n])
    if isVulnerable(response) {
        return &Finding{
            TemplateID:  "template-id",
            Severity:    "high",
            Confidence:  90,
            Title:       "Vulnerability Found",
            Description: fmt.Sprintf("Found issue on %s", address),
            Evidence:    map[string]interface{}{"response": response},
        }
    }
    return nil
}

func main() {
    target := os.Getenv("CERT_X_GEN_TARGET_HOST")
    if target == "" && len(os.Args) > 1 {
        target = os.Args[1]
    }
    
    portStr := os.Getenv("CERT_X_GEN_TARGET_PORT")
    if portStr == "" {
        portStr = "80"
    }
    port, _ := strconv.Atoi(portStr)
    
    if target == "" {
        fmt.Fprintln(os.Stderr, "Error: No target specified")
        fmt.Println("[]")
        return
    }
    
    findings := []Finding{}
    
    if finding := checkVulnerability(target, port); finding != nil {
        findings = append(findings, *finding)
    }
    
    output, _ := json.Marshal(findings)
    fmt.Println(string(output))
}
```

## Things to AVOID

1. **No fmt.Println() for debugging** - use fmt.Fprintln(os.Stderr, ...) instead
2. **No panic()** - handle errors gracefully
3. **No naked returns** - always specify return values
4. **No ignored error values** - always check `if err != nil`
5. **No hardcoded targets** - always use environment/args
6. **No multi-target loops** - engine handles this
7. **No goroutines without sync** - keep it simple for templates

## Example: Memcached Auth Check

```go
// @id: memcached-unauth-check
// @name: Memcached Unauthenticated Access
// @author: Security Team
// @severity: high
// @description: Detects Memcached instances without authentication
// @tags: memcached, cache, unauth, misconfiguration
// @cwe: CWE-306
// @confidence: 95

package main

import (
    "encoding/json"
    "fmt"
    "net"
    "os"
    "strconv"
    "strings"
    "time"
)

type Finding struct {
    TemplateID  string                 `json:"template_id"`
    Severity    string                 `json:"severity"`
    Confidence  int                    `json:"confidence"`
    Title       string                 `json:"title"`
    Description string                 `json:"description"`
    Evidence    map[string]interface{} `json:"evidence,omitempty"`
    CWE         string                 `json:"cwe,omitempty"`
    Remediation string                 `json:"remediation,omitempty"`
}

func checkMemcached(host string, port int) *Finding {
    address := fmt.Sprintf("%s:%d", host, port)
    
    conn, err := net.DialTimeout("tcp", address, 5*time.Second)
    if err != nil {
        fmt.Fprintln(os.Stderr, "Connection error:", err)
        return nil
    }
    defer conn.Close()
    
    conn.SetDeadline(time.Now().Add(5 * time.Second))
    
    // Send stats command
    _, err = conn.Write([]byte("stats\r\n"))
    if err != nil {
        return nil
    }
    
    // Read response
    buffer := make([]byte, 4096)
    n, err := conn.Read(buffer)
    if err != nil {
        return nil
    }
    
    response := string(buffer[:n])
    
    // Check for successful stats response
    if strings.Contains(response, "STAT") && strings.Contains(response, "version") {
        return &Finding{
            TemplateID:  "memcached-unauth-check",
            Severity:    "high",
            Confidence:  95,
            Title:       "Memcached Unauthenticated Access",
            Description: fmt.Sprintf("Memcached on %s allows unauthenticated access", address),
            Evidence:    map[string]interface{}{"response": response[:min(len(response), 500)]},
            CWE:         "CWE-306",
            Remediation: "Enable SASL authentication or restrict network access",
        }
    }
    return nil
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func main() {
    target := os.Getenv("CERT_X_GEN_TARGET_HOST")
    if target == "" && len(os.Args) > 1 {
        target = os.Args[1]
    }
    
    portStr := os.Getenv("CERT_X_GEN_TARGET_PORT")
    if portStr == "" {
        portStr = "11211"
    }
    port, _ := strconv.Atoi(portStr)
    
    if target == "" {
        fmt.Fprintln(os.Stderr, "Error: No target specified")
        fmt.Println("[]")
        return
    }
    
    findings := []Finding{}
    
    if finding := checkMemcached(target, port); finding != nil {
        findings = append(findings, *finding)
    }
    
    output, _ := json.Marshal(findings)
    fmt.Println(string(output))
}
```
