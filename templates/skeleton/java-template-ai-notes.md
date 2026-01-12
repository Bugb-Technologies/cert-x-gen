# CERT-X-GEN Java Template – AI Generation Guide

## Purpose
This document provides authoritative guidance for AI systems generating Java security templates for CERT-X-GEN. Follow these rules exactly to ensure templates pass validation and execute correctly.

## Metadata Format (CRITICAL)

Templates MUST include metadata in the header using `@field:` annotations. The CLI parser extracts metadata from the first 50 lines.

```java
// CERT-X-GEN Java Template
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

import java.net.*;
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
      "response": "banner data..."
    },
    "cwe": "CWE-89",
    "remediation": "Steps to fix"
  }
]
```

### Required Finding Fields
- `template_id` - Must match `@id` from metadata
- `severity` - critical/high/medium/low/info
- `title` - Short finding title
- `description` - Detailed description

### Output Rules
- JSON goes to **stdout** via `System.out.println()` only
- Logs/errors go to **stderr** via `System.err.println()` only
- Empty findings array `[]` is valid (no vulnerability found)
- Do NOT mix human-readable text with JSON output

## Validation Requirements

Templates are validated before execution. Ensure:

### 1. Network/Socket Code
Include proper imports for network operations:
```java
import java.net.Socket;
import java.net.InetSocketAddress;
import java.io.InputStream;
import java.io.OutputStream;
```

### 2. Error Handling
Use try-catch blocks:
```java
try {
    Socket socket = new Socket();
    socket.connect(new InetSocketAddress(host, port), 5000);
} catch (IOException e) {
    System.err.println("Error: " + e.getMessage());
}
```

### 3. Timeout Handling
Set socket timeouts:
```java
socket.setSoTimeout(5000);  // Read timeout
socket.connect(address, 5000);  // Connect timeout
```

### 4. JSON Output
Use StringBuilder for manual JSON construction:
```java
StringBuilder json = new StringBuilder();
json.append("[{\"template_id\":\"").append(id).append("\"}]");
System.out.println(json.toString());
```

### 5. Entry Point
Must have `public static void main`:
```java
public static void main(String[] args) {
    // Template logic
}
```

## Code Structure

```java
// @id: template-id
// @name: Template Name
// ... (metadata)

import java.io.*;
import java.net.*;
import java.util.*;

public class Template {
    
    private static final int TIMEOUT_MS = 5000;
    
    static class Finding {
        String templateId;
        String severity;
        int confidence;
        String title;
        String description;
        String evidence;
        String cwe;
        
        String toJson() {
            return String.format(
                "{\"template_id\":\"%s\",\"severity\":\"%s\",\"confidence\":%d," +
                "\"title\":\"%s\",\"description\":\"%s\"," +
                "\"evidence\":{\"response\":\"%s\"},\"cwe\":\"%s\"}",
                templateId, severity, confidence,
                escapeJson(title), escapeJson(description),
                escapeJson(evidence), cwe
            );
        }
        
        static String escapeJson(String s) {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    default:
                        if (c >= 32 && c < 127) sb.append(c);
                        break;
                }
            }
            return sb.toString();
        }
    }
    
    public static Finding checkVulnerability(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            
            // Send probe
            out.write("PROBE\r\n".getBytes());
            out.flush();
            
            // Read response
            byte[] buffer = new byte[4096];
            int n = in.read(buffer);
            
            if (n > 0) {
                String response = new String(buffer, 0, n);
                
                if (isVulnerable(response)) {
                    Finding f = new Finding();
                    f.templateId = "template-id";
                    f.severity = "high";
                    f.confidence = 90;
                    f.title = "Vulnerability Found";
                    f.description = "Found issue on " + host + ":" + port;
                    f.evidence = response.substring(0, Math.min(response.length(), 500));
                    f.cwe = "CWE-XXX";
                    return f;
                }
            }
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
        return null;
    }
    
    private static boolean isVulnerable(String response) {
        // Your detection logic here
        return response.contains("VULNERABLE_INDICATOR");
    }
    
    public static void main(String[] args) {
        String target = System.getenv("CERT_X_GEN_TARGET_HOST");
        String portStr = System.getenv("CERT_X_GEN_TARGET_PORT");
        
        if (target == null && args.length > 0) {
            target = args[0];
        }
        int port = (portStr != null) ? Integer.parseInt(portStr) : 80;
        
        if (target == null) {
            System.err.println("Error: No target specified");
            System.out.println("[]");
            return;
        }
        
        List<Finding> findings = new ArrayList<>();
        
        Finding finding = checkVulnerability(target, port);
        if (finding != null) {
            findings.add(finding);
        }
        
        // Output JSON
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < findings.size(); i++) {
            if (i > 0) json.append(",");
            json.append(findings.get(i).toJson());
        }
        json.append("]");
        System.out.println(json.toString());
    }
}
```

## Things to AVOID

1. **No System.out.println() for debugging** - use System.err.println() instead
2. **No string == comparison** - use .equals() for strings
3. **No empty catch blocks** - always log or handle errors
4. **No resource leaks** - use try-with-resources
5. **No hardcoded targets** - always use environment/args
6. **No multi-target loops** - engine handles this
7. **No Runtime.exec()** - avoid command execution vulnerabilities

## Example: SSH Banner Grab

```java
// @id: ssh-banner-check
// @name: SSH Banner Information Disclosure
// @author: Security Team
// @severity: low
// @description: Grabs SSH banner for service identification and version detection
// @tags: ssh, banner, enumeration
// @cwe: CWE-200
// @confidence: 95

import java.io.*;
import java.net.*;
import java.util.*;

public class SSHBannerCheck {
    
    private static final int TIMEOUT_MS = 5000;
    
    static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c >= 32 && c < 127) sb.append(c);
                    break;
            }
        }
        return sb.toString();
    }
    
    public static void main(String[] args) {
        String target = System.getenv("CERT_X_GEN_TARGET_HOST");
        String portStr = System.getenv("CERT_X_GEN_TARGET_PORT");
        
        if (target == null && args.length > 0) {
            target = args[0];
        }
        int port = (portStr != null) ? Integer.parseInt(portStr) : 22;
        
        if (target == null) {
            System.err.println("Error: No target specified");
            System.out.println("[]");
            return;
        }
        
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(target, port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream())
            );
            
            String banner = reader.readLine();
            
            if (banner != null && banner.startsWith("SSH-")) {
                String json = String.format(
                    "[{\"template_id\":\"ssh-banner-check\"," +
                    "\"severity\":\"low\"," +
                    "\"confidence\":95," +
                    "\"title\":\"SSH Banner Detected\"," +
                    "\"description\":\"SSH service on %s:%d disclosed version information\"," +
                    "\"evidence\":{\"response\":\"%s\"}," +
                    "\"cwe\":\"CWE-200\"," +
                    "\"remediation\":\"Consider hiding SSH version in banner\"}]",
                    target, port, escapeJson(banner)
                );
                System.out.println(json);
            } else {
                System.out.println("[]");
            }
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            System.out.println("[]");
        }
    }
}
```
