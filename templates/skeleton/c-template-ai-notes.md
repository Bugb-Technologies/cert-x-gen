# CERT-X-GEN C Template – AI Generation Guide

## Purpose
This document provides authoritative guidance for AI systems generating C security templates for CERT-X-GEN. Follow these rules exactly to ensure templates pass validation and execute correctly.

## Metadata Format (CRITICAL)

Templates MUST include metadata in the header using `@field:` annotations. The CLI parser extracts metadata from the first 50 lines.

```c
// CERT-X-GEN C Template
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

#include <stdio.h>
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
- JSON goes to **stdout** via `printf()` only
- Logs/errors go to **stderr** via `fprintf(stderr, ...)` only
- Empty findings array `[]` is valid (no vulnerability found)
- Do NOT mix human-readable text with JSON output

## Validation Requirements

Templates are validated before execution. Ensure:

### 1. Network/Socket Code
Include proper headers for network operations:
```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
```

### 2. Error Handling
Always check return values:
```c
int sock = socket(AF_INET, SOCK_STREAM, 0);
if (sock < 0) {
    fprintf(stderr, "Error: socket creation failed\n");
    return NULL;
}
```

### 3. Timeout Handling
Set socket timeouts:
```c
struct timeval timeout;
timeout.tv_sec = 5;
timeout.tv_usec = 0;
setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
```

### 4. JSON Output
Use manual JSON construction or a library:
```c
printf("[{\"template_id\":\"%s\",\"severity\":\"%s\"}]\n", id, severity);
```

### 5. Entry Point
Must have `int main()`:
```c
int main(int argc, char *argv[]) {
    // Template logic
    return 0;
}
```

## Code Structure

```c
// @id: template-id
// @name: Template Name
// ... (metadata)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define TIMEOUT_SEC 5
#define BUFFER_SIZE 4096

typedef struct {
    char template_id[256];
    char severity[32];
    int confidence;
    char title[256];
    char description[1024];
    char evidence[2048];
    char cwe[32];
} Finding;

void print_json_findings(Finding *findings, int count) {
    printf("[");
    for (int i = 0; i < count; i++) {
        if (i > 0) printf(",");
        printf("{\"template_id\":\"%s\",", findings[i].template_id);
        printf("\"severity\":\"%s\",", findings[i].severity);
        printf("\"confidence\":%d,", findings[i].confidence);
        printf("\"title\":\"%s\",", findings[i].title);
        printf("\"description\":\"%s\",", findings[i].description);
        printf("\"evidence\":{\"response\":\"%s\"},", findings[i].evidence);
        printf("\"cwe\":\"%s\"}", findings[i].cwe);
    }
    printf("]\n");
}

int check_vulnerability(const char *host, int port, Finding *finding) {
    int sock;
    struct sockaddr_in server;
    struct hostent *he;
    char buffer[BUFFER_SIZE];
    struct timeval timeout = {TIMEOUT_SEC, 0};
    
    // Resolve hostname
    he = gethostbyname(host);
    if (he == NULL) {
        fprintf(stderr, "Error: Cannot resolve host %s\n", host);
        return 0;
    }
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Error: Socket creation failed\n");
        return 0;
    }
    
    // Set timeouts
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Connect
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
    
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "Error: Connection failed\n");
        close(sock);
        return 0;
    }
    
    // Send probe
    send(sock, "PROBE\r\n", 7, 0);
    
    // Receive response
    int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    close(sock);
    
    if (n > 0) {
        buffer[n] = '\0';
        if (is_vulnerable(buffer)) {
            strcpy(finding->template_id, "template-id");
            strcpy(finding->severity, "high");
            finding->confidence = 90;
            strcpy(finding->title, "Vulnerability Found");
            snprintf(finding->description, sizeof(finding->description),
                     "Found issue on %s:%d", host, port);
            strncpy(finding->evidence, buffer, sizeof(finding->evidence) - 1);
            strcpy(finding->cwe, "CWE-XXX");
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    char *target = getenv("CERT_X_GEN_TARGET_HOST");
    char *port_str = getenv("CERT_X_GEN_TARGET_PORT");
    int port = 80;
    
    if (target == NULL && argc > 1) {
        target = argv[1];
    }
    if (port_str != NULL) {
        port = atoi(port_str);
    }
    
    if (target == NULL) {
        fprintf(stderr, "Error: No target specified\n");
        printf("[]\n");
        return 1;
    }
    
    Finding findings[10];
    int count = 0;
    
    if (check_vulnerability(target, port, &findings[count])) {
        count++;
    }
    
    print_json_findings(findings, count);
    return 0;
}
```

## Things to AVOID

1. **No printf() for debugging** - use fprintf(stderr, ...) instead
2. **No gets()** - use fgets() instead (buffer overflow)
3. **No strcpy()** - use strncpy() or strlcpy()
4. **No sprintf()** - use snprintf()
5. **No unchecked malloc()** - always check return value
6. **No hardcoded targets** - always use environment/args
7. **No multi-target loops** - engine handles this
8. **No memory leaks** - free all allocated memory

## Example: Telnet Banner Grab

```c
// @id: telnet-banner-check
// @name: Telnet Banner Information Disclosure
// @author: Security Team
// @severity: low
// @description: Grabs Telnet banner for service identification
// @tags: telnet, banner, enumeration
// @cwe: CWE-200
// @confidence: 95

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define TIMEOUT_SEC 5
#define BUFFER_SIZE 1024

void escape_json_string(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
        switch (src[i]) {
            case '"':  if (j < dst_size - 2) { dst[j++] = '\\'; dst[j++] = '"'; } break;
            case '\\': if (j < dst_size - 2) { dst[j++] = '\\'; dst[j++] = '\\'; } break;
            case '\n': if (j < dst_size - 2) { dst[j++] = '\\'; dst[j++] = 'n'; } break;
            case '\r': if (j < dst_size - 2) { dst[j++] = '\\'; dst[j++] = 'r'; } break;
            case '\t': if (j < dst_size - 2) { dst[j++] = '\\'; dst[j++] = 't'; } break;
            default:
                if ((unsigned char)src[i] >= 32 && (unsigned char)src[i] < 127) {
                    dst[j++] = src[i];
                }
                break;
        }
    }
    dst[j] = '\0';
}

int main(int argc, char *argv[]) {
    char *target = getenv("CERT_X_GEN_TARGET_HOST");
    char *port_str = getenv("CERT_X_GEN_TARGET_PORT");
    int port = 23;
    
    if (target == NULL && argc > 1) target = argv[1];
    if (port_str != NULL) port = atoi(port_str);
    
    if (target == NULL) {
        fprintf(stderr, "Error: No target specified\n");
        printf("[]\n");
        return 1;
    }
    
    struct hostent *he = gethostbyname(target);
    if (he == NULL) {
        fprintf(stderr, "Error: Cannot resolve host\n");
        printf("[]\n");
        return 1;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Error: Socket creation failed\n");
        printf("[]\n");
        return 1;
    }
    
    struct timeval timeout = {TIMEOUT_SEC, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
    
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        close(sock);
        printf("[]\n");
        return 0;
    }
    
    char buffer[BUFFER_SIZE];
    int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    close(sock);
    
    if (n > 0) {
        buffer[n] = '\0';
        char escaped[BUFFER_SIZE * 2];
        escape_json_string(buffer, escaped, sizeof(escaped));
        
        printf("[{");
        printf("\"template_id\":\"telnet-banner-check\",");
        printf("\"severity\":\"low\",");
        printf("\"confidence\":95,");
        printf("\"title\":\"Telnet Banner Detected\",");
        printf("\"description\":\"Telnet service on %s:%d disclosed banner\",", target, port);
        printf("\"evidence\":{\"response\":\"%s\"},", escaped);
        printf("\"cwe\":\"CWE-200\",");
        printf("\"remediation\":\"Disable Telnet and use SSH instead\"");
        printf("}]\n");
    } else {
        printf("[]\n");
    }
    
    return 0;
}
```
