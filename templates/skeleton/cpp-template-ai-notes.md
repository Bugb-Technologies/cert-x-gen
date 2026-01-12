# CERT-X-GEN C++ Template – AI Generation Guide

## Purpose
This document provides authoritative guidance for AI systems generating C++ security templates for CERT-X-GEN. Follow these rules exactly to ensure templates pass validation and execute correctly.

## Metadata Format (CRITICAL)

Templates MUST include metadata in the header using `@field:` annotations. The CLI parser extracts metadata from the first 50 lines.

```cpp
// CERT-X-GEN C++ Template
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

#include <iostream>
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
- JSON goes to **stdout** via `std::cout` only
- Logs/errors go to **stderr** via `std::cerr` only
- Empty findings vector `[]` is valid (no vulnerability found)
- Do NOT mix human-readable text with JSON output

## Validation Requirements

Templates are validated before execution. Ensure:

### 1. Network/Socket Code
Include proper headers for network operations:
```cpp
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
```

### 2. Error Handling
Use exception handling or check return values:
```cpp
try {
    // network operation
} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
}
```

### 3. Timeout Handling
Set socket timeouts:
```cpp
struct timeval timeout{5, 0};
setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
```

### 4. JSON Output
Use string streams or manual construction:
```cpp
std::cout << "[{\"template_id\":\"" << id << "\"}]" << std::endl;
```

### 5. Entry Point
Must have `int main()`:
```cpp
int main(int argc, char* argv[]) {
    // Template logic
    return 0;
}
```

## Code Structure

```cpp
// @id: template-id
// @name: Template Name
// ... (metadata)

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

struct Finding {
    std::string template_id;
    std::string severity;
    int confidence;
    std::string title;
    std::string description;
    std::string evidence;
    std::string cwe;
    
    std::string to_json() const {
        return "{\"template_id\":\"" + template_id + "\","
               "\"severity\":\"" + severity + "\","
               "\"confidence\":" + std::to_string(confidence) + ","
               "\"title\":\"" + title + "\","
               "\"description\":\"" + description + "\","
               "\"evidence\":{\"response\":\"" + escape_json(evidence) + "\"},"
               "\"cwe\":\"" + cwe + "\"}";
    }
    
    static std::string escape_json(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:
                    if (c >= 32 && c < 127) result += c;
                    break;
            }
        }
        return result;
    }
};

std::optional<Finding> check_vulnerability(const std::string& host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error: Socket creation failed" << std::endl;
        return std::nullopt;
    }
    
    // Set timeout
    struct timeval timeout{5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Resolve hostname
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) {
        std::cerr << "Error: Cannot resolve host" << std::endl;
        close(sock);
        return std::nullopt;
    }
    
    // Connect
    struct sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    std::memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
    
    if (connect(sock, reinterpret_cast<sockaddr*>(&server), sizeof(server)) < 0) {
        close(sock);
        return std::nullopt;
    }
    
    // Send probe
    const char* probe = "PROBE\r\n";
    send(sock, probe, strlen(probe), 0);
    
    // Receive response
    char buffer[4096];
    int n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    close(sock);
    
    if (n > 0) {
        buffer[n] = '\0';
        std::string response(buffer);
        
        if (is_vulnerable(response)) {
            Finding f;
            f.template_id = "template-id";
            f.severity = "high";
            f.confidence = 90;
            f.title = "Vulnerability Found";
            f.description = "Found issue on " + host + ":" + std::to_string(port);
            f.evidence = response.substr(0, 500);
            f.cwe = "CWE-XXX";
            return f;
        }
    }
    
    return std::nullopt;
}

int main(int argc, char* argv[]) {
    const char* target_env = std::getenv("CERT_X_GEN_TARGET_HOST");
    const char* port_env = std::getenv("CERT_X_GEN_TARGET_PORT");
    
    std::string target = target_env ? target_env : (argc > 1 ? argv[1] : "");
    int port = port_env ? std::atoi(port_env) : 80;
    
    if (target.empty()) {
        std::cerr << "Error: No target specified" << std::endl;
        std::cout << "[]" << std::endl;
        return 1;
    }
    
    std::vector<Finding> findings;
    
    if (auto finding = check_vulnerability(target, port)) {
        findings.push_back(*finding);
    }
    
    // Output JSON
    std::cout << "[";
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i > 0) std::cout << ",";
        std::cout << findings[i].to_json();
    }
    std::cout << "]" << std::endl;
    
    return 0;
}
```

## Things to AVOID

1. **No std::cout for debugging** - use std::cerr instead
2. **No raw new/delete** - use smart pointers (unique_ptr, shared_ptr)
3. **No C-style casts** - use static_cast, dynamic_cast, etc.
4. **No NULL** - use nullptr
5. **No using namespace std** in headers
6. **No hardcoded targets** - always use environment/args
7. **No multi-target loops** - engine handles this
8. **No memory leaks** - use RAII

## Example: SMTP Banner Grab

```cpp
// @id: smtp-banner-check
// @name: SMTP Banner Information Disclosure
// @author: Security Team
// @severity: low
// @description: Grabs SMTP banner for service identification
// @tags: smtp, banner, enumeration, email
// @cwe: CWE-200
// @confidence: 95

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

std::string escape_json(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            default:
                if (c >= 32 && c < 127) result += c;
                break;
        }
    }
    return result;
}

int main(int argc, char* argv[]) {
    const char* target_env = std::getenv("CERT_X_GEN_TARGET_HOST");
    const char* port_env = std::getenv("CERT_X_GEN_TARGET_PORT");
    
    std::string target = target_env ? target_env : (argc > 1 ? argv[1] : "");
    int port = port_env ? std::atoi(port_env) : 25;
    
    if (target.empty()) {
        std::cerr << "Error: No target specified" << std::endl;
        std::cout << "[]" << std::endl;
        return 1;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error: Socket creation failed" << std::endl;
        std::cout << "[]" << std::endl;
        return 1;
    }
    
    struct timeval timeout{5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    struct hostent* he = gethostbyname(target.c_str());
    if (!he) {
        std::cerr << "Error: Cannot resolve host" << std::endl;
        close(sock);
        std::cout << "[]" << std::endl;
        return 1;
    }
    
    struct sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    std::memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
    
    if (connect(sock, reinterpret_cast<sockaddr*>(&server), sizeof(server)) < 0) {
        close(sock);
        std::cout << "[]" << std::endl;
        return 0;
    }
    
    char buffer[1024];
    int n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    // Send QUIT
    send(sock, "QUIT\r\n", 6, 0);
    close(sock);
    
    if (n > 0 && buffer[0] == '2') {
        buffer[n] = '\0';
        std::string banner(buffer);
        
        std::cout << "[{"
                  << "\"template_id\":\"smtp-banner-check\","
                  << "\"severity\":\"low\","
                  << "\"confidence\":95,"
                  << "\"title\":\"SMTP Banner Detected\","
                  << "\"description\":\"SMTP service on " << target << ":" << port << " disclosed banner\","
                  << "\"evidence\":{\"response\":\"" << escape_json(banner) << "\"},"
                  << "\"cwe\":\"CWE-200\","
                  << "\"remediation\":\"Consider hiding SMTP version information\""
                  << "}]" << std::endl;
    } else {
        std::cout << "[]" << std::endl;
    }
    
    return 0;
}
```
